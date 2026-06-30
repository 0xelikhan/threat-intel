"""Stress probe — for each working source, fire N concurrent requests
against benign well-known indicators and report success rate, latency
percentiles, and rate-limit / circuit-breaker events.

This is NOT a pytest run — it's a runnable script that hits real
external services. Run on demand to confirm your keys + the upstream
endpoints stay healthy under realistic analyst-batch load (~10 IOCs
per investigation × a few investigations in parallel).

Usage (from project root):
    python backend/tests/stress_test_apis.py
Or from the backend directory:
    python tests/stress_test_apis.py

Tunables:
    CONCURRENCY   number of in-flight requests per source (default 20)
    REQUESTS      total requests per source (default 30)
    TIMEOUT_S     per-request wall-clock cap (default 12)

Benign test indicators (same set as test_all_apis.py):
    IP     1.1.1.1
    Domain google.com
    Hash   275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
                                          (EICAR — every TI source has it)

Output: one table per source with OK / FAIL / rate-limited counts and
p50 / p95 / max latency in ms.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiohttp


# Unicode-safe stdout for Windows cmd / PowerShell.
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass


# ─── Config loading (mirrors test_all_apis.py) ─────────────────────────────
def _load_keys() -> Dict[str, str]:
    keys: Dict[str, str] = {}
    backend_dir = Path(__file__).resolve().parent.parent
    candidates = [
        backend_dir / "data" / "config.json",
        backend_dir.parent / "backend" / "data" / "config.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            try:
                keys.update({k: str(v) for k, v in json.loads(candidate.read_text()).items()})
                break
            except Exception:
                pass
    for k in (
        "VIRUSTOTAL_KEY", "ABUSEIPDB_KEY", "OTX_KEY", "URLSCAN_KEY",
        "GREYNOISE_KEY", "PULSEDIVE_KEY", "MALTIVERSE_KEY",
        "IPINFO_TOKEN", "WHOISXML_KEY", "GOOGLE_API_KEY",
        "HYBRID_ANALYSIS_KEY", "MALWAREBAZAAR_API_KEY",
        "CENSYS_API_KEY", "CENSYS_ID", "CENSYS_SECRET",
        "PROXYCHECK_KEY", "OPENAI_API_KEY", "CRIMINAL_IP_KEY",
        "ABUSECH_AUTH_KEY",
    ):
        v = os.environ.get(k)
        if v and not keys.get(k):
            keys[k] = v
    return keys


KEYS = _load_keys()

CONCURRENCY = int(os.environ.get("STRESS_CONCURRENCY", "20"))
REQUESTS    = int(os.environ.get("STRESS_REQUESTS",    "30"))
TIMEOUT_S   = float(os.environ.get("STRESS_TIMEOUT_S", "12"))

TEST_IP     = "1.1.1.1"
TEST_DOMAIN = "google.com"
TEST_HASH   = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


# ─── Result aggregation ───────────────────────────────────────────────────
@dataclass
class Bucket:
    name: str
    ok: int = 0
    fail: int = 0
    rate_limited: int = 0
    timed_out: int = 0
    auth_failed: int = 0
    latencies_ms: List[float] = field(default_factory=list)
    sample_error: str = ""

    def add(self, status_code: int, elapsed_ms: float, body_snippet: str) -> None:
        self.latencies_ms.append(elapsed_ms)
        if status_code == 429:
            self.rate_limited += 1
            self.fail += 1
            if not self.sample_error:
                self.sample_error = f"HTTP 429 · {body_snippet[:120]}"
        elif status_code in (401, 403):
            self.auth_failed += 1
            self.fail += 1
            if not self.sample_error:
                self.sample_error = f"HTTP {status_code} · {body_snippet[:120]}"
        elif status_code == -1:
            self.timed_out += 1
            self.fail += 1
            if not self.sample_error:
                self.sample_error = "timed out"
        elif status_code >= 500:
            self.fail += 1
            if not self.sample_error:
                self.sample_error = f"HTTP {status_code} · {body_snippet[:120]}"
        else:
            self.ok += 1

    @property
    def total(self) -> int:
        return self.ok + self.fail

    @property
    def success_rate(self) -> float:
        if not self.total:
            return 0.0
        return 100.0 * self.ok / self.total

    def percentiles(self) -> Tuple[float, float, float]:
        if not self.latencies_ms:
            return 0.0, 0.0, 0.0
        s = sorted(self.latencies_ms)
        p50 = statistics.median(s)
        # Manual p95 — statistics.quantiles is awkward for small N.
        p95 = s[int(max(0, min(len(s) - 1, round(0.95 * (len(s) - 1)))))]
        return p50, p95, max(s)


# ─── Concurrency helper ────────────────────────────────────────────────────
async def _hammer(name: str, do_one, requests: int = REQUESTS,
                  concurrency: int = CONCURRENCY) -> Bucket:
    """Fire `requests` total calls of `do_one()` with `concurrency` in
    flight at a time. do_one is an async callable that returns
    (status_code, body_snippet, elapsed_ms). status_code = -1 signals
    timeout / connection error."""
    bucket = Bucket(name=name)
    sem = asyncio.Semaphore(concurrency)

    async def _one():
        async with sem:
            try:
                status, body, elapsed = await do_one()
            except asyncio.TimeoutError:
                status, body, elapsed = -1, "", TIMEOUT_S * 1000.0
            except Exception as e:
                status, body, elapsed = -1, f"{type(e).__name__}: {e}", 0.0
            bucket.add(status, elapsed, body)

    await asyncio.gather(*(_one() for _ in range(requests)))
    return bucket


# ─── Per-source probes ────────────────────────────────────────────────────
def _gen(session: aiohttp.ClientSession, url: str, *,
         headers: Optional[Dict] = None, params: Optional[Dict] = None,
         data: Any = None, method: str = "GET"):
    async def _one():
        t0 = time.perf_counter()
        async with session.request(method, url, headers=headers,
                                   params=params, data=data,
                                   timeout=aiohttp.ClientTimeout(total=TIMEOUT_S)) as r:
            body = (await r.text())[:200]
            return r.status, body, (time.perf_counter() - t0) * 1000.0
    return _one


async def _build_sources(session: aiohttp.ClientSession) -> List[Tuple[str, str, Any]]:
    """Return a list of (group, label, do_one) tuples. Each source only
    appears if its key is configured; otherwise it's silently skipped to
    avoid noise."""
    s: List[Tuple[str, str, Any]] = []
    K = KEYS

    # IP enrichment
    if K.get("VIRUSTOTAL_KEY"):
        s.append(("IP", "VirusTotal", _gen(session,
            f"https://www.virustotal.com/api/v3/ip_addresses/{TEST_IP}",
            headers={"x-apikey": K["VIRUSTOTAL_KEY"]})))
    if K.get("ABUSEIPDB_KEY"):
        s.append(("IP", "AbuseIPDB", _gen(session,
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": TEST_IP, "maxAgeInDays": 90},
            headers={"Key": K["ABUSEIPDB_KEY"], "Accept": "application/json"})))
    if K.get("IPINFO_TOKEN"):
        s.append(("IP", "IPInfo", _gen(session,
            f"https://ipinfo.io/{TEST_IP}/json",
            params={"token": K["IPINFO_TOKEN"]})))
    if K.get("GREYNOISE_KEY"):
        s.append(("IP", "GreyNoise Community", _gen(session,
            f"https://api.greynoise.io/v3/community/{TEST_IP}",
            headers={"key": K["GREYNOISE_KEY"]})))
    if K.get("OTX_KEY"):
        s.append(("IP", "OTX (IP)", _gen(session,
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{TEST_IP}/general",
            headers={"X-OTX-API-KEY": K["OTX_KEY"]})))
    if K.get("CRIMINAL_IP_KEY"):
        s.append(("IP", "Criminal IP", _gen(session,
            f"https://api.criminalip.io/v1/asset/ip/report?ip={TEST_IP}",
            headers={"x-api-key": K["CRIMINAL_IP_KEY"]})))
    if K.get("PROXYCHECK_KEY"):
        s.append(("IP", "ProxyCheck", _gen(session,
            f"https://proxycheck.io/v2/{TEST_IP}",
            params={"key": K["PROXYCHECK_KEY"], "vpn": "1", "asn": "1"})))

    # Domain enrichment
    if K.get("VIRUSTOTAL_KEY"):
        s.append(("Domain", "VirusTotal (domain)", _gen(session,
            f"https://www.virustotal.com/api/v3/domains/{TEST_DOMAIN}",
            headers={"x-apikey": K["VIRUSTOTAL_KEY"]})))
    if K.get("OTX_KEY"):
        s.append(("Domain", "OTX (domain)", _gen(session,
            f"https://otx.alienvault.com/api/v1/indicators/domain/{TEST_DOMAIN}/general",
            headers={"X-OTX-API-KEY": K["OTX_KEY"]})))
    if K.get("URLSCAN_KEY"):
        s.append(("Domain", "URLScan search", _gen(session,
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{TEST_DOMAIN}", "size": 1},
            headers={"API-Key": K["URLSCAN_KEY"]})))
    if K.get("PULSEDIVE_KEY"):
        s.append(("Domain", "Pulsedive", _gen(session,
            "https://pulsedive.com/api/info.php",
            params={"indicator": TEST_DOMAIN, "pretty": 1, "key": K["PULSEDIVE_KEY"]})))

    # Hash enrichment
    if K.get("VIRUSTOTAL_KEY"):
        s.append(("Hash", "VirusTotal (file)", _gen(session,
            f"https://www.virustotal.com/api/v3/files/{TEST_HASH}",
            headers={"x-apikey": K["VIRUSTOTAL_KEY"]})))
    if K.get("OTX_KEY"):
        s.append(("Hash", "OTX (file)", _gen(session,
            f"https://otx.alienvault.com/api/v1/indicators/file/{TEST_HASH}/general",
            headers={"X-OTX-API-KEY": K["OTX_KEY"]})))
    s.append(("Hash", "CIRCL hashlookup", _gen(session,
        f"https://hashlookup.circl.lu/lookup/sha256/{TEST_HASH}")))
    if K.get("MALWAREBAZAAR_API_KEY") or K.get("ABUSECH_AUTH_KEY"):
        auth = K.get("MALWAREBAZAAR_API_KEY") or K.get("ABUSECH_AUTH_KEY") or ""
        s.append(("Hash", "MalwareBazaar", _gen(session,
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": TEST_HASH},
            method="POST",
            headers={"Auth-Key": auth})))

    # Free / keyless
    s.append(("Free", "Robtex", _gen(session,
        f"https://freeapi.robtex.com/ipquery/{TEST_IP}")))
    s.append(("Free", "HackerTarget reverse-IP", _gen(session,
        f"https://api.hackertarget.com/reverseiplookup/?q={TEST_IP}")))
    s.append(("Free", "Wayback Machine", _gen(session,
        "https://archive.org/wayback/available",
        params={"url": TEST_DOMAIN})))
    s.append(("Free", "Feodo Tracker", _gen(session,
        "https://feodotracker.abuse.ch/downloads/ipblocklist.json")))
    s.append(("Free", "CISA KEV", _gen(session,
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")))
    s.append(("Free", "EPSS", _gen(session,
        "https://api.first.org/data/v1/epss",
        params={"cve": "CVE-2021-44228"})))
    s.append(("Free", "DShield", _gen(session,
        f"https://isc.sans.edu/api/ip/{TEST_IP}",
        params={"json": "1"})))
    s.append(("Free", "Tor exit list", _gen(session,
        "https://check.torproject.org/torbulkexitlist")))
    s.append(("Free", "StopForumSpam", _gen(session,
        f"https://api.stopforumspam.org/api?ip={TEST_IP}&json")))
    s.append(("Free", "who-dat WHOIS", _gen(session,
        f"https://who-dat.as93.net/{TEST_DOMAIN}")))
    s.append(("Free", "BGP Ranking", _gen(session,
        "https://bgpranking-ng.circl.lu/json")))
    s.append(("Free", "Emerging Threats", _gen(session,
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt")))
    s.append(("Free", "NVD CVE", _gen(session,
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": "CVE-2021-44228"})))

    return s


# ─── Runner ───────────────────────────────────────────────────────────────
async def main() -> int:
    print(f"Stress probe — {REQUESTS} requests, {CONCURRENCY} in flight, "
          f"{TIMEOUT_S}s per-request cap")
    t0 = time.time()
    connector = aiohttp.TCPConnector(limit=80, limit_per_host=20,
                                      ttl_dns_cache=300)
    async with aiohttp.ClientSession(connector=connector) as session:
        sources = await _build_sources(session)
        print(f"Configured sources: {len(sources)}")
        if not sources:
            print("No keys configured — nothing to probe.")
            return 1

        results: List[Tuple[str, Bucket]] = []
        # Run sources sequentially (not concurrently across sources) so
        # one source's quota burn doesn't cross-contaminate another.
        for group, name, do_one in sources:
            sys.stdout.write(f"  · {name:<32} ")
            sys.stdout.flush()
            bucket = await _hammer(name, do_one)
            p50, p95, pmax = bucket.percentiles()
            mark = "✓" if bucket.success_rate >= 95 else \
                   "~" if bucket.success_rate >= 75 else \
                   "✗"
            print(f"{mark} {bucket.ok}/{bucket.total} ok "
                  f"· p50 {p50:.0f}ms / p95 {p95:.0f}ms / max {pmax:.0f}ms"
                  + (f" · {bucket.rate_limited} rate-limited" if bucket.rate_limited else "")
                  + (f" · {bucket.timed_out} timed out" if bucket.timed_out else "")
                  + (f" · {bucket.auth_failed} auth-failed" if bucket.auth_failed else ""))
            results.append((group, bucket))

    elapsed = time.time() - t0
    print("\n" + "─" * 96)
    print(f"Summary · {len(results)} sources · {elapsed:.1f}s wall clock")
    print("─" * 96)

    by_group: Dict[str, List[Bucket]] = {}
    for grp, b in results:
        by_group.setdefault(grp, []).append(b)

    healthy: List[str] = []
    degraded: List[str] = []
    broken: List[str] = []
    for _grp, b in results:
        if b.success_rate >= 95:
            healthy.append(b.name)
        elif b.success_rate >= 75:
            degraded.append(b.name)
        else:
            broken.append(b.name)

    print(f"\n  ✓ Healthy (≥95%): {len(healthy)}")
    if healthy:
        for n in healthy:
            print(f"      - {n}")
    print(f"\n  ~ Degraded (75-94%): {len(degraded)}")
    for n in degraded:
        b = next(x[1] for x in results if x[1].name == n)
        print(f"      - {n}  ({b.success_rate:.0f}% ok, {b.sample_error or 'no detail'})")
    print(f"\n  ✗ Broken (<75%): {len(broken)}")
    for n in broken:
        b = next(x[1] for x in results if x[1].name == n)
        print(f"      - {n}  ({b.success_rate:.0f}% ok, {b.sample_error or 'no detail'})")

    return 0 if not broken else 2


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
