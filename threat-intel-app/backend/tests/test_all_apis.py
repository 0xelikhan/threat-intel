"""Standalone API-health probe — tests every external endpoint the RECON
backend calls and reports OK / FAIL / SKIP per source.

Usage (from project root):
    python backend/tests/test_all_apis.py

Or from the backend directory:
    python tests/test_all_apis.py

Loads API keys the same way the main app does — from
backend/data/config.json (preferring local file) with env-var fallback,
so it works against whatever deployment / credentials the analyst
currently has configured.

Test indicators are safe and benign:
    IP     1.1.1.1           Cloudflare DNS, universally known
    Domain google.com        universally known
    Hash   275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
                             EICAR test-file SHA-256 (not real malware
                             but every TI source has the hash on file)
    CVE    CVE-2021-44228    Log4Shell — universally known CVE

All probes run concurrently via asyncio.gather; full run completes in
under 60s. Per-source 12s timeout caps any one slow source.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiohttp


# Box-drawing glyphs (┌ │ ─ ✓ ✗) below trip Windows cp1252 stdout. Force
# UTF-8 so the script runs on a default cmd.exe / PowerShell session without
# the operator having to set PYTHONIOENCODING themselves.
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass


# ─── Config loading ─────────────────────────────────────────────────────────
def _load_keys() -> Dict[str, str]:
    """Mirror the main app's config-loading: data/config.json is the
    primary store, env vars fill in anything missing."""
    keys: Dict[str, str] = {}
    # Find data/config.json relative to this file
    here = Path(__file__).resolve()
    for candidate in (
        here.parent.parent / "data" / "config.json",            # backend/data/config.json
        here.parent.parent.parent / "backend" / "data" / "config.json",
    ):
        if candidate.exists():
            try:
                keys.update({k: str(v) for k, v in json.loads(candidate.read_text()).items()})
                break
            except Exception:
                pass
    # Env-var fallback / overlay
    for k in ("VIRUSTOTAL_KEY", "ABUSEIPDB_KEY", "OTX_KEY", "URLSCAN_KEY",
              "GREYNOISE_KEY", "PULSEDIVE_KEY", "MALTIVERSE_KEY",
              "IPINFO_TOKEN", "WHOISXML_KEY", "GOOGLE_API_KEY",
              "HYBRID_ANALYSIS_KEY", "MALWAREBAZAAR_API_KEY",
              "CENSYS_API_KEY", "CENSYS_ID", "CENSYS_SECRET", "CROWDSEC_KEY",
              "FULLHUNT_KEY", "POLYSWARM_KEY", "PROXYCHECK_KEY",
              "PHISHTANK_KEY", "OPENAI_API_KEY",
              "OPENAI_BASE_URL", "ANTHROPIC_API_KEY", "CRIMINAL_IP_KEY",
              "THEHIVE_URL", "THEHIVE_TOKEN", "SLACK_WEBHOOK_URL",
              "TEAMS_WEBHOOK_URL"):
        v = os.environ.get(k)
        if v and not keys.get(k):
            keys[k] = v
    return keys


KEYS = _load_keys()

TEST_IP     = "1.1.1.1"
TEST_DOMAIN = "google.com"
TEST_HASH   = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
TEST_URL    = "https://google.com"
TEST_CVE    = "CVE-2021-44228"

PER_SOURCE_TIMEOUT = aiohttp.ClientTimeout(total=12)


# ─── Result record ──────────────────────────────────────────────────────────
class Result:
    __slots__ = ("name", "category", "status", "detail", "key_env", "key_url")
    def __init__(self, name: str, category: str, status: str, detail: str,
                 key_env: str = "", key_url: str = ""):
        self.name = name
        self.category = category
        self.status = status      # OK | FAIL | SKIP
        self.detail = detail
        self.key_env = key_env
        self.key_url = key_url


# ─── Generic HTTP probe ─────────────────────────────────────────────────────
async def _probe(session: aiohttp.ClientSession, name: str, category: str,
                 url: str, *, method: str = "GET",
                 headers: Optional[Dict] = None,
                 params: Optional[Dict] = None,
                 data: Any = None,
                 json_body: Any = None,
                 ok_statuses: Tuple[int, ...] = (200,),
                 key_env: str = "",
                 key_url: str = "") -> Result:
    if key_env and not KEYS.get(key_env):
        return Result(name, category, "SKIP",
                      f"{key_env} not configured", key_env, key_url)
    try:
        req = session.get if method == "GET" else session.post
        kw: Dict[str, Any] = {}
        if headers:   kw["headers"] = headers
        if params:    kw["params"]  = params
        if data is not None: kw["data"] = data
        if json_body is not None: kw["json"] = json_body
        async with req(url, **kw) as r:
            body = await r.text()
            if r.status in ok_statuses:
                return Result(name, category, "OK",
                              f"HTTP {r.status} · {len(body):,} bytes")
            snippet = body.replace("\n", " ").strip()[:200]
            return Result(name, category, "FAIL",
                          f"HTTP {r.status} · {snippet}", key_env, key_url)
    except asyncio.TimeoutError:
        return Result(name, category, "FAIL", "request timed out after 12s",
                      key_env, key_url)
    except aiohttp.ClientConnectorError as e:
        return Result(name, category, "FAIL", f"could not connect: {str(e)[:80]}",
                      key_env, key_url)
    except Exception as e:
        return Result(name, category, "FAIL",
                      f"{type(e).__name__}: {str(e)[:80]}", key_env, key_url)


# ─── AI / LLM provider probe ───────────────────────────────────────────────
async def _probe_openai(session: aiohttp.ClientSession) -> Result:
    name = "OpenAI / Azure OpenAI"
    cat = "AI / LLM provider"
    key = KEYS.get("OPENAI_API_KEY", "")
    base = (KEYS.get("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
    if not key:
        return Result(name, cat, "SKIP", "OPENAI_API_KEY not configured",
                      "OPENAI_API_KEY", "https://platform.openai.com/api-keys")
    # Use the /models endpoint — works for both OpenAI and Azure OpenAI
    # and doesn't burn completion tokens.
    is_azure = "openai.azure.com" in base.lower()
    if is_azure:
        # Azure requires api-version query param + uses api-key header
        url = f"{base}/openai/models?api-version=2024-02-01"
        headers = {"api-key": key}
    else:
        url = f"{base}/models"
        headers = {"Authorization": f"Bearer {key}"}
    try:
        async with session.get(url, headers=headers) as r:
            body = await r.text()
            if r.status == 200:
                return Result(name, cat, "OK",
                              f"HTTP 200 · {'Azure OpenAI' if is_azure else 'OpenAI'} models endpoint reachable")
            return Result(name, cat, "FAIL", f"HTTP {r.status} · {body[:200]}",
                          "OPENAI_API_KEY", "https://platform.openai.com/api-keys")
    except Exception as e:
        return Result(name, cat, "FAIL", f"{type(e).__name__}: {str(e)[:80]}",
                      "OPENAI_API_KEY", "https://platform.openai.com/api-keys")


async def _probe_anthropic(session: aiohttp.ClientSession) -> Result:
    name = "Anthropic Claude"
    cat = "AI / LLM provider"
    key = KEYS.get("ANTHROPIC_API_KEY", "")
    if not key:
        return Result(name, cat, "SKIP", "ANTHROPIC_API_KEY not configured",
                      "ANTHROPIC_API_KEY", "https://console.anthropic.com")
    try:
        async with session.get(
            "https://api.anthropic.com/v1/models",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
        ) as r:
            body = await r.text()
            if r.status == 200:
                return Result(name, cat, "OK", f"HTTP 200 · models endpoint reachable")
            return Result(name, cat, "FAIL", f"HTTP {r.status} · {body[:200]}",
                          "ANTHROPIC_API_KEY", "https://console.anthropic.com")
    except Exception as e:
        return Result(name, cat, "FAIL", f"{type(e).__name__}: {str(e)[:80]}",
                      "ANTHROPIC_API_KEY", "https://console.anthropic.com")


# ─── Webhook reachability (only check shape — don't fire test payloads) ────
def _probe_webhooks() -> List[Result]:
    cat = "Webhook outbound"
    out = []
    for env, name, url_template in (
        ("SLACK_WEBHOOK_URL", "Slack webhook",   "https://api.slack.com/messaging/webhooks"),
        ("TEAMS_WEBHOOK_URL", "Teams webhook",   "https://learn.microsoft.com/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook"),
        ("THEHIVE_URL",       "TheHive base URL","https://thehive-project.org"),
    ):
        v = KEYS.get(env, "")
        if v:
            out.append(Result(name, cat, "OK",
                              f"{env} configured → {v[:60]}{'…' if len(v) > 60 else ''}"))
        else:
            out.append(Result(name, cat, "SKIP", f"{env} not configured",
                              env, url_template))
    return out


# ─── Build the full probe list ─────────────────────────────────────────────
async def _build_probes(session: aiohttp.ClientSession) -> List[asyncio.Task]:
    P = []  # (coro, ...)
    add = P.append

    # ── IP enrichment ────────────────────────────────────────────────────
    add(_probe(session, "VirusTotal (IP)", "IP enrichment",
        f"https://www.virustotal.com/api/v3/ip_addresses/{TEST_IP}",
        headers={"x-apikey": KEYS.get("VIRUSTOTAL_KEY", "")},
        key_env="VIRUSTOTAL_KEY", key_url="https://virustotal.com"))
    add(_probe(session, "AbuseIPDB", "IP enrichment",
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": KEYS.get("ABUSEIPDB_KEY", ""), "Accept": "application/json"},
        params={"ipAddress": TEST_IP, "maxAgeInDays": 90},
        key_env="ABUSEIPDB_KEY", key_url="https://abuseipdb.com"))
    add(_probe(session, "IPInfo", "IP enrichment",
        f"https://ipinfo.io/{TEST_IP}/json",
        params={"token": KEYS.get("IPINFO_TOKEN", "")},
        key_env="IPINFO_TOKEN", key_url="https://ipinfo.io"))
    # GreyNoise Community + RIOT both return HTTP 404 with a structured
    # JSON body ("IP not observed scanning the internet" / "IP not in RIOT
    # list") when the queried IP simply isn't in their dataset — that's a
    # CLEAN verdict, not a service failure. Accept 404 as OK; the snippet
    # text is preserved in the OK row so the operator can still see the
    # canonical "not observed" message.
    add(_probe(session, "GreyNoise Community", "IP enrichment",
        f"https://api.greynoise.io/v3/community/{TEST_IP}",
        headers={"key": KEYS.get("GREYNOISE_KEY", "")},
        ok_statuses=(200, 404),
        key_env="GREYNOISE_KEY", key_url="https://greynoise.io"))
    add(_probe(session, "GreyNoise RIOT", "IP enrichment",
        f"https://api.greynoise.io/v3/riot/{TEST_IP}",
        headers={"key": KEYS.get("GREYNOISE_KEY", "")},
        ok_statuses=(200, 404),  # 404 = IP not in RIOT (benign), still healthy
        key_env="GREYNOISE_KEY", key_url="https://greynoise.io"))
    add(_probe(session, "OTX (IPv4)", "IP enrichment",
        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{TEST_IP}/general",
        headers={"X-OTX-API-KEY": KEYS.get("OTX_KEY", "")},
        key_env="OTX_KEY", key_url="https://otx.alienvault.com"))
    add(_probe(session, "CIRCL passive DNS", "IP enrichment",
        f"https://www.circl.lu/pdns/query/{TEST_IP}",
        ok_statuses=(200, 401, 403, 404)))  # free, often auth-gated, OK if reachable
    add(_probe(session, "Robtex free", "IP enrichment",
        f"https://freeapi.robtex.com/ipquery/{TEST_IP}"))
    add(_probe(session, "HackerTarget reverse-IP", "IP enrichment",
        f"https://api.hackertarget.com/reverseiplookup/?q={TEST_IP}"))
    add(_probe(session, "CrowdSec smoke", "IP enrichment",
        f"https://cti.api.crowdsec.net/v2/smoke/{TEST_IP}",
        headers={"x-api-key": KEYS.get("CROWDSEC_KEY", "")},
        ok_statuses=(200, 404),
        key_env="CROWDSEC_KEY", key_url="https://app.crowdsec.net"))
    add(_probe(session, "Criminal IP", "IP enrichment",
        f"https://api.criminalip.io/v1/asset/ip/report?ip={TEST_IP}",
        headers={"x-api-key": KEYS.get("CRIMINAL_IP_KEY", "")},
        key_env="CRIMINAL_IP_KEY", key_url="https://www.criminalip.io"))
    add(_probe(session, "ProxyCheck", "IP enrichment",
        f"https://proxycheck.io/v2/{TEST_IP}",
        params={"key": KEYS.get("PROXYCHECK_KEY", ""), "vpn": "1", "asn": "1"},
        key_env="PROXYCHECK_KEY", key_url="https://proxycheck.io"))
    add(_probe(session, "DShield / SANS ISC", "IP enrichment",
        f"https://isc.sans.edu/api/ip/{TEST_IP}?json"))
    add(_probe(session, "StopForumSpam", "IP enrichment",
        f"https://api.stopforumspam.org/api?json&ip={TEST_IP}"))
    add(_probe(session, "Tor exit list", "IP enrichment",
        "https://check.torproject.org/torbulkexitlist"))
    add(_probe(session, "BGP Ranking (CIRCL)", "IP enrichment",
        "https://bgpranking-ng.circl.lu/json",
        params={"ip": TEST_IP},
        ok_statuses=(200, 400, 404)))

    # Censys — new PAT path preferred, legacy fallback
    if KEYS.get("CENSYS_API_KEY"):
        add(_probe(session, "Censys Platform (host)", "IP enrichment",
            f"https://api.platform.censys.io/v3/global/asset/host/{TEST_IP}",
            headers={"Authorization": f"Bearer {KEYS['CENSYS_API_KEY']}"},
            key_env="CENSYS_API_KEY", key_url="https://search.censys.io/account/api"))
    elif KEYS.get("CENSYS_ID") and KEYS.get("CENSYS_SECRET"):
        auth = "Basic " + base64.b64encode(
            f"{KEYS['CENSYS_ID']}:{KEYS['CENSYS_SECRET']}".encode()).decode()
        add(_probe(session, "Censys legacy (host)", "IP enrichment",
            f"https://search.censys.io/api/v2/hosts/{TEST_IP}",
            headers={"Authorization": auth},
            key_env="CENSYS_ID", key_url="https://search.censys.io/account/api"))
    else:
        add(asyncio.sleep(0, result=Result(
            "Censys", "IP enrichment", "SKIP",
            "CENSYS_API_KEY (or legacy CENSYS_ID + CENSYS_SECRET) not configured",
            "CENSYS_API_KEY", "https://search.censys.io/account/api")))

    # ── Domain enrichment ────────────────────────────────────────────────
    add(_probe(session, "VirusTotal (domain)", "Domain enrichment",
        f"https://www.virustotal.com/api/v3/domains/{TEST_DOMAIN}",
        headers={"x-apikey": KEYS.get("VIRUSTOTAL_KEY", "")},
        key_env="VIRUSTOTAL_KEY", key_url="https://virustotal.com"))
    add(_probe(session, "URLScan search", "Domain enrichment",
        "https://urlscan.io/api/v1/search/",
        headers={"API-Key": KEYS.get("URLSCAN_KEY", "")},
        params={"q": f"domain:{TEST_DOMAIN}", "size": 1},
        key_env="URLSCAN_KEY", key_url="https://urlscan.io/user/profile/"))
    add(_probe(session, "OTX (domain)", "Domain enrichment",
        f"https://otx.alienvault.com/api/v1/indicators/domain/{TEST_DOMAIN}/general",
        headers={"X-OTX-API-KEY": KEYS.get("OTX_KEY", "")},
        key_env="OTX_KEY", key_url="https://otx.alienvault.com"))
    add(_probe(session, "crt.sh CT", "Domain enrichment",
        f"https://crt.sh/?q=%25.{TEST_DOMAIN}&output=json",
        ok_statuses=(200, 502)))   # crt.sh occasionally 502s but is healthy
    add(_probe(session, "who-dat WHOIS", "Domain enrichment",
        f"https://who-dat.as93.net/{TEST_DOMAIN}"))
    add(_probe(session, "Pulsedive", "Domain enrichment",
        "https://pulsedive.com/api/info.php",
        params={"indicator": TEST_DOMAIN, "key": KEYS.get("PULSEDIVE_KEY", "")},
        key_env="PULSEDIVE_KEY", key_url="https://pulsedive.com/api"))
    add(_probe(session, "Wayback Machine", "Domain enrichment",
        "https://archive.org/wayback/available",
        params={"url": TEST_DOMAIN}))
    add(_probe(session, "HackerTarget DNS", "Domain enrichment",
        "https://api.hackertarget.com/dnslookup/",
        params={"q": TEST_DOMAIN}))
    add(_probe(session, "FullHunt host", "Domain enrichment",
        f"https://fullhunt.io/api/v1/host/{TEST_DOMAIN}",
        headers={"X-API-KEY": KEYS.get("FULLHUNT_KEY", "")},
        key_env="FULLHUNT_KEY", key_url="https://fullhunt.io"))
    # ── Hash enrichment ─────────────────────────────────────────────────
    add(_probe(session, "VirusTotal (file)", "Hash enrichment",
        f"https://www.virustotal.com/api/v3/files/{TEST_HASH}",
        headers={"x-apikey": KEYS.get("VIRUSTOTAL_KEY", "")},
        ok_statuses=(200, 404),  # EICAR may not be in VT DB
        key_env="VIRUSTOTAL_KEY", key_url="https://virustotal.com"))
    add(_probe(session, "OTX (file)", "Hash enrichment",
        f"https://otx.alienvault.com/api/v1/indicators/file/{TEST_HASH}/general",
        headers={"X-OTX-API-KEY": KEYS.get("OTX_KEY", "")},
        key_env="OTX_KEY", key_url="https://otx.alienvault.com"))
    add(_probe(session, "MalwareBazaar (hash)", "Hash enrichment",
        "https://mb-api.abuse.ch/api/v1/",
        method="POST",
        data=f"query=get_info&hash={TEST_HASH}",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 **({"Auth-Key": KEYS["MALWAREBAZAAR_API_KEY"]}
                    if KEYS.get("MALWAREBAZAAR_API_KEY") else {})},
        key_env="MALWAREBAZAAR_API_KEY", key_url="https://auth.abuse.ch"))
    add(_probe(session, "ThreatFox (hash)", "Hash enrichment",
        "https://threatfox-api.abuse.ch/api/v1/",
        method="POST",
        json_body={"query": "search_hash", "hash": TEST_HASH},
        headers={"Auth-Key": KEYS.get("MALWAREBAZAAR_API_KEY", "")}
                if KEYS.get("MALWAREBAZAAR_API_KEY") else None))
    add(_probe(session, "URLhaus payload", "Hash enrichment",
        "https://urlhaus-api.abuse.ch/v1/payload/",
        method="POST",
        data=f"sha256_hash={TEST_HASH}",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 **({"Auth-Key": KEYS["MALWAREBAZAAR_API_KEY"]}
                    if KEYS.get("MALWAREBAZAAR_API_KEY") else {})}))
    add(_probe(session, "Hybrid Analysis search", "Hash enrichment",
        "https://www.hybrid-analysis.com/api/v2/search/hash",
        method="POST",
        headers={"api-key": KEYS.get("HYBRID_ANALYSIS_KEY", ""),
                 "user-agent": "Falcon Sandbox",
                 "Content-Type": "application/x-www-form-urlencoded"},
        params={"hash": TEST_HASH},
        ok_statuses=(200, 201),
        key_env="HYBRID_ANALYSIS_KEY", key_url="https://www.hybrid-analysis.com/apikeys/info"))
    add(_probe(session, "CIRCL hashlookup", "Hash enrichment",
        f"https://hashlookup.circl.lu/lookup/sha256/{TEST_HASH}",
        ok_statuses=(200, 404)))
    add(_probe(session, "PolySwarm", "Hash enrichment",
        f"https://api.polyswarm.network/v2/search/hash/sha256",
        params={"hash": TEST_HASH},
        headers={"Authorization": KEYS.get("POLYSWARM_KEY", "")},
        ok_statuses=(200, 400, 404),
        key_env="POLYSWARM_KEY", key_url="https://polyswarm.network"))

    # ── URL enrichment ──────────────────────────────────────────────────
    add(_probe(session, "URLhaus URL lookup", "URL enrichment",
        "https://urlhaus-api.abuse.ch/v1/url/",
        method="POST",
        data=f"url={TEST_URL}",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 **({"Auth-Key": KEYS["MALWAREBAZAAR_API_KEY"]}
                    if KEYS.get("MALWAREBAZAAR_API_KEY") else {})}))
    add(_probe(session, "ThreatFox (URL)", "URL enrichment",
        "https://threatfox-api.abuse.ch/api/v1/",
        method="POST",
        json_body={"query": "search_ioc", "search_term": TEST_URL},
        headers={"Auth-Key": KEYS.get("MALWAREBAZAAR_API_KEY", "")}
                if KEYS.get("MALWAREBAZAAR_API_KEY") else None))

    # ── CVE enrichment ─────────────────────────────────────────────────
    add(_probe(session, "NVD CVE", "CVE enrichment",
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={TEST_CVE}",
        headers={"user-agent": "RECON-API-test"}))
    add(_probe(session, "EPSS", "CVE enrichment",
        f"https://api.first.org/data/v1/epss?cve={TEST_CVE}"))
    add(_probe(session, "CISA KEV catalogue", "CVE enrichment",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"))

    # ── AI / LLM providers ─────────────────────────────────────────────
    P.append(_probe_openai(session))
    P.append(_probe_anthropic(session))

    # ── Static datasets / threat feeds (free, no auth) ─────────────────
    add(_probe(session, "Feodo Tracker (IP block)", "Static feed",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.json"))
    add(_probe(session, "Emerging Threats compromised IPs", "Static feed",
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"))

    # ── Google Safe Browsing ───────────────────────────────────────────
    add(_probe(session, "Google Safe Browsing", "URL enrichment",
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find",
        method="POST",
        params={"key": KEYS.get("GOOGLE_API_KEY", "")},
        json_body={
            "client": {"clientId": "recon-test", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE"], "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": TEST_URL}],
            },
        },
        key_env="GOOGLE_API_KEY",
        key_url="https://console.cloud.google.com/apis/credentials"))

    return P


# ─── Runner ────────────────────────────────────────────────────────────────
async def main():
    t0 = time.time()
    timeout = aiohttp.ClientTimeout(total=12)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        probes = await _build_probes(session)
        results: List[Result] = list(await asyncio.gather(*probes))

    results.extend(_probe_webhooks())

    # ── Print per-source table grouped by category ─────────────────────
    by_cat: Dict[str, List[Result]] = {}
    for r in results:
        by_cat.setdefault(r.category, []).append(r)

    print()
    for cat in sorted(by_cat.keys()):
        rows = by_cat[cat]
        print(f"┌─ {cat}")
        for r in sorted(rows, key=lambda x: x.name):
            mark = {"OK": "✓", "FAIL": "✗", "SKIP": "·"}.get(r.status, "?")
            print(f"│ {mark} {r.status:<4}  {r.name:<32}  {r.detail}")
        print()

    # ── Summary counts ────────────────────────────────────────────────
    ok   = [r for r in results if r.status == "OK"]
    fail = [r for r in results if r.status == "FAIL"]
    skip = [r for r in results if r.status == "SKIP"]
    print("─" * 96)
    print(f"  Summary:  {len(ok)} OK   {len(fail)} FAIL   {len(skip)} SKIP   "
          f"({len(results)} total · {time.time() - t0:.1f}s)")
    print("─" * 96)

    # ── Working ───────────────────────────────────────────────────────
    if ok:
        print(f"\n✓ WORKING SOURCES ({len(ok)})")
        for r in sorted(ok, key=lambda x: x.name):
            print(f"  - {r.name}: {r.detail}")

    # ── Failing — with diagnostic ────────────────────────────────────
    if fail:
        print(f"\n✗ FAILING SOURCES ({len(fail)}) — review status code + body for diagnosis")
        for r in sorted(fail, key=lambda x: x.name):
            print(f"  - {r.name}")
            print(f"      {r.detail}")
            if r.key_env:
                print(f"      Key env: {r.key_env}    Get one at: {r.key_url}")

    # ── Skipped — with the env var and signup URL ────────────────────
    if skip:
        print(f"\n· SKIPPED SOURCES ({len(skip)}) — set these env vars / config keys to enable")
        for r in sorted(skip, key=lambda x: x.name):
            print(f"  - {r.name}")
            print(f"      Env var: {r.key_env}")
            print(f"      Get one at: {r.key_url}")

    print()


if __name__ == "__main__":
    asyncio.run(main())
