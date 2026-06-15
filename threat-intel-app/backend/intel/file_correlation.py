"""
Threat-intel correlation for file analysis — spec §4 of the all-in-one
scanner plan. Runs async after static analysis completes.

For a file's hashes + extracted IOCs + imphash + format-specific metadata,
queries every configured TI source and the local case/file histories to
build a single correlation report attached to the analysis result.
"""

from __future__ import annotations

import asyncio
import aiohttp
from collections import OrderedDict
from typing import Dict, List, Optional


_TIMEOUT = aiohttp.ClientTimeout(total=15)

# Per-process scan store. Replaces the previous on-disk
# backend/data/scanned_files/*.json layout — analyst-uploaded file
# analyses are not persisted (see platform no-persistence policy). The
# UI's progressive-scan polling still works against this dict because
# the scan finishes within the lifetime of the same container; long-
# term cross-restart history is intentionally not available.
_SCAN_CAP = 500
_scan_store: "OrderedDict[str, Dict]" = OrderedDict()


def _scan_set(sha256: str, record: Dict) -> None:
    if sha256 in _scan_store:
        _scan_store.move_to_end(sha256)
    _scan_store[sha256] = record
    while len(_scan_store) > _SCAN_CAP:
        _scan_store.popitem(last=False)


# ─── public entry point ────────────────────────────────────────────────────────
async def correlate(analysis: Dict, config) -> Dict:
    """Run all TI correlations in parallel. Returns dict to merge under
    analysis['threat_intel']."""
    sha256 = (analysis.get("hashes") or {}).get("sha256")
    iocs   = analysis.get("iocs") or {}
    family_hint = None  # filled below if VT / MalwareBazaar return one

    keys = {
        "VIRUSTOTAL_KEY":      config.get("VIRUSTOTAL_KEY"),
        "HYBRID_ANALYSIS_KEY": config.get("HYBRID_ANALYSIS_KEY"),
        # abuse.ch unified Auth-Key — MalwareBazaar / ThreatFox / URLhaus all
        # use the same one. Anonymous requests have been rate-limited /
        # soft-blocked since mid-2024 so file scans were silently hitting
        # MalwareBazaar without auth and getting throttled.
        "ABUSECH_AUTH_KEY":    (config.get("ABUSECH_AUTH_KEY")
                                or config.get("MALWAREBAZAAR_API_KEY")),
    }

    out: Dict = {}

    # Full per-investigation isolation: do NOT correlate against prior scans
    # ("similar files" by sha256/imphash/tlsh/ssdeep). Each scan stands alone.

    # Reuse the process-wide TCPConnector (DNS cache + keep-alive
    # sockets + TLS sessions) instead of building a fresh pool per
    # file scan. File correlation hits 4-7 TI sources concurrently —
    # without sharing the connector, every scan paid a full TLS
    # handshake to each. connector_owner=False keeps the singleton
    # alive after this session closes.
    from agents.enrichment import _get_connector
    async with aiohttp.ClientSession(
        timeout=_TIMEOUT,
        connector=_get_connector(),
        connector_owner=False,
    ) as session:
        tasks = {
            "virustotal":      _vt_file(session, sha256, keys["VIRUSTOTAL_KEY"])  if sha256 else _noop(),
            "malwarebazaar":   _malwarebazaar(session, sha256, keys["ABUSECH_AUTH_KEY"]) if sha256 else _noop(),
            "hybrid_analysis": _hybrid_analysis(session, sha256, keys["HYBRID_ANALYSIS_KEY"]) if sha256 else _noop(),
            "feed_cache":      _feed_cache_for_iocs(iocs),
        }
        # Domain extras run only when we have domains
        if iocs.get("domains"):
            tasks["domain_intel"] = _domain_pivots(session, iocs["domains"][:5])

        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for (name, _), result in zip(tasks.items(), results):
            if isinstance(result, Exception):
                out[name] = {"error": str(result)}
            elif result:
                out[name] = result

    # Family hint propagation (used by detection content + scoring)
    for src in ("virustotal", "malwarebazaar", "hybrid_analysis"):
        v = out.get(src) or {}
        f = v.get("malware_family")
        if f and not family_hint:
            family_hint = f
    if family_hint:
        out["malware_family_consensus"] = family_hint

    # Sandbox auto-submit if HA key available + no existing report.
    # When the analysis dict carries the raw file bytes (the file
    # analyzer keeps them on _file_bytes until just before persistence),
    # kick off a fire-and-forget detonation job. The submission +
    # polling runs in the background and writes the final summary to
    # the in-memory _sandbox_results dict in intel/sandbox.py, which
    # the UI fetches via GET /api/sandbox/result/{sha256}. Used to
    # persist to backend/data/sandbox_results/{sha256}.json but the
    # no-persistence policy moved it in-process only.
    if (sha256 and keys["HYBRID_ANALYSIS_KEY"]
        and not (out.get("hybrid_analysis") and not out["hybrid_analysis"].get("error"))):
        out["sandbox_submission_eligible"] = True
        file_bytes = analysis.get("_file_bytes")
        if file_bytes:
            try:
                from intel.sandbox import auto_submit_and_poll
                filename = (analysis.get("filename")
                            or (analysis.get("file_name"))
                            or f"{sha256[:12]}.bin")
                # Don't await — the polling loop is up to 10 min and the
                # analyst is waiting on the synchronous response. Register
                # the task so the GC doesn't collect it mid-flight.
                # Import from bg_utils directly (instead of main) to avoid
                # the circular-import risk that historically forced an
                # `except Exception: asyncio.create_task(...)` fallback
                # — which created an untracked task and re-introduced the
                # exact GC-mid-flight bug track_task was built to prevent.
                from bg_utils import track_task
                track_task(asyncio.create_task(
                    auto_submit_and_poll(file_bytes, filename, sha256,
                                          keys["HYBRID_ANALYSIS_KEY"])
                ))
                out["sandbox_auto_submitted"] = True
                out["sandbox_status_path"] = f"/api/sandbox/result/{sha256}"
            except Exception as e:
                out["sandbox_auto_submit_error"] = str(e)
    return out


async def _noop():
    return None


# ─── VirusTotal ────────────────────────────────────────────────────────────────
async def _vt_file(session, sha256, key) -> Optional[Dict]:
    if not key:
        return {"error": "no VIRUSTOTAL_KEY configured"}
    try:
        async with session.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": key},
        ) as r:
            if r.status == 404:
                return {"found": False}
            if r.status != 200:
                return {"error": f"HTTP {r.status}"}
            d = await r.json()
    except Exception as e:
        return {"error": str(e)}
    attrs = (d.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    results = attrs.get("last_analysis_results") or {}
    engines = []
    for engine, info in list(results.items())[:80]:
        if isinstance(info, dict) and info.get("category") == "malicious":
            engines.append({"engine": engine, "result": info.get("result"),
                            "version": info.get("engine_version")})
    families = attrs.get("popular_threat_classification") or {}
    # Pre-compute the totals so total_engines and detection_ratio don't
    # each walk stats.values() independently.
    _total_engines = sum(stats.values())
    _mal           = stats.get("malicious", 0)
    return {
        "found":              True,
        "malicious":          _mal,
        "suspicious":         stats.get("suspicious", 0),
        "harmless":           stats.get("harmless", 0),
        "undetected":         stats.get("undetected", 0),
        "total_engines":      _total_engines,
        "detection_ratio":    f"{_mal}/{_total_engines}",
        "malware_family":     families.get("suggested_threat_label"),
        "categories":         [c.get("value") for c in (families.get("popular_threat_category") or [])][:5],
        "names":              (attrs.get("names") or [])[:10],
        "first_submission":   attrs.get("first_submission_date"),
        "last_analysis":      attrs.get("last_analysis_date"),
        "reputation":         attrs.get("reputation"),
        "tags":               attrs.get("tags") or [],
        "engine_verdicts":    engines[:25],
    }


# ─── MalwareBazaar ─────────────────────────────────────────────────────────────
async def _malwarebazaar(session, sha256, auth_key: str = "") -> Optional[Dict]:
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if auth_key:
        headers["Auth-Key"] = auth_key
    try:
        async with session.post(
            "https://mb-api.abuse.ch/api/v1/",
            data=f"query=get_info&hash={sha256}",
            headers=headers,
        ) as r:
            if r.status == 401:
                # abuse.ch rejected the Auth-Key. Make the error
                # actionable so an operator seeing the source row in
                # the UI knows the fix is to rotate the key — without
                # rotating, every MalwareBazaar/ThreatFox/URLhaus call
                # on the same key will keep failing.
                return {"error": "auth failed (HTTP 401) — rotate ABUSECH_AUTH_KEY at https://auth.abuse.ch",
                        "error_type": "auth_failed",
                        "fix_hint": "abuse.ch issues free Auth-Keys. The current key is expired or revoked."}
            if r.status != 200:
                return {"error": f"HTTP {r.status}"}
            d = await r.json()
    except Exception as e:
        return {"error": str(e)}
    if d.get("query_status") != "ok":
        return {"found": False, "status": d.get("query_status")}
    top = (d.get("data") or [{}])[0]
    return {
        "found":          True,
        "malware_family": top.get("signature"),
        "tags":           top.get("tags") or [],
        "file_type":      top.get("file_type"),
        "file_size":      top.get("file_size"),
        "first_seen":     top.get("first_seen"),
        "last_seen":      top.get("last_seen"),
        "delivery_method": top.get("delivery_method"),
        "yara_rules":     [y.get("rule_name") for y in (top.get("yara_rules") or [])][:8],
    }


# ─── Hybrid Analysis (existing report search) ─────────────────────────────────
async def _hybrid_analysis(session, sha256, key) -> Optional[Dict]:
    if not key:
        return {"error": "no HYBRID_ANALYSIS_KEY configured"}
    headers = {"api-key": key, "user-agent": "Falcon Sandbox"}
    try:
        async with session.post(
            "https://www.hybrid-analysis.com/api/v2/search/hash",
            data={"hash": sha256}, headers=headers,
        ) as r:
            if r.status != 200:
                return {"error": f"HTTP {r.status}"}
            d = await r.json()
    except Exception as e:
        return {"error": str(e)}
    if not d:
        return {"found": False}
    top = d[0] if isinstance(d, list) and d else None
    if not top:
        return {"found": False}
    return {
        "found":          True,
        "verdict":        top.get("verdict"),
        "threat_score":   top.get("threat_score"),
        "av_detect":      top.get("av_detect"),
        "malware_family": top.get("vx_family"),
        "environment":    top.get("environment_description"),
        "submit_name":    top.get("submit_name"),
        "tags":           top.get("tags") or [],
        "mitre":          [f"{t.get('technique') or ''} - {t.get('name') or ''}"
                           for t in (top.get("mitre_attcks") or [])][:8],
        "report_url":     f"https://www.hybrid-analysis.com/sample/{sha256}",
    }


# ─── feed cache (TAXII + FreshRSS) ────────────────────────────────────────────
async def _feed_cache_for_iocs(iocs: Dict) -> Optional[Dict]:
    try:
        from intel.feed_aggregator import check_ioc
    except Exception:
        return None
    hits = []
    for cat in ("ips", "domains", "urls", "hashes"):
        for v in (iocs.get(cat) or [])[:25]:
            r = check_ioc(v)
            if r:
                hits.append({"ioc": v, "type": cat, "source": r.get("source"),
                             "seen_at": r.get("seen_at")})
    return {"hits": hits, "hit_count": len(hits)} if hits else {"hit_count": 0}




def append_scan_history(analysis: Dict) -> None:
    """Stash a scan record in the per-process store so progressive AI
    polling can find it later in the same container's lifetime. No
    disk write — analyst-uploaded file content stays in memory only."""
    hashes = analysis.get("hashes") or {}
    sha = hashes.get("sha256")
    if not sha:
        return
    _scan_set(sha, analysis)


def get_scan_history() -> List[Dict]:
    return []


def load_scan(sha256: str) -> Optional[Dict]:
    return _scan_store.get(sha256)


# ─── domain pivots (WHOIS age + crt.sh) ───────────────────────────────────────
async def _domain_pivots(session, domains) -> Optional[Dict]:
    if not domains:
        return None
    results = await asyncio.gather(
        *(_one_domain_pivot(session, d) for d in domains),
        return_exceptions=True,
    )
    out = []
    for d, r in zip(domains, results):
        if isinstance(r, Exception):
            out.append({"domain": d, "error": str(r)})
        elif r:
            out.append({"domain": d, **r})
    return {"domains": out}


async def _one_domain_pivot(session, domain) -> Dict:
    pivot = {}
    # WHOIS — reuse the existing free who-dat service we already use elsewhere
    try:
        async with session.get(f"https://who-dat.as93.net/{domain}") as r:
            if r.status == 200:
                d = await r.json()
                created = ((d.get("domain") or {}).get("created_date"))
                pivot["whois_created"] = created
                if created:
                    try:
                        from datetime import datetime as dt
                        age_days = (dt.utcnow() - dt.fromisoformat(str(created).split("T")[0])).days
                        pivot["age_days"] = age_days
                        if age_days < 30:
                            pivot["nrd_flag"] = "registered_within_last_30_days"
                    except Exception:
                        pass
    except Exception:
        pass
    # crt.sh — sample of certificates for the domain
    try:
        async with session.get(f"https://crt.sh/?q={domain}&output=json") as r:
            if r.status == 200:
                d = await r.json()
                if isinstance(d, list):
                    pivot["cert_count"] = len(d)
                    pivot["subjects"] = sorted({c.get("name_value") for c in d[:30] if c.get("name_value")})[:10]
    except Exception:
        pass
    return pivot
