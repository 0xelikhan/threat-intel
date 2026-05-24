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
from typing import Dict, List, Optional

from pathlib import Path

_TIMEOUT = aiohttp.ClientTimeout(total=15)
_SCAN_HISTORY_DIR = Path(__file__).resolve().parents[1] / "data" / "scanned_files"
_SCAN_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
_SCAN_INDEX = _SCAN_HISTORY_DIR / "index.json"


# ─── public entry point ────────────────────────────────────────────────────────
async def correlate(analysis: Dict, config) -> Dict:
    """Run all TI correlations in parallel. Returns dict to merge under
    analysis['threat_intel']."""
    sha256 = (analysis.get("hashes") or {}).get("sha256")
    md5    = (analysis.get("hashes") or {}).get("md5")
    iocs   = analysis.get("iocs") or {}
    pe     = (analysis.get("format_specific") or {}).get("pe") or {}
    imphash = pe.get("imphash")
    tlsh   = (analysis.get("hashes") or {}).get("tlsh")
    ssdeep_h = (analysis.get("hashes") or {}).get("ssdeep")
    family_hint = None  # filled below if VT / MalwareBazaar return one

    keys = {
        "VIRUSTOTAL_KEY":      config.get("VIRUSTOTAL_KEY"),
        "HYBRID_ANALYSIS_KEY": config.get("HYBRID_ANALYSIS_KEY"),
        "ANYRUN_KEY":          config.get("ANYRUN_KEY"),
    }

    out: Dict = {}

    # Synchronous lookups first (no I/O)
    scan_hist = _scan_history_match(sha256, imphash, tlsh, ssdeep_h)
    if scan_hist:
        out["scan_history"] = scan_hist

    async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
        tasks = {
            "virustotal":      _vt_file(session, sha256, keys["VIRUSTOTAL_KEY"])  if sha256 else _noop(),
            "malwarebazaar":   _malwarebazaar(session, sha256)                    if sha256 else _noop(),
            "hybrid_analysis": _hybrid_analysis(session, sha256, keys["HYBRID_ANALYSIS_KEY"]) if sha256 else _noop(),
            "anyrun":          _anyrun(session, sha256, keys["ANYRUN_KEY"])       if sha256 else _noop(),
            "feed_cache":      _feed_cache_for_iocs(iocs),
            "case_history":    _case_history_for(sha256, iocs),
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

    # Sandbox auto-submit if HA key available + no existing report
    if (sha256 and keys["HYBRID_ANALYSIS_KEY"]
        and not (out.get("hybrid_analysis") and not out["hybrid_analysis"].get("error"))):
        out["sandbox_submission_eligible"] = True
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
    return {
        "found":              True,
        "malicious":          stats.get("malicious", 0),
        "suspicious":         stats.get("suspicious", 0),
        "harmless":           stats.get("harmless", 0),
        "undetected":         stats.get("undetected", 0),
        "total_engines":      sum(stats.values()),
        "detection_ratio":    f"{stats.get('malicious', 0)}/{sum(stats.values())}",
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
async def _malwarebazaar(session, sha256) -> Optional[Dict]:
    try:
        async with session.post(
            "https://mb-api.abuse.ch/api/v1/",
            data=f"query=get_info&hash={sha256}",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ) as r:
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
        "mitre":          [t.get("technique") + " - " + t.get("name", "")
                           for t in (top.get("mitre_attcks") or [])][:8],
        "report_url":     f"https://www.hybrid-analysis.com/sample/{sha256}",
    }


# ─── ANY.RUN public reports ────────────────────────────────────────────────────
async def _anyrun(session, sha256, key) -> Optional[Dict]:
    if not key:
        return None
    try:
        async with session.get(
            "https://api.any.run/v1/analysis",
            params={"hash": sha256, "skip": 0, "limit": 1},
            headers={"Authorization": f"API-Key {key}"},
        ) as r:
            if r.status != 200:
                return {"error": f"HTTP {r.status}"}
            d = await r.json()
    except Exception as e:
        return {"error": str(e)}
    tasks = ((d or {}).get("data") or {}).get("tasks") or []
    if not tasks:
        return {"found": False}
    t = tasks[0]
    return {
        "found":        True,
        "verdict":      t.get("verdict") or (t.get("scores") or {}).get("verdict", {}).get("threatLevelText"),
        "threat_score": (t.get("scores") or {}).get("verdict", {}).get("score"),
        "uuid":         t.get("uuid"),
        "report_url":   f"https://app.any.run/tasks/{t.get('uuid')}",
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


# ─── case history search ──────────────────────────────────────────────────────
async def _case_history_for(sha256: Optional[str], iocs: Dict) -> Optional[Dict]:
    try:
        from intel.case_store import search_cases
    except Exception:
        return None
    related = []
    if sha256:
        related.extend(search_cases(sha256, limit=10))
    for cat in ("ips", "domains", "urls"):
        for v in (iocs.get(cat) or [])[:5]:
            for c in search_cases(v, limit=5):
                if c not in related:
                    related.append(c)
    if not related:
        return {"related_cases": 0}
    return {
        "related_cases": len(related),
        "cases": [
            {"runId": c.get("runId"), "label": c.get("label"),
             "threat_level": c.get("threat_level"), "timestamp": c.get("timestamp"),
             "summary": (c.get("summary") or "")[:160]}
            for c in related[:10]
        ],
    }


# ─── prior scan history (file scanner's own index) ────────────────────────────
def _scan_history_match(sha256, imphash, tlsh_h, ssdeep_h) -> Optional[Dict]:
    """Look up any prior file scans matching by exact sha256, imphash, or
    fuzzy hash (TLSH numeric distance, ssdeep score)."""
    import json
    if not _SCAN_INDEX.exists():
        return None
    try:
        with open(_SCAN_INDEX, encoding="utf-8") as f:
            idx = json.load(f)
    except Exception:
        return None
    if not isinstance(idx, list):
        return None

    matches = {"exact": [], "imphash": [], "tlsh_similar": [], "ssdeep_similar": []}
    for entry in idx:
        e_sha    = entry.get("sha256")
        e_imp    = entry.get("imphash")
        e_tlsh   = entry.get("tlsh")
        e_ssdeep = entry.get("ssdeep")
        if sha256 and e_sha == sha256:
            matches["exact"].append(entry)
            continue
        if imphash and e_imp and e_imp == imphash:
            matches["imphash"].append(entry)
        if tlsh_h and e_tlsh:
            try:
                import tlsh
                d = tlsh.diff(tlsh_h, e_tlsh)
                if d < 60:  # tighter = more similar
                    matches["tlsh_similar"].append({**entry, "tlsh_distance": d})
            except Exception:
                pass
        if ssdeep_h and e_ssdeep:
            try:
                import ssdeep
                score = ssdeep.compare(ssdeep_h, e_ssdeep)
                if score > 50:
                    matches["ssdeep_similar"].append({**entry, "ssdeep_score": score})
            except Exception:
                pass

    matches["imphash"]        = matches["imphash"][:10]
    matches["tlsh_similar"]   = sorted(matches["tlsh_similar"], key=lambda x: x.get("tlsh_distance", 999))[:10]
    matches["ssdeep_similar"] = sorted(matches["ssdeep_similar"], key=lambda x: -x.get("ssdeep_score", 0))[:10]
    total = sum(len(v) for v in matches.values())
    return matches if total else {"exact": [], "imphash": [], "tlsh_similar": [], "ssdeep_similar": []}


def append_scan_history(analysis: Dict) -> None:
    """Persist a scan record so future analyses can correlate against it.
    Stored at backend/data/scanned_files/index.json (gitignored)."""
    import json
    hashes = analysis.get("hashes") or {}
    if not hashes.get("sha256"):
        return
    entry = {
        "sha256":    hashes.get("sha256"),
        "md5":       hashes.get("md5"),
        "sha1":      hashes.get("sha1"),
        "tlsh":      hashes.get("tlsh"),
        "ssdeep":    hashes.get("ssdeep"),
        "imphash":   ((analysis.get("format_specific") or {}).get("pe") or {}).get("imphash"),
        "filename":  analysis.get("filename"),
        "size":      analysis.get("size"),
        "analyzed_at": analysis.get("analyzed_at"),
        "verdict":   analysis.get("verdict"),
        "confidence": analysis.get("confidence"),
        "yara_match_count": len(analysis.get("yara_matches") or []),
    }
    try:
        idx = []
        if _SCAN_INDEX.exists():
            with open(_SCAN_INDEX, encoding="utf-8") as f:
                idx = json.load(f) or []
        # Replace any existing entry for this hash, else prepend
        idx = [e for e in idx if e.get("sha256") != entry["sha256"]]
        idx.insert(0, entry)
        idx = idx[:1000]
        with open(_SCAN_INDEX, "w", encoding="utf-8") as f:
            json.dump(idx, f, indent=2, default=str)
        # Full record per file (so the UI can re-load any prior scan)
        with open(_SCAN_HISTORY_DIR / f"{entry['sha256']}.json", "w", encoding="utf-8") as f:
            json.dump(analysis, f, indent=2, default=str)
    except Exception:
        pass


def get_scan_history() -> List[Dict]:
    import json
    if not _SCAN_INDEX.exists():
        return []
    try:
        with open(_SCAN_INDEX, encoding="utf-8") as f:
            return json.load(f) or []
    except Exception:
        return []


def load_scan(sha256: str) -> Optional[Dict]:
    import json
    p = _SCAN_HISTORY_DIR / f"{sha256}.json"
    if not p.exists():
        return None
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


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
