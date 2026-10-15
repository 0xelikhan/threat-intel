"""
Hybrid Analysis (CrowdStrike Falcon Sandbox) hash + URL lookup.

Source: https://www.hybrid-analysis.com/ — CrowdStrike's public
sandbox report corpus. Free API tier: 500 req/month.

  Header: api-key: <HYBRID_ANALYSIS_KEY>
          User-Agent: Falcon Sandbox   (required)

Endpoints:
  Hash summary:    GET  https://www.hybrid-analysis.com/api/v2/overview/<sha256>
  Hash search:     GET  https://www.hybrid-analysis.com/api/v2/search/hash?hash=<hash>
  URL/term search: POST https://www.hybrid-analysis.com/api/v2/search/terms
                    Body: url=<url> or host=<domain>

Response (overview):
  {
    "sha256": "...", "classification_tags": [...],
    "verdict": "malicious|suspicious|whitelisted|no specific threat",
    "threat_score": N, "threat_level": N,
    "size": N, "type": "...", "last_file_name": "...",
    "signatures": [...], "mitre_attcks": [...]
  }
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

_log = logging.getLogger("recon.intel.hybrid_analysis")

_BASE = "https://www.hybrid-analysis.com/api/v2"
_HEADERS_BASE = {
    "User-Agent": "Falcon Sandbox",
    "Accept": "application/json",
}


def _classify(threat_score, threat_level, verdict_raw: str) -> str:
    try:
        ts = int(threat_score) if threat_score is not None else None
    except (TypeError, ValueError):
        ts = None
    try:
        tl = int(threat_level) if threat_level is not None else None
    except (TypeError, ValueError):
        tl = None
    if verdict_raw in ("malicious",) or (ts is not None and ts >= 70) or tl == 2:
        return "MALICIOUS"
    if verdict_raw in ("suspicious",) or (ts is not None and ts >= 30) or tl == 1:
        return "SUSPICIOUS"
    if verdict_raw in ("whitelisted", "no specific threat"):
        return "CLEAN"
    return "UNKNOWN"


async def lookup_hash(session, hash_val: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"source": "hybrid_analysis", "found": False,
                "error": "HYBRID_ANALYSIS_KEY not configured",
                "error_type": "missing_key"}
    if not isinstance(hash_val, str) or not hash_val:
        return {"source": "hybrid_analysis", "found": False,
                "error": "missing hash"}
    try:
        from agents.enrichment import _get
        r = await _get(
            session, f"{_BASE}/overview/{hash_val}",
            headers={**_HEADERS_BASE, "api-key": api_key},
            timeout=10,
        )
    except Exception as e:
        return {"source": "hybrid_analysis", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "hybrid_analysis", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error") or r.get("message") == "Not Found":
        return {"source": "hybrid_analysis", "found": False,
                "summary": "Hybrid Analysis: hash not in dataset."}

    verdict_raw = (r.get("verdict") or "").lower()
    threat_score = r.get("threat_score")
    threat_level = r.get("threat_level")
    verdict = _classify(threat_score, threat_level, verdict_raw)

    mitre = [
        f"{m.get('technique_id') or m.get('attck_id')} ({m.get('technique') or m.get('tactic')})"
        for m in (r.get("mitre_attcks") or [])[:5]
        if m.get("technique_id") or m.get("attck_id")
    ]
    tags = r.get("classification_tags") or []
    sigs = [
        {"name": s.get("name"), "threat_level": s.get("threat_level"),
         "category": s.get("category")}
        for s in (r.get("signatures") or [])[:6]
    ]

    return {
        "source":          "hybrid_analysis",
        "found":           True,
        "sha256":          r.get("sha256") or hash_val,
        "verdict_raw":     verdict_raw,
        "threat_score":    threat_score,
        "threat_level":    threat_level,
        "type":            r.get("type"),
        "last_file_name":  r.get("last_file_name"),
        "size":            r.get("size"),
        "classification_tags": tags[:10],
        "mitre":           mitre,
        "signatures":      sigs,
        "details_url":     f"https://www.hybrid-analysis.com/sample/{hash_val}",
        "verdict":         verdict,
        "summary":         (f"Hybrid Analysis: {verdict_raw or 'unknown'}"
                            + (f", threat_score={threat_score}"
                               if threat_score is not None else "")
                            + (f", {len(sigs)} signatures" if sigs else "")),
    }


async def _search_terms(session, key: str, value: str, api_key: str) -> Any:
    from agents.enrichment import _post
    return await _post(
        session, f"{_BASE}/search/terms",
        data=f"{key}={value}",
        headers={**_HEADERS_BASE, "api-key": api_key,
                 "Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )


def _build_from_search(payload: Any, label: str) -> Dict[str, Any]:
    if isinstance(payload, dict):
        results = payload.get("result") or payload.get("results") or []
    elif isinstance(payload, list):
        results = payload
    else:
        results = []
    if not results:
        return {"source": "hybrid_analysis", "found": False,
                "summary": f"Hybrid Analysis: no sandbox reports for {label}."}
    counts = {"MALICIOUS": 0, "SUSPICIOUS": 0, "CLEAN": 0, "UNKNOWN": 0}
    for r in results:
        if isinstance(r, dict):
            counts[_classify(r.get("threat_score"), r.get("threat_level"),
                             (r.get("verdict") or "").lower())] += 1
    if counts["MALICIOUS"]:
        verdict = "MALICIOUS"
    elif counts["SUSPICIOUS"]:
        verdict = "SUSPICIOUS"
    elif counts["CLEAN"]:
        verdict = "CLEAN"
    else:
        verdict = "UNKNOWN"
    return {
        "source":        "hybrid_analysis",
        "found":         True,
        "report_count":  len(results),
        "counts":        counts,
        "sample":        [
            {"sha256": r.get("sha256"), "verdict": r.get("verdict"),
             "threat_score": r.get("threat_score"), "last_file_name": r.get("last_file_name")}
            for r in results[:5] if isinstance(r, dict)
        ],
        "details_url":   f"https://www.hybrid-analysis.com/search?query={label}",
        "verdict":       verdict,
        "summary":       (f"Hybrid Analysis: {len(results)} report"
                          f"{'s' if len(results) != 1 else ''} for {label}"
                          + (f" ({counts['MALICIOUS']} malicious)"
                             if counts["MALICIOUS"] else "")),
    }


async def lookup_url(session, url: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"source": "hybrid_analysis", "found": False,
                "error": "HYBRID_ANALYSIS_KEY not configured",
                "error_type": "missing_key"}
    try:
        r = await _search_terms(session, "url", url, api_key)
    except Exception as e:
        return {"source": "hybrid_analysis", "error": str(e)[:120],
                "error_type": "unreachable"}
    return _build_from_search(r, url)


async def lookup_domain(session, domain: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"source": "hybrid_analysis", "found": False,
                "error": "HYBRID_ANALYSIS_KEY not configured",
                "error_type": "missing_key"}
    try:
        r = await _search_terms(session, "host", domain, api_key)
    except Exception as e:
        return {"source": "hybrid_analysis", "error": str(e)[:120],
                "error_type": "unreachable"}
    return _build_from_search(r, domain)
