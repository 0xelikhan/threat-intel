"""
URLdna URL analysis / scan lookup.

Source: https://urldna.io/ — URLdna performs sandboxed URL analysis
and returns reputation + screenshots. We only hit the SEARCH endpoint
for existing public scans, not NEW_SCAN (which takes 5-10s).

  GET  https://api.urldna.io/scan/search?submitted_url=<url>
  Header: Authorization: <URLDNA_KEY>

Response: array of scan records (shape varies by API version). We
surface: scan uuid, submitted_url, final_url, verdict (clean/
suspicious/malicious), threat tags, screenshot_url, scan_date.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List
from urllib.parse import quote

_log = logging.getLogger("recon.intel.urldna")

_BASE = "https://api.urldna.io"


async def _search(session, query: str, api_key: str) -> Any:
    from agents.enrichment import _get
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "RECON-ThreatIntel/1.0",
        "Authorization": api_key,
    }
    url = f"{_BASE}/scan/search?submitted_url={quote(query, safe='')}"
    return await _get(session, url, headers=headers, timeout=8)


def _build(records: List[Dict[str, Any]], label: str) -> Dict[str, Any]:
    if not records:
        return {"source": "urldna", "found": False,
                "summary": f"URLdna: no scans found for {label}."}
    # Pick the most recent scan with a verdict
    with_verdict = [r for r in records if r.get("verdict") or r.get("classification")]
    first = (with_verdict or records)[0]
    verdict_raw = ((first.get("verdict") or first.get("classification") or "")
                   .strip().upper())
    if verdict_raw in ("MALICIOUS", "PHISHING", "MALWARE"):
        verdict = "MALICIOUS"
    elif verdict_raw in ("SUSPICIOUS", "WARN"):
        verdict = "SUSPICIOUS"
    elif verdict_raw in ("CLEAN", "SAFE"):
        verdict = "CLEAN"
    else:
        verdict = "UNKNOWN"
    tags = first.get("threat_tags") or first.get("tags") or []
    return {
        "source":        "urldna",
        "found":         True,
        "scan_count":    len(records),
        "latest_scan_id": first.get("uuid") or first.get("id"),
        "submitted_url": first.get("submitted_url"),
        "final_url":     first.get("final_url"),
        "scan_date":     first.get("scan_date") or first.get("date"),
        "screenshot":    first.get("screenshot_url") or first.get("screenshot"),
        "threat_tags":   tags[:8] if isinstance(tags, list) else [],
        "details_url":   (f"https://urldna.io/scan/{first.get('uuid') or first.get('id')}"
                           if first.get("uuid") or first.get("id")
                           else f"https://urldna.io/search?q={label}"),
        "verdict":       verdict,
        "summary":       (f"URLdna: {len(records)} public scan"
                          f"{'s' if len(records) != 1 else ''}"
                          + (f" (latest: {verdict_raw.lower()})"
                             if verdict_raw else "")),
    }


async def _run(session, query: str, label: str, api_key: str) -> Dict[str, Any]:
    if not api_key:
        return {"source": "urldna", "found": False,
                "error": "URLDNA_KEY not configured",
                "error_type": "missing_key"}
    if not isinstance(query, str) or not query:
        return {"source": "urldna", "found": False,
                "error": "missing query"}
    try:
        r = await _search(session, query, api_key)
    except Exception as e:
        return {"source": "urldna", "error": str(e)[:120],
                "error_type": "unreachable"}
    if isinstance(r, dict) and r.get("error"):
        return {"source": "urldna", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    if isinstance(r, dict):
        # Some endpoints return {"results": [...]} wrappers
        inner = r.get("results") or r.get("scans") or r.get("data")
        if isinstance(inner, list):
            return _build([e for e in inner if isinstance(e, dict)], label)
        return {"source": "urldna", "found": False,
                "summary": f"URLdna: unexpected shape for {label}."}
    if isinstance(r, list):
        return _build([e for e in r if isinstance(e, dict)], label)
    return {"source": "urldna", "found": False,
            "summary": f"URLdna: unexpected shape for {label}."}


async def lookup_url(session, url: str, api_key: str = "") -> Dict[str, Any]:
    return await _run(session, url, url, api_key)


async def lookup_domain(session, domain: str, api_key: str = "") -> Dict[str, Any]:
    return await _run(session, domain, domain, api_key)
