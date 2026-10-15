"""
FileScan.io hash + URL + IP + domain lookup.

Source: https://www.filescan.io/ — OPSWAT MetaDefender's community
sandbox. Free API tier: 500 req/month.

  GET https://www.filescan.io/api/reports/search?query=<b64>
  Header: X-Api-Key: <FILESCAN_KEY>

The query is a base64-encoded IOC (hash / URL / IP / domain) — the
search endpoint matches across all public reports.

Response:
  {
    "query": "...",
    "count": N,
    "reports": [
      {"report_id": "...", "file": {...}, "verdict": "informational|likely-malicious|malicious", "..."}
    ]
  }
"""

from __future__ import annotations

import base64
import logging
from typing import Any, Dict, List

_log = logging.getLogger("recon.intel.filescan")

_BASE = "https://www.filescan.io/api/reports/search"


def _classify(reports: List[Dict[str, Any]]) -> str:
    counts = {"MALICIOUS": 0, "SUSPICIOUS": 0, "CLEAN": 0, "UNKNOWN": 0}
    for r in reports:
        v = (r.get("verdict") or "").lower()
        if "malicious" in v and "likely" not in v:
            counts["MALICIOUS"] += 1
        elif "likely-malicious" in v or "suspicious" in v:
            counts["SUSPICIOUS"] += 1
        elif v in ("informational", "clean", "benign"):
            counts["CLEAN"] += 1
        else:
            counts["UNKNOWN"] += 1
    if counts["MALICIOUS"]:
        return "MALICIOUS"
    if counts["SUSPICIOUS"]:
        return "SUSPICIOUS"
    if counts["CLEAN"]:
        return "CLEAN"
    return "UNKNOWN"


async def _run(session, ioc: str, label: str, api_key: str) -> Dict[str, Any]:
    if not api_key:
        return {"source": "filescan", "found": False,
                "error": "FILESCAN_KEY not configured",
                "error_type": "missing_key"}
    if not isinstance(ioc, str) or not ioc:
        return {"source": "filescan", "found": False,
                "error": "missing ioc"}
    b64 = base64.b64encode(ioc.encode()).decode()
    try:
        from agents.enrichment import _get
        r = await _get(
            session, f"{_BASE}?query={b64}",
            headers={"X-Api-Key": api_key, "Accept": "application/json"},
            timeout=10,
        )
    except Exception as e:
        return {"source": "filescan", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "filescan", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error"):
        return {"source": "filescan", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}

    reports = r.get("reports") or r.get("items") or r.get("data") or []
    if not reports:
        return {"source": "filescan", "found": False,
                "summary": f"FileScan: no reports for {label}."}
    verdict = _classify([x for x in reports if isinstance(x, dict)])
    first = reports[0] if isinstance(reports, list) and reports else {}
    return {
        "source":        "filescan",
        "found":         True,
        "report_count":  r.get("count") or len(reports),
        "latest_id":     (first.get("report_id") if isinstance(first, dict) else None),
        "latest_verdict": (first.get("verdict") if isinstance(first, dict) else None),
        "sample":        [
            {"report_id": x.get("report_id"),
             "verdict": x.get("verdict"),
             "file": (x.get("file") or {}).get("name"),
             "scan_date": x.get("date") or x.get("scan_date")}
            for x in reports[:5] if isinstance(x, dict)
        ],
        "details_url":   f"https://www.filescan.io/search?query={label}",
        "verdict":       verdict,
        "summary":       (f"FileScan: {len(reports)} report"
                          f"{'s' if len(reports) != 1 else ''} for {label}"),
    }


async def lookup_hash(session, hash_val: str, api_key: str = "") -> Dict[str, Any]:
    return await _run(session, hash_val, hash_val, api_key)


async def lookup_url(session, url: str, api_key: str = "") -> Dict[str, Any]:
    return await _run(session, url, url, api_key)


async def lookup_domain(session, domain: str, api_key: str = "") -> Dict[str, Any]:
    return await _run(session, domain, domain, api_key)


async def lookup_ip(session, ip: str, api_key: str = "") -> Dict[str, Any]:
    return await _run(session, ip, ip, api_key)
