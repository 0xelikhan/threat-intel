"""
Hatching Triage (tria.ge) hash + URL lookup.

Source: https://tria.ge/ — cloud sandbox + public report corpus by
Hatching. Free API tier available.

  Header: Authorization: Bearer <TRIAGE_KEY>

Endpoints:
  Search:    GET https://tria.ge/api/v0/search?query=<q>
     where q = hash:<hash> or url:<url>
  Report:    GET https://tria.ge/api/v0/samples/<sample_id>/summary

Response (search):
  {
    "data": [
      {"id": "...", "status": "...", "kind": "...",
       "filename": "...", "submitted": "...", "completed": "..."}
    ],
    "next": "..."
  }
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

_log = logging.getLogger("recon.intel.triage")

_BASE = "https://tria.ge/api/v0"


async def _get_json(session, path: str, api_key: str) -> Any:
    from agents.enrichment import _get
    return await _get(
        session, f"{_BASE}/{path}",
        headers={"Authorization": f"Bearer {api_key}",
                 "Accept": "application/json"},
        timeout=10,
    )


async def _summary_for_id(session, sample_id: str, api_key: str) -> Dict[str, Any]:
    try:
        r = await _get_json(session, f"samples/{sample_id}/summary", api_key)
    except Exception:
        return {}
    if isinstance(r, dict) and not r.get("error"):
        return r
    return {}


def _classify(summary: Dict[str, Any]) -> str:
    score = summary.get("score")
    try:
        s = int(score) if score is not None else None
    except (TypeError, ValueError):
        s = None
    if s is not None:
        if s >= 8:
            return "MALICIOUS"
        if s >= 5:
            return "SUSPICIOUS"
        if s <= 2:
            return "CLEAN"
    return "UNKNOWN"


async def _run(session, query: str, label: str, api_key: str,
                kind: str) -> Dict[str, Any]:
    if not api_key:
        return {"source": "triage", "found": False,
                "error": "TRIAGE_KEY not configured",
                "error_type": "missing_key"}
    try:
        r = await _get_json(session, f"search?query={query}", api_key)
    except Exception as e:
        return {"source": "triage", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "triage", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error"):
        return {"source": "triage", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}

    hits = r.get("data") or []
    if not hits:
        return {"source": "triage", "found": False,
                "summary": f"Triage: no analyses for {label}."}
    first = hits[0] if hits else {}
    sample_id = first.get("id") if isinstance(first, dict) else None
    summary = await _summary_for_id(session, sample_id, api_key) if sample_id else {}
    verdict = _classify(summary)
    families = (summary.get("sample") or {}).get("family") or summary.get("family") or []
    if isinstance(families, str):
        families = [families]
    return {
        "source":        "triage",
        "found":         True,
        "kind":          kind,
        "report_count":  len(hits),
        "latest_id":     sample_id,
        "latest_score":  summary.get("score"),
        "families":      families[:5] if isinstance(families, list) else [],
        "tags":          (summary.get("tags") or [])[:8],
        "signatures":    [s.get("name") for s in (summary.get("signatures") or [])[:5] if s.get("name")],
        "sample":        [{"id": h.get("id"),
                           "filename": h.get("filename"),
                           "submitted": h.get("submitted")}
                           for h in hits[:5] if isinstance(h, dict)],
        "details_url":   f"https://tria.ge/s?q={label}",
        "verdict":       verdict,
        "summary":       (f"Triage: {len(hits)} analysis record"
                          f"{'s' if len(hits) != 1 else ''} for {label}"
                          + (f" (score {summary.get('score')})"
                             if summary.get("score") is not None else "")),
    }


async def lookup_hash(session, hash_val: str, api_key: str = "") -> Dict[str, Any]:
    return await _run(session, f"hash:{hash_val}", hash_val, api_key, "hash")


async def lookup_url(session, url: str, api_key: str = "") -> Dict[str, Any]:
    return await _run(session, f"url:{url}", url, api_key, "url")
