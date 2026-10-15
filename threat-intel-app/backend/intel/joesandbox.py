"""
Joe Sandbox Cloud hash + URL lookup.

Source: https://www.joesandbox.com/ — commercial sandbox with free
tier (Joe Sandbox Cloud Basic). API key passed as a form field, not
a header.

  POST https://jbxcloud.joesecurity.org/api/v2/analysis/search
  Body: apikey=<KEY>&q=<hash|url>

Response:
  {
    "data": [
      {"webid": "...", "md5": "...", "sha1": "...", "sha256": "...",
       "filename": "...", "detection": "malicious|suspicious|clean|unknown",
       "threatname": "...", "time": "..."}
    ]
  }

Report deep-link uses webid: https://jbxcloud.joesecurity.org/analysis/<webid>
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

_log = logging.getLogger("recon.intel.joesandbox")

_BASE = "https://jbxcloud.joesecurity.org/api/v2"


async def _search(session, query: str, api_key: str) -> Any:
    from agents.enrichment import _post
    return await _post(
        session, f"{_BASE}/analysis/search",
        data=f"apikey={api_key}&q={query}",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )


def _classify(records: List[Dict[str, Any]]) -> str:
    counts = {"MALICIOUS": 0, "SUSPICIOUS": 0, "CLEAN": 0, "UNKNOWN": 0}
    for r in records:
        d = (r.get("detection") or "").lower()
        if d == "malicious":
            counts["MALICIOUS"] += 1
        elif d == "suspicious":
            counts["SUSPICIOUS"] += 1
        elif d == "clean":
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


async def _run(session, query: str, label: str, api_key: str,
                kind: str) -> Dict[str, Any]:
    if not api_key:
        return {"source": "joesandbox", "found": False,
                "error": "JOESANDBOX_KEY not configured",
                "error_type": "missing_key"}
    try:
        r = await _search(session, query, api_key)
    except Exception as e:
        return {"source": "joesandbox", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "joesandbox", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error"):
        return {"source": "joesandbox", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    records = r.get("data") or []
    if not records:
        return {"source": "joesandbox", "found": False,
                "summary": f"Joe Sandbox: no analyses for {label}."}
    rec_dicts = [x for x in records if isinstance(x, dict)]
    verdict = _classify(rec_dicts)
    first = rec_dicts[0] if rec_dicts else {}
    threat_names = sorted({r.get("threatname") for r in rec_dicts if r.get("threatname")})
    return {
        "source":        "joesandbox",
        "found":         True,
        "kind":          kind,
        "report_count":  len(rec_dicts),
        "latest_webid":  first.get("webid"),
        "latest_detection": first.get("detection"),
        "threat_names":  list(threat_names)[:5],
        "sample":        [
            {"webid": r.get("webid"),
             "filename": r.get("filename"),
             "detection": r.get("detection"),
             "threatname": r.get("threatname"),
             "time": r.get("time")}
            for r in rec_dicts[:5]
        ],
        "details_url":   (f"https://jbxcloud.joesecurity.org/analysis/{first.get('webid')}"
                           if first.get("webid")
                           else f"https://jbxcloud.joesecurity.org/search?q={label}"),
        "verdict":       verdict,
        "summary":       (f"Joe Sandbox: {len(rec_dicts)} analysis record"
                          f"{'s' if len(rec_dicts) != 1 else ''}"
                          + (f" (latest: {first.get('detection')})"
                             if first.get("detection") else "")),
    }


async def lookup_hash(session, hash_val: str, api_key: str = "") -> Dict[str, Any]:
    return await _run(session, hash_val, hash_val, api_key, "hash")


async def lookup_url(session, url: str, api_key: str = "") -> Dict[str, Any]:
    return await _run(session, url, url, api_key, "url")
