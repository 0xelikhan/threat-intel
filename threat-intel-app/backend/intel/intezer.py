"""
Intezer Analyze hash lookup.

Source: https://analyze.intezer.com/ — code-reuse analysis + family
attribution for malware samples. Free tier available.

Auth flow:
  1. POST https://analyze.intezer.com/api/v2-0/get-access-token
     Body: {"api_key": "<INTEZER_KEY>"}
     Returns: {"result": "<jwt>"}
  2. GET https://analyze.intezer.com/api/v2-0/files/<sha256>
     Header: Authorization: Bearer <jwt>

Response (file found):
  {
    "result": {
      "sha256": "...",
      "verdict": "malicious|trusted|suspicious|unknown",
      "sub_verdict": "known_malicious|...",
      "family_name": "...",
      "family_id": "...",
      "analysis_url": "...",
      "analysis_time": "...",
      "iocs": {...}
    }
  }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

_log = logging.getLogger("recon.intel.intezer")

_BASE = "https://analyze.intezer.com/api/v2-0"


async def _get_token(session, api_key: str) -> str:
    from agents.enrichment import _post
    r = await _post(
        session, f"{_BASE}/get-access-token",
        json={"api_key": api_key},
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    if isinstance(r, dict) and r.get("result"):
        return str(r["result"])
    return ""


async def lookup_hash(session, hash_val: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"source": "intezer", "found": False,
                "error": "INTEZER_KEY not configured",
                "error_type": "missing_key"}
    if not isinstance(hash_val, str) or not hash_val:
        return {"source": "intezer", "found": False,
                "error": "missing hash"}
    try:
        token = await _get_token(session, api_key)
        if not token:
            return {"source": "intezer", "found": False,
                    "error": "token exchange failed",
                    "error_type": "auth_failed"}
        from agents.enrichment import _get
        r = await _get(
            session, f"{_BASE}/files/{hash_val}",
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/json"},
            timeout=10,
        )
    except Exception as e:
        return {"source": "intezer", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "intezer", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error") or r.get("status") == 404:
        return {"source": "intezer", "found": False,
                "summary": f"Intezer: hash not in dataset."}

    result = r.get("result") or r
    verdict_raw = (result.get("verdict") or "").lower()
    if verdict_raw in ("malicious", "known_malicious"):
        verdict = "MALICIOUS"
    elif verdict_raw == "suspicious":
        verdict = "SUSPICIOUS"
    elif verdict_raw == "trusted":
        verdict = "CLEAN"
    else:
        verdict = "UNKNOWN"

    return {
        "source":          "intezer",
        "found":           True,
        "sha256":          result.get("sha256"),
        "verdict_raw":     verdict_raw,
        "sub_verdict":     result.get("sub_verdict"),
        "family_name":     result.get("family_name"),
        "family_id":       result.get("family_id"),
        "analysis_time":   result.get("analysis_time"),
        "details_url":     result.get("analysis_url")
                             or f"https://analyze.intezer.com/analyses/{hash_val}",
        "verdict":         verdict,
        "summary":         (f"Intezer: {verdict_raw or 'unknown'}"
                            + (f" ({result.get('family_name')})"
                               if result.get("family_name") else "")),
    }
