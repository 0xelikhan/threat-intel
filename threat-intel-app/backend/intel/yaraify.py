"""
abuse.ch YARAify hash lookup.

Source: https://yaraify-api.abuse.ch/ — YARAify runs YARA + ClamAV
across the abuse.ch sample pool. The hash-lookup endpoint returns
YARA rule hits and ClamAV detections for a submitted sample.

  POST https://yaraify-api.abuse.ch/api/v1/
  Headers: Auth-Key: <abuse.ch Auth-Key>
  Body:    {"query": "lookup_hash", "search_term": "<sha256|md5|sha1>"}

Response shape (query_status=="ok"):
  {
    "query_status": "ok",
    "data": [
      {
        "sha256_hash": "...",
        "file_name": "...",
        "file_size": N,
        "mime_type": "...",
        "first_seen": "...",
        "yara_rules": [
          {"rule_name": "...", "author": "...", "description": "..."},
          ...
        ],
        "clamav_results": ["Win.Trojan.Agent-...", ...]
      }
    ]
  }

Uses the same abuse.ch Auth-Key shared with URLhaus / ThreatFox /
MalwareBazaar; anonymous requests have been throttled since 2024.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

_log = logging.getLogger("recon.intel.yaraify")


async def lookup(session, hash_val: str, auth_key: str = "") -> Dict[str, Any]:
    """Return YARAify's YARA + ClamAV hits for a hash. Empty dict with
    found=False when YARAify has no record."""
    if not isinstance(hash_val, str) or not hash_val:
        return {"source": "yaraify", "found": False,
                "error": "missing hash"}
    try:
        from agents.enrichment import _post
        headers = {"Auth-Key": auth_key} if auth_key else {}
        r = await _post(
            session, "https://yaraify-api.abuse.ch/api/v1/",
            json={"query": "lookup_hash", "search_term": hash_val},
            headers=headers,
            timeout=8,
        )
    except Exception as e:
        return {"source": "yaraify", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "yaraify", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error"):
        return {"source": "yaraify", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}

    status = (r.get("query_status") or "").lower()
    if status == "no_results":
        return {"source": "yaraify", "found": False,
                "summary": f"YARAify has no record for {hash_val[:16]}..."}
    if status != "ok":
        return {"source": "yaraify", "found": False,
                "error": f"query_status={status}",
                "error_type": "api_error"}

    rows = r.get("data") or []
    if not rows:
        return {"source": "yaraify", "found": False,
                "summary": f"YARAify empty response for {hash_val[:16]}..."}
    first = rows[0]
    yara_hits = first.get("yara_rules") or []
    clam_hits = first.get("clamav_results") or []

    hit_count = len(yara_hits) + len(clam_hits)
    verdict = "MALICIOUS" if hit_count >= 1 else "UNKNOWN"

    return {
        "source":        "yaraify",
        "found":         True,
        "sha256":        first.get("sha256_hash"),
        "file_name":     first.get("file_name"),
        "file_size":     first.get("file_size"),
        "mime_type":     first.get("mime_type"),
        "first_seen":    first.get("first_seen"),
        "yara_rules":    [
            {"name": y.get("rule_name"), "author": y.get("author"),
             "description": (y.get("description") or "")[:200]}
            for y in yara_hits[:10]
        ],
        "clamav_results": clam_hits[:10],
        "details_url":   f"https://yaraify.abuse.ch/sample/{first.get('sha256_hash') or hash_val}/",
        "verdict":       verdict,
        "summary":       (f"YARAify: {len(yara_hits)} YARA rule hit"
                          f"{'s' if len(yara_hits) != 1 else ''}"
                          f", {len(clam_hits)} ClamAV detection"
                          f"{'s' if len(clam_hits) != 1 else ''}"
                          + (f" (top rule: {yara_hits[0].get('rule_name')})"
                             if yara_hits else "")),
    }
