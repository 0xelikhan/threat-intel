"""
MWDB (CERT.pl Malware repository) hash lookup.

Source: https://mwdb.cert.pl/ — CERT Polska's malware repository with
rich metadata, YARA matches, config extraction, and family tags.
Free account required for API access.

  Header: Authorization: Bearer <MWDB_KEY>

Endpoints:
  File metadata: GET https://mwdb.cert.pl/api/file/<sha256>
  Attributes:    GET https://mwdb.cert.pl/api/object/<sha256>/attribute

Response (file):
  {
    "id": "...", "sha256": "...", "md5": "...", "sha1": "...",
    "file_name": "...", "file_size": N, "file_type": "...",
    "tags": [{"tag": "..."}, ...],
    "parents": [...], "children": [...],
    "upload_time": "...", "latest_config": {...}
  }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

_log = logging.getLogger("recon.intel.mwdb")

_BASE = "https://mwdb.cert.pl/api"


async def lookup_hash(session, hash_val: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"source": "mwdb", "found": False,
                "error": "MWDB_KEY not configured",
                "error_type": "missing_key"}
    if not isinstance(hash_val, str) or not hash_val:
        return {"source": "mwdb", "found": False,
                "error": "missing hash"}
    try:
        from agents.enrichment import _get
        r = await _get(
            session, f"{_BASE}/file/{hash_val}",
            headers={"Authorization": f"Bearer {api_key}",
                     "Accept": "application/json"},
            timeout=10,
        )
    except Exception as e:
        return {"source": "mwdb", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "mwdb", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("message") in ("Object not found", "Not Found") or r.get("status") == 404:
        return {"source": "mwdb", "found": False,
                "summary": "MWDB: hash not in repository."}
    if r.get("error") or r.get("errors"):
        return {"source": "mwdb",
                "error": r.get("error") or (r.get("errors") or [{}])[0].get("message", "API error"),
                "error_type": "api_error"}

    tags = [t.get("tag") for t in (r.get("tags") or []) if isinstance(t, dict) and t.get("tag")]
    config = r.get("latest_config") or {}
    family = config.get("family")
    children_count = len(r.get("children") or [])
    parents_count = len(r.get("parents") or [])

    # MWDB records are malware repository entries by definition — the mere
    # presence of a record is a strong "this is malware" signal, especially
    # when a config was extracted.
    verdict = "MALICIOUS" if (family or config) else "SUSPICIOUS"

    return {
        "source":          "mwdb",
        "found":           True,
        "sha256":          r.get("sha256"),
        "file_name":       r.get("file_name"),
        "file_size":       r.get("file_size"),
        "file_type":       r.get("file_type"),
        "tags":            tags[:10],
        "family":          family,
        "config_type":     config.get("type"),
        "config_present":  bool(config),
        "parents_count":   parents_count,
        "children_count":  children_count,
        "upload_time":     r.get("upload_time"),
        "details_url":     f"https://mwdb.cert.pl/file/{hash_val}",
        "verdict":         verdict,
        "summary":         (f"MWDB: {r.get('file_name') or 'sample'}"
                            + (f" ({family})" if family else "")
                            + (f", {len(tags)} tag" + ("s" if len(tags) != 1 else "")
                               if tags else "")),
    }
