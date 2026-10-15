"""
Koodous Android APK sample lookup.

Source: https://developer.koodous.com/ — Koodous indexes Android APK
samples with static analysis + crowd-sourced tags.

  Header: Authorization: Token <KOODOUS_KEY>

Endpoints:
  APK info:    GET https://developer.koodous.com/apks/<sha256>
  APK analysis: GET https://developer.koodous.com/apks/<sha256>/analysis

Response (info):
  {
    "sha256": "...", "sha1": "...", "md5": "...",
    "package_name": "...", "app": "...",
    "detected": true|false,
    "corrupted": true|false,
    "trusted": true|false,
    "size": N, "tags": [...]
  }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

_log = logging.getLogger("recon.intel.koodous")

_BASE = "https://developer.koodous.com/apks"


async def lookup_hash(session, hash_val: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"source": "koodous", "found": False,
                "error": "KOODOUS_KEY not configured",
                "error_type": "missing_key"}
    if not isinstance(hash_val, str) or not hash_val:
        return {"source": "koodous", "found": False,
                "error": "missing hash"}
    # Koodous indexes APK SHA256. Accept any hash length; the API will
    # return 404 for non-SHA256 or for samples not in the APK dataset.
    try:
        from agents.enrichment import _get
        headers = {"Authorization": f"Token {api_key}",
                    "Accept": "application/json"}
        info = await _get(session, f"{_BASE}/{hash_val}", headers=headers, timeout=10)
        analysis = await _get(session, f"{_BASE}/{hash_val}/analysis",
                                headers=headers, timeout=10)
    except Exception as e:
        return {"source": "koodous", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(info, dict):
        return {"source": "koodous", "found": False,
                "summary": "Koodous: hash not an APK or not in dataset."}
    if info.get("error") or info.get("detail") == "Not found.":
        return {"source": "koodous", "found": False,
                "summary": "Koodous: no APK record."}

    detected = bool(info.get("detected"))
    trusted = bool(info.get("trusted"))
    corrupted = bool(info.get("corrupted"))
    if detected:
        verdict = "MALICIOUS"
    elif trusted:
        verdict = "CLEAN"
    elif corrupted:
        verdict = "SUSPICIOUS"
    else:
        verdict = "UNKNOWN"

    permissions = []
    if isinstance(analysis, dict):
        perms = (((analysis.get("androguard") or {}).get("permissions"))
                  or analysis.get("permissions") or [])
        if isinstance(perms, list):
            permissions = perms[:10]

    return {
        "source":        "koodous",
        "found":         True,
        "sha256":        info.get("sha256"),
        "package_name":  info.get("package_name"),
        "app":           info.get("app"),
        "detected":      detected,
        "trusted":       trusted,
        "corrupted":     corrupted,
        "size":          info.get("size"),
        "tags":          (info.get("tags") or [])[:10],
        "permissions":   permissions,
        "details_url":   f"https://koodous.com/apks/{hash_val}",
        "verdict":       verdict,
        "summary":       (f"Koodous: APK {info.get('package_name') or '?'}"
                          + (f" — detected malicious" if detected else "")
                          + (f", trusted" if trusted else "")),
    }
