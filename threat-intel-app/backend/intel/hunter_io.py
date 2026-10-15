"""
Hunter.io domain email enumeration.

Source: https://hunter.io/ — enumerates known email addresses + roles
+ patterns for a given domain. Useful for BEC / phishing-reconnaissance
pivots. Free tier: 25 req/month, 50 email results per query.

  GET https://api.hunter.io/v2/domain-search?domain=<domain>&api_key=<KEY>

Response:
  {
    "data": {
      "domain": "...",
      "organization": "...",
      "country": "...",
      "pattern": "{first}.{last}",
      "disposable": false,
      "webmail": false,
      "emails": [
        {"value": "...", "type": "personal|generic",
         "confidence": N, "first_name": "...", "last_name": "...",
         "position": "...", "department": "...",
         "sources": [...]},
        ...
      ],
      "linked_domains": [...]
    }
  }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

_log = logging.getLogger("recon.intel.hunter_io")


async def lookup_domain(session, domain: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"source": "hunter_io", "found": False,
                "error": "HUNTER_IO_KEY not configured",
                "error_type": "missing_key"}
    if not isinstance(domain, str) or not domain:
        return {"source": "hunter_io", "found": False,
                "error": "missing domain"}
    try:
        from agents.enrichment import _get
        r = await _get(
            session,
            f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}&limit=25",
            headers={"Accept": "application/json"},
            timeout=10,
        )
    except Exception as e:
        return {"source": "hunter_io", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "hunter_io", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("errors"):
        err = r["errors"][0] if isinstance(r.get("errors"), list) and r["errors"] else {}
        return {"source": "hunter_io",
                "error": err.get("details") or err.get("error") or "API error",
                "error_type": "api_error"}
    if r.get("error"):
        return {"source": "hunter_io", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}

    data = r.get("data") or {}
    emails = data.get("emails") or []
    if not data.get("domain") and not emails:
        return {"source": "hunter_io", "found": False,
                "summary": f"Hunter.io: no email records for {domain}."}

    personal_count = sum(1 for e in emails if e.get("type") == "personal")
    generic_count = sum(1 for e in emails if e.get("type") == "generic")

    return {
        "source":          "hunter_io",
        "found":           True,
        "organization":    data.get("organization"),
        "country":         data.get("country"),
        "pattern":         data.get("pattern"),
        "disposable":      bool(data.get("disposable")),
        "webmail":         bool(data.get("webmail")),
        "email_count":     len(emails),
        "personal_count":  personal_count,
        "generic_count":   generic_count,
        "linked_domains":  (data.get("linked_domains") or [])[:5],
        "emails":          [
            {"value": e.get("value"),
             "type": e.get("type"),
             "confidence": e.get("confidence"),
             "name": " ".join([n for n in [e.get("first_name"), e.get("last_name")] if n]).strip() or None,
             "position": e.get("position"),
             "department": e.get("department")}
            for e in emails[:15]
        ],
        "details_url":     f"https://hunter.io/search/{domain}",
        "verdict":         "UNKNOWN",
        "summary":         (f"Hunter.io: {len(emails)} email address"
                            f"{'es' if len(emails) != 1 else ''} enumerated"
                            + (f" (pattern: {data.get('pattern')})"
                               if data.get("pattern") else "")),
    }
