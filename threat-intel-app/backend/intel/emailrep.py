"""
EmailRep email reputation lookup.

Source: https://emailrep.io/ — reputation + context for email
addresses (profile presence, deliverability, breaches, blacklists,
disposable/freemail flags). API key optional (raises daily quota).

  GET https://emailrep.io/<email>
  Header: Key: <EMAILREP_KEY>  (optional)

Response:
  {
    "email": "...",
    "reputation": "high|medium|low|none",
    "suspicious": true|false,
    "references": N,
    "details": {
      "blacklisted": true|false,
      "malicious_activity": true|false,
      "credentials_leaked": true|false,
      "data_breach": true|false,
      "first_seen": "...", "last_seen": "...",
      "domain_exists": true|false,
      "domain_reputation": "...",
      "new_domain": true|false,
      "disposable": true|false,
      "deliverable": true|false,
      "spam": true|false,
      "free_provider": true|false,
      "profiles": ["twitter", "github", ...]
    }
  }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

_log = logging.getLogger("recon.intel.emailrep")


async def lookup(session, email: str, api_key: str = "") -> Dict[str, Any]:
    if not isinstance(email, str) or "@" not in email:
        return {"source": "emailrep", "found": False,
                "error": "invalid email"}
    headers = {
        "User-Agent": "RECON-ThreatIntel/1.0",
        "Accept": "application/json",
    }
    if api_key:
        headers["Key"] = api_key
    try:
        from agents.enrichment import _get
        r = await _get(session, f"https://emailrep.io/{email}",
                        headers=headers, timeout=8)
    except Exception as e:
        return {"source": "emailrep", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "emailrep", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error"):
        return {"source": "emailrep", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}

    details = r.get("details") or {}
    reputation = (r.get("reputation") or "").lower()
    suspicious = bool(r.get("suspicious"))
    blacklisted = bool(details.get("blacklisted"))
    malicious_activity = bool(details.get("malicious_activity"))
    creds_leaked = bool(details.get("credentials_leaked"))
    disposable = bool(details.get("disposable"))

    if malicious_activity or blacklisted or reputation == "low":
        verdict = "MALICIOUS"
    elif suspicious or creds_leaked or disposable:
        verdict = "SUSPICIOUS"
    elif reputation == "high":
        verdict = "CLEAN"
    else:
        verdict = "UNKNOWN"

    profiles = details.get("profiles") or []

    return {
        "source":              "emailrep",
        "found":               True,
        "reputation":          reputation,
        "suspicious":          suspicious,
        "references":          r.get("references"),
        "malicious_activity":  malicious_activity,
        "blacklisted":         blacklisted,
        "credentials_leaked":  creds_leaked,
        "disposable":          disposable,
        "free_provider":       bool(details.get("free_provider")),
        "deliverable":         bool(details.get("deliverable")),
        "new_domain":          bool(details.get("new_domain")),
        "domain_reputation":   details.get("domain_reputation"),
        "first_seen":          details.get("first_seen"),
        "last_seen":           details.get("last_seen"),
        "profiles":            profiles[:10] if isinstance(profiles, list) else [],
        "details_url":         f"https://emailrep.io/{email}",
        "verdict":             verdict,
        "summary":             (f"EmailRep: reputation={reputation}"
                                + (f", malicious activity"
                                   if malicious_activity else "")
                                + (f", in breach(es)"
                                   if creds_leaked else "")
                                + (f", disposable" if disposable else "")),
    }
