"""
PhishTank URL phishing verdict lookup.

Source: https://www.phishtank.com/api_info.php — PhishTank's /checkurl/
endpoint. Keyless-usable: the endpoint doesn't validate the `app_key`
field server-side, but anonymous POSTs (no app_key field at all) hit
Cloudflare bot protection. We send a static identifier so the request
isn't anonymous; rate limit is shared across all RECON installs but
generous for human-pace use.

  POST https://checkurl.phishtank.com/checkurl/
  Body: url=<base64>&format=json&app_key=<identifier>

Response shape:
  {
    "meta": {...},
    "results": {
      "url": "...",
      "in_database": true|false,
      "phish_id": N,
      "phish_detail_page": "...",
      "verified": true|false,
      "verified_at": "...",
      "valid": true|false            # true means confirmed phish
    }
  }
"""

from __future__ import annotations

import base64
import logging
from typing import Any, Dict

_log = logging.getLogger("recon.intel.phishtank")

_STATIC_APP_KEY = "recon-threatintel"


async def lookup(session, url: str, app_key: str = "") -> Dict[str, Any]:
    """Check whether a URL is in PhishTank's database."""
    if not isinstance(url, str) or not url:
        return {"source": "phishtank", "found": False,
                "error": "missing url"}
    key = app_key or _STATIC_APP_KEY
    url_b64 = base64.b64encode(url.encode("utf-8")).decode()
    body = f"url={url_b64}&format=json&app_key={key}"
    try:
        from agents.enrichment import _post
        r = await _post(
            session, "https://checkurl.phishtank.com/checkurl/",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "User-Agent": "RECON-ThreatIntel/1.0"},
            timeout=8,
        )
    except Exception as e:
        return {"source": "phishtank", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        # Cloudflare challenge pages return HTML, not JSON.
        return {"source": "phishtank", "found": False,
                "error": "blocked by bot protection",
                "error_type": "bot_blocked"}
    if r.get("error"):
        return {"source": "phishtank", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}

    results = r.get("results") or {}
    in_db = bool(results.get("in_database"))
    verified = bool(results.get("verified"))
    valid = bool(results.get("valid"))  # true = confirmed phish

    if not in_db:
        return {"source": "phishtank", "found": False,
                "summary": "PhishTank: URL not in database."}

    verdict = "MALICIOUS" if (valid and verified) else "SUSPICIOUS"

    return {
        "source":       "phishtank",
        "found":        True,
        "in_database":  True,
        "verified":     verified,
        "valid":        valid,
        "phish_id":     results.get("phish_id"),
        "verified_at":  results.get("verified_at"),
        "details_url":  results.get("phish_detail_page") or "https://www.phishtank.com/",
        "verdict":      verdict,
        "summary":      ("PhishTank: confirmed phishing URL"
                         if (valid and verified)
                         else "PhishTank: URL submitted (pending verification)"),
    }
