"""subdomain.center — community-sourced subdomain enumeration.

  GET https://api.subdomain.center/?domain={word}

Returns a flat JSON array of hostnames. Free, no key, rate-limited
to ~1 req/sec by their CDN.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

_log = logging.getLogger("recon.intel.subdomain_center")


async def lookup(session, domain: str) -> Dict[str, Any]:
    if not isinstance(domain, str) or not domain:
        return {"source": "subdomain_center", "found": False, "error": "missing domain"}
    try:
        from agents.enrichment import _get
        r = await _get(
            session, f"https://api.subdomain.center/?domain={domain}",
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "application/json"},
            timeout=10,
        )
    except Exception as e:
        return {"source": "subdomain_center", "error": str(e)[:120],
                "error_type": "unreachable"}
    if isinstance(r, dict) and r.get("error"):
        return {"source": "subdomain_center", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    if not isinstance(r, list) or not r:
        return {"source": "subdomain_center", "found": False,
                "summary": f"subdomain.center: no results for {domain}."}
    subs = sorted({str(h).lower().rstrip(".") for h in r if isinstance(h, str) and h.strip()})
    return {
        "source":          "subdomain_center",
        "found":           True,
        "subdomain_count": len(subs),
        "subdomains":      subs[:30],
        "details_url":     f"https://www.subdomain.center/?domain={domain}",
        "verdict":         "UNKNOWN",
        "summary":         (f"subdomain.center: {len(subs)} subdomain"
                            f"{'s' if len(subs) != 1 else ''}"),
    }
