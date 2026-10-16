"""crt.name — alternative Certificate Transparency log search.

Faster than crt.sh for subdomain enumeration (indexed differently),
and often up when crt.sh's postgres backend is 502ing. Free, no key.

  GET https://crt.name/v1/search?domain={domain}
"""

from __future__ import annotations

import logging
from typing import Any, Dict

_log = logging.getLogger("recon.intel.crtname")


async def lookup(session, domain: str) -> Dict[str, Any]:
    if not isinstance(domain, str) or not domain:
        return {"source": "crtname", "found": False, "error": "missing domain"}
    try:
        from agents.enrichment import _get
        r = await _get(
            session, f"https://crt.name/v1/search?domain={domain}",
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "application/json"},
            timeout=12,
        )
    except Exception as e:
        return {"source": "crtname", "error": str(e)[:120],
                "error_type": "unreachable"}
    if isinstance(r, dict) and r.get("error"):
        return {"source": "crtname", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    # crt.name returns either a list of hostname strings or a dict with
    # a "hostnames" key — depends on API version. Normalise both.
    hosts: list = []
    if isinstance(r, list):
        hosts = [h for h in r if isinstance(h, str)]
    elif isinstance(r, dict):
        v = r.get("hostnames") or r.get("results") or r.get("data")
        if isinstance(v, list):
            hosts = [h for h in v if isinstance(h, str)]

    subs = sorted({h.lower().rstrip(".") for h in hosts if h and h.strip()})
    if not subs:
        return {"source": "crtname", "found": False,
                "summary": f"crt.name: no CT entries for {domain}."}
    return {
        "source":          "crtname",
        "found":           True,
        "subdomain_count": len(subs),
        "subdomains":      subs[:30],
        "details_url":     f"https://crt.name/?domain={domain}",
        "verdict":         "UNKNOWN",
        "summary":         (f"crt.name: {len(subs)} subdomain"
                            f"{'s' if len(subs) != 1 else ''}"),
    }
