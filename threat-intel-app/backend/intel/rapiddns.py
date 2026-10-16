"""RapidDNS — passive DNS subdomain enumeration via HTML scrape.

  GET https://rapiddns.io/subdomain/{domain}?full=1#result

RapidDNS doesn't publish a JSON API; we scrape the subdomain table
from the HTML response. Free, no key.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict

_log = logging.getLogger("recon.intel.rapiddns")

_ROW_RE = re.compile(
    r"<tr[^>]*>\s*<th[^>]*>[^<]*</th>\s*"
    r"<td[^>]*>\s*(?:<a[^>]*>)?([^\s<]+)",
    re.IGNORECASE,
)


async def lookup(session, domain: str) -> Dict[str, Any]:
    if not isinstance(domain, str) or not domain:
        return {"source": "rapiddns", "found": False, "error": "missing domain"}
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    import aiohttp
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=12),
            headers={"User-Agent": "Mozilla/5.0 RECON-ThreatIntel/1.0"},
        ) as r:
            if r.status in (401, 403, 429):
                return {"source": "rapiddns", "found": False,
                        "error": f"HTTP {r.status}",
                        "error_type": "rate_limited" if r.status == 429 else "auth_failed"}
            if r.status >= 400:
                return {"source": "rapiddns", "found": False,
                        "error": f"HTTP {r.status}", "error_type": "unreachable"}
            text = await r.text()
    except Exception as e:
        return {"source": "rapiddns", "error": str(e)[:120],
                "error_type": "unreachable"}

    subs: set = set()
    for m in _ROW_RE.finditer(text):
        host = m.group(1).strip().lower().rstrip(".")
        if host and (host == domain or host.endswith("." + domain)):
            subs.add(host)

    if not subs:
        return {"source": "rapiddns", "found": False,
                "summary": f"RapidDNS: no subdomains for {domain}."}
    return {
        "source":          "rapiddns",
        "found":           True,
        "subdomain_count": len(subs),
        "subdomains":      sorted(subs)[:30],
        "details_url":     f"https://rapiddns.io/subdomain/{domain}?full=1",
        "verdict":         "UNKNOWN",
        "summary":         (f"RapidDNS: {len(subs)} subdomain"
                            f"{'s' if len(subs) != 1 else ''}"),
    }
