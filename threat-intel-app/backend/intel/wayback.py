"""Wayback Machine CDX API — historical subdomain + URL mining.

The Internet Archive's CDX index returns every URL archived under a
host pattern. Querying `*.domain` surfaces every subdomain and path
ever snapshotted — strong signal for shadow IT and abandoned infra.

  GET https://web.archive.org/cdx/search/cdx?url=*.{domain}
       &output=json&collapse=urlkey&fl=original,timestamp&limit=1000

Free, no key, generous rate limit.
"""

from __future__ import annotations

import logging
from typing import Any, Dict
from urllib.parse import urlsplit

_log = logging.getLogger("recon.intel.wayback")


async def lookup(session, domain: str) -> Dict[str, Any]:
    if not isinstance(domain, str) or not domain:
        return {"source": "wayback", "found": False, "error": "missing domain"}
    url = (f"https://web.archive.org/cdx/search/cdx?url=*.{domain}"
           "&output=json&collapse=urlkey&fl=original,timestamp&limit=1000")
    import aiohttp
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=15),
            headers={"User-Agent": "RECON-ThreatIntel/1.0"},
        ) as r:
            if r.status >= 400:
                return {"source": "wayback", "found": False,
                        "error": f"HTTP {r.status}", "error_type": "unreachable"}
            rows = await r.json(content_type=None)
    except Exception as e:
        return {"source": "wayback", "error": str(e)[:120],
                "error_type": "unreachable"}

    if not isinstance(rows, list) or len(rows) <= 1:
        return {"source": "wayback", "found": False,
                "summary": f"Wayback: no snapshots under *.{domain}."}

    # First row is the header (['original', 'timestamp']). Skip it.
    hosts: set = set()
    first_seen: str = ""
    last_seen: str = ""
    sample_urls = []
    for row in rows[1:]:
        if not isinstance(row, list) or len(row) < 2:
            continue
        try:
            host = (urlsplit(row[0]).hostname or "").lower().rstrip(".")
        except Exception:
            continue
        ts = row[1] if isinstance(row[1], str) else ""
        if host and (host == domain or host.endswith("." + domain)):
            hosts.add(host)
            if not first_seen or (ts and ts < first_seen):
                first_seen = ts
            if ts and ts > last_seen:
                last_seen = ts
            if len(sample_urls) < 10:
                sample_urls.append(row[0])

    if not hosts:
        return {"source": "wayback", "found": False,
                "summary": f"Wayback: no subdomains under {domain}."}
    return {
        "source":        "wayback",
        "found":         True,
        "snapshot_rows": len(rows) - 1,
        "subdomain_count": len(hosts),
        "subdomains":    sorted(hosts)[:30],
        "first_seen":    first_seen,
        "last_seen":     last_seen,
        "sample_urls":   sample_urls,
        "details_url":   f"https://web.archive.org/web/*/{domain}",
        "verdict":       "UNKNOWN",
        "summary":       (f"Wayback: {len(hosts)} unique subdomain"
                          f"{'s' if len(hosts) != 1 else ''} across "
                          f"{len(rows) - 1} snapshot URL"
                          f"{'s' if len(rows) - 1 != 1 else ''}"),
    }
