"""Common Crawl index — passive subdomain mining from the public
web-scale crawl archive.

Catalog:        https://index.commoncrawl.org/collinfo.json
Per-index:      https://index.commoncrawl.org/<id>-index?url=*.{domain}&output=json

We query only the most recent crawl index for speed. Each JSONL line
has a `url` field we parse to extract historical subdomains tied to
the target. No key required; large indices are rate-limited.
"""

from __future__ import annotations

import json as _json
import logging
from typing import Any, Dict
from urllib.parse import urlsplit

_log = logging.getLogger("recon.intel.commoncrawl")

_CATALOG_URL = "https://index.commoncrawl.org/collinfo.json"


async def _get_recent_index(session) -> str:
    import aiohttp
    try:
        async with session.get(
            _CATALOG_URL, timeout=aiohttp.ClientTimeout(total=10),
            headers={"User-Agent": "RECON-ThreatIntel/1.0"},
        ) as r:
            if r.status >= 400:
                return ""
            cat = await r.json(content_type=None)
    except Exception:
        return ""
    if not isinstance(cat, list) or not cat:
        return ""
    # First entry is the most recent crawl.
    return str((cat[0] or {}).get("id") or (cat[0] or {}).get("cdx-api") or "")


async def lookup(session, domain: str) -> Dict[str, Any]:
    if not isinstance(domain, str) or not domain:
        return {"source": "commoncrawl", "found": False, "error": "missing domain"}
    idx = await _get_recent_index(session)
    if not idx:
        return {"source": "commoncrawl", "found": False,
                "error": "catalog unreachable", "error_type": "unreachable"}
    url = f"https://index.commoncrawl.org/{idx}-index?url=*.{domain}&output=json&limit=200"
    import aiohttp
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=15),
            headers={"User-Agent": "RECON-ThreatIntel/1.0"},
        ) as r:
            if r.status == 404:
                return {"source": "commoncrawl", "found": False,
                        "summary": f"Common Crawl: no results for *.{domain}."}
            if r.status >= 400:
                return {"source": "commoncrawl", "found": False,
                        "error": f"HTTP {r.status}", "error_type": "unreachable"}
            text = await r.text()
    except Exception as e:
        return {"source": "commoncrawl", "error": str(e)[:120],
                "error_type": "unreachable"}

    subs: set = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = _json.loads(line)
        except Exception:
            continue
        host = ""
        try:
            host = (urlsplit(obj.get("url") or "").hostname or "").lower().rstrip(".")
        except Exception:
            continue
        if host and (host == domain or host.endswith("." + domain)):
            subs.add(host)

    if not subs:
        return {"source": "commoncrawl", "found": False,
                "summary": f"Common Crawl: no indexed subdomains for {domain}."}
    return {
        "source":        "commoncrawl",
        "found":         True,
        "subdomain_count": len(subs),
        "subdomains":    sorted(subs)[:30],
        "index":         idx,
        "details_url":   f"https://index.commoncrawl.org/{idx}-index?url=*.{domain}",
        "verdict":       "UNKNOWN",
        "summary":       (f"Common Crawl: {len(subs)} indexed subdomain"
                          f"{'s' if len(subs) != 1 else ''}"),
    }
