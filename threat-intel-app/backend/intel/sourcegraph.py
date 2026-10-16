"""Sourcegraph code search — queries sourcegraph.com's public index
for a domain string. Covers public GitHub + GitLab + many self-hosted
mirrors Sourcegraph has crawled.

  GET https://sourcegraph.com/.api/search/stream?q={query}&v=V3

Response is server-sent events; we parse the first chunk for hit
counts. Token optional — SOURCEGRAPH_TOKEN raises the free quota
beyond ~30 search/day.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict
from urllib.parse import quote

_log = logging.getLogger("recon.intel.sourcegraph")


async def lookup(session, domain: str, api_key: str = "") -> Dict[str, Any]:
    if not isinstance(domain, str) or not domain:
        return {"source": "sourcegraph", "found": False, "error": "missing domain"}
    headers = {
        "User-Agent": "RECON-ThreatIntel/1.0",
        "Accept":     "text/event-stream",
    }
    if api_key:
        headers["Authorization"] = f"token {api_key}"
    # Non-literal regex-free search for the domain substring
    q = quote(f'"{domain}" count:50', safe="")
    url = f"https://sourcegraph.com/.api/search/stream?q={q}&v=V3"
    import aiohttp
    try:
        async with session.get(
            url, headers=headers,
            timeout=aiohttp.ClientTimeout(total=12),
        ) as r:
            if r.status in (401, 403):
                return {"source": "sourcegraph", "found": False,
                        "error": f"auth failed (HTTP {r.status})",
                        "error_type": "auth_failed"}
            if r.status >= 400:
                return {"source": "sourcegraph", "found": False,
                        "error": f"HTTP {r.status}", "error_type": "unreachable"}
            text = await r.text()
    except Exception as e:
        return {"source": "sourcegraph", "error": str(e)[:120],
                "error_type": "unreachable"}

    # Count match events. Format: lines like `event: matches` followed
    # by `data: [...]`. We just look for match-event counts in the
    # progress stream and a repository summary line at end-of-stream.
    match_events = len(re.findall(r"^event:\s*matches", text, re.MULTILINE))
    repos: set = set()
    for m in re.finditer(r'"repository"\s*:\s*"([^"]+)"', text):
        repos.add(m.group(1))

    if match_events == 0 and not repos:
        return {"source": "sourcegraph", "found": False,
                "summary": f"Sourcegraph: no public code results for {domain}."}

    return {
        "source":        "sourcegraph",
        "found":         True,
        "match_events":  match_events,
        "repo_count":    len(repos),
        "repos":         sorted(repos)[:10],
        "details_url":   f"https://sourcegraph.com/search?q=%22{domain}%22",
        "verdict":       "SUSPICIOUS",
        "summary":       (f"Sourcegraph: {match_events} match event"
                          f"{'s' if match_events != 1 else ''}"
                          + (f" across {len(repos)} repo"
                             f"{'s' if len(repos) != 1 else ''}"
                             if repos else "")),
    }
