"""GitLab code search — mirror of the GitHub pattern for GitLab.com
public repos.

  GET https://gitlab.com/api/v4/search?scope=blobs&search={domain}
  Headers: PRIVATE-TOKEN: <GITLAB_TOKEN>  (optional for public search)

The public search endpoint is throttled (~60 req/hour) without a
token. With a free GitLab personal-access-token (read_api scope),
quotas rise substantially.
"""

from __future__ import annotations

import logging
from typing import Any, Dict
from urllib.parse import quote

_log = logging.getLogger("recon.intel.gitlabsearch")


async def lookup(session, domain: str, api_key: str = "") -> Dict[str, Any]:
    if not isinstance(domain, str) or not domain:
        return {"source": "gitlabsearch", "found": False, "error": "missing domain"}
    headers = {
        "User-Agent": "RECON-ThreatIntel/1.0",
        "Accept":     "application/json",
    }
    if api_key:
        headers["PRIVATE-TOKEN"] = api_key
    q = quote(domain, safe="")
    url = f"https://gitlab.com/api/v4/search?scope=blobs&search={q}&per_page=20"
    try:
        from agents.enrichment import _get
        r = await _get(session, url, headers=headers, timeout=12)
    except Exception as e:
        return {"source": "gitlabsearch", "error": str(e)[:120],
                "error_type": "unreachable"}
    if isinstance(r, dict) and r.get("error"):
        return {"source": "gitlabsearch", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    hits = r if isinstance(r, list) else (r.get("items") if isinstance(r, dict) else None)
    if not isinstance(hits, list) or not hits:
        return {"source": "gitlabsearch", "found": False,
                "summary": f"GitLab code: no results for {domain}."}
    projects = sorted({str(h.get("project_id")) for h in hits
                        if isinstance(h, dict) and h.get("project_id")})
    return {
        "source":        "gitlabsearch",
        "found":         True,
        "total":         len(hits),
        "project_count": len(projects),
        "samples":       [
            {"project_id": h.get("project_id"),
             "path":       h.get("path"),
             "ref":        h.get("ref")}
            for h in hits[:5] if isinstance(h, dict)
        ],
        "details_url":   f"https://gitlab.com/search?scope=blobs&search={q}",
        "verdict":       "SUSPICIOUS",
        "summary":       (f"GitLab code: {len(hits)} hit"
                          f"{'s' if len(hits) != 1 else ''} across "
                          f"{len(projects)} project"
                          f"{'s' if len(projects) != 1 else ''}"),
    }
