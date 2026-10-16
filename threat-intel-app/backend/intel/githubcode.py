"""GitHub code search — look for a domain string in public code,
surfacing leaked API tokens, config files, and shadow repos tied to
the target.

  GET https://api.github.com/search/code?q="{domain}"
  Headers: Authorization: Bearer <GITHUB_TOKEN>, Accept: application/vnd.github+json

Requires a GitHub personal access token (any scope works for code
search; `public_repo` recommended). Free tier: 30 req/min, 10 req/
min burst limit on the code-search endpoint specifically.
"""

from __future__ import annotations

import logging
from typing import Any, Dict
from urllib.parse import quote

_log = logging.getLogger("recon.intel.githubcode")


async def lookup(session, domain: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"source": "githubcode", "found": False,
                "error": "GITHUB_TOKEN not configured",
                "error_type": "missing_key"}
    if not isinstance(domain, str) or not domain:
        return {"source": "githubcode", "found": False, "error": "missing domain"}
    q = quote(f'"{domain}"', safe="")
    url = f"https://api.github.com/search/code?q={q}&per_page=20"
    try:
        from agents.enrichment import _get
        r = await _get(session, url, headers={
            "Authorization": f"Bearer {api_key}",
            "Accept":        "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }, timeout=15)
    except Exception as e:
        return {"source": "githubcode", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "githubcode", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error"):
        return {"source": "githubcode", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    if r.get("message") and r.get("total_count") is None:
        return {"source": "githubcode", "found": False,
                "error": r.get("message")[:160], "error_type": "api_error"}

    total = r.get("total_count") or 0
    items = r.get("items") or []
    if not total:
        return {"source": "githubcode", "found": False,
                "summary": f"GitHub code: no results for {domain}."}
    # A match in public code is suspicious if it's in a non-owner repo
    # (the usual shadow-IT / leaked-secrets pattern). We can't verify
    # ownership here, so default to SUSPICIOUS when any hits exist.
    repos = sorted({(it.get("repository") or {}).get("full_name")
                     for it in items if (it.get("repository") or {}).get("full_name")})
    return {
        "source":       "githubcode",
        "found":        True,
        "total":        total,
        "repo_count":   len(repos),
        "repos":        repos[:10],
        "samples":      [
            {"repo": (it.get("repository") or {}).get("full_name"),
             "path": it.get("path"),
             "url":  it.get("html_url")}
            for it in items[:5]
        ],
        "details_url":  f"https://github.com/search?q=%22{domain}%22&type=code",
        "verdict":      "SUSPICIOUS",
        "summary":      (f"GitHub code: {total} hit"
                         f"{'s' if total != 1 else ''} across {len(repos)} repo"
                         f"{'s' if len(repos) != 1 else ''}"),
    }
