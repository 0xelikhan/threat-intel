"""
OpenSSF Scorecards API client.

Source: https://api.securityscorecards.dev (Apache-2.0). Per-repo
supply-chain security posture scoring — Branch-Protection, Code-Review,
Dependency-Update-Tool, SAST, Token-Permissions, Vulnerabilities, etc.

When a GHSA finding fingers a package, the upstream repo's Scorecard
gives the analyst supply-chain context: a critical CVE on a low-
Scorecard repo is more concerning than the same CVE on a hardened
project with active maintenance and dependency review.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

_log = logging.getLogger("recon.intel.scorecards")

# Scorecards API uses a hierarchical URL: /projects/{platform}/{org}/{repo}
# We only care about github.com repos in practice.
_BASE = "https://api.securityscorecards.dev/projects/github.com"


async def lookup(session, owner: str, repo: str) -> Dict[str, Any]:
    """Fetch the Scorecards JSON for a github.com repo. Returns the
    normalised summary {score, checks, date} or {found: False}."""
    if not owner or not repo:
        return {"source": "scorecards", "found": False,
                "error": "missing owner/repo"}
    try:
        from agents.enrichment import _get
        r = await _get(
            session, f"{_BASE}/{owner}/{repo}",
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "application/json"},
            timeout=8,
        )
    except Exception as e:
        return {"source": "scorecards", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "scorecards", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error") and "404" in str(r.get("error")):
        return {"source": "scorecards", "found": False,
                "summary": f"Scorecards has no record for {owner}/{repo}"}
    if r.get("error"):
        return {"source": "scorecards", "error": r["error"],
                "error_type": r.get("error_type", "unreachable")}

    score  = r.get("score")
    checks_raw = r.get("checks") or []
    checks: list = []
    if isinstance(checks_raw, list):
        for c in checks_raw[:20]:
            if not isinstance(c, dict):
                continue
            checks.append({
                "name":   c.get("name"),
                "score":  c.get("score"),
                "reason": (c.get("reason") or "")[:160],
            })

    summary = (f"OpenSSF Scorecard {score}/10 for {owner}/{repo}"
               if score is not None
               else f"OpenSSF Scorecard generated for {owner}/{repo}")
    verdict = "UNKNOWN"
    if isinstance(score, (int, float)):
        if score < 4.0:
            verdict = "SUSPICIOUS"
        elif score >= 7.0:
            verdict = "CLEAN"

    return {
        "source":     "scorecards",
        "found":      True,
        "owner":      owner,
        "repo":       repo,
        "score":      score,
        "date":       r.get("date"),
        "checks":     checks,
        "verdict":    verdict,
        "summary":    summary,
    }
