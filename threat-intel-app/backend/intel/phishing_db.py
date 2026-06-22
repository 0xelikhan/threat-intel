"""
mitchellkrogza/Phishing.Database — live phishing-domain feed.

Source: https://github.com/mitchellkrogza/Phishing.Database (MIT). The
repo publishes hourly-refreshed text files of validated phishing
domains. We poll the `ACTIVE` list — domains confirmed to currently
resolve to phishing infrastructure by PyFunceble — and keep an
in-memory set.

Triage's domain branch calls `is_known_phish(domain)` so a hit lifts
the verdict to MALICIOUS / bumps the triage_score by 0.25.

The feed is poll-once-then-cache for an hour. We use the existing
`intel.cache` TTLCache namespace so refreshes happen on the same
cadence as other live TI sources. The fetch goes through the shared
`agents/enrichment._get` helper so it inherits the per-host circuit
breaker — a GitHub outage can't stall triage.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, Optional, Set

_log = logging.getLogger("recon.intel.phishing_db")

# Raw text file of currently-active validated phishing domains.
# About 60-90k entries; 3 MB on disk.
_FEED_URL = ("https://raw.githubusercontent.com/mitchellkrogza/"
             "Phishing.Database/master/phishing-domains-ACTIVE.txt")

_TTL_S       = 3600   # hourly refresh per upstream cadence
_LOAD_LOCK   = asyncio.Lock()
_state: Dict[str, Any] = {
    "loaded_at":   0.0,
    "domains":     set(),  # set[str]
    "size":        0,
    "error":       None,
}


async def _refresh(session) -> None:
    """Fetch the ACTIVE list and replace the in-memory set. Goes
    through agents/enrichment._get so it inherits the circuit breaker
    + the 12s safety timeout the rest of the fan-out uses."""
    try:
        from agents.enrichment import _get
        text = await _get(
            session, _FEED_URL,
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "text/plain"},
            json_response=False,  # raw text endpoint
        )
    except TypeError:
        # Older _get signature without json_response — fall back to dict path.
        from agents.enrichment import _get
        text = await _get(
            session, _FEED_URL,
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "text/plain"},
        )
    if not isinstance(text, str):
        _state["error"] = "phishing_db feed: unexpected non-text payload"
        return
    domains: Set[str] = set()
    for line in text.splitlines():
        d = line.strip().lower().rstrip(".")
        if not d or d.startswith("#"):
            continue
        if "." not in d or " " in d:
            continue
        domains.add(d)
    _state["domains"]   = domains
    _state["size"]      = len(domains)
    _state["loaded_at"] = time.time()
    _state["error"]     = None
    _log.info("phishing_db: %d active phishing domains loaded", len(domains))


async def ensure_loaded(session) -> None:
    """Lifespan-warmable + per-call idempotent loader. The lifespan
    handler can fire-and-forget a single call at startup, and triage
    can keep calling it — only the first within the TTL window does
    actual work."""
    async with _LOAD_LOCK:
        age = time.time() - _state["loaded_at"]
        if _state["domains"] and age < _TTL_S:
            return
        try:
            await _refresh(session)
        except Exception as e:
            _state["error"] = f"phishing_db refresh failed: {e}"
            _log.warning("phishing_db refresh failed: %s", e)


def is_known_phish(domain: str) -> bool:
    """Synchronous lookup. Returns False when the feed hasn't been loaded
    yet (lifespan startup race) or the domain isn't in the active set."""
    if not isinstance(domain, str) or not domain:
        return False
    d = domain.strip().lower().rstrip(".")
    return d in _state.get("domains", set())


def stats() -> Dict[str, Any]:
    age = time.time() - _state["loaded_at"] if _state["loaded_at"] else None
    return {
        "loaded":     bool(_state.get("size")),
        "size":       _state.get("size", 0),
        "age_s":      int(age) if age is not None else None,
        "ttl_s":      _TTL_S,
        "error":      _state.get("error"),
    }
