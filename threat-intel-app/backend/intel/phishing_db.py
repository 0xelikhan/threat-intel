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

# Phishing-domain feeds. Domains union from both sources — diversity
# matters because Phishing.Database and OpenPhish ingest different
# upstream submissions, so each catches what the other misses.
_FEED_URL = ("https://raw.githubusercontent.com/mitchellkrogza/"
             "Phishing.Database/master/phishing-domains-ACTIVE.txt")
# OpenPhish community feed — free, no key. Lines are full URLs; we
# extract the host portion to match the in-memory set.
_OPENPHISH_URL = "https://openphish.com/feed.txt"

_TTL_S       = 3600   # hourly refresh per upstream cadence
_LOAD_LOCK   = asyncio.Lock()
_state: Dict[str, Any] = {
    "loaded_at":   0.0,
    "domains":     set(),  # set[str]
    "size":        0,
    "error":       None,
}


async def _fetch_text(session, url: str) -> str:
    """Fetch a text feed via agents/enrichment._get with the json_response
    fallback for older signatures."""
    from agents.enrichment import _get
    try:
        r = await _get(
            session, url,
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "text/plain"},
            json_response=False,
        )
    except TypeError:
        r = await _get(
            session, url,
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "text/plain"},
        )
    if isinstance(r, str):
        return r
    if isinstance(r, (bytes, bytearray)):
        return r.decode("utf-8", errors="ignore")
    return ""


def _extract_host(line: str) -> str:
    """OpenPhish ships full URLs; Phishing.Database ships bare hosts.
    Normalise both to a lowercase host string, no trailing dot."""
    s = (line or "").strip().lower()
    if not s or s.startswith("#"):
        return ""
    # Strip protocol / path if present (OpenPhish-style URLs).
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]
    s = s.split("?", 1)[0]
    s = s.rstrip(".")
    if "." not in s or " " in s:
        return ""
    return s


async def _refresh(session) -> None:
    """Fetch BOTH the Phishing.Database ACTIVE list and the OpenPhish
    community feed; union the host set. Either feed failing is fine —
    we keep whatever we got."""
    domains: Set[str] = set()
    sources_loaded: int = 0

    # Phishing.Database — mitchellkrogza, hourly-refreshed validated set
    try:
        text = await _fetch_text(session, _FEED_URL)
        if text:
            for line in text.splitlines():
                h = _extract_host(line)
                if h:
                    domains.add(h)
            sources_loaded += 1
    except Exception as e:
        _log.debug("phishing_db: Phishing.Database fetch failed: %s", e)

    # OpenPhish community feed — independent submissions
    try:
        text = await _fetch_text(session, _OPENPHISH_URL)
        if text:
            for line in text.splitlines():
                h = _extract_host(line)
                if h:
                    domains.add(h)
            sources_loaded += 1
    except Exception as e:
        _log.debug("phishing_db: OpenPhish fetch failed: %s", e)

    if sources_loaded == 0:
        _state["error"] = "phishing_db: both feeds unreachable"
        return
    _state["domains"]   = domains
    _state["size"]      = len(domains)
    _state["loaded_at"] = time.time()
    _state["error"]     = None
    _log.info("phishing_db: %d phishing domains loaded from %d feed(s)",
              len(domains), sources_loaded)


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
