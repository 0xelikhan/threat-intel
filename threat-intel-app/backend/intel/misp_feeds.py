"""
MISP-format flat IOC feed lookup.

Several MISP communities publish a `hashes.csv` flat dump alongside the
per-event MISP JSON. Each row is `sha1,sha256,md5,event_uuid,filename`.
That gives us a fast, free, daily-refreshing set-membership check for
file hashes against curated threat-intel — no MISP server required.

Feeds polled (all public, no key, MISP-recommended in
https://www.misp-project.org/feeds/):
  - CIRCL OSINT             (broad coverage, daily)
  - The DigitalSide T-I     (malware-focused)
  - Botvrij OSINT           (Dutch CERT community)

Lookup contract:
  lookup_hash(value)      -> [{feed, event_uuid, filename, source_url}, ...]
  lookup_ioc("hash", v)   -> same as lookup_hash
  lookup_ioc("ip", v)     -> [] (hashes.csv has no IPs; future expansion)

Refresh cadence: 6 hours (TTL in the namespaced cache module).
Fetch is lazy on first call and never blocks startup. If any feed fails
the whole module continues with whatever feeds succeeded — degrades
gracefully like every other source in the enrichment fan-out.
"""

from __future__ import annotations

import asyncio
import csv
import io
import logging
import time
from typing import Any, Dict, List, Optional

import aiohttp

_log = logging.getLogger("recon.misp_feeds")

# Refresh interval matches the spec §8 static-feed cadence (6h).
_TTL_SECONDS = 6 * 3600
_FETCH_TIMEOUT = aiohttp.ClientTimeout(total=30)
_USER_AGENT = "RECON-MDR-Platform/1.0 (+misp-feed-poller)"

# (display_name, base_url) — the hashes.csv lives at base_url + "/hashes.csv"
# for every MISP feed that publishes a flat dump.
_FEEDS = [
    ("CIRCL OSINT",
     "https://www.circl.lu/doc/misp/feed-osint"),
    ("DigitalSide Threat-Intel",
     "https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed"),
    ("Botvrij OSINT",
     "https://www.botvrij.eu/data/feed-osint"),
]

# Per-feed in-memory state.
# {feed_name: {
#    "fetched_at":  unix_ts | None,
#    "by_hash":     {hash_lower: {event_uuid, filename}},
#    "source_url":  base_url,
#    "error":       last error string when load fails, else None,
# }}
_state: Dict[str, Dict[str, Any]] = {}
_load_lock = asyncio.Lock()


def _ensure_state() -> None:
    if _state:
        return
    for name, base in _FEEDS:
        _state[name] = {
            "fetched_at": None,
            "by_hash":    {},
            "source_url": base,
            "error":      None,
        }


def _stale(feed_state: Dict[str, Any]) -> bool:
    ts = feed_state.get("fetched_at")
    return (not ts) or (time.time() - ts) > _TTL_SECONDS


async def _fetch_one(session: aiohttp.ClientSession,
                     feed_name: str, base_url: str) -> None:
    """Fetch a single feed's hashes.csv and rebuild its in-memory set.
    Never raises — failures land in _state[feed_name]["error"]."""
    url = f"{base_url}/hashes.csv"
    try:
        async with session.get(url, timeout=_FETCH_TIMEOUT,
                               headers={"User-Agent": _USER_AGENT}) as r:
            if r.status != 200:
                _state[feed_name]["error"] = f"HTTP {r.status}"
                _state[feed_name]["fetched_at"] = time.time()
                return
            text = await r.text(errors="replace")
    except Exception as e:
        _state[feed_name]["error"] = type(e).__name__
        _state[feed_name]["fetched_at"] = time.time()
        return

    by_hash: Dict[str, Dict[str, str]] = {}
    # MISP hashes.csv shape: sha1,sha256,md5,event_uuid,filename
    # Some feeds drop columns. Parse defensively by index.
    reader = csv.reader(io.StringIO(text))
    rows = 0
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        sha1     = (row[0] if len(row) > 0 else "").strip().lower()
        sha256   = (row[1] if len(row) > 1 else "").strip().lower()
        md5      = (row[2] if len(row) > 2 else "").strip().lower()
        evt_uuid = (row[3] if len(row) > 3 else "").strip()
        fname    = (row[4] if len(row) > 4 else "").strip()
        entry = {"event_uuid": evt_uuid, "filename": fname}
        for h in (sha1, sha256, md5):
            if h and len(h) in (32, 40, 64):
                by_hash[h] = entry
                rows += 1

    _state[feed_name]["by_hash"]    = by_hash
    _state[feed_name]["fetched_at"] = time.time()
    _state[feed_name]["error"]      = None
    _log.info("MISP feed %s loaded: %d hash entries", feed_name, len(by_hash))


def _refresh_sync() -> None:
    """Sync entrypoint the pre-warm loop can call from a thread.
    Wraps _refresh_if_stale in a fresh event loop so the async fetch
    runs synchronously from the caller's perspective."""
    _ensure_state()
    if not any(_stale(_state[n]) for n, _ in _FEEDS):
        return
    try:
        asyncio.run(_refresh_if_stale())
    except Exception as e:
        _log.warning("misp_feeds pre-warm refresh failed: %s", e)


def _schedule_bg_refresh_if_stale() -> None:
    """Kick off a background refresh when the cache is stale. Never
    blocks the caller. If no event loop is running (unlikely in this
    codebase), silently no-ops so pure-sync callers can invoke the
    lookup path without a crash."""
    _ensure_state()
    if not any(_stale(_state[n]) for n, _ in _FEEDS):
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    # A single background task suffices — _refresh_if_stale is guarded
    # by an asyncio.Lock so parallel schedule calls collapse into one
    # real fetch. Detach the task; we intentionally don't track it.
    loop.create_task(_refresh_if_stale())


async def _refresh_if_stale() -> None:
    """Refresh every feed whose cache is past TTL. Concurrent, serialized
    by a single asyncio lock so concurrent enrichment runs don't all
    re-fetch at once."""
    _ensure_state()
    if not any(_stale(_state[n]) for n, _ in _FEEDS):
        return
    async with _load_lock:
        # Re-check after acquiring the lock — another coroutine may have
        # already refreshed while we were waiting.
        to_fetch = [(n, b) for (n, b) in _FEEDS if _stale(_state[n])]
        if not to_fetch:
            return
        async with aiohttp.ClientSession() as session:
            await asyncio.gather(
                *(_fetch_one(session, n, b) for n, b in to_fetch),
                return_exceptions=True,
            )


async def lookup_hash(value: str) -> List[Dict[str, Any]]:
    """Look up a hash across every loaded MISP feed. Returns one entry
    per feed that has the hash. Empty list = no matches (or all feeds
    failed to load — analyst can still rely on other enrichment sources).

    Perf: the first hash lookup in a fresh process used to await
    _refresh_if_stale(), which downloads three multi-MB hashes.csv
    feeds. That blocked the enrichment fan-out for ~30 s on cold
    start (measured 2026-07). We now fire the refresh in the
    background and serve whatever's already indexed — for the very
    first hash the analyst may get an empty result from this source,
    but every source in the fan-out is best-effort by design. The
    lifespan pre-warm in main.py primes the feeds at startup so most
    calls hit warm data.
    """
    if not value:
        return []
    _schedule_bg_refresh_if_stale()
    h = value.strip().lower()
    if not h or len(h) not in (32, 40, 64):
        return []
    hits: List[Dict[str, Any]] = []
    for name, _ in _FEEDS:
        st = _state.get(name) or {}
        entry = (st.get("by_hash") or {}).get(h)
        if not entry:
            continue
        hits.append({
            "feed":       name,
            "source_url": st.get("source_url"),
            "event_uuid": entry.get("event_uuid"),
            "filename":   entry.get("filename"),
        })
    return hits


async def lookup_ioc(ioc_type: str, value: str) -> List[Dict[str, Any]]:
    """Generic dispatch by IOC type. Only "hash" is meaningful today; IP /
    domain / URL paths return [] until we add the per-event JSON parser
    or a fast equivalent. The signature lives here now so enrichment.py
    can call it uniformly and we can extend without changing callers."""
    if ioc_type == "hash":
        return await lookup_hash(value)
    return []


def stats() -> Dict[str, Any]:
    """Health/status summary, surfaced at /api/status."""
    _ensure_state()
    return {
        feed: {
            "loaded_at":   st.get("fetched_at"),
            "entry_count": len(st.get("by_hash") or {}),
            "error":       st.get("error"),
        }
        for feed, st in _state.items()
    }
