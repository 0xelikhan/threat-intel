"""
Spamhaus DROP / EDROP loader.

Source: https://www.spamhaus.org/drop/ — Spamhaus "Do not Route Or
Peer" feeds. Two daily-refreshed plain-text CIDR lists:

  drop.txt   — netblocks under direct control of professional
                spammers / cyber-criminals. Conservative; only the
                worst offenders.
  edrop.txt  — netblocks hijacked from legitimate owners.

Both are public, attribution-only redistribution, considered the
canonical authoritative list of hijacked / criminal infrastructure
on the open internet. FireHOL aggregates some of this; querying
Spamhaus directly gives us the clean upstream signal with no
aggregator-mixing noise.

Format per line:
  1.2.3.0/24 ; SBL12345

We parse the CIDR, the associated SBL (Spamhaus Block List) reference,
and tag each entry with which feed (DROP or EDROP) it came from.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.intel.spamhaus_drop")

_FEEDS = [
    ("DROP",  "https://www.spamhaus.org/drop/drop.txt"),
    ("EDROP", "https://www.spamhaus.org/drop/edrop.txt"),
]
_TTL_S = 24 * 3600

_LOAD_LOCK = asyncio.Lock()
_state: Dict[str, Any] = {
    "loaded_at": 0.0,
    "entries":   [],   # list[(network, {feed, sbl})]
    "by_sbl":    {},
    "feed_counts": {},
    "error":     None,
}


async def _fetch_text(session, url: str) -> Optional[str]:
    from agents.enrichment import _get
    try:
        r = await _get(
            session, url,
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "text/plain"},
            json_response=False,
            timeout=10,
        )
    except TypeError:
        r = await _get(
            session, url,
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "text/plain"},
            timeout=10,
        )
    except Exception as e:
        _log.debug("spamhaus fetch failed %s: %s", url, e)
        return None
    if isinstance(r, str):
        return r
    if isinstance(r, (bytes, bytearray)):
        return r.decode("utf-8", errors="ignore")
    return None


def _parse_feed(text: str, feed: str,
                entries: List, by_sbl: Dict[str, List]) -> int:
    if not isinstance(text, str):
        return 0
    count = 0
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith(";") or s.startswith("#"):
            continue
        # `CIDR ; SBL12345`
        parts = [p.strip() for p in s.split(";", 1)]
        if not parts:
            continue
        cidr = parts[0]
        sbl  = parts[1] if len(parts) > 1 else ""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except (ValueError, TypeError):
            continue
        meta = {"feed": feed, "sbl": sbl[:24], "cidr": str(net)}
        entries.append((net, meta))
        if sbl:
            by_sbl.setdefault(sbl, []).append(meta)
        count += 1
    return count


async def _refresh(session) -> None:
    entries: List = []
    by_sbl:  Dict[str, List] = {}
    feed_counts: Dict[str, int] = {}

    texts = await asyncio.gather(
        *[_fetch_text(session, url) for _feed, url in _FEEDS],
        return_exceptions=True,
    )
    for (feed, _url), text in zip(_FEEDS, texts):
        if not isinstance(text, str):
            continue
        feed_counts[feed] = _parse_feed(text, feed, entries, by_sbl)

    _state["entries"]     = entries
    _state["by_sbl"]      = by_sbl
    _state["feed_counts"] = feed_counts
    _state["loaded_at"]   = time.time()
    _state["error"]       = None if entries else "no entries loaded"
    _log.info("spamhaus_drop loaded: %d entries across %d feeds",
              len(entries), len(feed_counts))


async def ensure_loaded(session) -> None:
    async with _LOAD_LOCK:
        age = time.time() - _state["loaded_at"]
        if _state["entries"] and age < _TTL_S:
            return
        try:
            await _refresh(session)
        except Exception as e:
            _state["error"] = f"spamhaus refresh failed: {e}"
            _log.warning("spamhaus_drop refresh failed: %s", e)


def lookup(ip: str) -> Optional[Dict[str, Any]]:
    """Return the first DROP/EDROP entry containing this IP, or None."""
    if not isinstance(ip, str) or not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net, meta in (_state.get("entries") or []):
        try:
            if addr in net:
                return meta
        except TypeError:
            continue
    return None


def stats() -> Dict[str, Any]:
    age = time.time() - _state["loaded_at"] if _state["loaded_at"] else None
    return {
        "loaded":      bool(_state.get("entries")),
        "total":       len(_state.get("entries") or []),
        "feed_counts": _state.get("feed_counts") or {},
        "age_s":       int(age) if age is not None else None,
        "ttl_s":       _TTL_S,
        "error":       _state.get("error"),
    }
