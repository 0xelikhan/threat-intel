"""ThreatCluster blocklist ingestor.

Pulls the keyless 30-day public feed at
https://threatcluster.io/api/iocs/public/feed.txt and seeds a
per-process cache keyed by IOC value. Any IOC that hits this cache
during enrichment surfaces a 'seen on ThreatCluster blocklist' row
without an extra HTTP round-trip.

Feed format is plain text - one value per line, commented header
lines. Each poll replaces the cache atomically (the feed is the
authoritative list for the 30-day window).

Hourly cadence matches ThreatCluster's own refresh schedule (their
cache_ttl_hours=1), so polling faster than that returns identical
content.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, AsyncIterator, Dict, Set

from plugins import Ingestor, register

_log = logging.getLogger("recon.plugins.ingestors.threatcluster")


_FEED_URL      = "https://threatcluster.io/api/iocs/public/feed.txt"
_CACHE_TTL_SEC = 2 * 3600                  # rebuild if last poll > 2h ago


# Shared in-process cache. `agents/enrichment.py` imports this
# directly to look up an IOC without another HTTP round-trip after
# the ingestor has run.
_TC_CACHE: Set[str] = set()
_TC_CACHE_AT: float = 0.0


# Rough IPv4/IPv6 shape sniffer so we can tell IPs apart from domains
# at ingest time. Not a validator - just picks which bucket the value
# belongs in for the per-type renderer cue.
_IPV4_RX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_IPV6_RX = re.compile(r"^[0-9a-fA-F:]+$")


def lookup(value: str) -> Dict[str, Any] | None:
    """Return a per-IOC hit blob when `value` is in the current cache.
    None on cache miss or stale cache (older than TTL). Enricher-side
    helper - keeps the per-enrichment cost at one dict hit."""
    if not value or not _TC_CACHE:
        return None
    if time.time() - _TC_CACHE_AT > _CACHE_TTL_SEC:
        return None
    if value not in _TC_CACHE:
        return None
    return {
        "source":    "threatcluster_feed",
        "found":     True,
        "summary":   "On ThreatCluster public blocklist (30-day window)",
        "verdict":   "SUSPICIOUS",
        "details_url": "https://threatcluster.io/iocs",
    }


class ThreatClusterIngestor(Ingestor):
    name = "threatcluster"
    description = (
        "Pull ThreatCluster's keyless 30-day public blocklist (domains "
        "+ IPv4 + IPv6). Hourly refresh. Seeds a process-local cache "
        "so per-IOC enrichment gets a 'seen in 30-day feed' row "
        "without a round-trip."
    )
    interval_seconds = 3600                # hourly - matches vendor cache
    optional_keys = []
    homepage = "https://threatcluster.io/"

    async def poll(self, session) -> AsyncIterator[Dict[str, Any]]:
        values = await _fetch_feed(session)
        if not values:
            return
        global _TC_CACHE, _TC_CACHE_AT
        _TC_CACHE = values
        _TC_CACHE_AT = time.time()
        _log.info("threatcluster ingestor cached %d IOCs", len(values))
        for v in values:
            t = _detect_type(v)
            if t:
                yield {"type": t, "value": v, "source": "threatcluster"}


def _detect_type(value: str) -> str:
    """Coarse type classification for the ingestor's yielded dict.
    Falls back to 'domain' for anything that isn't an IP - the
    feed only contains domains + IPv4 + IPv6 per the vendor header."""
    if _IPV4_RX.match(value):
        return "ipv4"
    if ":" in value and _IPV6_RX.match(value):
        return "ipv6"
    return "domain"


async def _fetch_feed(session) -> Set[str]:
    """Download + parse the plain-text feed. Comment lines (starting
    with '#') and empty lines are skipped. Returns the parsed set."""
    if session is None:
        import aiohttp
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as s:
            return await _fetch_feed(s)
    headers = {"Accept": "text/plain",
               "User-Agent": "RECON-ThreatCluster-Ingestor/1.0"}
    try:
        async with session.get(_FEED_URL, headers=headers) as r:
            if r.status >= 400:
                _log.warning("threatcluster feed HTTP %d", r.status)
                return set()
            text = await r.text()
    except Exception as e:
        _log.warning("threatcluster feed fetch failed: %s", e)
        return set()
    out: Set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Cap individual entries - a malformed feed with a mega-string
        # could otherwise balloon the cache. 200 chars is more than
        # enough for any real IP/domain.
        if len(line) <= 200:
            out.add(line)
    return out


register(ThreatClusterIngestor)
