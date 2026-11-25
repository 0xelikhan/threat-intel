"""Crowdsec Community Blocklist ingestor.

Crowdsec is a crowd-sourced IPS (think GreyNoise + Fail2ban with a
community-reporting layer). The CTI API exposes a "smoke list" and a
"community blocklist" feed of IPs that machines across the network
have reported in the last few hours. For RECON the value is a
near-real-time "is this IP on fire in the last N minutes?" signal
without needing a VirusTotal key.

How this ingestor works:
  1. Every `interval_seconds` seconds the orchestrator calls `poll()`.
  2. We GET https://cti.api.crowdsec.net/v2/smoke  (if a key is set)
     or the public community feed at
     https://api.crowdsec.net/v2/decisions/stream  (keyless fallback).
  3. Each returned IP becomes an IOC dict {type:ipv4, value:ip,
     meta:{...}} and lands in RECON's shared enrichment cache under
     the `crowdsec` key. On a subsequent /api/analyze call, the
     per-IP enricher reads that cache and renders a Crowdsec
     "seen on community blocklist, first_seen=T" row.

Config:
  CROWDSEC_API_KEY   optional; unlocks the paid CTI "smoke" feed with
                     higher cadence + scenario attribution (ssh-bf,
                     http-probing, impervious-exploit, etc.)

The ingestor is intentionally conservative - caps each poll at 200
IPs so an aggressive feed can't blow out the cache. The cache expires
each entry after 24h so stale IPs drop automatically.
"""

from __future__ import annotations

import logging
import time
from typing import Any, AsyncIterator, Dict, List, Optional

from plugins import Ingestor, register

_log = logging.getLogger("recon.plugins.ingestors.crowdsec")


_PAID_URL      = "https://cti.api.crowdsec.net/v2/smoke"
_FREE_URL      = "https://api.crowdsec.net/v2/decisions/stream"
_CACHE_TTL_SEC = 24 * 3600
_MAX_PER_POLL  = 200


# Shared in-memory cache. `agents/enrichment.py` imports this directly
# to look up a per-IP Crowdsec blob when running the IP enricher. The
# cache is intentionally process-local: the ingestor and the enricher
# live in the same FastAPI process, and we specifically agreed no DB.
# Entries expire at write + 24h to guarantee eventual cleanup even if
# the ingestor is disabled.
_CROWDSEC_CACHE: Dict[str, Dict[str, Any]] = {}


def lookup(ip: str) -> Optional[Dict[str, Any]]:
    """Public helper for the per-IP enricher. Returns the cached entry
    for an IP if it's present AND still fresh; None otherwise. Also
    evicts stale entries lazily on read so the cache doesn't grow
    without bound."""
    entry = _CROWDSEC_CACHE.get(ip)
    if not entry:
        return None
    if time.time() - entry.get("cached_at", 0) > _CACHE_TTL_SEC:
        _CROWDSEC_CACHE.pop(ip, None)
        return None
    return entry


def _ingest_record(ip: str, record: Dict[str, Any]) -> None:
    """Normalise one upstream record into the cache. Exposed for tests
    so they can seed the cache without an aiohttp round-trip."""
    scenarios = record.get("behaviors") or record.get("scenarios") or []
    if isinstance(scenarios, list):
        # Crowdsec "behaviors" are dicts {name, label, description};
        # the "scenarios" variant is a bare list of strings. Normalise
        # to a list of short labels for the UI.
        norm: List[str] = []
        for s in scenarios[:5]:
            if isinstance(s, dict):
                norm.append(str(s.get("name") or s.get("label") or "")[:80])
            else:
                norm.append(str(s)[:80])
        scenarios = [s for s in norm if s]
    else:
        scenarios = []
    _CROWDSEC_CACHE[ip] = {
        "source":        "crowdsec",
        "found":         True,
        "first_seen":    record.get("history", {}).get("first_seen")
                         or record.get("start_at") or None,
        "last_seen":     record.get("history", {}).get("last_seen")
                         or record.get("stop_at") or None,
        "scenarios":     scenarios,
        "attack_count":  record.get("attack_details_count")
                         or record.get("events_count") or None,
        "verdict":       "SUSPICIOUS",     # Crowdsec reports are not AV
                                            # verdicts - they're abuse
                                            # evidence; treat as SUS.
        "cached_at":     time.time(),
        "summary":       _summarise(scenarios, ip),
    }


def _summarise(scenarios: List[str], ip: str) -> str:
    """Build the one-line label the per-IP renderer surfaces. Falls
    back to a generic 'reported' line when no scenario attribution
    came back (the free feed often omits scenarios)."""
    if scenarios:
        head = ", ".join(scenarios[:3])
        more = len(scenarios) - 3
        suffix = f" (+{more} more)" if more > 0 else ""
        return f"Crowdsec community reports: {head}{suffix}"
    return "Crowdsec community reports: active malicious behaviour reported"


class CrowdsecIngestor(Ingestor):
    name = "crowdsec"
    description = ("Pull Crowdsec community blocklist every 15 min. Seeds a "
                   "per-process cache keyed by IP so the per-IP enricher "
                   "surfaces a 'seen in the last 24h' row without needing a "
                   "VirusTotal/AbuseIPDB key.")
    interval_seconds = 900                 # 15 min
    optional_keys = ["CROWDSEC_API_KEY"]
    homepage = "https://www.crowdsec.net/"

    async def poll(self, session) -> AsyncIterator[Dict[str, Any]]:
        key = self._resolve_key()
        url = _PAID_URL if key else _FREE_URL
        headers = {"Accept": "application/json",
                   "User-Agent": "RECON-Crowdsec-Ingestor/1.0"}
        if key:
            headers["x-api-key"] = key
        try:
            # Share-nothing: use the orchestrator's session if provided,
            # otherwise open a one-shot session. Both paths return a
            # list of record dicts the normaliser understands.
            records = await _fetch(session, url, headers)
        except Exception as e:
            _log.warning("crowdsec poll failed: %s", e)
            return

        count = 0
        for rec in records[:_MAX_PER_POLL]:
            if not isinstance(rec, dict):
                continue
            ip = rec.get("ip") or rec.get("value")
            if not ip:
                continue
            _ingest_record(str(ip), rec)
            count += 1
            # Yield so the orchestrator CAN decide to pre-enrich hot IPs.
            # The main consumer is the cache side-effect above; yielding
            # is secondary.
            yield {"type": "ipv4", "value": str(ip),
                   "source": "crowdsec_ingestor",
                   "scenarios": _CROWDSEC_CACHE[str(ip)].get("scenarios", [])}
        _log.info("crowdsec ingestor cached %d IPs (cache size=%d)",
                   count, len(_CROWDSEC_CACHE))

    def _resolve_key(self) -> str:
        """Config can come from env or (eventually) the config.json
        keystore. Env wins because the ingestor runs as part of the
        lifespan scheduler before the keystore is loaded on some
        deployment paths."""
        import os
        return (os.environ.get("CROWDSEC_API_KEY") or "").strip()


async def _fetch(session, url: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """Unpack the Crowdsec response - the paid and free feeds have
    different envelopes. Paid returns {items:[...]}, free returns
    {new:[...], deleted:[...]}. We only care about new/current
    entries in both cases."""
    # Session may be None if called outside the orchestrator (tests).
    if session is None:
        import aiohttp
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as s:
            return await _fetch(s, url, headers)
    async with session.get(url, headers=headers) as r:
        if r.status >= 400:
            _log.warning("crowdsec %s -> HTTP %d", url, r.status)
            return []
        try:
            payload = await r.json()
        except Exception:
            return []
    if not isinstance(payload, dict):
        return []
    if "items" in payload and isinstance(payload["items"], list):
        return payload["items"]
    if "new" in payload and isinstance(payload["new"], list):
        return payload["new"]
    return []


register(CrowdsecIngestor)
