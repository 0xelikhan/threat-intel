"""
Tranco Top-1M domain ranking loader.

Source: https://tranco-list.eu (CC BY 4.0). An academic, hardened
top-domains list combining rankings from Alexa / Cisco Umbrella /
Majestic / Quantcast / Cloudflare. The published list URL pattern is

  https://tranco-list.eu/top-1m.csv.zip

Inside the zip is a CSV of `rank,domain` rows. We fetch on lifespan
warm, cache the rank dict in memory, refresh once per day. Cap the
parsed set at 1M entries (~25 MB resident).

The lookup is used in two places:
  1. triage's domain branch — adjusts triage_score *downward* when the
     analyst's input domain is in the top 1000. A top-100 brand that
     appears in an alert is almost certainly NOT itself the attacker.
  2. enrichment summary — surfaces the rank so the analyst sees the
     popularity context next to the verdict.
"""

from __future__ import annotations

import asyncio
import csv
import io
import logging
import threading
import time
import zipfile
from typing import Any, Dict, Optional

_log = logging.getLogger("recon.intel.tranco")

_TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
_TTL_S      = 24 * 3600   # refresh once a day

_LOAD_LOCK = asyncio.Lock()
_state: Dict[str, Any] = {
    "loaded_at": 0.0,
    "rank":      {},   # dict[str(domain.lower()), int(rank)]
    "size":      0,
    "error":     None,
}


async def _refresh(session) -> None:
    """Download tranco-list.eu/top-1m.csv.zip, parse the CSV, populate
    the in-memory rank dict. Same general pattern as phishing_db."""
    try:
        from agents.enrichment import _get
        # Tranco's endpoint returns a zip; _get supports binary responses
        # via the `raw=True` kwarg when present, else fall back to bytes
        # via the SDK helper. We try the simpler path first.
        from intel.cache import cache_for  # noqa: F401 — namespace marker
        raw = await _get(
            session, _TRANCO_URL,
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "application/zip,application/octet-stream"},
            raw_bytes=True,
        )
    except TypeError:
        # _get without raw_bytes kwarg — try a manual aiohttp pull.
        raw = await _fetch_bytes_directly(_TRANCO_URL)
    except Exception as e:
        _state["error"] = f"tranco fetch failed: {e}"
        return

    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 1024:
        _state["error"] = "tranco feed returned no payload"
        return

    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
        names = zf.namelist()
        if not names:
            _state["error"] = "tranco zip is empty"
            return
        with zf.open(names[0]) as f:
            text = f.read().decode("utf-8", errors="ignore")
    except Exception as e:
        _state["error"] = f"tranco zip parse failed: {e}"
        return

    rank: Dict[str, int] = {}
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if len(row) < 2:
            continue
        try:
            r = int(row[0])
        except ValueError:
            continue
        d = (row[1] or "").strip().lower().rstrip(".")
        if d and "." in d:
            rank[d] = r
        if len(rank) >= 1_000_000:
            break
    _state["rank"]      = rank
    _state["size"]      = len(rank)
    _state["loaded_at"] = time.time()
    _state["error"]     = None
    _log.info("tranco loaded: %d ranked domains", len(rank))


async def _fetch_bytes_directly(url: str) -> bytes:
    """Fallback when agents/enrichment._get doesn't accept raw_bytes."""
    import aiohttp
    async with aiohttp.ClientSession() as s:
        async with s.get(url, headers={"User-Agent": "RECON-ThreatIntel/1.0"},
                          timeout=aiohttp.ClientTimeout(total=30)) as r:
            return await r.read()


async def ensure_loaded(session) -> None:
    """Idempotent loader for the lifespan warm task."""
    async with _LOAD_LOCK:
        age = time.time() - _state["loaded_at"]
        if _state["rank"] and age < _TTL_S:
            return
        try:
            await _refresh(session)
        except Exception as e:
            _state["error"] = f"tranco refresh failed: {e}"
            _log.warning("tranco refresh failed: %s", e)


def rank(domain: str) -> Optional[int]:
    """Return the Tranco rank for a domain (1 = google.com etc.), or None
    when the domain isn't in the top 1M or the feed isn't loaded yet."""
    if not isinstance(domain, str) or not domain:
        return None
    d = domain.strip().lower().rstrip(".")
    r = _state.get("rank", {}).get(d)
    if r is not None:
        return r
    # Strip a leading subdomain or two so `mail.google.com` resolves
    # against `google.com`'s rank. Top-1M lists are eTLD+1 oriented.
    parts = d.split(".")
    while len(parts) > 2:
        parts = parts[1:]
        cand = ".".join(parts)
        if cand in _state.get("rank", {}):
            return _state["rank"][cand]
    return None


def is_top_n(domain: str, n: int = 1000) -> bool:
    """True when the domain (or its eTLD+1) is in the top-N. Useful in
    triage to short-circuit "this is too popular to be the attacker"."""
    r = rank(domain)
    return r is not None and r <= n


def stats() -> Dict[str, Any]:
    age = time.time() - _state["loaded_at"] if _state["loaded_at"] else None
    return {
        "loaded":  bool(_state.get("size")),
        "size":    _state.get("size", 0),
        "age_s":   int(age) if age is not None else None,
        "ttl_s":   _TTL_S,
        "error":   _state.get("error"),
    }
