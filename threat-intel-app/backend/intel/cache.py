"""
TTLCache — per-key TTL, thread-safe, lazy eviction, hit/miss tracking.

Single concern: prevent redundant external API calls for IOCs that were
recently enriched. Backed by a plain dict with monotonic-time expiries;
no background sweeper thread — entries are checked for expiry on every
get() and the dead ones are evicted in place.

Public API:
    cache = TTLCache(default_ttl=3600)
    cache.set("key", value, ttl=None)     # use default_ttl when ttl is None
    cache.get("key")                       # returns None on miss / expired
    cache.delete("key")
    cache.clear()
    cache.stats()                          # {entries, hits, misses, ...}

Module-level singleton + helpers:
    cache_for(namespace) -> TTLCache       # one cache per logical bucket
    global_stats() -> dict                 # rollup across every namespace

Namespaces let us tune TTL per source class — see DEFAULT_TTL_BY_NAMESPACE
below (MITRE / warninglists / KEV live for a day; live TI sources for an
hour). Sources never need to know about TTLs — they just call
`cache_for("virustotal").get(...)`.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional


# ─── per-namespace defaults ───────────────────────────────────────────────────
#
# Static reference data is cheap to keep around for a day. Live TI sources
# rotate fast — an hour is the sweet spot between freshness and saving API
# quota. Tune via env-overrides at the call site when needed.
DEFAULT_TTL_BY_NAMESPACE: Dict[str, int] = {
    "mitre":         86400,
    "warninglists":  86400,
    "feodo":         86400,
    "sslbl":         86400,
    "kev":           86400,
    "lolbas":        86400,
    "loldrivers":    86400,
    # everything else (virustotal, abuseipdb, otx, urlscan, …) → 1 hour
}
_FALLBACK_TTL = 3600


class TTLCache:
    """Thread-safe TTL cache. Lazy eviction on read."""

    def __init__(self, default_ttl: int = _FALLBACK_TTL) -> None:
        self._default_ttl = int(default_ttl)
        self._store: Dict[str, tuple] = {}     # key -> (value, expires_at)
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
        self._sets = 0
        self._evictions = 0

    # ── primary API ───────────────────────────────────────────────────────────
    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return None
            value, expires_at = entry
            if expires_at <= time.monotonic():
                del self._store[key]
                self._evictions += 1
                self._misses += 1
                return None
            self._hits += 1
            return value

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        ttl_s = int(ttl) if ttl is not None else self._default_ttl
        with self._lock:
            self._store[key] = (value, time.monotonic() + ttl_s)
            self._sets += 1

    def delete(self, key: str) -> None:
        with self._lock:
            if key in self._store:
                del self._store[key]

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._hits = 0
            self._misses = 0
            self._sets = 0
            self._evictions = 0

    # ── introspection ─────────────────────────────────────────────────────────
    def __len__(self) -> int:
        with self._lock:
            return len(self._store)

    def stats(self) -> Dict[str, Any]:
        """Live stats. hit_rate and miss_rate are in percent (0-100)."""
        with self._lock:
            total = self._hits + self._misses
            hit_rate = (self._hits / total * 100) if total else 0.0
            # bytes_estimate was an O(N) `str(v).encode()` over every
            # cached value on every /api/status hit. For the warninglists
            # namespace (~30k entries, each ~200 B serialised) that was
            # a ~6 MB string allocation per status call. A periodic
            # frontend healthcheck doing 1 req/s would burn measurable
            # CPU on the estimate alone. Sample the first 50 entries
            # instead and extrapolate — same signal ("is this growing
            # unboundedly?") at constant cost.
            _SAMPLE_N = 50
            sampled = 0
            sample_bytes = 0
            for k, (v, _) in self._store.items():
                if sampled >= _SAMPLE_N:
                    break
                sample_bytes += (len(k.encode("utf-8", errors="ignore"))
                                 + len(str(v).encode("utf-8", errors="ignore")))
                sampled += 1
            if sampled == 0:
                bytes_estimate = 0
            else:
                bytes_estimate = int(sample_bytes / sampled * len(self._store))
            return {
                "entries":   len(self._store),
                "hits":      self._hits,
                "misses":    self._misses,
                "sets":      self._sets,
                "evictions": self._evictions,
                "hit_rate":  round(hit_rate, 1),
                "miss_rate": round(100 - hit_rate, 1) if total else 0.0,
                # Stable signal for "is this cache growing unbounded?"
                # — extrapolated from a small sample, not exact.
                "bytes_estimate": bytes_estimate,
            }


# ─── namespaced registry ──────────────────────────────────────────────────────
_CACHES: Dict[str, TTLCache] = {}
_REGISTRY_LOCK = threading.RLock()


def cache_for(namespace: str) -> TTLCache:
    """Get-or-create the TTLCache for `namespace`. The default TTL is
    picked from DEFAULT_TTL_BY_NAMESPACE, falling back to _FALLBACK_TTL
    (3600s) for anything not listed."""
    with _REGISTRY_LOCK:
        c = _CACHES.get(namespace)
        if c is None:
            c = TTLCache(default_ttl=DEFAULT_TTL_BY_NAMESPACE.get(namespace, _FALLBACK_TTL))
            _CACHES[namespace] = c
        return c


def clear_all() -> None:
    """Wipe every namespaced cache and forget the namespace registry.
    Used by tests to start each one from a clean slate. Callers that
    held a TTLCache reference from a prior `cache_for(...)` will keep
    seeing an empty cache; the next `cache_for(name)` returns a fresh
    instance."""
    with _REGISTRY_LOCK:
        for c in _CACHES.values():
            c.clear()
        _CACHES.clear()


def global_stats() -> Dict[str, Any]:
    """Per-namespace stats + an aggregate rollup. Returned by
    /api/status under the `cache` key."""
    with _REGISTRY_LOCK:
        per_ns = {ns: c.stats() for ns, c in _CACHES.items()}
    total_hits      = sum(s["hits"]      for s in per_ns.values())
    total_misses    = sum(s["misses"]    for s in per_ns.values())
    total_entries   = sum(s["entries"]   for s in per_ns.values())
    total_evictions = sum(s["evictions"] for s in per_ns.values())
    total_bytes     = sum(s["bytes_estimate"] for s in per_ns.values())
    total_lookups   = total_hits + total_misses
    return {
        "namespaces": per_ns,
        "totals": {
            "entries":        total_entries,
            "hits":           total_hits,
            "misses":         total_misses,
            "evictions":      total_evictions,
            "hit_rate":       round(total_hits / total_lookups * 100, 1) if total_lookups else 0.0,
            "miss_rate":      round(total_misses / total_lookups * 100, 1) if total_lookups else 0.0,
            "bytes_estimate": total_bytes,
            "namespaces":     len(per_ns),
        },
    }
