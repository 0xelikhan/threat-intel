"""
Circuit breaker for enrichment sources.

Tracks per-host failure streaks. After `failure_threshold` consecutive
failures the breaker opens — calls to that host short-circuit with a
synthesized `{"error": "circuit open"}` for `cooldown_s` seconds. After
the cooldown a single probe call is allowed (half-open); success resets
the streak, failure re-opens the breaker for another cooldown window.

Why per-host rather than per-source: enrichment.py fans out to many
sources whose endpoints map cleanly to a hostname. Tracking by host
catches "VirusTotal is down" (covers vt-file + vt-url + vt-domain in
one shot) without needing each source to register itself.

Public surface:
    breaker = get_breaker()
    if breaker.is_open(host): return {"error": "circuit open for host"}
    try:
        result = await call()
        breaker.record_success(host)
    except Exception:
        breaker.record_failure(host)

The breaker is process-wide. Stats are exposed via global_stats() so
/api/status (Section 3) can surface degraded sources without a separate
endpoint.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, Dict, Optional
from urllib.parse import urlparse


_FAILURE_THRESHOLD = int(os.environ.get("CIRCUIT_BREAKER_THRESHOLD", "3"))
_COOLDOWN_S        = int(os.environ.get("CIRCUIT_BREAKER_COOLDOWN_S", "300"))


class _HostState:
    __slots__ = ("failure_streak", "open_until", "total_failures", "total_successes")

    def __init__(self) -> None:
        self.failure_streak  = 0
        self.open_until      = 0.0   # monotonic
        self.total_failures  = 0
        self.total_successes = 0


class CircuitBreaker:
    """Thread-safe per-host breaker. Lazy state — hosts only enter the
    table on first failure."""

    def __init__(self,
                 failure_threshold: int = _FAILURE_THRESHOLD,
                 cooldown_s:        int = _COOLDOWN_S) -> None:
        self._threshold = failure_threshold
        self._cooldown  = cooldown_s
        self._hosts: Dict[str, _HostState] = {}
        self._lock = threading.RLock()

    # ── primary API ───────────────────────────────────────────────────────────
    def is_open(self, host: str) -> bool:
        """True if the breaker is currently rejecting calls to `host`."""
        with self._lock:
            st = self._hosts.get(host)
            if st is None:
                return False
            if st.open_until and time.monotonic() < st.open_until:
                return True
            return False

    def record_success(self, host: str) -> None:
        with self._lock:
            st = self._hosts.setdefault(host, _HostState())
            st.failure_streak  = 0
            st.open_until      = 0.0
            st.total_successes += 1

    def record_failure(self, host: str) -> None:
        with self._lock:
            st = self._hosts.setdefault(host, _HostState())
            st.failure_streak  += 1
            st.total_failures  += 1
            if st.failure_streak >= self._threshold:
                st.open_until = time.monotonic() + self._cooldown

    # ── introspection ─────────────────────────────────────────────────────────
    def stats(self) -> Dict[str, Any]:
        """Per-host status block, suitable for /api/status output."""
        now = time.monotonic()
        with self._lock:
            return {
                host: {
                    "state":       "open" if (st.open_until and now < st.open_until) else "closed",
                    "failures":    st.total_failures,
                    "successes":   st.total_successes,
                    "streak":      st.failure_streak,
                    "reopens_in_s": max(0, int(st.open_until - now)) if st.open_until else 0,
                }
                for host, st in self._hosts.items()
            }

    def reset(self) -> None:
        """Wipe all state — used by tests."""
        with self._lock:
            self._hosts.clear()


# ── module-level singleton ────────────────────────────────────────────────────
_BREAKER = CircuitBreaker()


def get_breaker() -> CircuitBreaker:
    return _BREAKER


def host_of(url: str) -> Optional[str]:
    """Extract the hostname from a URL — returns None when the URL is
    unparseable so callers can no-op gracefully."""
    try:
        return (urlparse(url).hostname or "").lower() or None
    except Exception:
        return None
