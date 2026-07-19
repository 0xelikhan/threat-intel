"""
ThreatView.io High-Confidence Cobalt Strike C2 IPs — free, no key.

RECON's existing C2 feeds (Feodo, ThreatFox, URLhaus, FireHOL) are
family-agnostic — they flag an IP as bad but not "this is a Cobalt
Strike team server." ThreatView's Proactive C2 Hunter publishes a
CS-specific IP list built from active-scan discovery of default
CS listener signatures. Complements the JARM known-bad list we
already surface in the response phase.

Feed refreshes irregularly — some updates monthly, others weekly.
We reload every 12h in the lifespan warm loop.
"""

from __future__ import annotations

import logging
import threading
import time
import urllib.request
from typing import Any, Dict, Optional, Set

_log = logging.getLogger("recon.intel.threatview_c2")

_URL = "https://threatview.io/Downloads/High-Confidence-CobaltstrikeC2_IP_feed.txt"
_TTL_SECONDS = 12 * 3600

_lock = threading.RLock()  # reentrant: _ensure_loaded holds it, then
                            # _refresh_sync re-acquires — a plain Lock
                            # deadlocks; RLock is a drop-in fix.
_state: Dict[str, Any] = {
    "loaded_at": 0.0,
    "ips":       set(),   # {str}
    "generated_note": "",
    "error":     None,
}


def _refresh_sync() -> None:
    from intel._http import fetch_bytes
    try:
        text = fetch_bytes(_URL, timeout=20, accept="text/plain")\
            .decode("utf-8", errors="ignore")
    except Exception as e:
        with _lock:
            _state["error"] = str(e)[:200]
            # Short backoff on failure: retry in ~60s instead of hiding
            # the empty state behind the full TTL. Prevents a transient
            # network blip during lifespan warm from silently killing
            # this source for the entire refresh window.
            _state["loaded_at"] = time.time() - _TTL_SECONDS + 60
        _log.warning("ThreatView CS C2 fetch failed: %s", e)
        return

    ips: Set[str] = set()
    generated_note = ""
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("#"):
            if not generated_note:
                generated_note = s.lstrip("# ").strip()[:200]
            continue
        # Each remaining line is a single IPv4 (per upstream format).
        # Basic sanity: must have three dots + only digits/dots.
        if s.count(".") == 3 and all(part.isdigit() and 0 <= int(part) <= 255
                                       for part in s.split(".")):
            ips.add(s)
    with _lock:
        _state["ips"] = ips
        _state["generated_note"] = generated_note
        _state["loaded_at"] = time.time()
        _state["error"] = None
    _log.info("ThreatView CS C2 loaded: %d IPs", len(ips))


def _ensure_loaded() -> None:
    if _state["loaded_at"] and (time.time() - _state["loaded_at"]) < _TTL_SECONDS:
        return
    with _lock:
        if _state["loaded_at"] and (time.time() - _state["loaded_at"]) < _TTL_SECONDS:
            return
        try:
            _refresh_sync()
        except Exception as e:
            _state["error"] = str(e)[:200]
            _state["loaded_at"] = time.time()


def lookup(ip: str) -> Optional[Dict[str, Any]]:
    """Return a hit record if the IP is on ThreatView's high-confidence
    Cobalt Strike C2 list, else None."""
    _ensure_loaded()
    if not isinstance(ip, str) or not ip:
        return None
    # Read the ips set + note under lock — _refresh_sync replaces both
    # atomically per key but 'in' + subsequent .get() are separate ops.
    with _lock:
        if ip.strip() not in (_state.get("ips") or set()):
            return None
        note = (_state.get("generated_note", "") or "")[:80]
    return {
        "source":       "ThreatView.io CS C2",
        "found":        True,
        "verdict":      "MALICIOUS",
        "framework":    "Cobalt Strike",
        "summary":      (f"IP is on ThreatView's high-confidence Cobalt Strike "
                          f"team-server list ({note})"),
    }


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    with _lock:
        return {
            "loaded_at": _state.get("loaded_at"),
            "ip_count":  len(_state.get("ips") or set()),
            "error":     _state.get("error"),
        }
