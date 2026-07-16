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

_lock = threading.Lock()
_state: Dict[str, Any] = {
    "loaded_at": 0.0,
    "ips":       set(),   # {str}
    "generated_note": "",
    "error":     None,
}


def _refresh_sync() -> None:
    req = urllib.request.Request(_URL, headers={
        "User-Agent": "RECON-ThreatIntel/1.0",
        "Accept":     "text/plain",
    })
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            text = r.read().decode("utf-8", errors="ignore")
    except Exception as e:
        with _lock:
            _state["error"] = str(e)[:200]
            _state["loaded_at"] = time.time()
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
    if ip.strip() not in (_state.get("ips") or set()):
        return None
    return {
        "source":       "ThreatView.io CS C2",
        "found":        True,
        "verdict":      "MALICIOUS",
        "framework":    "Cobalt Strike",
        "summary":      (f"IP is on ThreatView's high-confidence Cobalt Strike "
                          f"team-server list ({_state.get('generated_note', '')[:80]})"),
    }


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded_at": _state.get("loaded_at"),
        "ip_count":  len(_state.get("ips") or set()),
        "error":     _state.get("error"),
    }
