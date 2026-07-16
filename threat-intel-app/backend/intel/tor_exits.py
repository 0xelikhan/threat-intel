"""
Tor Exit Nodes — official Tor Project Onionoo API, free, no key.

Onionoo publishes every currently-known Tor relay + bridge. We filter
to Exit-flagged relays (the ones actually egress-capable) and index by
BOTH `exit_addresses` and the IP portion of `or_addresses` — a relay
often accepts exit traffic on a different IP than its OR socket, and
either can appear as the source of a real-world sign-in.

RECON's existing warninglists include a Tor exit list from MISP but
that snapshot is stale (updated ad-hoc). Onionoo is the canonical
Tor Project feed — hourly-fresh, includes verified reverse-DNS names
+ ASN context, and lets us distinguish a real exit from a random
Tor bridge or relay that happens to share ASN with an exit.

Refreshed every 6h from the lifespan warm loop (pre-warmed so the
first analyze doesn't pay the ~1s network + JSON parse cost).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import threading
import time
import urllib.request
from typing import Any, Dict, Optional

_log = logging.getLogger("recon.intel.tor_exits")

_URL = ("https://onionoo.torproject.org/details"
        "?flag=Exit&fields=fingerprint,or_addresses,exit_addresses,"
        "as_number,as_name,country,country_name,"
        "verified_host_names,last_seen")

_TTL_SECONDS = 6 * 3600

_lock = threading.Lock()
_state: Dict[str, Any] = {
    "loaded_at":     0.0,
    "by_ip":         {},   # {"1.2.3.4": {"fingerprint": ..., "as_number": ..., ...}}
    "total_relays":  0,
    "error":         None,
}


def _strip_port(addr: str) -> str:
    """or_addresses entries include :port suffixes and IPv6 brackets.
    Normalise to the plain address."""
    if not addr:
        return ""
    if addr.startswith("["):
        # [::1]:8443 -> ::1
        end = addr.find("]")
        return addr[1:end] if end != -1 else ""
    # IPv4 with :port  →  drop the port
    if addr.count(":") == 1:
        return addr.split(":", 1)[0]
    return addr


def _valid_ip(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False


def _refresh_sync() -> None:
    """Blocking Onionoo fetch. Called from lifespan warm loop via
    to_thread; also self-refreshes via _ensure_loaded on lookup."""
    req = urllib.request.Request(_URL, headers={
        "User-Agent": "RECON-ThreatIntel/1.0",
        "Accept":     "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            payload = json.loads(r.read().decode("utf-8", errors="ignore"))
    except Exception as e:
        with _lock:
            _state["error"] = str(e)[:200]
            _state["loaded_at"] = time.time()   # backoff
        _log.warning("Onionoo fetch failed: %s", e)
        return

    relays = payload.get("relays") or []
    by_ip: Dict[str, Dict[str, Any]] = {}
    for r_ in relays:
        if not isinstance(r_, dict):
            continue
        base = {
            "fingerprint":        r_.get("fingerprint"),
            "as_number":          r_.get("as_number"),
            "as_name":            r_.get("as_name"),
            "country":            r_.get("country"),
            "country_name":       r_.get("country_name"),
            "verified_host_names": r_.get("verified_host_names") or [],
            "last_seen":          r_.get("last_seen"),
        }
        # Prefer exit_addresses (definitively exit-capable IPs) over
        # or_addresses (OR socket, only exit-capable on some relays).
        for src in ("exit_addresses", "or_addresses"):
            for a in (r_.get(src) or []):
                ip = _strip_port(str(a))
                if _valid_ip(ip):
                    by_ip[ip] = {**base, "matched_field": src}
    with _lock:
        _state["by_ip"]        = by_ip
        _state["total_relays"] = len(relays)
        _state["loaded_at"]    = time.time()
        _state["error"]        = None
    _log.info("Tor exit index loaded: %d relays, %d unique IPs",
              len(relays), len(by_ip))


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
            _state["loaded_at"] = time.time()   # backoff


def lookup(ip: str) -> Optional[Dict[str, Any]]:
    """Return the Tor-relay record for an IP if it's an active exit,
    or None."""
    _ensure_loaded()
    if not isinstance(ip, str) or not ip:
        return None
    return (_state.get("by_ip") or {}).get(ip.strip())


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded_at":    _state.get("loaded_at"),
        "total_relays": _state.get("total_relays"),
        "unique_ips":   len(_state.get("by_ip") or {}),
        "error":        _state.get("error"),
    }
