"""
abuse.ch SSL Blacklist (SSLBL) — free, no key.

Three feeds. Note: abuse.ch deprecated the IP feed on 2025-01-03; it
still fetches (returning the deprecation header + no rows) so the
loader keeps working, but the IP index will be empty on modern loads.
The SHA1 and JA3 feeds are still actively maintained:

  - sslipblacklist.csv       IP + port    [deprecated 2025-01-03]
  - sslblacklist.csv         Cert SHA1 + malware family  (~10k entries)
  - ja3_fingerprints.csv     JA3 hash + malware family   (~100 entries)

The primary cross-reference vector is now cert SHA1 — matched against
whatever cert fingerprints upstream sources (Censys / Shodan) return
for the IP under investigation.

Feeds refresh multiple times per day. We reload every 6h in the
lifespan warm loop; between reloads the in-memory index is authoritative.
"""

from __future__ import annotations

import csv
import io
import logging
import threading
import time
from typing import Any, Dict, Optional

_log = logging.getLogger("recon.intel.sslbl")

_URLS = {
    "ip":   "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
    "sha1": "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
    "ja3":  "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
}

_TTL_SECONDS = 6 * 3600

_lock = threading.Lock()
_state: Dict[str, Any] = {
    "loaded_at":     0.0,
    "by_ip":         {},   # {"1.2.3.4:443": {"family": "Emotet", "listed": "..."}}
    "by_ip_any":     {},   # {"1.2.3.4": {"family": "Emotet", ...}}  (port-agnostic)
    "by_sha1":       {},   # {sha1 lower: {"family": ..., "listed": ...}}
    "by_ja3":        {},   # {ja3 lower: {"family": ..., "listed": ...}}
    "error":         None,
}


def _parse_ip_csv(text: str) -> Dict[str, Dict[str, Any]]:
    """SSLBL sslipblacklist.csv columns:
       # DstIP, DstPort, Listing_date, Listing_reason"""
    out: Dict[str, Dict[str, Any]] = {}
    rdr = csv.reader(io.StringIO(text))
    for row in rdr:
        if not row or row[0].startswith("#"):
            continue
        if len(row) < 4:
            continue
        ip, port, listed, reason = row[0].strip(), row[1].strip(), row[2].strip(), row[3].strip()
        if not ip:
            continue
        family = reason.split()[0] if reason else ""
        out[f"{ip}:{port}"] = {"family": family, "listing_reason": reason,
                                 "listed": listed, "port": port}
    return out


def _parse_sha1_csv(text: str) -> Dict[str, Dict[str, Any]]:
    """SSLBL sslblacklist.csv columns:
       # Listingdate, SHA1, Listingreason"""
    out: Dict[str, Dict[str, Any]] = {}
    rdr = csv.reader(io.StringIO(text))
    for row in rdr:
        if not row or row[0].startswith("#"):
            continue
        if len(row) < 3:
            continue
        listed, sha1, reason = row[0].strip(), row[1].strip().lower(), row[2].strip()
        if len(sha1) != 40:
            continue
        family = reason.split()[0] if reason else ""
        out[sha1] = {"family": family, "listing_reason": reason, "listed": listed}
    return out


def _parse_ja3_csv(text: str) -> Dict[str, Dict[str, Any]]:
    """SSLBL ja3_fingerprints.csv columns:
       # ja3_md5, Firstseen, Lastseen, Listingreason"""
    out: Dict[str, Dict[str, Any]] = {}
    rdr = csv.reader(io.StringIO(text))
    for row in rdr:
        if not row or row[0].startswith("#"):
            continue
        if len(row) < 4:
            continue
        ja3, first, last, reason = (row[0].strip().lower(), row[1].strip(),
                                     row[2].strip(), row[3].strip())
        if len(ja3) != 32:
            continue
        family = reason.split()[0] if reason else ""
        out[ja3] = {"family": family, "listing_reason": reason,
                    "first_seen": first, "last_seen": last}
    return out


def _refresh_sync() -> None:
    """Blocking refresh. Called from lifespan warm loop via to_thread."""
    import urllib.request
    global _state
    fresh: Dict[str, Any] = {"by_ip": {}, "by_ip_any": {}, "by_sha1": {}, "by_ja3": {}}
    hdr = {"User-Agent": "RECON-ThreatIntel/1.0"}
    for kind, url in _URLS.items():
        try:
            req = urllib.request.Request(url, headers=hdr)
            with urllib.request.urlopen(req, timeout=15) as r:
                text = r.read().decode("utf-8", errors="ignore")
            if kind == "ip":
                fresh["by_ip"] = _parse_ip_csv(text)
                for k, v in fresh["by_ip"].items():
                    ip = k.split(":", 1)[0]
                    fresh["by_ip_any"].setdefault(ip, v)
            elif kind == "sha1":
                fresh["by_sha1"] = _parse_sha1_csv(text)
            elif kind == "ja3":
                fresh["by_ja3"] = _parse_ja3_csv(text)
        except Exception as e:
            _log.warning("SSLBL %s refresh failed: %s", kind, e)
            # Keep whatever we already had for that kind.
            fresh[f"by_{kind}"] = _state.get(f"by_{kind}", {}) or {}
            if kind == "ip":
                fresh["by_ip_any"] = _state.get("by_ip_any", {}) or {}

    with _lock:
        _state.update(fresh)
        _state["loaded_at"] = time.time()
        _state["error"] = None
    _log.info("SSLBL loaded: %d IPs (%d unique), %d SHA1, %d JA3",
              len(fresh["by_ip"]), len(fresh["by_ip_any"]),
              len(fresh["by_sha1"]), len(fresh["by_ja3"]))


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


def lookup_ip(ip: str, port: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """Cross-ref an IP (optionally with port) against SSLBL's C2 IP feed.
    Returns the row (family + listing reason + date) or None."""
    _ensure_loaded()
    if not isinstance(ip, str) or not ip:
        return None
    if port is not None:
        hit = (_state.get("by_ip") or {}).get(f"{ip}:{port}")
        if hit:
            return hit
    return (_state.get("by_ip_any") or {}).get(ip)


def lookup_sha1(sha1: str) -> Optional[Dict[str, Any]]:
    _ensure_loaded()
    if not isinstance(sha1, str) or len(sha1) != 40:
        return None
    return (_state.get("by_sha1") or {}).get(sha1.lower())


def lookup_ja3(ja3: str) -> Optional[Dict[str, Any]]:
    _ensure_loaded()
    if not isinstance(ja3, str) or len(ja3) != 32:
        return None
    return (_state.get("by_ja3") or {}).get(ja3.lower())


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded_at":     _state.get("loaded_at"),
        "ip_entries":    len(_state.get("by_ip") or {}),
        "ip_unique":     len(_state.get("by_ip_any") or {}),
        "sha1_entries":  len(_state.get("by_sha1") or {}),
        "ja3_entries":   len(_state.get("by_ja3") or {}),
        "error":         _state.get("error"),
    }
