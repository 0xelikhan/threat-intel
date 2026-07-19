"""
ViriBack Tracker — free CSV, no key. Live at tracker.viriback.com/dump.php.

Format:  Family,URL,IP,FirstSeen
Example: Amadey,http://196.251.107.186/qK3mRv9L/Login.php,196.251.107.186,09-07-2026

Adds per-IOC MALWARE FAMILY attribution — the abuse.ch trio (URLhaus,
Feodo, ThreatFox) flag the URL/IP as bad but not always which family;
Feodo especially is dropper-focused. ViriBack tracks C2 panels + login
endpoints with clean family labels (RedLine, Lumma, Amadey, StealC,
Vidar, MetaStealer, and dozens of others).

We index by BOTH IP and URL so enrich_ip and enrich_url can each
cross-reference. Refreshed every 12h in the lifespan warm loop.
"""

from __future__ import annotations

import csv
import io
import logging
import threading
import time
import urllib.request
from typing import Any, Dict, Optional

_log = logging.getLogger("recon.intel.viriback")

_URL = "https://tracker.viriback.com/dump.php"
_TTL_SECONDS = 12 * 3600

_lock = threading.RLock()  # reentrant: _ensure_loaded holds it, then
                            # _refresh_sync re-acquires — a plain Lock
                            # deadlocks; RLock is a drop-in fix.
_state: Dict[str, Any] = {
    "loaded_at":   0.0,
    "by_ip":       {},   # {"1.2.3.4": [{"family": "Amadey", ...}, ...]}
    "by_url":      {},   # {"http://.../login.php": {"family": ..., ...}}
    "family_counts": {},
    "error":       None,
}


def _refresh_sync() -> None:
    req = urllib.request.Request(_URL, headers={
        "User-Agent": "RECON-ThreatIntel/1.0",
        "Accept":     "text/csv",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            text = r.read().decode("utf-8", errors="ignore")
    except Exception as e:
        with _lock:
            _state["error"] = str(e)[:200]
            _state["loaded_at"] = time.time()
        _log.warning("ViriBack fetch failed: %s", e)
        return

    by_ip: Dict[str, list] = {}
    by_url: Dict[str, Dict[str, Any]] = {}
    families: Dict[str, int] = {}

    rdr = csv.reader(io.StringIO(text))
    header = next(rdr, None)
    if not header or [c.lower() for c in header[:4]] != ["family", "url", "ip", "firstseen"]:
        _log.warning("ViriBack CSV header unexpected: %r", header)
    for row in rdr:
        if len(row) < 4:
            continue
        family, url, ip, first_seen = row[0].strip(), row[1].strip(), row[2].strip(), row[3].strip()
        if not family or not ip:
            continue
        rec = {"family": family, "url": url,
               "ip":     ip,     "first_seen": first_seen}
        by_ip.setdefault(ip, []).append(rec)
        if url:
            # Latest observation wins for a given URL.
            by_url[url] = rec
        families[family] = families.get(family, 0) + 1

    with _lock:
        _state["by_ip"]         = by_ip
        _state["by_url"]        = by_url
        _state["family_counts"] = families
        _state["loaded_at"]     = time.time()
        _state["error"]         = None
    _log.info("ViriBack loaded: %d IPs · %d URLs · %d families",
              len(by_ip), len(by_url), len(families))


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


def _pack(records: list, ip: str = "", url: str = "") -> Dict[str, Any]:
    """Collapse one or more raw records into an analyst-friendly hit."""
    if not records:
        return {}
    # Prefer the newest observation, sort by first_seen descending on
    # DD-MM-YYYY. Fall back to alphabetical when parse fails.
    def _key(r):
        s = r.get("first_seen") or ""
        try:
            d, m, y = s.split("-")
            return (int(y), int(m), int(d))
        except Exception:
            return (0, 0, 0)
    records = sorted(records, key=_key, reverse=True)
    families = sorted({r.get("family") for r in records if r.get("family")})
    latest   = records[0]
    return {
        "source":       "ViriBack Tracker",
        "found":        True,
        "verdict":      "MALICIOUS",
        "family":       latest.get("family"),
        "all_families": families,
        "first_seen":   latest.get("first_seen"),
        "hit_count":    len(records),
        "sample_url":   latest.get("url") or url,
        "summary":      (f"ViriBack: {latest.get('family')} C2 panel — "
                          f"observed {len(records)}x, latest {latest.get('first_seen')}"),
    }


def lookup_ip(ip: str) -> Optional[Dict[str, Any]]:
    _ensure_loaded()
    if not isinstance(ip, str) or not ip:
        return None
    recs = (_state.get("by_ip") or {}).get(ip.strip())
    return _pack(recs, ip=ip) if recs else None


def lookup_url(url: str) -> Optional[Dict[str, Any]]:
    _ensure_loaded()
    if not isinstance(url, str) or not url:
        return None
    rec = (_state.get("by_url") or {}).get(url.strip())
    return _pack([rec], url=url) if rec else None


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded_at": _state.get("loaded_at"),
        "ip_count":  len(_state.get("by_ip") or {}),
        "url_count": len(_state.get("by_url") or {}),
        "families":  len(_state.get("family_counts") or {}),
        "error":     _state.get("error"),
    }
