"""
Ransomware.live — recent ransomware victim postings scraped from leak
sites. Free API, no key.

Answers a question static intel can't:
  "Is this group active RIGHT NOW?"

The static family list in intel/misp_galaxies is authoritative for
attribution but says nothing about who's still operating. A hit here
means the group's leak site was updated in the last ~48 hours — that
directly changes the recommended actions the analyst produces.

Cached hourly. All lookups are keyed by lowercased family/group name.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.request
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.intel.ransomware_live")

_TTL_SECONDS = 3600  # refresh every hour

_URLS = {
    "recent":       "https://api.ransomware.live/v2/recentvictims",
    "groups":       "https://api.ransomware.live/v2/groups",
}

_lock = threading.RLock()  # reentrant: _ensure_loaded holds it, then
                            # _refresh_sync re-acquires — a plain Lock
                            # deadlocks; RLock is a drop-in fix.
_state: Dict[str, Any] = {
    "loaded_at":    0.0,
    "by_group":     {},   # {group_name lower: {"latest": iso, "count_30d": int, "recent": [...]}}
    "active_groups": [],  # groups with at least one post in last 30 days
    "total_victims": 0,
    "error":        None,
}


def _http_json(url: str) -> Any:
    from intel._http import fetch_json
    return fetch_json(url, timeout=15)


def _refresh_sync() -> None:
    """Blocking fetch of both feeds. Called from lifespan warm loop."""
    try:
        recent = _http_json(_URLS["recent"])
    except Exception as e:
        _log.warning("ransomware.live recent-victims fetch failed: %s", e)
        _state["error"] = str(e)[:200]
        # Short backoff — retry in ~60s, not the full 1h TTL. See
        # threatview_c2.py for the same pattern + rationale.
        _state["loaded_at"] = time.time() - _TTL_SECONDS + 60
        return

    if not isinstance(recent, list):
        _state["error"] = "unexpected recent-victims shape"
        _state["loaded_at"] = time.time() - _TTL_SECONDS + 60
        return

    by_group: Dict[str, Dict[str, Any]] = {}
    now = time.time()
    cutoff_30 = now - 30 * 86400

    for v in recent:
        if not isinstance(v, dict):
            continue
        group = (v.get("group") or v.get("group_name") or "").strip().lower()
        if not group:
            continue
        posted = v.get("attackdate") or v.get("published") or v.get("date") or ""
        try:
            when = time.mktime(time.strptime(posted[:10], "%Y-%m-%d"))
        except (ValueError, TypeError):
            when = 0.0

        row = by_group.setdefault(group, {
            "group":     group,
            "latest":    "",
            "victims_30d": 0,
            "sample":    [],
        })
        if posted and posted > row["latest"]:
            row["latest"] = posted
        if when and when >= cutoff_30:
            row["victims_30d"] += 1
        if len(row["sample"]) < 5:
            victim = (v.get("victim") or v.get("post_title") or "").strip()[:120]
            if victim:
                row["sample"].append({"victim": victim, "posted": posted})

    active = sorted([g for g, r in by_group.items() if r["victims_30d"] > 0],
                    key=lambda g: -by_group[g]["victims_30d"])

    with _lock:
        _state["by_group"]      = by_group
        _state["active_groups"] = active
        _state["total_victims"] = len(recent)
        _state["loaded_at"]     = now
        _state["error"]         = None
    _log.info("ransomware.live loaded: %d victims across %d groups, %d active in 30d",
              len(recent), len(by_group), len(active))


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
            _state["loaded_at"] = time.time() - _TTL_SECONDS + 60


def lookup_group(name: str) -> Optional[Dict[str, Any]]:
    """Match a group / malware family name against active leak-site
    posters. Returns latest post date + last-30d victim count + sample
    victims, or None if the group isn't in the feed."""
    _ensure_loaded()
    if not isinstance(name, str) or not name:
        return None
    key = name.strip().lower()
    # Read under lock — iterating by_group.items() while _refresh_sync
    # replaces the dict would raise RuntimeError.
    with _lock:
        by_group = _state.get("by_group") or {}
        hit = by_group.get(key)
        if hit:
            return hit
        # Loose match — many families have suffix variants
        # ('LockBit3', 'lockbit-3').
        for g, row in by_group.items():
            if key in g or g in key:
                return row
        return None


def active_groups(limit: int = 15) -> List[str]:
    _ensure_loaded()
    with _lock:
        return list((_state.get("active_groups") or [])[:limit])


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    with _lock:
        return {
            "loaded_at":     _state.get("loaded_at"),
            "total_victims": _state.get("total_victims"),
            "groups":        len(_state.get("by_group") or {}),
            "active_30d":    len(_state.get("active_groups") or []),
            "error":         _state.get("error"),
        }
