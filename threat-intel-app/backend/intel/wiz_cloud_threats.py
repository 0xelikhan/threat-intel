"""
Wiz Threat Landscape — free, no key. https://threats.wiz.io

Wiz publishes a cloud-native threat catalog covering:
  - all-actors      threat groups active in cloud environments
                    (0ktapus, 8220-gang, TeamTNT, DEV-0537 / LAPSUS$, …)
  - all-tools       tools + malware families used in cloud attacks
  - all-techniques  cloud-specific TTPs beyond MITRE Enterprise
                    (abuse-access-to-existing-kms-key, …)
  - all-incidents   named incidents with narrative context

RECON's existing MISP galaxy + actor_data are on-prem/APT-focused.
Wiz fills the cloud-attribution gap — when an AI investigation names
an actor or family that matches a Wiz slug, we can tag the alert as
"cloud-tracked" and link to the Wiz page for context.

Data access: Wiz threats.wiz.io uses Next.js App Router (React Server
Components) — no __NEXT_DATA__ JSON blob to parse. But the four `/all-*`
index pages embed every slug as `/all-{category}/{slug}` href attrs.
We regex-harvest those into an in-memory index. The RSC hydration
means slug names are stable across page refreshes even if the layout
churns.

Refreshed every 24h in the lifespan warm loop.
"""

from __future__ import annotations

import logging
import re
import threading
import time
import urllib.request
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.intel.wiz")

_BASE = "https://threats.wiz.io"
_CATEGORIES = ("actors", "tools", "techniques", "incidents")
_TTL_SECONDS = 24 * 3600

# Matches `/all-actors/0ktapus`, `/all-tools/4l4md4r-loader-and-stager`, etc.
_SLUG_RE = re.compile(r'"/all-([a-z]+)/([a-z0-9][a-z0-9\-]{1,120})"')

_lock = threading.RLock()  # reentrant: _ensure_loaded holds it, then
                            # _refresh_sync re-acquires — a plain Lock
                            # deadlocks; RLock is a drop-in fix.
_state: Dict[str, Any] = {
    "loaded_at":     0.0,
    "by_slug":       {},      # {"0ktapus": {"category": "actors", "url": ...}}
    "by_name":       {},      # normalized display name -> record
    "count_by_cat":  {},
    "error":         None,
}


def _slug_to_display(slug: str) -> str:
    """Slugs are lowercase-hyphenated; convert to a normalisable
    display form for name matching."""
    return slug.replace("-", " ").strip().lower()


def _fetch_page(path: str) -> str:
    req = urllib.request.Request(f"{_BASE}{path}", headers={
        "User-Agent": "RECON-ThreatIntel/1.0",
        "Accept":     "text/html",
    })
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", errors="ignore")


def _refresh_sync() -> None:
    by_slug: Dict[str, Dict[str, Any]] = {}
    by_name: Dict[str, Dict[str, Any]] = {}
    count_by_cat: Dict[str, int] = {}
    errs = []

    for cat in _CATEGORIES:
        try:
            html = _fetch_page(f"/all-{cat}")
        except Exception as e:
            errs.append(f"{cat}:{e}")
            continue
        found_this_cat = 0
        for m in _SLUG_RE.finditer(html):
            page_cat = m.group(1)   # actors / tools / techniques / incidents
            slug     = m.group(2)
            # Only accept slugs from the category page we're on — the
            # rendered HTML cross-links between categories (e.g. incident
            # page lists actors), which would poison the index.
            if page_cat != cat:
                continue
            if slug in by_slug:
                continue
            rec = {
                "slug":     slug,
                "category": cat.rstrip("s"),   # "actors" -> "actor"
                "url":      f"{_BASE}/all-{cat}/{slug}",
                "display":  _slug_to_display(slug),
            }
            by_slug[slug] = rec
            by_name[rec["display"]] = rec
            found_this_cat += 1
        count_by_cat[cat] = found_this_cat

    if not by_slug and errs:
        with _lock:
            _state["error"] = "; ".join(errs)[:200]
            _state["loaded_at"] = time.time()
        _log.warning("Wiz fetch failed for all categories: %s", errs)
        return

    with _lock:
        _state["by_slug"]      = by_slug
        _state["by_name"]      = by_name
        _state["count_by_cat"] = count_by_cat
        _state["loaded_at"]    = time.time()
        _state["error"]        = "; ".join(errs)[:200] if errs else None
    _log.info("Wiz threats loaded: %s", count_by_cat)


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


def _normalise_query(name: str) -> str:
    """Match logic: lowercase, strip punctuation apart from digits,
    collapse whitespace + hyphens. Same normalisation applied on both
    sides of a comparison."""
    s = (name or "").lower().strip()
    s = re.sub(r"[^a-z0-9]+", " ", s)
    return " ".join(s.split())


def lookup(name: str) -> Optional[Dict[str, Any]]:
    """Match an actor / family / technique / incident name against
    Wiz's slug index. Case-insensitive with hyphen/space/punctuation
    tolerance. Returns None when no confident match."""
    _ensure_loaded()
    if not isinstance(name, str) or not name.strip():
        return None
    q = _normalise_query(name)
    if not q:
        return None
    by_name = _state.get("by_name") or {}
    # Exact match after normalisation
    if q in by_name:
        rec = by_name[q]
        return {**rec, "match": "exact"}
    # Loose containment — either direction — but only when the shorter
    # side is >= 4 chars so a 3-letter query like "apt" doesn't match
    # every APT slug.
    if len(q) >= 4:
        for k, rec in by_name.items():
            if len(k) >= 4 and (q in k or k in q):
                return {**rec, "match": "loose"}
    return None


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded_at":    _state.get("loaded_at"),
        "total_slugs":  len(_state.get("by_slug") or {}),
        "count_by_cat": _state.get("count_by_cat") or {},
        "error":        _state.get("error"),
    }
