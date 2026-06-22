"""
ETDA (Thailand CERT) APT cyberMonitor actor encyclopedia loader.

Source: https://apt.etda.or.th + https://github.com/etda-pt/cybermonitor
(MIT, data published by ThaiCERT). Comprehensive threat-actor profiles
covering ~250+ named clusters. Each entry has shape:

  - actor:                   "APT29"
    names:                   ["Cozy Bear", "The Dukes", ...]
    country:                 "Russia"
    motivation:              "Information theft / Espionage"
    sponsor:                 "State-sponsored, SVR..."
    sectors:                 ["Government", "Defense", ...]
    countries-attacked:      ["United States", "Germany", ...]
    tools:                   ["Mimikatz", "Cobalt Strike", ...]
    description:             "..."
    references:              [...]

Augments RECON's MISP-galaxy threat-actor lookup with richer metadata
(target sectors, attacker country, motivation) that MISP galaxies don't
carry consistently. Cross-indexed by canonical name AND every alias so
"Cozy Bear" → "APT29" → full profile in one lookup.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.intel.etda")

# Possible vendoring layouts. The upstream publishes per-actor YAML
# under `groups/` in the repo; we accept either the repo clone OR a
# pre-flattened JSON if the operator built one.
_ETDA_ROOT_CANDIDATES = [
    Path(__file__).parent.parent.parent / "vendor" / "etda-cybermonitor",
    Path(__file__).parent.parent.parent / "vendor" / "etda-apt",
]

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":    False,
    "actors":    {},   # dict[canonical_name, profile]
    "aliases":   {},   # dict[normalised alias, canonical_name]
    "error":     None,
}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (s or "").lower()).strip("_")


def _safe_yaml(text: str) -> Optional[Dict[str, Any]]:
    try:
        import yaml
    except Exception:
        return None
    try:
        for doc in yaml.safe_load_all(text):
            if isinstance(doc, dict):
                return doc
    except Exception:
        return None
    return None


def _find_root() -> Optional[Path]:
    for c in _ETDA_ROOT_CANDIDATES:
        if c.exists():
            return c
    return None


def _normalize_profile(doc: Dict[str, Any], path: Path) -> Optional[Dict[str, Any]]:
    """Coerce per-actor doc into our common shape. Tolerant of YAML
    schema drift across the upstream repo."""
    # Pull names from any of the common keys upstream uses.
    actor = (doc.get("actor") or doc.get("name") or doc.get("group_name")
             or "").strip()
    if not actor:
        return None
    names = doc.get("names") or doc.get("aliases") or doc.get("synonyms") or []
    if isinstance(names, str):
        names = [names]
    if not isinstance(names, list):
        names = []
    countries = doc.get("country") or doc.get("origin") or ""
    if isinstance(countries, list):
        countries = ", ".join(str(c) for c in countries if c)
    sectors = doc.get("sectors") or doc.get("targeted_sectors") or []
    if isinstance(sectors, str):
        sectors = [sectors]
    attacked = doc.get("countries-attacked") or doc.get("victim_countries") or []
    if isinstance(attacked, str):
        attacked = [attacked]
    tools = doc.get("tools") or doc.get("malware") or []
    if isinstance(tools, str):
        tools = [tools]
    references = doc.get("references") or []
    if not isinstance(references, list):
        references = []
    return {
        "actor":      actor,
        "names":      [str(n)[:80] for n in names][:12],
        "country":    str(countries)[:120],
        "motivation": (doc.get("motivation") or "")[:200],
        "sponsor":    (doc.get("sponsor") or "")[:200],
        "sectors":    [str(s)[:60] for s in sectors][:10],
        "victim_countries": [str(c)[:80] for c in attacked][:12],
        "tools":      [str(t)[:80] for t in tools][:20],
        "description": (doc.get("description") or "")[:500],
        "references": [str(r)[:160] for r in references][:6],
        "source":     "ETDA APT cyberMonitor",
    }


def _build_index() -> None:
    root = _find_root()
    if not root:
        _state["error"]  = ("etda actor corpus not present at any of "
                            f"{[str(p) for p in _ETDA_ROOT_CANDIDATES]}")
        _state["loaded"] = True
        return

    actors:  Dict[str, Dict[str, Any]] = {}
    aliases: Dict[str, str] = {}

    # Look in groups/ first (the repo's canonical layout), fall back to
    # the root for flatter vendoring.
    walk_root = root / "groups" if (root / "groups").exists() else root
    for path in walk_root.rglob("*.yaml"):
        if not path.is_file() or path.stat().st_size > 256_000:
            continue
        try:
            doc = _safe_yaml(path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
        profile = _normalize_profile(doc or {}, path)
        if not profile:
            continue
        canonical = _norm(profile["actor"])
        actors[canonical] = profile
        aliases[canonical] = canonical
        for alt in profile["names"]:
            aliases[_norm(alt)] = canonical

    # Also accept a pre-flattened JSON named `actors.json` at the root.
    flat = root / "actors.json"
    if flat.exists():
        try:
            blob = json.loads(flat.read_text(encoding="utf-8"))
            if isinstance(blob, list):
                for entry in blob:
                    profile = _normalize_profile(entry, flat)
                    if not profile:
                        continue
                    canonical = _norm(profile["actor"])
                    actors[canonical] = profile
                    aliases[canonical] = canonical
                    for alt in profile["names"]:
                        aliases[_norm(alt)] = canonical
        except Exception as e:
            _log.warning("ETDA actors.json parse failed: %s", e)

    _state["actors"]  = actors
    _state["aliases"] = aliases
    _state["loaded"]  = True
    _state["error"]   = None
    _log.info("ETDA cyberMonitor loaded: %d actors | %d aliases",
              len(actors), len(aliases))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def lookup(actor_name: str) -> Optional[Dict[str, Any]]:
    """Find an actor profile by canonical name OR alias."""
    _ensure_loaded()
    if not actor_name:
        return None
    canonical = (_state.get("aliases") or {}).get(_norm(actor_name))
    if not canonical:
        return None
    return (_state.get("actors") or {}).get(canonical)


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":  bool(_state["loaded"]),
        "actors":  len(_state.get("actors") or {}),
        "aliases": len(_state.get("aliases") or {}),
        "error":   _state.get("error"),
    }
