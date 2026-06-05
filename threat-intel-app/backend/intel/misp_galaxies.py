"""
MISP galaxy lookup — threat-actor / malware family enrichment.

MISP publishes a free, MIT-licensed set of "galaxy clusters" — JSON
files describing threat actors, malware families, ransomware groups,
RATs, and offensive tools, each with aliases, country attribution,
target sectors, motivations, and external references. Source:
https://github.com/MISP/misp-galaxy/

We bundle five clusters into the container at build time (see
Dockerfile) and load them lazily on first lookup. Lookups are
case-insensitive, alias-aware, and substring-aware so the AI's loose
naming ("Lockbit", "lockbit", "LockBit 3.0") still hits a single
canonical record.

Public API:
  lookup_actor(name_or_alias)    -> dict | None
  lookup_malware(name_or_alias)  -> dict | None
  stats()                        -> per-cluster summary for /api/status

Each lookup returns a flat dict with the most analyst-relevant fields
(name, aliases, country, motivations, sectors, refs). The raw galaxy
JSON is much larger — we strip metadata the analyst doesn't need.
"""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.misp_galaxies")

_GALAXY_DIR = Path(__file__).parent / "misp_galaxy"

# Cluster file -> (display label, category)
_CLUSTERS = {
    "threat-actor.json": ("Threat Actor",    "actor"),
    "malpedia.json":     ("Malpedia",         "malware"),
    "ransomware.json":   ("Ransomware Group", "malware"),
    "rat.json":          ("RAT",              "malware"),
    "tool.json":         ("Tool",             "malware"),
}


def _normalize(s: str) -> str:
    """Lowercase + strip + collapse non-alphanumerics for fuzzy alias
    matching. 'LockBit 3.0' and 'lockbit-3-0' both normalize to
    'lockbit30'."""
    if not s:
        return ""
    out = []
    for ch in s.lower():
        if ch.isalnum():
            out.append(ch)
    return "".join(out)


@lru_cache(maxsize=1)
def _load_all() -> Dict[str, Dict[str, Any]]:
    """Parse every available cluster file once. Returns:
      {
        "actor":   {normalized_name: cluster_value},
        "malware": {normalized_name: cluster_value},
      }
    cluster_value is a flat dict with the analyst-facing fields below."""
    actor_idx:   Dict[str, Dict[str, Any]] = {}
    malware_idx: Dict[str, Dict[str, Any]] = {}

    if not _GALAXY_DIR.exists():
        _log.warning("MISP galaxy dir missing: %s (build-time fetch failed?)",
                     _GALAXY_DIR)
        return {"actor": actor_idx, "malware": malware_idx}

    for fname, (label, category) in _CLUSTERS.items():
        path = _GALAXY_DIR / fname
        if not path.exists():
            _log.info("MISP galaxy cluster missing: %s", fname)
            continue
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except Exception as e:
            _log.warning("Failed to parse %s: %s", fname, e)
            continue

        target_idx = actor_idx if category == "actor" else malware_idx
        for cv in doc.get("values", []) or []:
            name = (cv.get("value") or "").strip()
            if not name:
                continue
            meta = cv.get("meta") or {}
            aliases = list(meta.get("synonyms") or [])
            entry = {
                "cluster":      label,
                "name":         name,
                "description":  (cv.get("description") or "")[:600],
                "aliases":      aliases[:25],
                "country":      meta.get("country"),
                "motivations":  meta.get("motive") or meta.get("motivation"),
                "sectors":      meta.get("cfr-target-category")
                                or meta.get("target-category"),
                "regions":      meta.get("cfr-suspected-victims"),
                "refs":         (meta.get("refs") or [])[:5],
                "mitre_ids":    meta.get("external_id") and [meta["external_id"]]
                                or (meta.get("mitre-attack-id") and [meta["mitre-attack-id"]])
                                or [],
            }
            # Index under the canonical name and every alias.
            for key in [name, *aliases]:
                n = _normalize(key)
                if n and n not in target_idx:
                    target_idx[n] = entry

        _log.info("Loaded MISP galaxy: %s (%d entries)",
                  fname, len(doc.get("values") or []))

    return {"actor": actor_idx, "malware": malware_idx}


def lookup_actor(name_or_alias: str) -> Optional[Dict[str, Any]]:
    """Look up a threat-actor cluster by name or any known alias.
    Returns None when no match. Case- and punctuation-insensitive."""
    if not name_or_alias:
        return None
    idx = _load_all()["actor"]
    return idx.get(_normalize(name_or_alias))


def lookup_malware(name_or_alias: str) -> Optional[Dict[str, Any]]:
    """Look up a malware/ransomware/RAT/tool cluster by name or alias."""
    if not name_or_alias:
        return None
    idx = _load_all()["malware"]
    return idx.get(_normalize(name_or_alias))


def stats() -> Dict[str, Any]:
    """Per-cluster index sizes — surfaced at /api/status to confirm
    galaxy data is actually loaded in production."""
    by_cluster: Dict[str, int] = {}
    for fname, (label, _) in _CLUSTERS.items():
        path = _GALAXY_DIR / fname
        by_cluster[label] = path.stat().st_size if path.exists() else 0
    actor_n   = len(_load_all()["actor"])
    malware_n = len(_load_all()["malware"])
    return {
        "actor_index_size":   actor_n,
        "malware_index_size": malware_n,
        "cluster_files":      by_cluster,
    }
