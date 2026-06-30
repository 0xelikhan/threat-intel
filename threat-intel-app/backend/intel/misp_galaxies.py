"""
MISP galaxy lookup — threat-actor / malware / tool / cross-walk
enrichment.

MISP publishes a free, MIT-licensed set of "galaxy clusters" — JSON
files describing threat actors, malware families, offensive tools,
and target metadata, each with aliases, country attribution, target
sectors, motivations, and external references. Source:
https://github.com/MISP/misp-galaxy/

Round-16 bumps the cluster set from 5 to 10. The new clusters add a
*cross-walk* dimension — multiple community datasets can name the
same actor with different aliases (FIN7 / Carbanak / Storm-0867 /
G0046), and confirming the same identity across all three drives the
attribution chip's confidence tier without any new AI tokens.

Bundled clusters (see scripts/fetch_misp_galaxy.sh):

  Actor flavours (all merge into the actor index for fuzzy lookup):
    threat-actor.json              community-curated threat-actor set
    mitre-intrusion-set.json       MITRE-curated G#### catalog
    microsoft-activity-group.json  Microsoft Storm-/Typhoon naming

  Malware flavours (merge into the malware index):
    malpedia.json                  malware family catalog
    ransomware.json                ransomware groups
    rat.json                       remote-access trojans
    tool.json                      offensive-toolkit catalog (legacy)
    mitre-tool.json                MITRE-curated S#### tool catalog

  Reference clusters (small / loaded on demand):
    sector.json                    canonical industry sectors
    target-information.json        country profiles (calling-code, …)

Public API:

  lookup_actor(name_or_alias)        -> dict | None  (fuzzy actor lookup,
                                                       any source)
  lookup_malware(name_or_alias)      -> dict | None  (fuzzy malware/tool
                                                       lookup, any source)
  cross_walk_actor(name_or_alias)    -> dict | None  (returns hits across
                                                       all three actor
                                                       catalogues + a
                                                       confidence tier)
  list_sectors()                     -> list[str]
  list_countries()                   -> list[dict]
  stats()                            -> per-cluster summary for /api/status

Each lookup returns a flat dict with the most analyst-relevant fields
(name, aliases, country, motivations, sectors, refs, mitre_ids). The
raw galaxy JSON is much larger — we strip metadata the analyst
doesn't need.
"""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.misp_galaxies")

_GALAXY_DIR = Path(__file__).parent / "misp_galaxy"

# Cluster file -> (display label, category, source-tier)
#
# source-tier ranks how authoritative the dataset is for cross-walk
# confidence scoring. MITRE > Microsoft > community.
_CLUSTERS = {
    # Actor catalogues
    "threat-actor.json":             ("Threat Actor (community)", "actor", "community"),
    "mitre-intrusion-set.json":      ("Threat Actor (MITRE G#)",  "actor", "mitre"),
    "microsoft-activity-group.json": ("Threat Actor (Microsoft)", "actor", "microsoft"),
    # Malware / tool catalogues
    "malpedia.json":                 ("Malpedia",                  "malware", "community"),
    "ransomware.json":               ("Ransomware Group",          "malware", "community"),
    "rat.json":                      ("RAT",                       "malware", "community"),
    "tool.json":                     ("Tool",                      "malware", "community"),
    "mitre-tool.json":               ("Tool (MITRE S#)",           "malware", "mitre"),
}

# Reference clusters — small, indexed differently (no fuzzy lookup, just
# enumeration helpers).
_REFERENCE_CLUSTERS = (
    "sector.json",
    "target-information.json",
)


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


def _flatten_entry(cv: Dict[str, Any], label: str, source_tier: str) -> Dict[str, Any]:
    """Strip a raw cluster value down to the analyst-facing fields. Same
    output shape across every cluster — that's what lets cross_walk_actor
    treat them uniformly."""
    name = (cv.get("value") or "").strip()
    meta = cv.get("meta") or {}
    aliases = list(meta.get("synonyms") or [])
    external_id = meta.get("external_id")
    if isinstance(external_id, list):
        external_id = external_id[0] if external_id else None
    # Some MITRE entries include the external_id inside the value name
    # itself ("Cobalt Strike - S0154") — strip the trailing " - S####" /
    # " - G####" so the cross-walk fuzzy lookup matches on the friendly
    # name alone.
    bare_name = name
    for prefix in (" - S", " - G", " - C"):
        if prefix in bare_name:
            head, tail = bare_name.rsplit(prefix, 1)
            if tail and tail[0].isdigit():
                bare_name = head
                if not external_id:
                    external_id = prefix.strip(" -") + tail
                break
    return {
        "cluster":     label,
        "source_tier": source_tier,
        "name":        bare_name,
        "raw_value":   name,
        "description": (cv.get("description") or "")[:600],
        "aliases":     aliases[:25],
        "country":     meta.get("country"),
        "motivations": meta.get("motive") or meta.get("motivation"),
        "sectors":     meta.get("cfr-target-category")
                       or meta.get("target-category"),
        "regions":     meta.get("cfr-suspected-victims"),
        "refs":        (meta.get("refs") or [])[:5],
        "mitre_id":    external_id,
        "platforms":   meta.get("mitre_platforms") or [],
        # The Microsoft cluster carries the "what type of threat-actor is
        # this" tag — surface alongside attribution.
        "microsoft_origin": meta.get("microsoft-origin-threat"),
    }


@lru_cache(maxsize=1)
def _load_all() -> Dict[str, Any]:
    """Parse every available cluster file once. Returns:
      {
        "actor":           {normalized_name: entry},
        "actor_by_tier":   {tier: {normalized_name: entry}},
        "malware":         {normalized_name: entry},
        "sectors":         list[str],
        "countries":       list[dict],
      }
    """
    actor_idx:    Dict[str, Dict[str, Any]] = {}
    actor_tiers:  Dict[str, Dict[str, Dict[str, Any]]] = {}
    malware_idx:  Dict[str, Dict[str, Any]] = {}

    if not _GALAXY_DIR.exists():
        _log.warning("MISP galaxy dir missing: %s (build-time fetch failed?)",
                     _GALAXY_DIR)
        return {"actor": actor_idx, "actor_by_tier": actor_tiers,
                "malware": malware_idx, "sectors": [], "countries": []}

    for fname, (label, category, source_tier) in _CLUSTERS.items():
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
        tier_bucket: Dict[str, Dict[str, Any]] = {}
        if category == "actor":
            actor_tiers[source_tier] = tier_bucket

        for cv in doc.get("values", []) or []:
            entry = _flatten_entry(cv, label, source_tier)
            name = entry["name"]
            if not name:
                continue
            for key in [name, entry["raw_value"], *entry["aliases"]]:
                n = _normalize(key)
                if n and n not in target_idx:
                    target_idx[n] = entry
                if category == "actor" and n and n not in tier_bucket:
                    tier_bucket[n] = entry

        _log.info("Loaded MISP galaxy: %s (%d entries)",
                  fname, len(doc.get("values") or []))

    # Reference clusters — load if present but don't fold into the fuzzy
    # actor / malware indexes.
    sectors: List[str] = []
    countries: List[Dict[str, Any]] = []
    sector_path = _GALAXY_DIR / "sector.json"
    if sector_path.exists():
        try:
            with open(sector_path, encoding="utf-8") as f:
                doc = json.load(f)
            sectors = sorted({(v.get("value") or "").strip()
                              for v in (doc.get("values") or [])
                              if v.get("value")})
        except Exception as e:
            _log.debug("sector.json parse failed: %s", e)
    country_path = _GALAXY_DIR / "target-information.json"
    if country_path.exists():
        try:
            with open(country_path, encoding="utf-8") as f:
                doc = json.load(f)
            for v in (doc.get("values") or []):
                meta = v.get("meta") or {}
                countries.append({
                    "name":     (v.get("value") or "").strip(),
                    "iso":      meta.get("iso-code"),
                    "calling":  meta.get("calling-code"),
                    "tld":      meta.get("top-level-domain"),
                    "langs":    meta.get("official-languages"),
                    "capital":  meta.get("capital"),
                })
        except Exception as e:
            _log.debug("target-information.json parse failed: %s", e)

    return {
        "actor":         actor_idx,
        "actor_by_tier": actor_tiers,
        "malware":       malware_idx,
        "sectors":       sectors,
        "countries":     countries,
    }


def lookup_actor(name_or_alias: str) -> Optional[Dict[str, Any]]:
    """Fuzzy actor lookup across all three actor catalogues (community
    threat-actor, MITRE intrusion-set, Microsoft activity group).
    Returns the FIRST match found — for cross-walk results use
    cross_walk_actor() below."""
    if not name_or_alias:
        return None
    idx = _load_all()["actor"]
    return idx.get(_normalize(name_or_alias))


def lookup_malware(name_or_alias: str) -> Optional[Dict[str, Any]]:
    """Fuzzy malware / tool lookup across malpedia, ransomware, RAT,
    tool, and mitre-tool catalogues. Returns the FIRST match found —
    MITRE entries are preferred via cluster iteration order."""
    if not name_or_alias:
        return None
    idx = _load_all()["malware"]
    return idx.get(_normalize(name_or_alias))


def cross_walk_actor(name_or_alias: str) -> Optional[Dict[str, Any]]:
    """Resolve an actor name across all three actor catalogues and return
    a unified record. When the same actor appears in ≥2 catalogues,
    confidence='high' (cross-confirmed). Otherwise confidence='medium'
    (single-source).

    Output shape:
      {
        "name":         "<canonical name from the strongest match>",
        "aliases":      [...],
        "matches":      {
          "community":  entry | None,
          "mitre":      entry | None,
          "microsoft":  entry | None,
        },
        "confidence":   "high" | "medium" | "low",
        "tiers_hit":    ["mitre", "community", "microsoft"],
        "mitre_id":     "G####" | None,
        "microsoft_origin": str | None,
        "country":      str | None,
        "motivations":  ...,
        "sectors":      ...,
        "refs":         [...],
      }
    """
    if not name_or_alias:
        return None
    tiers = _load_all()["actor_by_tier"]
    norm = _normalize(name_or_alias)
    matches: Dict[str, Optional[Dict[str, Any]]] = {
        "community": None, "mitre": None, "microsoft": None,
    }
    for tier_name in ("community", "mitre", "microsoft"):
        bucket = tiers.get(tier_name) or {}
        matches[tier_name] = bucket.get(norm)

    # Also try fuzzy expansion via the master index aliases — when
    # community names "APT29" + Microsoft names "Midnight Blizzard"
    # and the operator queried for "Midnight Blizzard", the community
    # bucket won't match by direct normalisation. Walk each Microsoft
    # match's aliases and try the community + MITRE buckets again.
    seed = next((m for m in matches.values() if m), None)
    if seed:
        candidate_keys = {seed["name"], *seed.get("aliases", [])}
        for key in candidate_keys:
            n = _normalize(key)
            for tier_name in ("community", "mitre", "microsoft"):
                if matches[tier_name] is None:
                    bucket = tiers.get(tier_name) or {}
                    if n in bucket:
                        matches[tier_name] = bucket[n]

    tiers_hit = [t for t, m in matches.items() if m]
    if not tiers_hit:
        return None

    confidence = ("high" if len(tiers_hit) >= 2 else
                  "medium" if len(tiers_hit) == 1 else "low")

    # Pick a canonical record — prefer MITRE > community > microsoft
    canon = (matches["mitre"] or matches["community"] or matches["microsoft"])
    if not canon:
        return None

    # Union the aliases across all tiers so the cross-walk record is
    # the analyst's one-stop-shop.
    aliases: set = set()
    for m in matches.values():
        if not m:
            continue
        aliases.update(m.get("aliases") or [])
        aliases.add(m.get("name") or "")
    aliases.discard("")
    aliases.discard(canon.get("name", ""))

    return {
        "name":             canon["name"],
        "aliases":          sorted(aliases)[:30],
        "matches":          matches,
        "confidence":       confidence,
        "tiers_hit":        tiers_hit,
        "mitre_id":         (matches["mitre"] or {}).get("mitre_id"),
        "microsoft_origin": (matches["microsoft"] or {}).get("microsoft_origin"),
        "country":          canon.get("country"),
        "motivations":      canon.get("motivations"),
        "sectors":          canon.get("sectors"),
        "refs":             canon.get("refs"),
    }


def list_sectors() -> List[str]:
    """Canonical industry-sector names from sector.json. Used to validate
    AI-emitted sector strings against MISP's authoritative list."""
    return list(_load_all()["sectors"])


def list_countries() -> List[Dict[str, Any]]:
    """Country profile list from target-information.json. Each entry
    carries iso-code / calling-code / TLD / official-languages /
    capital."""
    return list(_load_all()["countries"])


def stats() -> Dict[str, Any]:
    """Per-cluster index sizes — surfaced at /api/status to confirm
    galaxy data is actually loaded in production."""
    by_cluster: Dict[str, int] = {}
    for fname, (label, _, _) in _CLUSTERS.items():
        path = _GALAXY_DIR / fname
        by_cluster[label] = path.stat().st_size if path.exists() else 0
    for fname in _REFERENCE_CLUSTERS:
        path = _GALAXY_DIR / fname
        by_cluster[fname.replace(".json", "")] = path.stat().st_size if path.exists() else 0
    state = _load_all()
    return {
        "actor_index_size":    len(state["actor"]),
        "malware_index_size":  len(state["malware"]),
        "sectors":             len(state["sectors"]),
        "countries":           len(state["countries"]),
        "actor_tiers": {
            tier: len(bucket) for tier, bucket in state.get("actor_by_tier", {}).items()
        },
        "cluster_files":       by_cluster,
    }
