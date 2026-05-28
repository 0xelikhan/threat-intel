"""
Threat Actor Data Layer
Combines MITRE ATT&CK Groups (via mitre_data.py) with MISP Galaxy threat-actor
metadata to give richer attribution info: aliases, country, sponsor, description.

Also normalises every alias to Microsoft's weather-naming taxonomy so the UI
shows a single canonical actor name across CrowdStrike (PANDA/BEAR/etc),
FireEye/Mandiant (APTxx, UNCxxxx), MITRE (Gxxxx), vendor (Lazarus, Kimsuky),
and Microsoft (Midnight Blizzard, Forest Blizzard, …) variants.
"""
import json
from pathlib import Path
from functools import lru_cache

MISP_GALAXY_FILE = Path(__file__).parent.parent.parent / "vendor" / "misp-galaxy" / "clusters" / "threat-actor.json"
MS_ACTORS_FILE   = Path(__file__).parent / "data" / "ms_threat_actors.json"


@lru_cache(maxsize=1)
def _ms_lookup() -> dict:
    """alias.lower() → {name, origin, aliases[]} for every Microsoft weather-
    named actor. Indexed by the MS name itself AND every published alias so
    a CrowdStrike/MITRE/FireEye/vendor name resolves to the canonical MS
    entry. Returns {} if the data file is missing (graceful degrade)."""
    if not MS_ACTORS_FILE.exists():
        return {}
    try:
        with MS_ACTORS_FILE.open("r", encoding="utf-8") as f:
            actors = json.load(f)
    except Exception:
        return {}
    lookup = {}
    for actor in actors:
        ms_name = actor.get("name") or ""
        if not ms_name:
            continue
        entry = {
            "name":    ms_name,
            "origin":  actor.get("origin") or "",
            "aliases": actor.get("aliases") or [],
        }
        lookup[ms_name.lower()] = entry
        for alias in entry["aliases"]:
            if alias:
                # First-wins on alias collisions — shared aliases like
                # "WICKED PANDA" map to whichever MS actor is listed first.
                lookup.setdefault(alias.lower(), entry)
    return lookup


def ms_normalize(name: str) -> dict:
    """Return the canonical Microsoft entry for any actor alias.
    Empty dict when the name isn't in the taxonomy."""
    if not name:
        return {}
    return _ms_lookup().get(name.lower(), {})


def ms_normalize_many(names) -> dict:
    """Look up every name and return a dict of {input_name → ms_entry} for
    matches only. Skips inputs that don't resolve to anything."""
    out = {}
    for n in names or []:
        m = ms_normalize(n)
        if m:
            out[n] = m
    return out


@lru_cache(maxsize=1)
def _misp_lookup() -> dict:
    """Build a lowercase synonym → galaxy entry lookup table."""
    if not MISP_GALAXY_FILE.exists():
        return {}
    try:
        with MISP_GALAXY_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        lookup = {}
        for entry in data.get("values", []):
            name = entry.get("value", "")
            if not name:
                continue
            entry_compact = {
                "name":        name,
                "description": (entry.get("description") or "")[:280],
                "synonyms":    entry.get("meta", {}).get("synonyms", [])[:8],
                "country":     entry.get("meta", {}).get("country", ""),
                "sponsor":     entry.get("meta", {}).get("cfr-suspected-state-sponsor", ""),
                "victims":     entry.get("meta", {}).get("cfr-target-category", [])[:5],
                "refs":        [r for r in entry.get("meta", {}).get("refs", [])
                                if "attack.mitre.org" in r or "mandiant.com" in r][:3],
            }
            # Index by name + all synonyms (lowercased)
            lookup[name.lower()] = entry_compact
            for syn in entry.get("meta", {}).get("synonyms", []):
                if syn:
                    lookup[syn.lower()] = entry_compact
        return lookup
    except Exception:
        return {}


def enrich_actor(name: str, mitre_id: str = "") -> dict:
    """Return MISP galaxy metadata for an actor (by name, alias, or MITRE Group ID)."""
    lookup = _misp_lookup()
    if not lookup:
        return {}
    for key in (mitre_id, name):
        if key and key.lower() in lookup:
            return lookup[key.lower()]
    # Try first synonym match (e.g. "APT28 (Fancy Bear)" -> "fancy bear")
    if name:
        parts = name.replace("(", " ").replace(")", " ").split()
        for p in parts:
            if p.lower() in lookup:
                return lookup[p.lower()]
    return {}


def match_threat_actors(mitre_techniques: list) -> list:
    """
    Return ranked threat actor matches with MISP galaxy enrichment AND the
    Microsoft weather-naming overlay. Each entry carries:
      * name          — MITRE/MISP canonical name (kept for backwards compat)
      * ms_name       — Microsoft weather name (or '' if not in MS taxonomy)
      * aliases       — full union of MITRE / MISP synonyms / MS aliases
      * origin        — country (preferring the MS-taxonomy origin string when
                        present because it covers PSOA / influence-ops / "Group
                        in development" categories that MISP doesn't tag)

    Falls back gracefully when MITRE / MISP / MS data are unavailable.
    """
    if not mitre_techniques:
        return []
    try:
        from intel.mitre_data import get_groups_by_techniques
        tech_ids = [t.split(" ")[0] for t in mitre_techniques]
        groups = get_groups_by_techniques(tech_ids)
        if not groups:
            return []
        out = []
        for g in groups[:8]:
            misp = enrich_actor(g["name"], g.get("id", ""))
            ms = (ms_normalize(g["name"])
                  or _ms_from_aliases(misp.get("synonyms") or g.get("aliases", [])))
            base_aliases = list(misp.get("synonyms") or g.get("aliases", []))
            if ms:
                # Add the MS canonical name + its full alias list so the UI
                # has every name a vendor might use for this actor in one
                # place. De-dupe case-insensitively while preserving order.
                seen = {a.lower() for a in base_aliases}
                seen.add((ms.get("name") or "").lower())
                merged_aliases = list(base_aliases)
                for a in ms.get("aliases", []):
                    if a and a.lower() not in seen:
                        merged_aliases.append(a)
                        seen.add(a.lower())
            else:
                merged_aliases = base_aliases

            out.append({
                "name":              g["name"],
                "ms_name":           (ms or {}).get("name", ""),
                "mitre_id":          g.get("id", ""),
                "aliases":           merged_aliases,
                "origin":            (ms or {}).get("origin", "") or _country_name(misp.get("country", "")),
                "sponsor":           misp.get("sponsor", ""),
                "victims":           misp.get("victims", []),
                "description":       misp.get("description") or g.get("description", ""),
                "matchedTechniques": g.get("matchedTechniques", []),
                "score":             g.get("score", 0),
                "refs":              misp.get("refs", []),
            })
        return out
    except Exception:
        return []


def _ms_from_aliases(aliases: list) -> dict:
    """Try every alias against the MS taxonomy and return the first hit. Used
    when the canonical MITRE name itself isn't in the MS map but an alias is
    (e.g. MITRE 'APT29' would already hit, but for less-common cases like
    matching via 'NOBELIUM' or 'COZY BEAR')."""
    for a in aliases or []:
        m = ms_normalize(a)
        if m:
            return m
    return {}


_COUNTRY_NAMES = {
    "RU": "Russia", "CN": "China", "KP": "North Korea", "IR": "Iran",
    "US": "United States", "GB": "United Kingdom", "IL": "Israel",
    "PK": "Pakistan", "IN": "India", "VN": "Vietnam", "BR": "Brazil",
    "TR": "Turkey", "SY": "Syria", "LB": "Lebanon", "UA": "Ukraine",
    "BY": "Belarus", "SA": "Saudi Arabia", "AE": "UAE", "EG": "Egypt",
}

def _country_name(code: str) -> str:
    if not code:
        return ""
    return _COUNTRY_NAMES.get(code.upper(), code.upper())


def stats() -> dict:
    return {
        "misp_galaxy_loaded": bool(_misp_lookup()),
        "misp_actor_count":   len(set(v["name"] for v in _misp_lookup().values())),
    }
