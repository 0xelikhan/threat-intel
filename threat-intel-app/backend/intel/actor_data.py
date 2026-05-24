"""
Threat Actor Data Layer
Combines MITRE ATT&CK Groups (via mitre_data.py) with MISP Galaxy threat-actor
metadata to give richer attribution info: aliases, country, sponsor, description.
"""
import json
from pathlib import Path
from functools import lru_cache

MISP_GALAXY_FILE = Path(__file__).parent.parent.parent / "vendor" / "misp-galaxy" / "clusters" / "threat-actor.json"


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
    Return ranked threat actor matches with MISP galaxy enrichment.
    Falls back gracefully when MITRE data isn't available.
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
            out.append({
                "name":              g["name"],
                "mitre_id":          g.get("id", ""),
                "aliases":           misp.get("synonyms") or g.get("aliases", []),
                "origin":            _country_name(misp.get("country", "")),
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
