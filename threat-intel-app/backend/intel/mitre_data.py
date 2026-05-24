"""
MITRE ATT&CK Data Layer
Source: github.com/mitre-attack/mitreattack-python (Apache 2.0)
Falls back gracefully if enterprise-attack.json is not present.
"""
from pathlib import Path
from functools import lru_cache

STIX_FILE = Path(__file__).parent / "mitre" / "enterprise-attack.json"


@lru_cache(maxsize=1)
def _mitre():
    try:
        from mitreattack.stix20 import MitreAttackData
        if STIX_FILE.exists():
            return MitreAttackData(str(STIX_FILE))
    except ImportError:
        pass
    return None


def get_all_techniques() -> list[dict]:
    m = _mitre()
    if not m:
        return []
    results = []
    for t in m.get_techniques(remove_revoked_deprecated=True):
        tid = next((r["external_id"] for r in t.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if not tid:
            continue
        tactics = [p["phase_name"].replace("-", " ").title()
                   for p in t.get("kill_chain_phases", [])
                   if p.get("kill_chain_name") == "mitre-attack"]
        results.append({
            "id":          tid,
            "name":        t.get("name", ""),
            "tactic":      tactics[0] if tactics else "Unknown",
            "tactics":     tactics,
            "description": (t.get("description") or "")[:300],
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
        })
    return sorted(results, key=lambda x: x["id"])


def search_techniques(query: str) -> list[dict]:
    q = query.lower().strip()
    if len(q) < 2:
        return get_all_techniques()[:20]
    return [t for t in get_all_techniques()
            if q in t["id"].lower() or q in t["name"].lower()
            or q in t["tactic"].lower()][:30]


def get_groups_by_techniques(technique_ids: list[str]) -> list[dict]:
    m = _mitre()
    if not m or not technique_ids:
        return []
    results = []
    for group in m.get_groups():
        group_tids = set()
        for t in m.get_techniques_used_by_group(group["id"]):
            for ref in t.get("object", {}).get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    group_tids.add(ref["external_id"])
        matches = [t for t in technique_ids if t in group_tids]
        if not matches:
            continue
        score = round(len(matches) / max(len(technique_ids), len(group_tids)) * 100)
        gid = next((r["external_id"] for r in group.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), "")
        results.append({
            "name":              group.get("name", ""),
            "id":                gid,
            "aliases":           group.get("aliases", [])[:3],
            "matchedTechniques": matches,
            "score":             score,
            "description":       (group.get("description") or "")[:200],
        })
    return sorted(results, key=lambda x: x["score"], reverse=True)[:10]
