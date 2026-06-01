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


# Kill-chain ordering — used to bucket an actor's TTPs as "look for before
# this alert" vs "look for after this alert" relative to the techniques that
# actually matched the log. Lower index = earlier in the attack lifecycle.
_KILL_CHAIN_ORDER = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Defense Evasion",
    "Persistence",
    "Privilege Escalation",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command And Control",
    "Exfiltration",
    "Impact",
)
_TACTIC_POS = {t: i for i, t in enumerate(_KILL_CHAIN_ORDER)}


@lru_cache(maxsize=1)
def _group_index() -> dict:
    """Build { mitre_group_id (G####): [ {id, name, tactic}, ... ] } once.
    Cached for the process lifetime — every subsequent attribution lookup
    is a dict access."""
    m = _mitre()
    if not m:
        return {}
    out: dict = {}
    for group in m.get_groups():
        gid = next((r["external_id"] for r in group.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), "")
        if not gid:
            continue
        techs = []
        for t in m.get_techniques_used_by_group(group["id"]):
            obj = t.get("object", {})
            tid = next((r["external_id"] for r in obj.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), None)
            if not tid:
                continue
            tactics = [p["phase_name"].replace("-", " ").title()
                       for p in obj.get("kill_chain_phases", [])
                       if p.get("kill_chain_name") == "mitre-attack"]
            techs.append({
                "id":     tid,
                "name":   obj.get("name", ""),
                "tactic": tactics[0] if tactics else "Unknown",
            })
        out[gid] = techs
    return out


def get_actor_ttps_by_phase(mitre_group_id: str,
                            matched_technique_ids: list[str]) -> dict:
    """For a given actor (MITRE G####), bucket their full TTP list relative to
    the techniques that already matched THIS alert. Returns:

      {
        "before":   [ {id, name, tactic}, … ],   # earlier in kill-chain
        "after":    [ {id, name, tactic}, … ],   # later in kill-chain
        "matched":  [ {id, name, tactic}, … ],   # already-fired techniques
        "all_count": N,
      }

    Empty buckets when MITRE data is unavailable or the group is unknown."""
    idx = _group_index()
    techs = idx.get(mitre_group_id or "")
    if not techs:
        return {"before": [], "after": [], "matched": [], "all_count": 0}
    matched_set = {str(t).strip().upper() for t in (matched_technique_ids or [])}
    # Pivot tactic = the LATEST kill-chain position among matched techniques.
    # Everything earlier becomes "before"; everything later becomes "after".
    matched_positions = []
    for t in techs:
        if t["id"].upper() in matched_set:
            pos = _TACTIC_POS.get(t["tactic"])
            if pos is not None:
                matched_positions.append(pos)
    pivot = max(matched_positions) if matched_positions else None

    before: list = []
    after:  list = []
    matched_tts: list = []
    for t in techs:
        is_match = t["id"].upper() in matched_set
        if is_match:
            matched_tts.append(t)
            continue
        pos = _TACTIC_POS.get(t["tactic"])
        if pos is None:
            continue
        if pivot is None or pos < pivot:
            before.append(t)
        elif pos > pivot:
            after.append(t)
        else:
            # Same tactic as the matched pivot — surface as "after" since
            # it's a sibling technique within the same phase the alert
            # represents.
            after.append(t)

    # Deterministic ordering by kill-chain position then technique id so the
    # UI list is stable across renders.
    before.sort(key=lambda t: (_TACTIC_POS.get(t["tactic"], 99), t["id"]))
    after.sort (key=lambda t: (_TACTIC_POS.get(t["tactic"], 99), t["id"]))
    return {
        "before":    before[:10],
        "after":     after[:10],
        "matched":   matched_tts,
        "all_count": len(techs),
    }


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
