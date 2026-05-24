"""
Threat actor intelligence — spec §7.

Uses MitreAttackData (mitreattack-python) loading
backend/intel/mitre/enterprise-attack.json, exposes:

  get_all_groups()
  get_group_techniques(group_id)
  get_group_software(group_id)
  get_group_campaigns(group_id)
  match_groups_by_techniques(technique_ids)  -> scored top-10 with match list

Optionally augments group profiles with APTnotes report references parsed from
vendor/aptnotes/APTnotes_summary.csv (filename + year + source URL when present).
"""

from __future__ import annotations
from pathlib import Path
from functools import lru_cache
from typing import List, Dict, Optional
import csv
import re

_REPO_ROOT  = Path(__file__).resolve().parents[3]
_STIX_FILE  = Path(__file__).parent / "mitre" / "enterprise-attack.json"
_APTNOTES_CSV = _REPO_ROOT / "threat-intel-app" / "vendor" / "aptnotes" / "APTnotes_summary.csv"

_TID_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


@lru_cache(maxsize=1)
def _mitre():
    try:
        from mitreattack.stix20 import MitreAttackData
        if _STIX_FILE.exists():
            return MitreAttackData(str(_STIX_FILE))
    except ImportError:
        pass
    return None


def _ext_id(obj: dict, source: str = "mitre-attack") -> Optional[str]:
    for r in obj.get("external_references") or []:
        if r.get("source_name") == source:
            return r.get("external_id")
    return None


def _aliases(group: dict) -> List[str]:
    """Aliases minus the group's primary name."""
    name = group.get("name", "")
    return [a for a in (group.get("aliases") or []) if a and a != name][:10]


# ─── public API ────────────────────────────────────────────────────────────────
@lru_cache(maxsize=1)
def get_all_groups() -> List[Dict]:
    """Return every documented MITRE ATT&CK group."""
    m = _mitre()
    if not m:
        return []
    aptnotes = _aptnotes_index()
    out = []
    for g in m.get_groups(remove_revoked_deprecated=True):
        gid = _ext_id(g)
        if not gid:
            continue
        techniques_count = len(m.get_techniques_used_by_group(g["id"]))
        out.append({
            "id":               gid,
            "name":             g.get("name", ""),
            "aliases":          _aliases(g),
            "description":      (g.get("description") or "")[:600],
            "created":          g.get("created"),
            "modified":         g.get("modified"),
            "country":          _country_from_description(g.get("description") or ""),
            "sponsor":          _sponsor_from_description(g.get("description") or ""),
            "techniques_count": techniques_count,
            "aptnotes":         aptnotes.get(g.get("name", "").lower(), [])[:5],
            "external_url":     f"https://attack.mitre.org/groups/{gid}/",
        })
    return sorted(out, key=lambda x: x["name"].lower())


def get_group_techniques(group_id: str) -> List[Dict]:
    """All techniques used by a group (by ATT&CK Gxxxx id)."""
    m = _mitre()
    if not m:
        return []
    g = _resolve_group(m, group_id)
    if not g:
        return []
    techniques = []
    for entry in m.get_techniques_used_by_group(g["id"]):
        t = entry.get("object") or {}
        tid = _ext_id(t)
        if not tid:
            continue
        tactics = [p["phase_name"].replace("-", " ").title()
                   for p in t.get("kill_chain_phases", [])
                   if p.get("kill_chain_name") == "mitre-attack"]
        techniques.append({
            "id":      tid,
            "name":    t.get("name", ""),
            "tactic":  tactics[0] if tactics else "",
            "tactics": tactics,
        })
    return sorted(techniques, key=lambda x: x["id"])


def get_group_software(group_id: str) -> List[Dict]:
    """Malware + tools associated with a group."""
    m = _mitre()
    if not m:
        return []
    g = _resolve_group(m, group_id)
    if not g:
        return []
    out = []
    for entry in m.get_software_used_by_group(g["id"]):
        s = entry.get("object") or {}
        sid = _ext_id(s)
        if not sid:
            continue
        out.append({
            "id":   sid,
            "name": s.get("name", ""),
            "type": s.get("type", "").replace("-", " "),  # malware or tool
            "description": (s.get("description") or "")[:240],
            "labels": s.get("labels", []),
        })
    return sorted(out, key=lambda x: x["name"].lower())


def get_group_campaigns(group_id: str) -> List[Dict]:
    """Campaigns attributed to a group."""
    m = _mitre()
    if not m:
        return []
    g = _resolve_group(m, group_id)
    if not g:
        return []
    out = []
    # mitreattack-python has get_campaigns_attributed_to_group on newer versions
    fn = getattr(m, "get_campaigns_attributed_to_group", None)
    if not fn:
        return []
    for c in fn(g["id"]):
        c = c.get("object") if isinstance(c, dict) and "object" in c else c
        cid = _ext_id(c)
        if not cid:
            continue
        out.append({
            "id":           cid,
            "name":         c.get("name", ""),
            "description":  (c.get("description") or "")[:240],
            "first_seen":   c.get("first_seen"),
            "last_seen":    c.get("last_seen"),
            "aliases":      [a for a in (c.get("aliases") or []) if a != c.get("name")][:5],
        })
    return out


def match_groups_by_techniques(technique_ids) -> List[Dict]:
    """Score every group by percentage of identified techniques they use.
    Returns top 10 sorted descending by score with matched_techniques listed."""
    m = _mitre()
    if not m:
        return []
    targets = set()
    for t in technique_ids or []:
        for tid in _TID_RE.findall(str(t)):
            targets.add(tid.upper())
    if not targets:
        return []
    aptnotes = _aptnotes_index()
    scored = []
    for g in m.get_groups(remove_revoked_deprecated=True):
        gid = _ext_id(g)
        if not gid:
            continue
        used = set()
        for entry in m.get_techniques_used_by_group(g["id"]):
            t = entry.get("object") or {}
            for ref in t.get("external_references") or []:
                if ref.get("source_name") == "mitre-attack":
                    used.add(ref["external_id"].upper())
        matched = targets & used
        if not matched:
            continue
        score = round(len(matched) / len(targets) * 100)
        scored.append({
            "id":                  gid,
            "name":                g.get("name", ""),
            "aliases":             _aliases(g)[:4],
            "score":               score,
            "matched_techniques":  sorted(matched),
            "total_techniques":    len(used),
            "country":             _country_from_description(g.get("description") or ""),
            "description":         (g.get("description") or "")[:220],
            "aptnotes":            aptnotes.get(g.get("name", "").lower(), [])[:3],
            "external_url":        f"https://attack.mitre.org/groups/{gid}/",
        })
    return sorted(scored, key=lambda x: (-x["score"], -x["total_techniques"], x["name"]))[:10]


# ─── helpers ───────────────────────────────────────────────────────────────────
def _resolve_group(m, group_id: str):
    """Look up by ATT&CK ID (Gxxxx) or by group name (case-insensitive)."""
    target = (group_id or "").strip().lower()
    if not target:
        return None
    for g in m.get_groups():
        if (g.get("name") or "").lower() == target:
            return g
        for r in g.get("external_references") or []:
            if (r.get("external_id") or "").lower() == target:
                return g
    return None


# ─── APTnotes index ────────────────────────────────────────────────────────────
@lru_cache(maxsize=1)
def _aptnotes_index() -> Dict[str, List[Dict]]:
    """Parse APTnotes summary CSV (columns: Filename, Title, Source, Year, …) and
    bucket entries by group name we can detect in the title."""
    if not _APTNOTES_CSV.exists():
        return {}
    by_group: Dict[str, List[Dict]] = {}
    try:
        with open(_APTNOTES_CSV, encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                title = (row.get("Title") or row.get("Filename") or "")
                src   = row.get("Source") or row.get("Link") or ""
                year  = row.get("Year") or row.get("Date") or ""
                entry = {"title": title, "source": src, "year": year}
                # Heuristic: match on common group naming patterns in title
                for tok in re.findall(r"\bAPT[\s\-]?\d+\b|\b[A-Z][a-zA-Z]+\s+(?:Bear|Panda|Tiger|Kitten|Spider)\b",
                                      title):
                    by_group.setdefault(tok.lower().replace(" ", ""), []).append(entry)
    except Exception:
        return {}
    return by_group


_COUNTRY_HINTS = [
    ("china", "China"), ("chinese", "China"),
    ("russia", "Russia"), ("russian", "Russia"),
    ("iran", "Iran"), ("iranian", "Iran"),
    ("north korea", "North Korea"), ("dprk", "North Korea"),
    ("vietnam", "Vietnam"), ("pakistan", "Pakistan"),
    ("united states", "USA"),
]


def _country_from_description(desc: str) -> Optional[str]:
    d = (desc or "").lower()
    for kw, country in _COUNTRY_HINTS:
        if kw in d:
            return country
    return None


def _sponsor_from_description(desc: str) -> Optional[str]:
    d = (desc or "").lower()
    if "state-sponsored" in d or "state sponsored" in d:
        return "State-sponsored"
    if "criminal" in d or "ecrime" in d or "for-profit" in d:
        return "Cybercrime"
    if "hacktivist" in d:
        return "Hacktivist"
    return None
