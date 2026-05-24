"""
Persistent case storage — spec §9.

Each completed investigation is serialized to:
  backend/data/cases/{run_id}.json   (full state, minus stix_bundle bloat)
  backend/data/cases/index.json       (compact list — read once at startup)

Replaces the in-memory _results / _history dicts so analyses survive restart
and can be searched by label / IOC / malware family / threat actor / MITRE.
"""

from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Optional, List, Dict

_BASE  = Path(__file__).resolve().parents[1] / "data" / "cases"
_INDEX = _BASE / "index.json"
_BASE.mkdir(parents=True, exist_ok=True)
_lock  = Lock()

# In-memory index loaded once at startup for fast queries
_INDEX_MEM: List[Dict] = []
_index_loaded = False


def _load_index_once():
    global _index_loaded
    if _index_loaded:
        return
    if _INDEX.exists():
        try:
            with open(_INDEX, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                _INDEX_MEM.extend(data)
        except Exception:
            pass
    _index_loaded = True


def _persist_index():
    try:
        with open(_INDEX, "w", encoding="utf-8") as f:
            json.dump(_INDEX_MEM, f, indent=2, default=str)
    except Exception:
        pass


# ─── write / read ─────────────────────────────────────────────────────────────
def save_case(run_id: str, state: Dict, label: str = "") -> Dict:
    """Persist a finished case + update the index. Strips stix_bundle to save space."""
    _load_index_once()
    payload = {k: v for k, v in state.items() if k != "stix_bundle"}
    payload["runId"] = run_id
    payload["label"] = label or payload.get("label") or ""
    payload.setdefault("timestamp", datetime.now(timezone.utc).isoformat())

    path = _BASE / f"{run_id}.json"
    with _lock:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, default=str)
        except Exception as e:
            return {"error": str(e)}

        # Build / update index entry
        idx_entry = _build_index_entry(run_id, payload)
        # Remove any prior entry with the same id
        for i, e in enumerate(_INDEX_MEM):
            if e.get("runId") == run_id:
                _INDEX_MEM.pop(i)
                break
        _INDEX_MEM.insert(0, idx_entry)
        # Cap index at 500 most recent
        del _INDEX_MEM[500:]
        _persist_index()
    return {"saved": True, "runId": run_id}


def load_case(run_id: str) -> Optional[Dict]:
    path = _BASE / f"{run_id}.json"
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def update_label(run_id: str, label: str) -> bool:
    """PUT /api/cases/{run_id}/label backing."""
    case = load_case(run_id)
    if not case:
        return False
    case["label"] = label
    return save_case(run_id, case, label).get("saved", False)


def append_note(run_id: str, note: str, analyst: str = "") -> bool:
    """POST /api/cases/{run_id}/notes backing."""
    case = load_case(run_id)
    if not case:
        return False
    notes = case.get("analyst_notes_list") or []
    notes.append({
        "text":      note,
        "analyst":   analyst,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    case["analyst_notes_list"] = notes
    return save_case(run_id, case, case.get("label", "")).get("saved", False)


def list_cases(threat_level: Optional[str] = None,
               malware_family: Optional[str] = None,
               since_days: Optional[int] = None,
               limit: int = 25) -> List[Dict]:
    """Return compact index entries (no full payload)."""
    _load_index_once()
    out = []
    for entry in _INDEX_MEM:
        if threat_level and (entry.get("threat_level") or "").upper() != threat_level.upper():
            continue
        if malware_family and (entry.get("malware_family") or "").lower() != malware_family.lower():
            continue
        if since_days:
            try:
                ts = datetime.fromisoformat((entry.get("timestamp") or "").replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - ts).days
                if age_days > since_days:
                    continue
            except Exception:
                pass
        out.append(entry)
        if len(out) >= limit:
            break
    return out


def search_cases(query: str, limit: int = 25) -> List[Dict]:
    """Substring search across label, IOC values, malware family, threat actor,
    MITRE techniques. Case-insensitive."""
    _load_index_once()
    q = (query or "").strip().lower()
    if not q:
        return []
    out = []
    for entry in _INDEX_MEM:
        # Quick checks against index entry fields
        hit = False
        for f in ("label", "malware_family", "threat_actor_name", "summary"):
            val = entry.get(f) or ""
            if q in str(val).lower():
                hit = True
                break
        if not hit:
            if any(q in (t or "").lower() for t in (entry.get("mitre_techniques") or [])):
                hit = True
        if not hit:
            if any(q in (ioc or "").lower() for ioc in (entry.get("ioc_values") or [])):
                hit = True
        if hit:
            out.append(entry)
            if len(out) >= limit:
                break
    return out


# ─── helpers ──────────────────────────────────────────────────────────────────
def _build_index_entry(run_id: str, payload: Dict) -> Dict:
    rs = payload.get("response_summary") or {}
    actor = payload.get("threat_actor") or rs.get("threat_actor") or {}
    actor_name = actor.get("name") if isinstance(actor, dict) else (str(actor) if actor else None)
    iocs = payload.get("iocs") or {}
    flat_iocs = []
    for cat in ("ips", "domains", "hashes", "urls", "emails"):
        for v in (iocs.get(cat) or []):
            flat_iocs.append(v)
    return {
        "runId":             run_id,
        "label":             payload.get("label", ""),
        "timestamp":         payload.get("timestamp"),
        "threat_level":      payload.get("threat_level") or rs.get("threat_level"),
        "confidence":        payload.get("confidence") or rs.get("confidence"),
        "summary":           (rs.get("summary") or "")[:200],
        "malware_family":    payload.get("malware_family") or rs.get("malware_family"),
        "threat_actor_name": actor_name,
        "campaign":          payload.get("campaign") or rs.get("campaign"),
        "mitre_techniques":  payload.get("mitre_techniques") or rs.get("mitre_techniques") or [],
        "ioc_count":         len(flat_iocs),
        "ioc_values":        flat_iocs[:25],   # sample for search; full case file has the rest
    }


def get_index() -> List[Dict]:
    _load_index_once()
    return list(_INDEX_MEM)
