"""
MITRE Cyber Analytics Repository (CAR) loader.

Source: https://github.com/mitre-attack/car (Apache-2.0). ~100 named
analytics (CAR-YYYY-MM-NNN.yaml) — each with pseudocode, a Sigma/EQL/
Splunk implementation, the ATT&CK techniques it covers, and the data-
source requirements. CAR closes the gap between "we know technique
T1059.001 is involved" and "here is a vetted analytic that detects it."

Loaded lazily, indexed by technique ID, mirroring sigma_corpus.py /
panther_rules.py.
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.mitre_car")

_CAR_ROOT = (Path(__file__).parent.parent.parent
             / "vendor" / "mitre-car")

_TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":       False,
    "analytics":    [],
    "by_technique": {},
    "error":        None,
}


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


def _extract_techniques(blob: Any) -> List[str]:
    """CAR encodes coverage as a list of dicts: {technique: T1059, subtechniques: [.001,...]}."""
    out: List[str] = []
    if isinstance(blob, list):
        for item in blob:
            if isinstance(item, dict):
                tid = item.get("technique") or item.get("id")
                if tid:
                    for m in _TECHNIQUE_RE.finditer(str(tid)):
                        out.append(m.group(1).upper())
                subs = item.get("subtechniques") or []
                if isinstance(subs, list):
                    for s in subs:
                        for m in _TECHNIQUE_RE.finditer(str(s)):
                            out.append(m.group(1).upper())
            elif isinstance(item, str):
                for m in _TECHNIQUE_RE.finditer(item):
                    out.append(m.group(1).upper())
    return list(dict.fromkeys(out))


def _build_index() -> None:
    if not _CAR_ROOT.exists():
        _state["error"]  = f"mitre-car dir not present at {_CAR_ROOT}"
        _state["loaded"] = True
        return

    analytics:  List[Dict[str, Any]] = []
    by_tech:    Dict[str, List[Dict[str, Any]]] = {}

    # CAR analytics live at analytics/CAR-*.yaml in the canonical repo.
    analytics_root = _CAR_ROOT / "analytics"
    if not analytics_root.exists():
        analytics_root = _CAR_ROOT

    for path in analytics_root.rglob("CAR-*.yaml"):
        if not path.is_file() or path.stat().st_size > 96_000:
            continue
        try:
            doc = _safe_yaml(path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
        if not isinstance(doc, dict):
            continue
        title = (doc.get("title") or "").strip()
        car_id = (doc.get("id") or path.stem).strip()
        techniques = _extract_techniques(doc.get("coverage") or [])
        data_model = doc.get("data_model_references") or []
        impl = doc.get("implementations") or []
        impls: List[Dict[str, str]] = []
        if isinstance(impl, list):
            for im in impl:
                if not isinstance(im, dict):
                    continue
                impls.append({
                    "name":     str(im.get("name") or "")[:80],
                    "type":     str(im.get("type") or "").lower(),
                    "code":     str(im.get("code") or "")[:600],
                })
        meta = {
            "id":             car_id,
            "title":          title[:200],
            "description":    (doc.get("description") or "")[:400],
            "techniques":     techniques,
            "data_sources":   [str(d).split("/")[-1] for d in data_model][:8],
            "implementations": impls[:4],
            "source":         "MITRE CAR",
        }
        analytics.append(meta)
        for t in techniques:
            by_tech.setdefault(t, []).append(meta)

    _state["analytics"]    = analytics
    _state["by_technique"] = by_tech
    _state["loaded"]       = True
    _state["error"]        = None
    _log.info("mitre-car loaded: %d analytics | %d techniques",
              len(analytics), len(by_tech))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def match_by_techniques(technique_ids: Iterable[str],
                        max_results: int = 8) -> List[Dict[str, Any]]:
    _ensure_loaded()
    wanted = {t.upper().strip() for t in (technique_ids or [])
              if isinstance(t, str) and t.strip()}
    if not wanted:
        return []
    by_tech = _state.get("by_technique") or {}
    scored: Dict[str, Any] = {}
    for t in wanted:
        keys = {t}
        if "." in t:
            keys.add(t.split(".", 1)[0])
        for k in keys:
            for meta in by_tech.get(k, []):
                key = meta.get("id") or meta.get("title")
                overlap = len(set(meta.get("techniques") or []) & wanted)
                prev = scored.get(key)
                if not prev or overlap > prev[0]:
                    scored[key] = (overlap, meta)
    ranked = sorted(scored.values(), key=lambda v: (-v[0], v[1]["title"].lower()))
    return [v[1] for v in ranked[:max_results]]


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":     bool(_state["loaded"]),
        "analytics":  len(_state.get("analytics") or []),
        "techniques": len(_state.get("by_technique") or {}),
        "error":      _state.get("error"),
    }
