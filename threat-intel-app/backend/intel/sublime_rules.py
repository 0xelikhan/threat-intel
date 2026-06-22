"""
Sublime-Security/sublime-rules corpus loader.

Source: https://github.com/sublime-security/sublime-rules (MIT). The
canonical open corpus of email detection rules — ~1,200 .yml rules
across phishing, BEC, callback phishing, malware delivery, brand
impersonation, account takeover, ATO, and more. Each rule has shape:

  name:        Suspicious sender pattern - lookalike
  type:        rule | exploit | spam
  severity:    high|medium|low
  tags:        [Initial Access, T1566, ...]
  source:      |
    ...DSL expression over an "email" object...
  attack_types: [Phishing, Credential Theft, ...]
  tactics_and_techniques: [...]
  detection_methods: [Sender analysis, Header analysis, ...]
  references: [...]

We index by tactics/techniques + attack_types so the investigation
node can cite Sublime rules when the alert is an email phishing
investigation. RECON has eml_analysis.py for parsing but no curated
email-detection corpus — this fills that gap.
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

_log = logging.getLogger("recon.intel.sublime_rules")

_SUBLIME_ROOT = (Path(__file__).parent.parent.parent
                 / "vendor" / "sublime-rules")

_TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":           False,
    "rules":            [],   # list[dict]
    "by_technique":     {},
    "by_attack_type":   {},
    "error":            None,
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


def _extract_techniques(doc: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    # Sublime rules use two fields: `tactics_and_techniques` and `tags`.
    for key in ("tactics_and_techniques", "tags"):
        v = doc.get(key) or []
        if isinstance(v, list):
            for item in v:
                for m in _TECHNIQUE_RE.finditer(str(item)):
                    out.append(m.group(1).upper())
        elif isinstance(v, str):
            for m in _TECHNIQUE_RE.finditer(v):
                out.append(m.group(1).upper())
    return list(dict.fromkeys(out))


def _build_index() -> None:
    if not _SUBLIME_ROOT.exists():
        _state["error"]  = f"sublime-rules dir not present at {_SUBLIME_ROOT}"
        _state["loaded"] = True
        return

    rules:          List[Dict[str, Any]] = []
    by_tech:        Dict[str, List[Dict[str, Any]]] = {}
    by_attack_type: Dict[str, List[Dict[str, Any]]] = {}

    detect_root = _SUBLIME_ROOT / "detection-rules"
    if not detect_root.exists():
        detect_root = _SUBLIME_ROOT

    for path in detect_root.rglob("*.yml"):
        if not path.is_file() or path.stat().st_size > 96_000:
            continue
        try:
            doc = _safe_yaml(path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
        if not isinstance(doc, dict):
            continue
        name = (doc.get("name") or "").strip()
        if not name:
            continue
        techniques  = _extract_techniques(doc)
        attack_types = doc.get("attack_types") or []
        if isinstance(attack_types, str):
            attack_types = [attack_types]
        meta = {
            "name":         name[:200],
            "type":         (doc.get("type") or "").strip().lower(),
            "severity":     (doc.get("severity") or "").strip().lower(),
            "techniques":   techniques,
            "attack_types": [str(a)[:80] for a in attack_types][:6],
            "description":  (doc.get("description") or "")[:300],
            "source":       "Sublime Security",
        }
        rules.append(meta)
        for t in techniques:
            by_tech.setdefault(t, []).append(meta)
        for at in meta["attack_types"]:
            by_attack_type.setdefault(at, []).append(meta)

    _state["rules"]          = rules
    _state["by_technique"]   = by_tech
    _state["by_attack_type"] = by_attack_type
    _state["loaded"]         = True
    _state["error"]          = None
    _log.info("sublime-rules loaded: %d rules | %d techniques | %d attack types",
              len(rules), len(by_tech), len(by_attack_type))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


_SEV_RANK = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def match_by_techniques(technique_ids: Iterable[str],
                        max_results: int = 10) -> List[Dict[str, Any]]:
    _ensure_loaded()
    wanted = {t.upper().strip() for t in (technique_ids or [])
              if isinstance(t, str) and t.strip()}
    if not wanted:
        return []
    by_tech = _state.get("by_technique") or {}
    scored: Dict[str, Tuple[int, int, Dict[str, Any]]] = {}
    for t in wanted:
        keys = {t}
        if "." in t:
            keys.add(t.split(".", 1)[0])
        for k in keys:
            for meta in by_tech.get(k, []):
                key = meta["name"]
                overlap = len(set(meta.get("techniques") or []) & wanted)
                sev = _SEV_RANK.get(meta.get("severity"), 0)
                prev = scored.get(key)
                if not prev or (overlap, sev) > (prev[0], prev[1]):
                    scored[key] = (overlap, sev, meta)
    ranked = sorted(scored.values(), key=lambda v: (-v[0], -v[1],
                                                    v[2]["name"].lower()))
    return [v[2] for v in ranked[:max_results]]


def match_by_attack_type(attack_type: str,
                         max_results: int = 10) -> List[Dict[str, Any]]:
    _ensure_loaded()
    if not attack_type:
        return []
    rows = (_state.get("by_attack_type") or {}).get(attack_type, [])
    return rows[:max_results]


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":       bool(_state["loaded"]),
        "rules":        len(_state.get("rules") or []),
        "techniques":   len(_state.get("by_technique") or {}),
        "attack_types": len(_state.get("by_attack_type") or {}),
        "error":        _state.get("error"),
    }
