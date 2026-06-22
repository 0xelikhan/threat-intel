"""
Sysdig Falco rules loader.

Source: https://github.com/falcosecurity/rules (Apache-2.0). Falco's
runtime container/Linux security rule set. Each rule has shape:

  - rule: Detect Crypto Mining Activity
    desc: Detect cryptocurrency mining activity
    condition: spawned_process and crypto_miners
    output:    "Crypto miner detected (...)"
    priority:  WARNING
    tags:      [mitre_execution, T1496]

We index by MITRE technique (tags carry T-IDs as community-conventional
strings) so investigation citations can extend into the container /
runtime-Linux vertical that RECON otherwise has zero coverage of.
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.falco_rules")

_FALCO_ROOT = (Path(__file__).parent.parent.parent
               / "vendor" / "falco-rules")

_TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":         False,
    "rules":          [],
    "by_technique":   {},
    "error":          None,
}


def _safe_yaml_all(text: str) -> List[Dict[str, Any]]:
    try:
        import yaml
    except Exception:
        return []
    try:
        # falco rule files are a single YAML document containing a list
        # of dicts (one entry per rule / macro / list).
        loaded = yaml.safe_load(text)
        if isinstance(loaded, list):
            return [d for d in loaded if isinstance(d, dict)]
        if isinstance(loaded, dict):
            return [loaded]
    except Exception:
        return []
    return []


def _build_index() -> None:
    if not _FALCO_ROOT.exists():
        _state["error"]  = f"falco-rules dir not present at {_FALCO_ROOT}"
        _state["loaded"] = True
        return

    rules:   List[Dict[str, Any]] = []
    by_tech: Dict[str, List[Dict[str, Any]]] = {}

    for path in _FALCO_ROOT.rglob("*.yaml"):
        if not path.is_file() or path.stat().st_size > 512_000:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for entry in _safe_yaml_all(text):
            if "rule" not in entry:
                continue  # skip macros/lists/etc.
            name = (entry.get("rule") or "").strip()
            if not name:
                continue
            tags = entry.get("tags") or []
            if isinstance(tags, str):
                tags = [tags]
            techniques = []
            for t in tags:
                for m in _TECHNIQUE_RE.finditer(str(t)):
                    techniques.append(m.group(1).upper())
            # Also grep the description for T-IDs.
            desc = (entry.get("desc") or "")[:300]
            for m in _TECHNIQUE_RE.finditer(desc):
                techniques.append(m.group(1).upper())
            techniques = list(dict.fromkeys(techniques))
            if not techniques:
                continue  # only index rules with at least one ATT&CK link
            meta = {
                "name":        name[:200],
                "description": desc,
                "priority":    (entry.get("priority") or "").strip().lower(),
                "techniques":  techniques,
                "tags":        [str(t)[:48] for t in tags][:8],
                "source":      "Sysdig falco-rules",
            }
            rules.append(meta)
            for t in techniques:
                by_tech.setdefault(t, []).append(meta)

    _state["rules"]        = rules
    _state["by_technique"] = by_tech
    _state["loaded"]       = True
    _state["error"]        = None
    _log.info("falco-rules loaded: %d rules | %d techniques",
              len(rules), len(by_tech))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


_PRIORITY_RANK = {
    "info": 1, "informational": 1, "notice": 2, "warning": 3,
    "error": 4, "critical": 5, "alert": 5, "emergency": 6,
}


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
                key = meta["name"]
                overlap = len(set(meta.get("techniques") or []) & wanted)
                prio = _PRIORITY_RANK.get(meta.get("priority"), 0)
                prev = scored.get(key)
                if not prev or (overlap, prio) > (prev[0], prev[1]):
                    scored[key] = (overlap, prio, meta)
    ranked = sorted(scored.values(), key=lambda v: (-v[0], -v[1],
                                                    v[2]["name"].lower()))
    return [v[2] for v in ranked[:max_results]]


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":     bool(_state["loaded"]),
        "rules":      len(_state.get("rules") or []),
        "techniques": len(_state.get("by_technique") or {}),
        "error":      _state.get("error"),
    }
