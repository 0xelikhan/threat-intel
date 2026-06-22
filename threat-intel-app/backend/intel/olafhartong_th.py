"""
olafhartong/ThreatHunting + BlueTeamLabs/sentinel-attack KQL corpus loader.

Sources:
  - https://github.com/olafhartong/ThreatHunting           (MIT) — KQL queries
    for Microsoft Sentinel + Defender XDR, mapped to ATT&CK.
  - https://github.com/BlueTeamLabs/sentinel-attack        (MIT) — Sentinel
    rules organised by ATT&CK technique with technique-keyed folders.

Both ship Sentinel/KQL rules organised by ATT&CK technique. RECON
generates KQL on demand, but has no curated reference catalogue to
match against — when the investigation surfaces T1059.001, we can
cite "olafhartong/ThreatHunting has 4 vetted Sentinel queries for
this technique" alongside the generated rule.

The two repos use slightly different layouts; the loader walks both
and unifies them under `intel/olafhartong_th`.
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.olafhartong_th")

_OH_ROOT       = (Path(__file__).parent.parent.parent
                  / "vendor" / "olafhartong-threathunting")
_SENT_ATK_ROOT = (Path(__file__).parent.parent.parent
                  / "vendor" / "sentinel-attack")

_TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
_KQL_TITLE_RE = re.compile(r"^//\s*Author:|^//\s*Description:", re.MULTILINE)

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":       False,
    "queries":      [],   # list[dict]
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


def _extract_techniques(blob: str) -> List[str]:
    return list({m.group(1).upper() for m in _TECHNIQUE_RE.finditer(blob)})


def _ingest_olafhartong(root: Path,
                        queries: List[Dict[str, Any]],
                        by_tech: Dict[str, List[Dict[str, Any]]]) -> None:
    """olafhartong/ThreatHunting layout: top-level technique-named dirs
    (T1059.001/, T1003/, ...) each containing one or more .yaml + .kql
    files. We pick up either: a YAML with metadata + queries, or a
    bare .kql with technique IDs embedded in the rel path."""
    if not root.exists():
        return
    for path in root.rglob("*.yaml"):
        if not path.is_file() or path.stat().st_size > 96_000:
            continue
        try:
            doc = _safe_yaml(path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
        if not isinstance(doc, dict):
            continue
        # Prefer the YAML's own field; fall back to path-derived IDs.
        rel = path.relative_to(root).as_posix()
        techs = _extract_techniques(rel) + _extract_techniques(str(doc))
        techs = list(dict.fromkeys(techs))
        title = (doc.get("title") or doc.get("name") or path.stem).strip()
        description = (doc.get("description") or "")[:300]
        meta = {
            "title":       title[:200],
            "techniques":  techs,
            "description": description,
            "path":        rel,
            "source":      "olafhartong/ThreatHunting",
        }
        queries.append(meta)
        for t in techs:
            by_tech.setdefault(t, []).append(meta)

    # Bare .kql files
    for path in root.rglob("*.kql"):
        if not path.is_file() or path.stat().st_size > 96_000:
            continue
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        techs = _extract_techniques(rel)
        if not techs:
            # If filename has no TID, parse first ~600 chars for one.
            try:
                head = path.read_text(encoding="utf-8", errors="ignore")[:600]
            except OSError:
                head = ""
            techs = _extract_techniques(head)
        if not techs:
            continue
        meta = {
            "title":       path.stem.replace("_", " "),
            "techniques":  techs,
            "description": "",
            "path":        rel,
            "source":      "olafhartong/ThreatHunting",
        }
        queries.append(meta)
        for t in techs:
            by_tech.setdefault(t, []).append(meta)


def _ingest_sentinel_attack(root: Path,
                            queries: List[Dict[str, Any]],
                            by_tech: Dict[str, List[Dict[str, Any]]]) -> None:
    """sentinel-attack layout: rules/ contains .yaml with `tactics:` and
    `relevantTechniques:` Sentinel-Detection-Rule-style metadata."""
    if not root.exists():
        return
    rules_root = root / "rules"
    if not rules_root.exists():
        rules_root = root
    for path in rules_root.rglob("*.yaml"):
        if not path.is_file() or path.stat().st_size > 96_000:
            continue
        try:
            doc = _safe_yaml(path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
        if not isinstance(doc, dict):
            continue
        techs: List[str] = []
        rt = doc.get("relevantTechniques") or doc.get("techniques") or []
        if isinstance(rt, list):
            for r in rt:
                for m in _TECHNIQUE_RE.finditer(str(r)):
                    techs.append(m.group(1).upper())
        if not techs:
            continue
        title = (doc.get("name") or doc.get("displayName")
                 or doc.get("title") or path.stem).strip()
        rel = path.relative_to(root).as_posix()
        meta = {
            "title":       title[:200],
            "techniques":  list(dict.fromkeys(techs)),
            "description": (doc.get("description") or "")[:300],
            "path":        rel,
            "source":      "BlueTeamLabs/sentinel-attack",
        }
        queries.append(meta)
        for t in meta["techniques"]:
            by_tech.setdefault(t, []).append(meta)


def _build_index() -> None:
    if not _OH_ROOT.exists() and not _SENT_ATK_ROOT.exists():
        _state["error"]  = ("olafhartong-threathunting / sentinel-attack "
                            f"dirs not present at {_OH_ROOT.parent}")
        _state["loaded"] = True
        return

    queries: List[Dict[str, Any]] = []
    by_tech: Dict[str, List[Dict[str, Any]]] = {}

    _ingest_olafhartong(_OH_ROOT, queries, by_tech)
    _ingest_sentinel_attack(_SENT_ATK_ROOT, queries, by_tech)

    _state["queries"]      = queries
    _state["by_technique"] = by_tech
    _state["loaded"]       = True
    _state["error"]        = None
    _log.info("olafhartong/sentinel-attack KQL loaded: %d queries | %d techniques",
              len(queries), len(by_tech))


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
    seen: Dict[str, Dict[str, Any]] = {}
    for t in wanted:
        keys = {t}
        if "." in t:
            keys.add(t.split(".", 1)[0])
        for k in keys:
            for meta in by_tech.get(k, []):
                seen.setdefault(meta["title"], meta)
    return list(seen.values())[:max_results]


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":     bool(_state["loaded"]),
        "queries":    len(_state.get("queries") or []),
        "techniques": len(_state.get("by_technique") or {}),
        "error":      _state.get("error"),
    }
