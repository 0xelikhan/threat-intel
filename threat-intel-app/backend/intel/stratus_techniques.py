"""
DataDog Stratus Red Team technique catalogue loader.

Source: https://github.com/DataDog/stratus-red-team (Apache-2.0). Ships
~50 named cloud attack techniques across AWS, Azure, GCP, Kubernetes.
Each is defined in Go at
  internal/attacktechniques/<provider>/<tactic>/<id>/main.go

with a `stratus.Registry().RegisterAttackTechnique(...)` call carrying
`ID`, `FriendlyName`, `Description`, `Platform`, `MitreAttackTactics`,
`MitreAttackTechniques`. This module extracts the metadata WITHOUT
running Go — we regex over the source files.

Companion to DataDog grimoire (which I integrated in round 3). Grimoire
gives the labelled CloudTrail samples; Stratus gives the canonical
attack-technique names + ATT&CK mappings. Together the analyst gets
both ground truth and naming.
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.stratus")

_STRATUS_ROOT = (Path(__file__).parent.parent.parent
                 / "vendor" / "stratus-red-team")

_ID_RE          = re.compile(r'\bID:\s*"([^"]+)"')
_FRIENDLY_RE    = re.compile(r'FriendlyName:\s*"([^"]+)"')
_DESC_RE        = re.compile(r'Description:\s*`([^`]+)`')
_PLATFORM_RE    = re.compile(r'Platform:\s*stratus\.(\w+)\b')
_TACTIC_RE      = re.compile(r'mitreattack\.(\w+),')
_TECHNIQUE_LIST_RE = re.compile(r'MitreAttackTechniques:\s*\[\]string\{([^}]+)\}')
_TECHNIQUE_INNER_RE = re.compile(r'"(T\d{4}(?:\.\d{3})?)"')
_TECHNIQUE_ID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":         False,
    "techniques":     [],
    "by_id":          {},
    "by_technique":   {},   # ATT&CK ID -> list[stratus]
    "by_platform":    {},
    "error":          None,
}


def _build_index() -> None:
    if not _STRATUS_ROOT.exists():
        _state["error"]  = f"stratus-red-team dir not present at {_STRATUS_ROOT}"
        _state["loaded"] = True
        return

    techniques:    List[Dict[str, Any]] = []
    by_id:         Dict[str, Dict[str, Any]] = {}
    by_technique:  Dict[str, List[Dict[str, Any]]] = {}
    by_platform:   Dict[str, List[Dict[str, Any]]] = {}

    techniques_root = _STRATUS_ROOT / "internal" / "attacktechniques"
    if not techniques_root.exists():
        techniques_root = _STRATUS_ROOT

    for path in techniques_root.rglob("main.go"):
        if not path.is_file() or path.stat().st_size > 256_000:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        m_id = _ID_RE.search(text)
        if not m_id:
            continue
        m_fr = _FRIENDLY_RE.search(text)
        m_de = _DESC_RE.search(text)
        m_pl = _PLATFORM_RE.search(text)
        m_tl = _TECHNIQUE_LIST_RE.search(text)

        techs: List[str] = []
        if m_tl:
            for t in _TECHNIQUE_INNER_RE.finditer(m_tl.group(1)):
                techs.append(t.group(1).upper())
        else:
            for t in _TECHNIQUE_ID_RE.finditer(text):
                techs.append(t.group(1).upper())
        techs = list(dict.fromkeys(techs))
        platform = m_pl.group(1) if m_pl else ""
        if not platform:
            # Fall back to the path provider name (aws/azure/gcp/k8s).
            try:
                rel = path.relative_to(techniques_root)
                if rel.parts:
                    platform = rel.parts[0]
            except ValueError:
                pass

        meta = {
            "stratus_id":  m_id.group(1),
            "name":        (m_fr.group(1) if m_fr else m_id.group(1))[:200],
            "description": (m_de.group(1) if m_de else "")[:400],
            "platform":    platform.lower(),
            "techniques":  techs,
            "source":      "DataDog Stratus Red Team",
        }
        techniques.append(meta)
        by_id[meta["stratus_id"]] = meta
        for t in techs:
            by_technique.setdefault(t, []).append(meta)
        if platform:
            by_platform.setdefault(platform.lower(), []).append(meta)

    _state["techniques"]   = techniques
    _state["by_id"]        = by_id
    _state["by_technique"] = by_technique
    _state["by_platform"]  = by_platform
    _state["loaded"]       = True
    _state["error"]        = None
    _log.info("stratus-red-team loaded: %d techniques | %d platforms",
              len(techniques), len(by_platform))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def lookup_id(stratus_id: str) -> Optional[Dict[str, Any]]:
    _ensure_loaded()
    return (_state.get("by_id") or {}).get(stratus_id)


def match_by_techniques(technique_ids: Iterable[str],
                        platform: Optional[str] = None,
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
                if platform and meta.get("platform") != platform.lower():
                    continue
                seen.setdefault(meta["stratus_id"], meta)
    return list(seen.values())[:max_results]


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":     bool(_state["loaded"]),
        "techniques": len(_state.get("techniques") or []),
        "platforms":  list((_state.get("by_platform") or {}).keys()),
        "error":      _state.get("error"),
    }
