r"""
ForensicArtifacts/artifacts loader — the de-facto YAML registry of
DFIR artefact definitions consumed by Plaso, Velociraptor, GRR.

Source: https://github.com/ForensicArtifacts/artifacts (Apache-2.0).
Each artefact YAML has shape:

  name: WindowsRunKeys
  doc:  Windows persistence registry Run keys
  sources:
    - type: REGISTRY_KEY
      attributes:
        keys:
          - HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
          - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
  supported_os: [Windows]
  labels: [Persistence]

We index two views:

  by_label  → {label, [artefact]}    (label is the closest analogue to a
                                       MITRE tactic — "Persistence",
                                       "Authentication", "ExternalMedia")
  by_keyword → {keyword, [artefact]} (keywords extracted from doc+name so
                                       investigation can pivot from
                                       "credential dumping" → relevant
                                       artefacts)
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.forensic_artifacts")

_FA_ROOT = (Path(__file__).parent.parent.parent
            / "vendor" / "forensic-artifacts")

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":     False,
    "artifacts":  [],
    "by_label":   {},
    "by_os":      {},
    "error":      None,
}


def _safe_yaml_all(text: str) -> List[Dict[str, Any]]:
    try:
        import yaml
    except Exception:
        return []
    try:
        return [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    except Exception:
        return []


def _extract_targets(sources: Any) -> List[Dict[str, Any]]:
    """Pull the artefact's collection targets — registry keys, file paths,
    EventLog channels, WMI queries — into a small uniform list."""
    out: List[Dict[str, Any]] = []
    if not isinstance(sources, list):
        return out
    for s in sources:
        if not isinstance(s, dict):
            continue
        kind = (s.get("type") or "").upper()
        attrs = s.get("attributes") or {}
        if not isinstance(attrs, dict):
            continue
        if kind == "REGISTRY_KEY":
            for k in (attrs.get("keys") or [])[:6]:
                out.append({"type": "registry_key", "target": str(k)[:200]})
        elif kind == "REGISTRY_VALUE":
            for kv in (attrs.get("key_value_pairs") or [])[:6]:
                if isinstance(kv, dict):
                    out.append({"type": "registry_value",
                                "target": (f"{kv.get('key','')} :: "
                                           f"{kv.get('value','')}")[:200]})
        elif kind == "FILE":
            for p in (attrs.get("paths") or [])[:6]:
                out.append({"type": "file", "target": str(p)[:200]})
        elif kind == "PATH":
            for p in (attrs.get("paths") or [])[:6]:
                out.append({"type": "path", "target": str(p)[:200]})
        elif kind == "WMI":
            q = attrs.get("query") or ""
            out.append({"type": "wmi", "target": str(q)[:200]})
        elif kind == "COMMAND":
            cmd = attrs.get("cmd") or ""
            out.append({"type": "command", "target": str(cmd)[:200]})
    return out[:12]


def _build_index() -> None:
    if not _FA_ROOT.exists():
        _state["error"]  = f"forensic-artifacts dir not present at {_FA_ROOT}"
        _state["loaded"] = True
        return

    artifacts: List[Dict[str, Any]] = []
    by_label:  Dict[str, List[Dict[str, Any]]] = {}
    by_os:     Dict[str, List[Dict[str, Any]]] = {}

    data_root = _FA_ROOT / "artifacts" / "data"
    if not data_root.exists():
        data_root = _FA_ROOT

    for path in data_root.rglob("*.yaml"):
        if not path.is_file() or path.stat().st_size > 256_000:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for doc in _safe_yaml_all(text):
            name = (doc.get("name") or "").strip()
            if not name:
                continue
            labels = doc.get("labels") or []
            if isinstance(labels, str):
                labels = [labels]
            supported = doc.get("supported_os") or []
            if isinstance(supported, str):
                supported = [supported]

            meta = {
                "name":        name,
                "doc":         (doc.get("doc") or "")[:300],
                "labels":      [str(l) for l in labels][:8],
                "supported_os": [str(o) for o in supported][:6],
                "targets":     _extract_targets(doc.get("sources") or []),
                "source":      "ForensicArtifacts",
            }
            artifacts.append(meta)
            for label in meta["labels"]:
                by_label.setdefault(label, []).append(meta)
            for os_name in meta["supported_os"]:
                by_os.setdefault(os_name, []).append(meta)

    _state["artifacts"] = artifacts
    _state["by_label"]  = by_label
    _state["by_os"]     = by_os
    _state["loaded"]    = True
    _state["error"]     = None
    _log.info("forensic-artifacts loaded: %d artefacts | %d labels | %d OSes",
              len(artifacts), len(by_label), len(by_os))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def evidence_for_techniques(technique_names: Iterable[str],
                            host_os: Optional[str] = None,
                            max_results: int = 12) -> List[Dict[str, Any]]:
    """Given a set of technique LABELS (free-text — e.g.
    'Persistence', 'Authentication'), return matching artefact
    collection targets, filtered to `host_os` when provided."""
    _ensure_loaded()
    wanted = {(t or "").strip() for t in (technique_names or []) if t}
    if not wanted:
        return []
    by_label = _state.get("by_label") or {}

    seen: Dict[str, Dict[str, Any]] = {}
    for label in wanted:
        for meta in by_label.get(label, []):
            if host_os and meta.get("supported_os") and \
               not any(host_os.lower() in o.lower() for o in meta["supported_os"]):
                continue
            seen.setdefault(meta["name"], meta)
    return list(seen.values())[:max_results]


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":     bool(_state["loaded"]),
        "artifacts":  len(_state.get("artifacts") or []),
        "labels":     len(_state.get("by_label") or {}),
        "platforms":  list((_state.get("by_os") or {}).keys()),
        "error":      _state.get("error"),
    }
