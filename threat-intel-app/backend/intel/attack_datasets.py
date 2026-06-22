"""
Mordor + Splunk attack_data fixtures loader.

Sources:
  - https://github.com/Cyb3rWard0g/mordor      (GPL-3.0 -> SKIPPED, but
    historical compatibility kept here; the loader returns 'unavailable'
    rather than ingesting a copyleft corpus into our pack.)
  - https://github.com/splunk/attack_data      (Apache-2.0). Labelled
    Windows event logs, Sysmon, AWS CloudTrail, Linux auditd captures
    organised by ATT&CK technique. Companion to DataDog grimoire (cloud-
    only) — this one covers the endpoint side.

Each attack_data dataset is a folder per ATT&CK technique with a
README.yaml shape:

  technique: T1059.001
  description: "PowerShell EncodedCommand execution"
  data:
    - log: windows-sysmon.log
      sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
    - log: ...

We index by technique ID, exposing
`samples_for_technique(T) -> [{name, description, sourcetype}]` for
prompt-context use by the response stage's KQL/SPL generation. We do
NOT actually load the multi-gigabyte log payloads; just metadata.
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.attack_datasets")

# Mordor is GPL-3.0 — the path is here only to surface the existence in
# stats(); we never ingest its contents.
_MORDOR_ROOT      = (Path(__file__).parent.parent.parent
                     / "vendor" / "mordor")
_ATTACK_DATA_ROOT = (Path(__file__).parent.parent.parent
                     / "vendor" / "splunk-attack-data")

_TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":        False,
    "datasets":      [],
    "by_technique":  {},
    "mordor_present": False,
    "mordor_skipped_reason": "Mordor is GPL-3.0; corpus not ingested",
    "error":         None,
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


def _build_index() -> None:
    _state["mordor_present"] = _MORDOR_ROOT.exists()

    if not _ATTACK_DATA_ROOT.exists():
        _state["error"]  = f"splunk-attack-data dir not present at {_ATTACK_DATA_ROOT}"
        _state["loaded"] = True
        return

    datasets: List[Dict[str, Any]] = []
    by_tech:  Dict[str, List[Dict[str, Any]]] = {}

    # splunk/attack_data layout: datasets/{attack_techniques,malware,...}/
    # T####/<dataset>/README.yaml. We walk every README.yaml; the
    # technique is in `technique`, the `data` list in `data`.
    for path in _ATTACK_DATA_ROOT.rglob("README.yaml"):
        if not path.is_file() or path.stat().st_size > 256_000:
            continue
        try:
            doc = _safe_yaml(path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
        if not isinstance(doc, dict):
            continue

        # Some datasets put the technique in `technique`, others in
        # `mitre_attack_technique`. Combine + regex out the IDs.
        tech_blob = " ".join(str(doc.get(k, "")) for k in
                              ("technique", "mitre_attack_technique",
                               "name", "id"))
        # Also grep the path because the canonical key is the folder name.
        try:
            rel = path.relative_to(_ATTACK_DATA_ROOT).as_posix()
        except ValueError:
            rel = path.as_posix()
        techs = list({m.group(1).upper()
                       for m in _TECHNIQUE_RE.finditer(tech_blob + " " + rel)})
        if not techs:
            continue

        data_blocks = doc.get("data") or []
        if not isinstance(data_blocks, list):
            data_blocks = []
        samples: List[Dict[str, str]] = []
        for entry in data_blocks[:6]:
            if not isinstance(entry, dict):
                continue
            samples.append({
                "log":         str(entry.get("log") or entry.get("file") or "")[:160],
                "sourcetype":  str(entry.get("sourcetype") or "")[:120],
                "description": str(entry.get("description") or "")[:200],
            })

        meta = {
            "name":         (doc.get("name") or doc.get("id")
                              or path.parent.name)[:160],
            "description":  (doc.get("description") or "")[:300],
            "techniques":   techs,
            "samples":      samples,
            "path":         rel,
            "source":       "splunk/attack_data",
        }
        datasets.append(meta)
        for t in techs:
            by_tech.setdefault(t, []).append(meta)

    _state["datasets"]     = datasets
    _state["by_technique"] = by_tech
    _state["loaded"]       = True
    _state["error"]        = None
    _log.info("attack_data fixtures loaded: %d datasets | %d techniques",
              len(datasets), len(by_tech))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def samples_for_technique(technique_id: str,
                          max_results: int = 4) -> List[Dict[str, Any]]:
    _ensure_loaded()
    if not technique_id:
        return []
    tid = technique_id.upper().strip()
    rows = (_state.get("by_technique") or {}).get(tid, [])
    if not rows and "." in tid:
        rows = (_state.get("by_technique") or {}).get(tid.split(".", 1)[0], [])
    return rows[:max_results]


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":          bool(_state["loaded"]),
        "datasets":        len(_state.get("datasets") or []),
        "techniques":      len(_state.get("by_technique") or {}),
        "mordor_present":  _state.get("mordor_present", False),
        "mordor_skipped":  _state.get("mordor_skipped_reason"),
        "error":           _state.get("error"),
    }
