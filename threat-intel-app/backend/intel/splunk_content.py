"""
Splunk security_content corpus loader.

Source: https://github.com/splunk/security_content (Apache-2.0). Ships
hundreds of detection YAMLs at `detections/{endpoint,cloud,network,
web,application}/*.yml` plus 300+ "analytic stories" at `stories/*.yml`
that group detections into hunt narratives.

Each detection has shape:

  name:        Some Detection
  id:          <uuid>
  type:        TTP|Hunting|Anomaly|Correlation
  search:      |
    | tstats … | rename …
  tags:
    mitre_attack_id:
      - T1059.001
    confidence:  high
    impact:      high

We index the metadata + the search text so the investigation node can
cite "Splunk security_content: Detect Base64-Encoded PowerShell" with
attribution.
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

_log = logging.getLogger("recon.intel.splunk_content")

_SPLUNK_ROOT = (Path(__file__).parent.parent.parent
                / "vendor" / "splunk-security-content")

_TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":         False,
    "detections":     [],
    "stories":        [],
    "by_technique":   {},
    "error":          None,
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


def _extract_techniques(tags: Any) -> List[str]:
    if not isinstance(tags, dict):
        return []
    out: List[str] = []
    raw = tags.get("mitre_attack_id") or []
    if isinstance(raw, list):
        for v in raw:
            for m in _TECHNIQUE_RE.finditer(str(v)):
                out.append(m.group(1).upper())
    elif isinstance(raw, str):
        for m in _TECHNIQUE_RE.finditer(raw):
            out.append(m.group(1).upper())
    return list(dict.fromkeys(out))


def _build_index() -> None:
    if not _SPLUNK_ROOT.exists():
        _state["error"]  = f"splunk-security-content dir not present at {_SPLUNK_ROOT}"
        _state["loaded"] = True
        return

    detections: List[Dict[str, Any]] = []
    stories:    List[Dict[str, Any]] = []
    by_tech:    Dict[str, List[Dict[str, Any]]] = {}

    det_root = _SPLUNK_ROOT / "detections"
    if det_root.exists():
        for path in det_root.rglob("*.yml"):
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
            tags = doc.get("tags") or {}
            techniques = _extract_techniques(tags)
            meta = {
                "id":          (doc.get("id") or "").strip(),
                "name":        name[:200],
                "type":        (doc.get("type") or "").strip(),
                "description": (doc.get("description") or "")[:300],
                "techniques":  techniques,
                "confidence":  str(tags.get("confidence") or "").lower(),
                "impact":      str(tags.get("impact") or "").lower(),
                "source":      "Splunk security_content",
            }
            detections.append(meta)
            for t in techniques:
                by_tech.setdefault(t, []).append(meta)

    story_root = _SPLUNK_ROOT / "stories"
    if story_root.exists():
        for path in story_root.rglob("*.yml"):
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
            narrative = (doc.get("narrative") or doc.get("description") or "")
            tags = doc.get("tags") or {}
            stories.append({
                "id":          (doc.get("id") or "").strip(),
                "name":        name[:200],
                "narrative":   narrative[:400],
                "categories":  (tags.get("category") or [])[:6]
                               if isinstance(tags.get("category"), list)
                               else [],
                "source":      "Splunk security_content (story)",
            })

    _state["detections"]   = detections
    _state["stories"]      = stories
    _state["by_technique"] = by_tech
    _state["loaded"]       = True
    _state["error"]        = None
    _log.info("splunk security_content loaded: %d detections | %d stories | %d techniques",
              len(detections), len(stories), len(by_tech))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


_CONF_RANK = {"low": 1, "medium": 2, "high": 3}


def match_by_techniques(technique_ids: Iterable[str],
                        max_results: int = 12) -> List[Dict[str, Any]]:
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
                key = meta.get("id") or meta.get("name")
                overlap = len(set(meta.get("techniques") or []) & wanted)
                conf = _CONF_RANK.get(meta.get("confidence"), 0)
                prev = scored.get(key)
                if not prev or (overlap, conf) > (prev[0], prev[1]):
                    scored[key] = (overlap, conf, meta)
    ranked = sorted(scored.values(), key=lambda v: (-v[0], -v[1],
                                                    v[2]["name"].lower()))
    return [v[2] for v in ranked[:max_results]]


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":     bool(_state["loaded"]),
        "detections": len(_state.get("detections") or []),
        "stories":    len(_state.get("stories") or []),
        "techniques": len(_state.get("by_technique") or {}),
        "error":      _state.get("error"),
    }
