"""
Panther Labs panther-analysis cloud/SaaS detection corpus loader.

Source: https://github.com/panther-labs/panther-analysis (Apache-2.0).
~1,500 detection rules covering AWS, GCP, Azure, Okta, Google Workspace,
M365, GitHub, Slack, Salesforce, Notion, Crowdstrike, Cloudflare, etc.

Each rule ships as a .py + .yml pair. The .yml has the metadata we care
about:

  LogTypes:    [Okta.SystemLog, ...]
  Severity:    Critical|High|Medium|Low|Info
  Reports:
    MITRE ATT&CK:
      - TA0001:T1078
      - TA0005:T1036.005
  Tags:        [Identity, Persistence, ...]
  Description: "..."
  Runbook:     "..."
  Reference:   "..."

We only consume the metadata — the .py rule bodies are bound to
Panther's runtime helpers and aren't portable. The inverted index keys
match the same shape as intel/sigma_corpus.py so investigation.py can
fan out the same lookup pattern across both corpora.
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

_log = logging.getLogger("recon.intel.panther")

_PANTHER_ROOT = (Path(__file__).parent.parent.parent
                 / "vendor" / "panther-analysis")

# Pull T1078 / T1078.001 / TA0001 out of the MITRE Reports list. Panther
# encodes them either as "T1078" or "TA0005:T1036.005" (tactic:technique).
_TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
_TACTIC_RE    = re.compile(r"\b(TA\d{4})\b")

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":         False,
    "rules":          [],     # list[dict]
    "by_technique":   {},
    "by_log_type":    {},
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


def _extract_mitre(reports: Any) -> Tuple[List[str], List[str]]:
    """Pull T#### technique IDs and TA#### tactic IDs out of the
    `Reports` block. Reports is a dict-of-lists like:
      Reports:
        MITRE ATT&CK:
          - TA0005:T1036.005
          - T1078
    """
    techniques: List[str] = []
    tactics:    List[str] = []
    if not isinstance(reports, dict):
        return techniques, tactics
    for vals in reports.values():
        if not isinstance(vals, list):
            continue
        for v in vals:
            s = str(v)
            for m in _TECHNIQUE_RE.finditer(s):
                techniques.append(m.group(1).upper())
            for m in _TACTIC_RE.finditer(s):
                tactics.append(m.group(1).upper())
    # Dedupe preserving order
    techniques = list(dict.fromkeys(techniques))
    tactics    = list(dict.fromkeys(tactics))
    return techniques, tactics


def _build_index() -> None:
    if not _PANTHER_ROOT.exists():
        _state["error"]  = f"panther-analysis dir not present at {_PANTHER_ROOT}"
        _state["loaded"] = True
        return

    rules:        List[Dict[str, Any]] = []
    by_tech:      Dict[str, List[Dict[str, Any]]] = {}
    by_logtype:   Dict[str, List[Dict[str, Any]]] = {}

    # Panther rules live in rules/ ; policies/ are static config posture,
    # not what RECON cares about.
    rules_root = _PANTHER_ROOT / "rules"
    if not rules_root.exists():
        rules_root = _PANTHER_ROOT  # tolerate stripped vendoring

    for path in rules_root.rglob("*.yml"):
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > 64_000:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        doc = _safe_yaml(text)
        if not isinstance(doc, dict):
            continue
        # Panther packs / data-models / templates also ship as .yml; we
        # only want the rule docs, which always carry an AnalysisType.
        atype = (doc.get("AnalysisType") or "").lower()
        if atype and atype not in ("rule", "scheduled_rule"):
            continue

        rule_id    = (doc.get("RuleID") or doc.get("PolicyID") or "").strip()
        display    = (doc.get("DisplayName") or rule_id).strip()
        severity   = (doc.get("Severity") or "").strip().lower()
        log_types  = doc.get("LogTypes") or []
        if not isinstance(log_types, list):
            log_types = [log_types] if isinstance(log_types, str) else []
        tags       = doc.get("Tags") or []
        techniques, tactics = _extract_mitre(doc.get("Reports") or {})
        description = (doc.get("Description") or "").strip()
        runbook    = (doc.get("Runbook") or "").strip()

        try:
            rel = path.relative_to(_PANTHER_ROOT).as_posix()
        except ValueError:
            rel = path.name

        meta = {
            "id":          rule_id,
            "title":       display[:200],
            "severity":    severity,
            "log_types":   [str(lt).strip() for lt in log_types][:6],
            "tags":        [str(t).strip() for t in tags][:8],
            "techniques":  techniques,
            "tactics":     tactics,
            "description": description[:300],
            "runbook":     runbook[:300],
            "path":        rel,
            "source":      "Panther Labs",
        }
        rules.append(meta)
        for t in techniques:
            by_tech.setdefault(t, []).append(meta)
        for lt in meta["log_types"]:
            by_logtype.setdefault(lt, []).append(meta)

    _state["rules"]        = rules
    _state["by_technique"] = by_tech
    _state["by_log_type"]  = by_logtype
    _state["loaded"]       = True
    _state["error"]        = None
    _log.info("panther-analysis loaded: %d rules | %d techniques | %d log types",
              len(rules), len(by_tech), len(by_logtype))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def match_by_techniques(technique_ids: Iterable[str],
                        max_results: int = 15) -> List[Dict[str, Any]]:
    """Return Panther rules whose MITRE-ATT&CK Reports overlap the
    supplied technique list. Ranked by overlap × severity."""
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
                key = meta.get("id") or meta.get("path") or meta["title"]
                overlap = len(set(meta.get("techniques") or []) & wanted)
                sev_rank = _SEV_RANK.get(meta.get("severity"), 0)
                prev = scored.get(key)
                if not prev or (overlap, sev_rank) > (prev[0], prev[1]):
                    scored[key] = (overlap, sev_rank, meta)

    ranked = sorted(scored.values(), key=lambda v: (-v[0], -v[1],
                                                    v[2]["title"].lower()))
    return [v[2] for v in ranked[:max_results]]


def match_by_log_type(log_type: str, max_results: int = 10) -> List[Dict[str, Any]]:
    _ensure_loaded()
    if not log_type:
        return []
    rows = (_state.get("by_log_type") or {}).get(log_type, [])
    return rows[:max_results]


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":     bool(_state["loaded"]),
        "rules":      len(_state.get("rules") or []),
        "techniques": len(_state.get("by_technique") or {}),
        "log_types":  len(_state.get("by_log_type") or {}),
        "error":      _state.get("error"),
    }


_SEV_RANK = {
    "info": 1, "informational": 1,
    "low": 2, "medium": 3, "high": 4, "critical": 5,
}
