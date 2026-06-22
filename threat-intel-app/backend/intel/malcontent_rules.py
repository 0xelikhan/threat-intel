"""
Chainguard malcontent capability-bucket loader.

The repo (https://github.com/chainguard-dev/malcontent, Apache-2.0)
ships ~14k YARA rules organised by *behavioural capability* — anti-
behavior, c2, credential, evasion, exec, exfil, persist, privesc, etc.
That taxonomy is orthogonal to capa's rule namespaces and to family-
named YARA corpora like Florian Roth's: a single rule maps to one of
~24 capability buckets, and the bucket tells the analyst WHAT the
sample does in plain English.

yara_scanner.py already includes malcontent in RULE_SOURCES so the
file scanner picks up its rules at scan time. This module adds a
*structured* view: given a scan's matched rule list, group hits by
capability bucket so the analyst report can render

  "Capabilities: 3 exec, 2 c2, 1 anti-behavior, 1 persist"

instead of just a flat rule-match table.
"""

from __future__ import annotations

import logging
import re
import threading
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.intel.malcontent")

_MALCONTENT_ROOT = (Path(__file__).parent.parent.parent
                    / "vendor" / "malcontent" / "rules")

# Capability bucket → MITRE ATT&CK tactic. Mapping derived from
# malcontent's own taxonomy doc; "stage" buckets are mapped to the
# closest tactic so RECON's existing MITRE coverage display can render
# them consistently. Buckets without a tactic stay as plain capability.
_BUCKET_TO_TACTIC: Dict[str, str] = {
    "anti-behavior":   "TA0005",  # Defense Evasion
    "anti-debug":      "TA0005",
    "anti-vm":         "TA0005",
    "anti-sandbox":    "TA0005",
    "anti-static":     "TA0005",
    "c2":              "TA0011",  # Command and Control
    "collect":         "TA0009",  # Collection
    "credential":      "TA0006",  # Credential Access
    "destruct":        "TA0040",  # Impact
    "discovery":       "TA0007",  # Discovery
    "evasion":         "TA0005",
    "exec":            "TA0002",  # Execution
    "exfil":           "TA0010",  # Exfiltration
    "exploit":         "TA0004",  # Privilege Escalation / Initial Access (best guess)
    "fingerprint":     "TA0007",
    "impact":          "TA0040",
    "lateral":         "TA0008",  # Lateral Movement
    "net":             "TA0011",
    "obfuscation":     "TA0005",
    "persist":         "TA0003",  # Persistence
    "privesc":         "TA0004",
    "stealth":         "TA0005",
    "exec/installer":  "TA0002",
}

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":            False,
    "rule_to_bucket":    {},   # dict[rule_name, bucket]
    "rules_by_bucket":   {},   # dict[bucket, list[rule_name]]
    "total_rules":       0,
    "error":             None,
}


def _bucket_from_path(path: Path) -> Optional[str]:
    """Pull the capability bucket out of the rule's path. malcontent's
    layout puts each bucket at the first directory below `rules/`."""
    try:
        rel = path.relative_to(_MALCONTENT_ROOT)
    except ValueError:
        return None
    parts = rel.parts
    return parts[0].lower() if parts else None


# YARA rule name regex — must match `rule NAME [: tags] {` even when
# preceded by `private` / `global` keywords. The captured group is the
# bare rule identifier so we can build the inverted index.
_RULE_DECL_RE = re.compile(
    r"^\s*(?:private\s+|global\s+){0,2}rule\s+([A-Za-z_][\w]*)\b",
    re.MULTILINE,
)


def _build_index() -> None:
    if not _MALCONTENT_ROOT.exists():
        _state["error"]  = f"malcontent dir not present at {_MALCONTENT_ROOT}"
        _state["loaded"] = True
        return

    rule_to_bucket: Dict[str, str] = {}
    rules_by_bucket: Dict[str, List[str]] = {}
    total = 0

    for path in _MALCONTENT_ROOT.rglob("*.y*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in (".yar", ".yara"):
            continue
        bucket = _bucket_from_path(path)
        if not bucket:
            continue
        try:
            if path.stat().st_size > 256_000:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m in _RULE_DECL_RE.finditer(text):
            name = m.group(1)
            if not name:
                continue
            # First-bucket-wins for cross-folder names (rare).
            if name not in rule_to_bucket:
                rule_to_bucket[name]  = bucket
                rules_by_bucket.setdefault(bucket, []).append(name)
                total += 1

    _state["rule_to_bucket"]  = rule_to_bucket
    _state["rules_by_bucket"] = rules_by_bucket
    _state["total_rules"]     = total
    _state["loaded"]          = True
    _state["error"]           = None
    _log.info("malcontent index loaded: %d rules across %d buckets",
              total, len(rules_by_bucket))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def classify(rule_names: List[str]) -> Dict[str, Any]:
    """Given a list of YARA rule names (e.g. from yara_scanner.scan_bytes),
    group them by capability bucket. Returns a structured summary
    suitable for direct rendering in the analyst report."""
    _ensure_loaded()
    by_bucket: Dict[str, List[str]] = {}
    unknown:   List[str] = []
    tactics: Counter = Counter()
    rb_index = _state.get("rule_to_bucket") or {}
    for name in rule_names or []:
        if not isinstance(name, str):
            continue
        bucket = rb_index.get(name)
        if bucket:
            by_bucket.setdefault(bucket, []).append(name)
            tactic = _BUCKET_TO_TACTIC.get(bucket)
            if tactic:
                tactics[tactic] += 1
        else:
            unknown.append(name)
    summary = {
        "by_bucket":  {b: sorted(v) for b, v in by_bucket.items()},
        "bucket_counts": {b: len(v) for b, v in by_bucket.items()},
        "tactics":    dict(tactics),
        "unmatched":  unknown[:50],
        "total_matched": sum(len(v) for v in by_bucket.values()),
    }
    return summary


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":     bool(_state["loaded"]),
        "rules":      _state.get("total_rules", 0),
        "buckets":    len(_state.get("rules_by_bucket") or {}),
        "error":      _state.get("error"),
    }
