"""
Google Chronicle detection-rules corpus loader.

Source: https://github.com/chronicle/detection-rules (Apache-2.0). YARA-L 2.0
rules contributed by Google's security teams + community. RECON's
response stage already *generates* YARA-L; this corpus gives it a
reference catalogue to cite from.

YARA-L 2.0 syntax is text-only (no formal binding), so we parse rules
with a small set of regex extractors instead of pulling in chronicle's
own Go parser. Each rule has a header block of `rule NAME {` with a
`meta`, `events`, `match`, `condition`, then optional `outcome`. The
`meta` block carries the descriptors we need (description, mitre,
severity, etc.).
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.chronicle_rules")

_CHRONICLE_ROOT = (Path(__file__).parent.parent.parent
                   / "vendor" / "chronicle-detection-rules")

_RULE_DECL_RE = re.compile(r"^\s*rule\s+([A-Za-z_][\w]*)\s*\{",
                            re.MULTILINE)
# meta lines look like:   description = "Detects ..."
_META_LINE_RE = re.compile(
    r"^\s*([A-Za-z_][\w]*)\s*=\s*(\"[^\"]*\"|`[^`]*`|'[^']*')",
    re.MULTILINE,
)
_TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
_TACTIC_RE    = re.compile(r"\b(TA\d{4})\b")

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":         False,
    "rules":          [],
    "by_technique":   {},
    "error":          None,
}


def _strip_quote(s: str) -> str:
    s = s.strip()
    if s.startswith(("'", '"', "`")) and s.endswith(("'", '"', "`")):
        return s[1:-1]
    return s


def _parse_rule_block(text: str, start: int) -> Dict[str, str]:
    """Pull the meta block following `rule NAME {` at offset start. We
    walk braces to find the matching closing brace, then regex out
    meta key/value pairs from inside."""
    depth = 0
    end   = -1
    for i in range(start, min(len(text), start + 12000)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end < 0:
        return {}
    block = text[start:end]
    meta: Dict[str, str] = {}
    for m in _META_LINE_RE.finditer(block):
        k = m.group(1).lower()
        v = _strip_quote(m.group(2))
        # Multiple lines with same key (e.g. multiple `reference =`) get
        # concatenated so we don't lose information.
        if k in meta:
            meta[k] = (meta[k] + " ; " + v)[:600]
        else:
            meta[k] = v[:600]
    return meta


def _build_index() -> None:
    if not _CHRONICLE_ROOT.exists():
        _state["error"]  = f"chronicle-detection-rules dir not present at {_CHRONICLE_ROOT}"
        _state["loaded"] = True
        return

    rules:    List[Dict[str, Any]] = []
    by_tech:  Dict[str, List[Dict[str, Any]]] = {}

    # YARA-L rule files end in .yaral; some templates use .yara-l.
    yaral_files = list(_CHRONICLE_ROOT.rglob("*.yaral"))
    yaral_files += list(_CHRONICLE_ROOT.rglob("*.yara-l"))

    for path in yaral_files:
        if not path.is_file() or path.stat().st_size > 128_000:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m in _RULE_DECL_RE.finditer(text):
            rule_name = m.group(1)
            # Brace-walk starts at the `{` (right after the match).
            brace_start = text.find("{", m.end() - 1)
            if brace_start < 0:
                continue
            meta = _parse_rule_block(text, brace_start)
            if not meta:
                continue
            description = meta.get("description") or meta.get("rule_name") or ""
            mitre_blob = " ".join(meta.get(k, "") for k in
                                  ("mitre_attack_tactic", "mitre_attack_technique",
                                   "mitre_attack_url", "tactic", "technique",
                                   "mitre", "tags"))
            techniques = list({m.group(1).upper()
                                for m in _TECHNIQUE_RE.finditer(mitre_blob)})
            tactics    = list({m.group(1).upper()
                                for m in _TACTIC_RE.finditer(mitre_blob)})
            severity   = (meta.get("severity") or
                          meta.get("priority") or "").strip().lower()
            entry = {
                "rule":         rule_name,
                "title":        meta.get("rule_name") or rule_name,
                "description":  description[:300],
                "severity":     severity,
                "techniques":   techniques,
                "tactics":      tactics,
                "reference":    (meta.get("reference") or "")[:300],
                "source":       "Google Chronicle (chronicle/detection-rules)",
            }
            rules.append(entry)
            for t in techniques:
                by_tech.setdefault(t, []).append(entry)

    _state["rules"]        = rules
    _state["by_technique"] = by_tech
    _state["loaded"]       = True
    _state["error"]        = None
    _log.info("chronicle-detection-rules loaded: %d rules | %d techniques",
              len(rules), len(by_tech))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


_SEV_RANK = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


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
                key = meta["rule"]
                overlap = len(set(meta.get("techniques") or []) & wanted)
                sev = _SEV_RANK.get(meta.get("severity"), 0)
                prev = scored.get(key)
                if not prev or (overlap, sev) > (prev[0], prev[1]):
                    scored[key] = (overlap, sev, meta)
    ranked = sorted(scored.values(), key=lambda v: (-v[0], -v[1],
                                                    v[2]["rule"].lower()))
    return [v[2] for v in ranked[:max_results]]


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":     bool(_state["loaded"]),
        "rules":      len(_state.get("rules") or []),
        "techniques": len(_state.get("by_technique") or {}),
        "error":      _state.get("error"),
    }
