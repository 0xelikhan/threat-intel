"""
OWASP ModSecurity Core Rule Set (CRS) loader.

Source: https://github.com/coreruleset/coreruleset (Apache-2.0). The
canonical open WAF rule set covering SQLi, XSS, RCE, LFI, RFI, PHP
injection, Java injection, deserialisation, scanner detection, session
fixation, etc.

CRS rules use ModSec's `SecRule` syntax — a single line per rule, e.g.:

  SecRule REQUEST_COOKIES "@rx (?i:..." \
    "id:932100,phase:2,block,msg:'Remote Command Execution: Unix Command Injection',\
     tag:'attack-rce',tag:'paranoia-level/1',tag:'capec/1000/152/248/88'"

We parse the `id:`, `msg:`, `tag:` action fields with a small regex
extractor — no actual ModSec engine needed. The inverted index keys
by CRS rule-id and attack-class tag so investigation can cite "OWASP
CRS rule 932100 covers Unix command injection".
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.owasp_crs")

_CRS_ROOT = (Path(__file__).parent.parent.parent
             / "vendor" / "owasp-crs")

# ModSec SecRule action fields look like:  id:932100,phase:2,block,msg:'...',tag:'...'
_ID_RE   = re.compile(r"\bid:\s*(\d+)")
_MSG_RE  = re.compile(r"\bmsg:'([^']+)'")
_TAG_RE  = re.compile(r"\btag:'([^']+)'")
_SECRULE_LINE_RE = re.compile(r"^\s*SecRule\s", re.MULTILINE)

# Map common CRS attack-class tags → human label for the analyst report.
_ATTACK_CLASS_FROM_TAG = {
    "attack-rce":          "Remote Code Execution",
    "attack-sqli":         "SQL Injection",
    "attack-xss":          "Cross-Site Scripting",
    "attack-lfi":          "Local File Inclusion",
    "attack-rfi":          "Remote File Inclusion",
    "attack-protocol":     "HTTP Protocol Violation",
    "attack-fixation":     "Session Fixation",
    "attack-injection-php": "PHP Injection",
    "attack-injection-java": "Java Injection",
    "attack-injection-generic": "Generic Injection",
    "attack-disclosure":   "Information Disclosure",
    "attack-reputation-scanner": "Scanner Reputation",
    "attack-generic":      "Generic Attack",
}

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":            False,
    "rules":             [],
    "by_id":             {},
    "by_attack_class":   {},
    "error":             None,
}


def _classify(tags: List[str]) -> List[str]:
    out: List[str] = []
    for t in tags:
        if t in _ATTACK_CLASS_FROM_TAG:
            out.append(_ATTACK_CLASS_FROM_TAG[t])
    return out or ["Other"]


def _build_index() -> None:
    if not _CRS_ROOT.exists():
        _state["error"]  = f"owasp-crs dir not present at {_CRS_ROOT}"
        _state["loaded"] = True
        return

    rules:           List[Dict[str, Any]] = []
    by_id:           Dict[str, Dict[str, Any]] = {}
    by_attack_class: Dict[str, List[Dict[str, Any]]] = {}

    rules_root = _CRS_ROOT / "rules"
    if not rules_root.exists():
        rules_root = _CRS_ROOT

    for path in rules_root.rglob("*.conf"):
        if not path.is_file() or path.stat().st_size > 800_000:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        # ModSec SecRule lines often span continuation backslashes — we
        # parse by splitting on the SecRule keyword and collecting until
        # the next blank line.
        chunks = re.split(r"(?<=^|\n)SecRule\s", text)[1:]
        for chunk in chunks:
            head = chunk[:8000]  # cap per rule
            m_id  = _ID_RE.search(head)
            if not m_id:
                continue
            m_msg = _MSG_RE.search(head)
            tags  = [m.group(1) for m in _TAG_RE.finditer(head)]
            rule_id = m_id.group(1)
            msg     = (m_msg.group(1) if m_msg else "").strip()
            attack_classes = _classify(tags)
            meta = {
                "id":           rule_id,
                "msg":          msg[:300],
                "tags":         tags[:12],
                "attack_class": attack_classes,
                "source":       "OWASP CRS",
            }
            rules.append(meta)
            by_id[rule_id] = meta
            for ac in attack_classes:
                by_attack_class.setdefault(ac, []).append(meta)

    _state["rules"]            = rules
    _state["by_id"]            = by_id
    _state["by_attack_class"]  = by_attack_class
    _state["loaded"]           = True
    _state["error"]            = None
    _log.info("owasp-crs loaded: %d rules | %d attack classes",
              len(rules), len(by_attack_class))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def match_by_attack_class(attack_class: str,
                          max_results: int = 12) -> List[Dict[str, Any]]:
    _ensure_loaded()
    rows = (_state.get("by_attack_class") or {}).get(attack_class, [])
    return rows[:max_results]


def match_by_keywords(text: str, max_results: int = 8) -> List[Dict[str, Any]]:
    """Best-effort keyword routing — if the analyst's input mentions
    'sql injection' / 'xss' / 'rce' / 'lfi', return matching CRS rules.
    Cheap text-matching; not an exhaustive classifier."""
    _ensure_loaded()
    if not text:
        return []
    text_l = text.lower()
    out: List[Dict[str, Any]] = []
    keyword_to_class = {
        "sql injection":  "SQL Injection",
        "sqli":           "SQL Injection",
        "xss":            "Cross-Site Scripting",
        "cross-site":     "Cross-Site Scripting",
        "rce":            "Remote Code Execution",
        "command inject": "Remote Code Execution",
        "lfi":            "Local File Inclusion",
        "rfi":            "Remote File Inclusion",
        "deserial":       "Java Injection",
        "log4j":          "Java Injection",
        "scanner":        "Scanner Reputation",
    }
    seen: set = set()
    for kw, ac in keyword_to_class.items():
        if kw in text_l:
            for r in match_by_attack_class(ac, max_results=max_results):
                if r["id"] not in seen:
                    seen.add(r["id"])
                    out.append(r)
                    if len(out) >= max_results:
                        return out
    return out


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":         bool(_state["loaded"]),
        "rules":          len(_state.get("rules") or []),
        "attack_classes": list((_state.get("by_attack_class") or {}).keys()),
        "error":          _state.get("error"),
    }
