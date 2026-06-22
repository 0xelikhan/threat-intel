"""
GitHub CodeQL query catalog loader.

Source: https://github.com/github/codeql (MIT). The full repo is ~1GB,
so the operator fetches with sparse-checkout limited to
`<lang>/ql/src/Security/**` (see scripts/fetch_codeql_queries.sh).

CodeQL queries are .ql files with a comment header that we parse for
metadata:

  /**
   * @name SQL injection
   * @description Building a SQL query from user input may allow ...
   * @kind path-problem
   * @problem.severity error
   * @security-severity 8.8
   * @precision high
   * @id py/sql-injection
   * @tags security
   *       external/cwe/cwe-089
   */

We bundle a fallback dataset of well-known queries so the module
returns useful data even when the operator hasn't populated the
vendor dir.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.codeql_queries")

_CODEQL_ROOT = (Path(__file__).parent.parent.parent
                / "vendor" / "codeql")

_HEADER_BLOCK_RE = re.compile(r"/\*\*([\s\S]*?)\*/")
_FIELD_RE = re.compile(r"^\s*\*\s*@(\w[\w\.]*)\s+(.+?)\s*$", re.MULTILINE)
_CWE_RE   = re.compile(r"\bcwe-(\d{1,4})\b", re.IGNORECASE)

# Built-in fallback so the module is useful without the heavy vendored
# clone. Highest-precision security queries per language; CWE-keyed.
_FALLBACK_QUERIES: List[Dict[str, Any]] = [
    {"id": "py/sql-injection",       "language": "python",     "name": "SQL injection",
     "cwes": ["CWE-89"],   "precision": "high", "severity": "error"},
    {"id": "py/command-line-injection", "language": "python",  "name": "Command-line injection",
     "cwes": ["CWE-78"],   "precision": "high", "severity": "error"},
    {"id": "py/code-injection",      "language": "python",     "name": "Code injection",
     "cwes": ["CWE-94"],   "precision": "high", "severity": "error"},
    {"id": "py/path-injection",      "language": "python",     "name": "Path injection",
     "cwes": ["CWE-22", "CWE-23"], "precision": "high", "severity": "error"},
    {"id": "py/unsafe-deserialization", "language": "python",  "name": "Unsafe deserialization",
     "cwes": ["CWE-502"],  "precision": "high", "severity": "error"},
    {"id": "py/ssrf",                "language": "python",     "name": "Server-side request forgery",
     "cwes": ["CWE-918"],  "precision": "high", "severity": "error"},
    {"id": "py/xxe",                 "language": "python",     "name": "XML external entity expansion",
     "cwes": ["CWE-611"],  "precision": "high", "severity": "error"},
    {"id": "js/sql-injection",       "language": "javascript", "name": "SQL injection",
     "cwes": ["CWE-89"],   "precision": "high", "severity": "error"},
    {"id": "js/xss",                 "language": "javascript", "name": "Cross-site scripting",
     "cwes": ["CWE-79"],   "precision": "high", "severity": "error"},
    {"id": "js/prototype-pollution", "language": "javascript", "name": "Prototype pollution",
     "cwes": ["CWE-1321"], "precision": "high", "severity": "error"},
    {"id": "js/code-injection",      "language": "javascript", "name": "Code injection",
     "cwes": ["CWE-94", "CWE-95"], "precision": "high", "severity": "error"},
    {"id": "java/sql-injection",     "language": "java",       "name": "Query built from user-controlled sources",
     "cwes": ["CWE-89"],   "precision": "high", "severity": "error"},
    {"id": "java/xxe",               "language": "java",       "name": "XML external entity",
     "cwes": ["CWE-611"],  "precision": "high", "severity": "error"},
    {"id": "java/deserialization",   "language": "java",       "name": "Unsafe deserialization",
     "cwes": ["CWE-502"],  "precision": "high", "severity": "error"},
    {"id": "java/log-injection",     "language": "java",       "name": "Log injection",
     "cwes": ["CWE-117"],  "precision": "medium", "severity": "warning"},
    {"id": "cpp/buffer-overflow",    "language": "cpp",        "name": "Buffer overflow",
     "cwes": ["CWE-120", "CWE-787"], "precision": "high", "severity": "error"},
    {"id": "cpp/use-after-free",     "language": "cpp",        "name": "Use after free",
     "cwes": ["CWE-416"],  "precision": "high", "severity": "error"},
    {"id": "go/sql-injection",       "language": "go",         "name": "SQL injection",
     "cwes": ["CWE-89"],   "precision": "high", "severity": "error"},
    {"id": "go/command-injection",   "language": "go",         "name": "Command injection",
     "cwes": ["CWE-78"],   "precision": "high", "severity": "error"},
    {"id": "ruby/sql-injection",     "language": "ruby",       "name": "SQL injection",
     "cwes": ["CWE-89"],   "precision": "high", "severity": "error"},
    {"id": "csharp/sql-injection",   "language": "csharp",     "name": "SQL query built from user-controlled sources",
     "cwes": ["CWE-89"],   "precision": "high", "severity": "error"},
]

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":     False,
    "queries":    [],
    "by_cwe":     {},      # dict[str(CWE-89), list[query]]
    "by_language": {},
    "source":     "fallback",
    "error":      None,
}


def _parse_header(block: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"tags": []}
    for m in _FIELD_RE.finditer(block):
        k = m.group(1).lower()
        v = m.group(2).strip()
        if k == "tags":
            out["tags"].append(v)
        else:
            out[k] = v
    # Continuation lines under @tags are picked up by inspecting the
    # block for `* external/cwe/cwe-XYZ` pattern lines after the field.
    out.setdefault("name", out.get("name", ""))
    return out


def _ingest_ql(path: Path,
               queries: List[Dict[str, Any]],
               by_cwe:  Dict[str, List[Dict[str, Any]]],
               by_lang: Dict[str, List[Dict[str, Any]]]) -> None:
    try:
        if path.stat().st_size > 96_000:
            return
        text = path.read_text(encoding="utf-8", errors="ignore")[:24_000]
    except OSError:
        return
    m = _HEADER_BLOCK_RE.search(text)
    if not m:
        return
    fields = _parse_header(m.group(1))
    name = fields.get("name", "").strip()
    qid  = fields.get("id", "").strip()
    if not name or not qid:
        return
    cwes: List[str] = []
    for blob in fields.get("tags", []):
        for cm in _CWE_RE.finditer(blob):
            cwes.append(f"CWE-{cm.group(1)}")
    # Also scrape the raw header for any unrecognised @tags rows.
    for cm in _CWE_RE.finditer(m.group(1)):
        cwes.append(f"CWE-{cm.group(1)}")
    cwes = list(dict.fromkeys(cwes))

    lang = ""
    try:
        rel = path.relative_to(_CODEQL_ROOT)
        # First path component is the language: python/ql/src/Security/...
        if rel.parts:
            lang = rel.parts[0]
    except ValueError:
        pass

    meta = {
        "id":          qid[:120],
        "name":        name[:200],
        "language":    lang,
        "cwes":        cwes,
        "precision":   fields.get("precision", ""),
        "severity":    fields.get("problem.severity") or fields.get("severity") or "",
        "kind":        fields.get("kind", ""),
        "description": fields.get("description", "")[:300],
        "source":      "GitHub CodeQL",
    }
    queries.append(meta)
    for c in cwes:
        by_cwe.setdefault(c, []).append(meta)
    if lang:
        by_lang.setdefault(lang, []).append(meta)


def _build_index() -> None:
    if _CODEQL_ROOT.exists():
        queries: List[Dict[str, Any]] = []
        by_cwe:  Dict[str, List[Dict[str, Any]]] = {}
        by_lang: Dict[str, List[Dict[str, Any]]] = {}
        for path in _CODEQL_ROOT.rglob("*.ql"):
            if "ql/src/Security" not in path.as_posix() and "/Security/" not in path.as_posix():
                continue
            _ingest_ql(path, queries, by_cwe, by_lang)
        if queries:
            _state["queries"]     = queries
            _state["by_cwe"]      = by_cwe
            _state["by_language"] = by_lang
            _state["source"]      = "vendored"
            _state["loaded"]      = True
            _state["error"]       = None
            _log.info("CodeQL queries loaded from vendor/: %d queries", len(queries))
            return

    # Fallback to the built-in subset.
    queries = list(_FALLBACK_QUERIES)
    by_cwe:  Dict[str, List[Dict[str, Any]]] = {}
    by_lang: Dict[str, List[Dict[str, Any]]] = {}
    for q in queries:
        for c in q.get("cwes") or []:
            by_cwe.setdefault(c, []).append(q)
        lang = q.get("language") or ""
        if lang:
            by_lang.setdefault(lang, []).append(q)
    _state["queries"]     = queries
    _state["by_cwe"]      = by_cwe
    _state["by_language"] = by_lang
    _state["source"]      = "fallback"
    _state["loaded"]      = True
    _state["error"]       = None


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def lookup_cwe(cwe: str, max_results: int = 6) -> List[Dict[str, Any]]:
    """Given a CWE id (with or without 'CWE-' prefix), return matching
    CodeQL query metadata."""
    _ensure_loaded()
    if not cwe:
        return []
    key = cwe.upper().strip()
    if not key.startswith("CWE-"):
        key = f"CWE-{key.lstrip('CWE').lstrip('-')}"
    rows = (_state.get("by_cwe") or {}).get(key, [])
    return rows[:max_results]


def queries_for_language(language: str, max_results: int = 20) -> List[Dict[str, Any]]:
    _ensure_loaded()
    if not language:
        return []
    rows = (_state.get("by_language") or {}).get(language.lower(), [])
    return rows[:max_results]


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":     bool(_state["loaded"]),
        "queries":    len(_state.get("queries") or []),
        "cwes":       len(_state.get("by_cwe") or {}),
        "languages":  list((_state.get("by_language") or {}).keys()),
        "source":     _state.get("source"),
        "error":      _state.get("error"),
    }
