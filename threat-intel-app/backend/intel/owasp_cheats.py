"""
OWASP Cheat Sheet Series loader.

Source: https://github.com/OWASP/CheatSheetSeries (CC-BY-4.0). ~90
defender-oriented cheat sheets covering Authentication, JWT, OAuth,
REST, Docker, Kubernetes, Logging, AppSec, etc. Each cheat sheet is a
markdown file at `cheatsheets/<Name>_Cheat_Sheet.md`.

This index gives the hypothesis-generator + analyst-summary prompts
a curated reference to cite when an alert touches a known security
domain. We extract the title, headings (defensive controls), and
short summary so it slots cleanly into LLM system-prompt context
without ingesting the full body.

The data is licensed CC-BY-4.0 (attribution only, no share-alike) so
inclusion in RECON's commercial portfolio is clean as long as we
attribute OWASP when surfacing content.
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.owasp_cheats")

_OWASP_ROOT_CANDIDATES = [
    Path(__file__).parent.parent.parent / "vendor" / "owasp-cheatsheets" / "cheatsheets",
    Path(__file__).parent.parent.parent / "vendor" / "owasp-cheatsheets",
    Path(__file__).parent.parent.parent / "vendor" / "CheatSheetSeries" / "cheatsheets",
]

_HEADING_RE = re.compile(r"^##\s+(.+?)\s*$", re.MULTILINE)
_TITLE_RE   = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)

# Topic-keyword routing — maps free-text alert keywords to cheat-sheet
# filename stems so the hypothesis-generator can pull the right ones
# in as prompt context.
_KEYWORD_TO_CHEAT = {
    "jwt":               ["JSON_Web_Token_for_Java"],
    "oauth":             ["OAuth2_Cheat_Sheet"],
    "csrf":              ["Cross-Site_Request_Forgery_Prevention"],
    "xss":               ["Cross_Site_Scripting_Prevention",
                          "DOM_based_XSS_Prevention"],
    "sql injection":     ["SQL_Injection_Prevention"],
    "sqli":              ["SQL_Injection_Prevention"],
    "command injection": ["OS_Command_Injection_Defense"],
    "rce":               ["OS_Command_Injection_Defense"],
    "lfi":               ["File_Upload"],
    "deserialization":   ["Deserialization"],
    "xxe":               ["XML_External_Entity_Prevention"],
    "ssrf":              ["Server_Side_Request_Forgery_Prevention"],
    "authentication":    ["Authentication"],
    "session":           ["Session_Management"],
    "password":          ["Password_Storage"],
    "logging":           ["Logging"],
    "rest":              ["REST_Security"],
    "graphql":           ["GraphQL"],
    "kubernetes":        ["Kubernetes_Security"],
    "docker":            ["Docker_Security"],
    "csp":               ["Content_Security_Policy"],
    "tls":               ["Transport_Layer_Protection"],
    "ldap":              ["LDAP_Injection_Prevention"],
}

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":      False,
    "cheats":      {},   # dict[slug, meta]
    "by_topic":    {},
    "error":       None,
}


def _find_root() -> Optional[Path]:
    for c in _OWASP_ROOT_CANDIDATES:
        if c.exists():
            return c
    return None


def _build_index() -> None:
    root = _find_root()
    if not root:
        _state["error"]  = ("OWASP cheatsheets dir not present at any of "
                            f"{[str(p) for p in _OWASP_ROOT_CANDIDATES]}")
        _state["loaded"] = True
        return

    cheats:   Dict[str, Dict[str, Any]] = {}
    by_topic: Dict[str, List[Dict[str, Any]]] = {}

    for path in root.rglob("*_Cheat_Sheet.md"):
        if not path.is_file() or path.stat().st_size > 128_000:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        m_title = _TITLE_RE.search(text)
        title = (m_title.group(1) if m_title else path.stem.replace("_", " ")).strip()
        headings = []
        for hm in _HEADING_RE.finditer(text):
            h = hm.group(1).strip()
            if h and h.lower() not in ("introduction", "references"):
                headings.append(h[:120])
            if len(headings) >= 12:
                break
        slug = path.stem  # e.g. "OAuth2_Cheat_Sheet"
        # First non-heading paragraph as a 1-line summary.
        summary = ""
        body = _TITLE_RE.sub("", text, count=1).strip()
        for chunk in body.split("\n\n", 4):
            chunk = chunk.strip()
            if chunk and not chunk.startswith("#"):
                summary = chunk[:320]
                break
        cheats[slug] = {
            "slug":      slug,
            "title":     title[:200],
            "headings":  headings,
            "summary":   summary,
            "source":    "OWASP Cheat Sheet Series (CC-BY-4.0)",
        }

    for kw, slugs in _KEYWORD_TO_CHEAT.items():
        for slug in slugs:
            meta = cheats.get(slug)
            if meta:
                by_topic.setdefault(kw, []).append(meta)

    _state["cheats"]   = cheats
    _state["by_topic"] = by_topic
    _state["loaded"]   = True
    _state["error"]    = None
    _log.info("OWASP Cheat Sheets loaded: %d sheets | %d topic keywords mapped",
              len(cheats), len(by_topic))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def lookup(slug: str) -> Optional[Dict[str, Any]]:
    _ensure_loaded()
    if not slug:
        return None
    return (_state.get("cheats") or {}).get(slug)


def sheets_for_keywords(text: str,
                        max_results: int = 4) -> List[Dict[str, Any]]:
    _ensure_loaded()
    if not isinstance(text, str) or not text:
        return []
    t = text.lower()
    seen: Dict[str, Dict[str, Any]] = {}
    by_topic = _state.get("by_topic") or {}
    for kw, sheets in by_topic.items():
        if kw in t:
            for s in sheets:
                seen.setdefault(s["slug"], s)
    return list(seen.values())[:max_results]


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":         bool(_state["loaded"]),
        "cheat_sheets":   len(_state.get("cheats") or {}),
        "topic_keywords": len(_state.get("by_topic") or {}),
        "error":          _state.get("error"),
    }
