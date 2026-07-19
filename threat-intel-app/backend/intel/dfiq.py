"""
DFIQ — Google Digital Forensics Investigative Questions.
https://github.com/google/dfiq (Apache-2.0)

DFIQ organises forensic knowledge as:
  Scenario  (broad situation, "compromised endpoint")
  Facet     (narrower topic, "USB device usage")
  Question  ("What USB devices were attached to a computer?")
  Approach  (concrete method to answer the question)

RECON's investigation node currently generates probing_questions
100% from the LLM, which produces plausible questions but not
grounded in curated forensic practice. DFIQ questions are hand-
authored by DF/IR practitioners at Google + community — they carry
signal a generalist LLM won't reliably reproduce.

Design:
  - One-time fetch at lifespan warm of all ~90 question YAMLs from
    the google/dfiq main branch. Tiny (~55 KB total).
  - Parse into a flat list of {id, name, facet_ids, keywords}.
  - Match against the alert's raw text + alert_type keywords, score
    by term overlap, return the top-N most relevant questions.
  - Inject into the investigation prompt as reference material so the
    AI's probing_questions builds on curated foundations.

Refresh weekly — DFIQ evolves slowly.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
import urllib.request
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.intel.dfiq")

_REPO       = "google/dfiq"
_TREE_URL   = f"https://api.github.com/repos/{_REPO}/git/trees/main?recursive=1"
_RAW_BASE   = f"https://raw.githubusercontent.com/{_REPO}/main/"
_TTL_SECONDS = 7 * 86400

_STOPWORDS = frozenset({
    "the","a","an","of","to","in","on","and","or","for","with","from",
    "by","at","is","are","was","were","be","been","being","have","has",
    "had","do","does","did","this","that","these","those","it","its",
    "as","if","then","else","not","no","yes","any","all","some",
    "what","which","when","where","why","how","who","whom","whose",
    "computer","system","device","file","data","log","logs",
})

_lock = threading.RLock()  # reentrant: _ensure_loaded holds it, then
                            # _refresh_sync re-acquires — a plain Lock
                            # deadlocks; RLock is a drop-in fix.
_state: Dict[str, Any] = {
    "loaded_at":  0.0,
    "questions":  [],   # [{id, name, facet_ids, keywords}, ...]
    "error":      None,
}

# Alert-type → seed keywords. Boosts DFIQ questions relevant to the
# alert's category even when the raw text is thin (e.g. an SSO event
# with no forensic prose).
_TYPE_KEYWORDS: Dict[str, List[str]] = {
    "phishing":    ["email", "attachment", "credential", "url", "click",
                    "browser", "download", "signin", "authentication",
                    "mfa", "session", "cookie", "spoof"],
    "ransomware":  ["encryption", "shadow", "copy", "vssadmin", "extension",
                    "ransom", "note", "delete", "backup", "recovery"],
    "c2":          ["network", "connection", "outbound", "beacon", "tls",
                    "certificate", "domain", "proxy", "tunnel"],
    "malware":     ["execute", "process", "child", "parent", "dll",
                    "load", "inject", "persistence", "autorun",
                    "scheduled", "task"],
    "exploitation": ["cve", "vulnerable", "patch", "update", "kernel",
                     "privilege", "escalation"],
    "cloud":       ["s3", "bucket", "iam", "role", "assume", "principal",
                    "gcp", "aws", "azure", "kms", "credential", "token",
                    "service", "account"],
    "insider":     ["user", "activity", "usb", "external", "storage",
                    "print", "clipboard", "copy", "upload"],
    "unknown":     ["network", "user", "process", "file", "authentication"],
}


def _tokenise(text: str) -> set:
    """Lowercase, split on non-alphanum, drop stopwords + <3 char terms."""
    if not text:
        return set()
    toks = re.findall(r"[a-z0-9]{3,}", text.lower())
    return {t for t in toks if t not in _STOPWORDS}


def _fetch_questions() -> List[Dict[str, Any]]:
    """One-time enumerate + fetch of all question YAMLs."""
    from intel._http import fetch_json, fetch_bytes
    tree = fetch_json(_TREE_URL, timeout=30)
    paths = [t["path"] for t in tree.get("tree", [])
             if t.get("type") == "blob"
             and t["path"].startswith("dfiq/data/questions/")
             and t["path"].endswith(".yaml")]
    _log.info("DFIQ tree lists %d question YAMLs", len(paths))

    # YAML is already in the venv (sigma-related). Import lazily so a
    # broken PyYAML install doesn't take down this module at import time.
    import yaml   # type: ignore

    def _fetch_one(path: str) -> Optional[Dict[str, Any]]:
        try:
            doc = yaml.safe_load(fetch_bytes(_RAW_BASE + path, timeout=15))
            if not isinstance(doc, dict) or doc.get("type") != "question":
                return None
            name = (doc.get("name") or "").strip()
            qid  = doc.get("id") or ""
            if not name or not qid:
                return None
            return {
                "id":         qid,
                "name":       name,
                "facet_ids":  doc.get("parent_ids") or [],
                "keywords":   _tokenise(name),
            }
        except Exception as e:
            _log.debug("DFIQ fetch %s failed: %s", path, e)
            return None

    # 90 GitHub raw fetches in serial takes 30-60s; a small worker pool
    # cuts it to ~5-8s without hammering the API.
    from concurrent.futures import ThreadPoolExecutor
    questions: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for res in pool.map(_fetch_one, paths):
            if res:
                questions.append(res)
    return questions


def _refresh_sync() -> None:
    try:
        qs = _fetch_questions()
    except Exception as e:
        with _lock:
            _state["error"] = str(e)[:200]
            _state["loaded_at"] = time.time()
        _log.warning("DFIQ refresh failed: %s", e)
        return
    with _lock:
        _state["questions"] = qs
        _state["loaded_at"] = time.time()
        _state["error"]     = None
    _log.info("DFIQ loaded: %d questions", len(qs))


def _ensure_loaded() -> None:
    if _state["loaded_at"] and (time.time() - _state["loaded_at"]) < _TTL_SECONDS:
        return
    with _lock:
        if _state["loaded_at"] and (time.time() - _state["loaded_at"]) < _TTL_SECONDS:
            return
        try:
            _refresh_sync()
        except Exception as e:
            _state["error"] = str(e)[:200]
            _state["loaded_at"] = time.time()


def get_questions(alert_type: str = "", raw_text: str = "",
                   max_results: int = 5) -> List[Dict[str, Any]]:
    """Return the top-N DFIQ questions most relevant to this alert.

    Scoring: overlap-count of alert-derived query terms against each
    question's tokenised name. Alert-type seed keywords are added to
    the query so a category-only ask still returns useful matches."""
    _ensure_loaded()
    # Snapshot the question list under lock so a concurrent refresh
    # can't swap `qs` out from under our iteration.
    with _lock:
        qs = list(_state.get("questions") or [])
    if not qs:
        return []
    query = _tokenise(raw_text)
    for kw in _TYPE_KEYWORDS.get((alert_type or "").lower().strip(), []):
        query.add(kw.lower())
    if not query:
        return []
    scored: List[tuple] = []
    for q in qs:
        overlap = len(query & q["keywords"])
        if overlap:
            scored.append((overlap, q))
    scored.sort(key=lambda t: (-t[0], t[1]["id"]))
    return [{
        "id":      q["id"],
        "name":    q["name"],
        "score":   score,
        "facets":  q["facet_ids"],
    } for score, q in scored[:max_results]]


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    with _lock:
        return {
            "loaded_at":     _state.get("loaded_at"),
            "question_count": len(_state.get("questions") or []),
            "error":         _state.get("error"),
        }
