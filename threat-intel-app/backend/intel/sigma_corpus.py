"""
SigmaHQ rule corpus loader + inverted index.

The repo ships 2,600+ Sigma rules at `backend/intel/sigma/` (cloud, network,
windows, etc., mirroring SigmaHQ/sigma's repository layout). The rules are
DRL 1.1 licensed — fine to *consume* (we match against them), but any UI
that surfaces full rule bodies must attribute SigmaHQ.

This module loads every .yml rule lazily on first call and builds two
inverted indexes:

  by_technique  — { "T1059.001": [rule_meta, ...], ... }
  by_logsource  — { ("process_creation","windows"): [rule_meta, ...], ... }

Each rule_meta is a small dict (title, id, description, tags, level,
logsource, file_path) — no full rule body — so 2,600 rules fit in ~3MB
of RAM. The inverted-index pattern mirrors intel/mitre_data.py and
intel/misp_galaxies.py so callers (investigation.py + the new
match_sigma_rules skill) get the same lookup ergonomics.

We never recompile the rules; matching is purely metadata-based. That
keeps load time under a second on first call and avoids the YAML-parse
cost incurred by sigma-cli (which RECON already uses for *validating*
its OWN generated rules in agents/response.validate_sigma_rule).
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

_log = logging.getLogger("recon.intel.sigma_corpus")

_CORPUS_ROOT = Path(__file__).parent / "sigma"
_CACHE_JSON  = _CORPUS_ROOT.parent / "sigma_corpus.cache.json"
_ATTACK_TAG_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)

# Single load lock — first caller into the module triggers the parse;
# subsequent threads block until the index is ready. Matches the lazy-
# load pattern used by intel/yara_scanner.py::_ruleset.
_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":       False,
    "rules":        [],     # list[dict] — all rule metadata
    "by_technique": {},     # dict[str, list[dict]]
    "by_logsource": {},     # dict[(str,str), list[dict]]
    "error":        None,
}


def _corpus_mtime() -> float:
    """Newest .yml mtime under _CORPUS_ROOT (0 if none). Cache is stale
    when this exceeds the JSON file's mtime."""
    try:
        return max((p.stat().st_mtime for p in _CORPUS_ROOT.rglob("*.yml")),
                    default=0.0)
    except Exception:
        return 0.0


def _load_from_cache() -> bool:
    """Populate _state from the JSON side-file when it exists AND is at
    least as new as the newest source .yml. Returns True on hit."""
    try:
        if not _CACHE_JSON.exists():
            return False
        if _CACHE_JSON.stat().st_mtime < _corpus_mtime():
            return False
        data = json.loads(_CACHE_JSON.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "rules" not in data:
            return False
        _state["rules"]        = data.get("rules") or []
        # JSON keys are strings; by_logsource keys were tuples in memory.
        # Re-tuple on load so match_by_logsource lookups still work.
        _state["by_technique"] = data.get("by_technique") or {}
        _state["by_logsource"] = {
            tuple(k.split("\x1f", 1)): v
            for k, v in (data.get("by_logsource") or {}).items()
        }
        _state["loaded"]       = True
        _state["error"]        = None
        _state["parsed"]       = data.get("parsed", len(_state["rules"]))
        _state["skipped"]      = data.get("skipped", 0)
        return True
    except Exception as e:
        _log.debug("sigma corpus cache load failed: %s", e)
        return False


def _write_cache() -> None:
    """Serialise the current _state to _CACHE_JSON. Tuples get flattened
    to a delimiter-joined string so JSON can round-trip them."""
    try:
        by_log_serial = {
            "\x1f".join(k) if isinstance(k, tuple) else str(k): v
            for k, v in (_state.get("by_logsource") or {}).items()
        }
        payload = {
            "rules":        _state.get("rules") or [],
            "by_technique": _state.get("by_technique") or {},
            "by_logsource": by_log_serial,
            "parsed":       _state.get("parsed", 0),
            "skipped":      _state.get("skipped", 0),
        }
        _CACHE_JSON.write_text(json.dumps(payload, separators=(",", ":")),
                                 encoding="utf-8")
    except Exception as e:
        _log.debug("sigma corpus cache write failed: %s", e)


def _safe_yaml_load(text: str) -> Optional[Dict[str, Any]]:
    """SigmaHQ rules occasionally have multi-doc YAML (one base rule + per-
    target overrides). For the inverted index we just need the first doc —
    that's where every meta field we care about lives."""
    try:
        import yaml  # ships as transitive dep of mitreattack-python / sigma-cli
    except Exception:
        return None
    try:
        for doc in yaml.safe_load_all(text):
            if isinstance(doc, dict):
                return doc
    except Exception:
        return None
    return None


def _extract_techniques(tags: Iterable[Any]) -> List[str]:
    """Pull T#### / T####.### technique IDs out of the rule's `tags:` list."""
    out: List[str] = []
    for raw in tags or []:
        if not isinstance(raw, str):
            continue
        m = _ATTACK_TAG_RE.search(raw)
        if m:
            out.append(m.group(1).upper())
    return out


def _build_index() -> None:
    """Walk _CORPUS_ROOT, parse every .yml, populate the indexes.

    Perf: 2,677 rules through pyyaml costs ~50 s per process cold-start.
    We cache the built indexes to a JSON side-file on first build;
    subsequent starts read it in ~150 ms. Cache is invalidated when the
    newest .yml in _CORPUS_ROOT is newer than the JSON file.
    """
    if not _CORPUS_ROOT.exists():
        _state["error"] = f"sigma corpus dir not found: {_CORPUS_ROOT}"
        _state["loaded"] = True
        return

    _t0 = time.perf_counter()
    if _load_from_cache():
        _log.info("Sigma corpus loaded from JSON cache: %d rules (%.2fs)",
                  len(_state.get("rules") or []), time.perf_counter() - _t0)
        return

    rules: List[Dict[str, Any]] = []
    by_tech: Dict[str, List[Dict[str, Any]]] = {}
    by_log:  Dict[Tuple[str, str], List[Dict[str, Any]]] = {}

    parsed = 0
    skipped = 0

    for path in _CORPUS_ROOT.rglob("*.yml"):
        if not path.is_file():
            continue
        # Cap individual file size (real SigmaHQ rules are tiny — anything
        # huge is almost certainly a non-rule YAML we accidentally walked).
        try:
            if path.stat().st_size > 64_000:
                skipped += 1
                continue
        except OSError:
            skipped += 1
            continue
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                doc = _safe_yaml_load(f.read())
        except Exception:
            skipped += 1
            continue
        if not isinstance(doc, dict):
            skipped += 1
            continue

        title = (doc.get("title") or "").strip()
        if not title:
            skipped += 1
            continue
        rule_id = (doc.get("id") or "").strip()
        desc    = (doc.get("description") or "").strip()
        level   = (doc.get("level") or "").strip().lower()
        author  = (doc.get("author") or "").strip()
        tags    = doc.get("tags") or []
        techniques = _extract_techniques(tags)

        ls = doc.get("logsource") or {}
        category = (ls.get("category") or "").strip().lower()
        product  = (ls.get("product")  or "").strip().lower()

        try:
            rel = path.relative_to(_CORPUS_ROOT).as_posix()
        except ValueError:
            rel = path.as_posix()

        meta = {
            "title":       title,
            "id":          rule_id,
            "description": desc[:300],
            "level":       level,
            "author":      author[:120],
            "techniques":  techniques,
            "category":    category,
            "product":     product,
            "path":        rel,
        }
        rules.append(meta)
        for t in techniques:
            by_tech.setdefault(t, []).append(meta)
        key = (category, product)
        by_log.setdefault(key, []).append(meta)
        parsed += 1

    _state["rules"]        = rules
    _state["by_technique"] = by_tech
    _state["by_logsource"] = by_log
    _state["loaded"]       = True
    _state["error"]        = None
    _state["parsed"]       = parsed
    _state["skipped"]      = skipped
    _write_cache()
    _log.info("Sigma corpus loaded: %d rules parsed, %d skipped (%.2fs; cache written)",
              parsed, skipped, time.perf_counter() - _t0)


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":       bool(_state["loaded"]),
        "rule_count":   len(_state.get("rules") or []),
        "skipped":      _state.get("skipped", 0),
        "techniques":   len(_state.get("by_technique") or {}),
        "logsources":   len(_state.get("by_logsource") or {}),
        "error":        _state.get("error"),
    }


def match_by_techniques(technique_ids: Iterable[str],
                        max_results: int = 25) -> List[Dict[str, Any]]:
    """Return Sigma rules whose `attack.*` tags overlap the supplied
    technique list. Ranked by overlap count (more matches → higher rank)
    then by rule level (critical > high > medium > low > informational)."""
    _ensure_loaded()
    if not technique_ids:
        return []
    wanted = {t.upper().strip() for t in technique_ids
              if isinstance(t, str) and t.strip()}
    if not wanted:
        return []
    candidate_scores: Dict[str, Tuple[int, int, Dict[str, Any]]] = {}
    by_tech = _state.get("by_technique") or {}
    for t in wanted:
        # Sub-techniques like T1059.001 should also match base T1059 rules.
        keys = {t}
        if "." in t:
            keys.add(t.split(".", 1)[0])
        for k in keys:
            for meta in (by_tech.get(k) or []):
                key = meta.get("id") or meta.get("path") or meta["title"]
                overlap = len(set(meta.get("techniques") or []) & wanted)
                level_rank = _LEVEL_RANK.get(meta.get("level"), 0)
                # Keep the highest-overlap, then highest-level entry per rule.
                prev = candidate_scores.get(key)
                if not prev or (overlap, level_rank) > (prev[0], prev[1]):
                    candidate_scores[key] = (overlap, level_rank, meta)

    ranked = sorted(
        candidate_scores.values(),
        key=lambda v: (-v[0], -v[1], v[2]["title"].lower()),
    )
    return [v[2] for v in ranked[:max_results]]


_LEVEL_RANK = {
    "informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5,
}
