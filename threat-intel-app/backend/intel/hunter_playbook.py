"""
OTRF ThreatHunter-Playbook loader.

Source: https://github.com/OTRF/ThreatHunter-Playbook (MIT). Hunt
documentation organised as Jupyter notebooks at
docs/notebooks/**/<technique>.ipynb. Each notebook has markdown cells
with: hypothesis, technical context, ATT&CK references, hunt query
implementations (KQL / EQL / SQL), and validation steps.

We strip the notebook JSON to a compact `{technique_id, hypothesis,
references, queries}` dict so the hypothesis-generator and
investigation prompts can pull in vetted hunt context as system-prompt
material.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.hunter_playbook")

_PB_ROOT = (Path(__file__).parent.parent.parent
            / "vendor" / "otrf-threathunter-playbook")

_TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
_HYPOTHESIS_RE = re.compile(
    r"##\s*hypothesis\s*\n+([\s\S]+?)(?=\n##|\Z)",
    re.IGNORECASE,
)
_OFFENSIVE_RE = re.compile(
    r"##\s*offensive\s+tradecraft\s*\n+([\s\S]+?)(?=\n##|\Z)",
    re.IGNORECASE,
)

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":         False,
    "playbooks":      [],
    "by_technique":   {},
    "error":          None,
}


def _extract_md_from_notebook(text: str) -> str:
    """Concatenate every markdown cell from a Jupyter notebook into
    a single string. We don't render — just grep for headings/queries."""
    try:
        nb = json.loads(text)
    except Exception:
        return ""
    cells = nb.get("cells") or []
    md_parts: List[str] = []
    for c in cells:
        if not isinstance(c, dict):
            continue
        if c.get("cell_type") != "markdown":
            continue
        src = c.get("source") or []
        if isinstance(src, list):
            md_parts.append("".join(src))
        elif isinstance(src, str):
            md_parts.append(src)
    return "\n\n".join(md_parts)


def _extract_section(md: str, regex: re.Pattern) -> str:
    m = regex.search(md)
    return (m.group(1).strip() if m else "")[:600]


def _build_index() -> None:
    if not _PB_ROOT.exists():
        _state["error"]  = f"otrf-threathunter-playbook dir not present at {_PB_ROOT}"
        _state["loaded"] = True
        return

    playbooks:   List[Dict[str, Any]] = []
    by_tech:     Dict[str, List[Dict[str, Any]]] = {}

    notebooks_root = _PB_ROOT / "docs" / "notebooks"
    if not notebooks_root.exists():
        notebooks_root = _PB_ROOT

    for path in notebooks_root.rglob("*.ipynb"):
        if not path.is_file() or path.stat().st_size > 1_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        md = _extract_md_from_notebook(text)
        if not md:
            continue
        techniques: List[str] = list({m.group(1).upper()
                                       for m in _TECHNIQUE_RE.finditer(md)})
        if not techniques:
            # Skip notebooks that don't reference a technique — these
            # are usually intro / scaffolding notebooks.
            continue

        title_line = next((line.strip() for line in md.splitlines()
                            if line.startswith("# ") and len(line) > 2), "")
        title = title_line.lstrip("# ").strip() or path.stem

        hypothesis = _extract_section(md, _HYPOTHESIS_RE)
        offensive  = _extract_section(md, _OFFENSIVE_RE)

        meta = {
            "title":       title[:200],
            "techniques":  techniques,
            "hypothesis":  hypothesis,
            "offensive":   offensive,
            "source":      "OTRF ThreatHunter-Playbook",
        }
        playbooks.append(meta)
        for t in techniques:
            by_tech.setdefault(t, []).append(meta)

    _state["playbooks"]    = playbooks
    _state["by_technique"] = by_tech
    _state["loaded"]       = True
    _state["error"]        = None
    _log.info("OTRF ThreatHunter-Playbook loaded: %d notebooks indexed",
              len(playbooks))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def match_by_techniques(technique_ids: Iterable[str],
                        max_results: int = 5) -> List[Dict[str, Any]]:
    _ensure_loaded()
    wanted = {t.upper().strip() for t in (technique_ids or [])
              if isinstance(t, str) and t.strip()}
    if not wanted:
        return []
    by_tech = _state.get("by_technique") or {}
    seen: Dict[str, Dict[str, Any]] = {}
    for t in wanted:
        keys = {t}
        if "." in t:
            keys.add(t.split(".", 1)[0])
        for k in keys:
            for meta in by_tech.get(k, []):
                key = meta.get("title")
                seen.setdefault(key, meta)
    return list(seen.values())[:max_results]


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":     bool(_state["loaded"]),
        "playbooks":  len(_state.get("playbooks") or []),
        "techniques": len(_state.get("by_technique") or {}),
        "error":      _state.get("error"),
    }
