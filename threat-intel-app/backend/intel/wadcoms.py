"""
WADComs Windows-AD attack reference loader.

Source: https://github.com/WADComs/WADComs.github.io (MIT). A
Jekyll-rendered command corpus for Windows / Active Directory
offensive tradecraft. Each command is a YAML-frontmatter markdown
file at `_commands/<id>.md` with shape:

  ---
  name:        Kerberoasting via Rubeus
  description: Request RC4 service tickets for kerberoastable accounts
  category:    Active Directory
  os:          windows
  attack:      [credential-access, T1558.003]
  examples:
    - command: Rubeus.exe kerberoast /outfile:hashes.txt
      tools:   [Rubeus]
      privileges: domain user
  references:
    - ...
  ---

We index by ATT&CK technique + category + tool so the hypothesis-
generator can answer "for T1558.003 Kerberoasting, expect Rubeus +
Mimikatz invocations" with named-command grounding.

Complements PayloadsAllTheThings (web-attack) + LOLBAS (signed-binary
abuse) by covering AD-specific tradecraft.
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.wadcoms")

_WADCOMS_ROOT_CANDIDATES = [
    Path(__file__).parent.parent.parent / "vendor" / "wadcoms" / "_commands",
    Path(__file__).parent.parent.parent / "vendor" / "WADComs.github.io" / "_commands",
    Path(__file__).parent.parent.parent / "vendor" / "wadcoms",
]

_TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
_FM_BLOCK_RE  = re.compile(r"^---\s*\n([\s\S]+?)\n---\s*\n",
                            re.MULTILINE)

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":         False,
    "commands":       [],
    "by_technique":   {},
    "by_category":    {},
    "by_tool":        {},
    "error":          None,
}


def _safe_yaml(text: str) -> Optional[Dict[str, Any]]:
    try:
        import yaml
    except Exception:
        return None
    try:
        loaded = yaml.safe_load(text)
        if isinstance(loaded, dict):
            return loaded
    except Exception:
        return None
    return None


def _extract_techniques(meta: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for field in ("attack", "mitre", "mitre_attack", "tags"):
        v = meta.get(field)
        if isinstance(v, str):
            v = [v]
        if isinstance(v, list):
            for item in v:
                for m in _TECHNIQUE_RE.finditer(str(item)):
                    out.append(m.group(1).upper())
    return list(dict.fromkeys(out))


def _extract_tools(meta: Dict[str, Any]) -> List[str]:
    tools: List[str] = []
    examples = meta.get("examples") or []
    if isinstance(examples, list):
        for ex in examples:
            if not isinstance(ex, dict):
                continue
            t = ex.get("tools") or []
            if isinstance(t, str):
                t = [t]
            if isinstance(t, list):
                tools.extend(str(x).strip() for x in t if x)
    return list(dict.fromkeys(tools))[:8]


def _find_root() -> Optional[Path]:
    for c in _WADCOMS_ROOT_CANDIDATES:
        if c.exists():
            return c
    return None


def _build_index() -> None:
    root = _find_root()
    if not root:
        _state["error"]  = ("WADComs commands dir not present at any of "
                            f"{[str(p) for p in _WADCOMS_ROOT_CANDIDATES]}")
        _state["loaded"] = True
        return

    commands:     List[Dict[str, Any]] = []
    by_technique: Dict[str, List[Dict[str, Any]]] = {}
    by_category:  Dict[str, List[Dict[str, Any]]] = {}
    by_tool:      Dict[str, List[Dict[str, Any]]] = {}

    for path in root.rglob("*.md"):
        if not path.is_file() or path.stat().st_size > 64_000:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        m = _FM_BLOCK_RE.search(text)
        if not m:
            continue
        meta = _safe_yaml(m.group(1))
        if not isinstance(meta, dict):
            continue
        name = (meta.get("name") or "").strip()
        if not name:
            continue
        techniques = _extract_techniques(meta)
        tools      = _extract_tools(meta)
        category   = str(meta.get("category") or meta.get("group") or "").strip()
        entry = {
            "name":        name[:200],
            "description": (meta.get("description") or "")[:300],
            "category":    category[:80],
            "techniques":  techniques,
            "tools":       tools,
            "os":          str(meta.get("os") or "windows"),
            "source":      "WADComs",
        }
        commands.append(entry)
        for t in techniques:
            by_technique.setdefault(t, []).append(entry)
        if category:
            by_category.setdefault(category, []).append(entry)
        for tool in tools:
            by_tool.setdefault(tool.lower(), []).append(entry)

    _state["commands"]     = commands
    _state["by_technique"] = by_technique
    _state["by_category"]  = by_category
    _state["by_tool"]      = by_tool
    _state["loaded"]       = True
    _state["error"]        = None
    _log.info("WADComs loaded: %d commands | %d techniques | %d categories | %d tools",
              len(commands), len(by_technique),
              len(by_category), len(by_tool))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def match_by_techniques(technique_ids: Iterable[str],
                        max_results: int = 8) -> List[Dict[str, Any]]:
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
                seen.setdefault(meta["name"], meta)
    return list(seen.values())[:max_results]


def match_by_tool(tool: str, max_results: int = 6) -> List[Dict[str, Any]]:
    _ensure_loaded()
    if not tool:
        return []
    rows = (_state.get("by_tool") or {}).get(tool.lower().strip(), [])
    return rows[:max_results]


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":     bool(_state["loaded"]),
        "commands":   len(_state.get("commands") or []),
        "techniques": len(_state.get("by_technique") or {}),
        "categories": len(_state.get("by_category") or {}),
        "tools":      len(_state.get("by_tool") or {}),
        "error":      _state.get("error"),
    }
