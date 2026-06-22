"""
CTID Adversary Emulation Library loader.

Source: https://github.com/center-for-threat-informed-defense/adversary_emulation_library
(Apache-2.0). Per-actor folders (apt29/, fin6/, fin7/, carbanak/, sandworm/,
turla/, wizard_spider/, menu_pass/, ocean_lotus/, oilrig/, blind_eagle/)
each ship a YAML emulation plan with sequenced steps:

  emulation_plan_details:
    adversary_name: APT29
    attack_types:   [Phishing, Credential Access, ...]
  Procedures:
    - procedure: Initial Access via Spearphishing
      procedure_step: 1
      mitre_attack:
        technique_id: T1566.001
      ...

This module gives the investigation agent a way to answer "we
attributed this to APT29 — what does APT29 typically do next?" with a
deterministic, vetted answer instead of asking the LLM to invent one.
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.emulation_plans")

_EMU_ROOT = (Path(__file__).parent.parent.parent
             / "vendor" / "ctid-emulation-library")

_TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":      False,
    "actors":      {},  # dict[normalised actor name, plan dict]
    "by_alias":    {},  # alternate names → canonical actor key
    "error":       None,
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


def _norm_actor(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (name or "").lower()).strip("_")


def _extract_step(step: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(step, dict):
        return None
    procedure = (step.get("procedure") or "").strip()
    if not procedure:
        return None
    attack = step.get("mitre_attack") or {}
    technique_id = ""
    if isinstance(attack, dict):
        tid = attack.get("technique_id") or ""
        m = _TECHNIQUE_RE.search(str(tid))
        if m:
            technique_id = m.group(1).upper()
    return {
        "step":          int(step.get("procedure_step") or 0) or None,
        "procedure":     procedure[:240],
        "technique_id":  technique_id,
        "description":   (step.get("procedure_description") or "")[:400],
        "command":       (step.get("commands") or [{}])[0].get("command", "")[:240]
                         if isinstance(step.get("commands"), list)
                         else "",
    }


def _build_index() -> None:
    if not _EMU_ROOT.exists():
        _state["error"]  = f"ctid-emulation-library dir not present at {_EMU_ROOT}"
        _state["loaded"] = True
        return

    actors:   Dict[str, Dict[str, Any]] = {}
    aliases:  Dict[str, str] = {}

    for actor_dir in _EMU_ROOT.iterdir():
        if not actor_dir.is_dir() or actor_dir.name.startswith("."):
            continue
        # The canonical layout is Emulation_Plan/yaml_files_in_progress/ —
        # but the actor folder may also ship .yaml at the top level. Be
        # tolerant of layout drift.
        plan_files = list(actor_dir.rglob("*.yaml"))
        if not plan_files:
            continue
        canonical = _norm_actor(actor_dir.name)
        adversary_name = actor_dir.name
        all_steps: List[Dict[str, Any]] = []
        all_techs: List[str] = []
        attack_types: List[str] = []
        aliases_for_actor: List[str] = []

        for path in plan_files:
            if not path.is_file() or path.stat().st_size > 256_000:
                continue
            try:
                doc = _safe_yaml(path.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                continue
            if not isinstance(doc, dict):
                continue
            details = doc.get("emulation_plan_details") or {}
            if isinstance(details, dict):
                an = details.get("adversary_name")
                if isinstance(an, str) and an.strip():
                    adversary_name = an.strip()
                ats = details.get("attack_types") or []
                if isinstance(ats, list):
                    attack_types.extend(str(a) for a in ats)
                ad_aliases = details.get("aliases") or details.get("adversary_aliases") or []
                if isinstance(ad_aliases, list):
                    aliases_for_actor.extend(str(a) for a in ad_aliases)
            proc = doc.get("Procedures") or doc.get("procedures") or []
            if not isinstance(proc, list):
                continue
            for s in proc:
                step = _extract_step(s)
                if step:
                    all_steps.append(step)
                    if step["technique_id"]:
                        all_techs.append(step["technique_id"])

        if not all_steps:
            continue

        # Sort by step number when available so downstream consumers
        # receive the procedure chain in execution order.
        all_steps.sort(key=lambda s: (s["step"] is None, s["step"] or 0))

        actor_meta = {
            "actor":         adversary_name,
            "slug":          canonical,
            "attack_types":  list(dict.fromkeys(attack_types))[:8],
            "techniques":    list(dict.fromkeys(all_techs))[:30],
            "steps":         all_steps[:80],
            "source":        "CTID Adversary Emulation Library",
        }
        actors[canonical] = actor_meta
        for a in aliases_for_actor:
            aliases[_norm_actor(a)] = canonical
        aliases[_norm_actor(adversary_name)] = canonical

    _state["actors"]    = actors
    _state["by_alias"]  = aliases
    _state["loaded"]    = True
    _state["error"]     = None
    _log.info("ctid-emulation-library loaded: %d actor plans", len(actors))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def lookup_actor(name: str) -> Optional[Dict[str, Any]]:
    """Look up an emulation plan by adversary name or alias. Returns the
    full plan (actor, attack types, technique list, step chain) or None."""
    _ensure_loaded()
    if not name:
        return None
    canonical = _state.get("by_alias", {}).get(_norm_actor(name)) \
                or _norm_actor(name)
    return (_state.get("actors") or {}).get(canonical)


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":  bool(_state["loaded"]),
        "actors":  len(_state.get("actors") or {}),
        "aliases": len(_state.get("by_alias") or {}),
        "error":   _state.get("error"),
    }
