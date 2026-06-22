"""
DataDog grimoire cloud-audit-log fixture loader.

Source: https://github.com/DataDog/grimoire (Apache-2.0). Companion to
Stratus Red Team — ships per-attack-technique fixtures of labelled
AWS CloudTrail and EKS audit-log samples that show what the technique
LOOKS LIKE in the data plane.

RECON has no cloud-log ground truth today; the KQL/SPL generation
prompts can leverage these fixtures as system-prompt exemplars when
the input is a cloud event. The module exposes a thin
`samples_for_technique(tactic, technique)` API; the actual prompt
injection happens in the response agent's KQL synthesis.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.cloud_fixtures")

_GRIMOIRE_ROOT = (Path(__file__).parent.parent.parent
                  / "vendor" / "datadog-grimoire")

# grimoire labels detonations with Stratus-RT names like
# "aws.persistence.iam-backdoor-user". Map a leading segment to the
# cloud provider so downstream callers can filter by aws|gcp|azure|k8s.
_PROVIDER_RE = re.compile(r"^(aws|gcp|azure|k8s)\.([a-z0-9_\-]+)\.([a-z0-9_\-]+)$",
                           re.IGNORECASE)

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":         False,
    "fixtures":       [],
    "by_provider":    {},
    "by_technique":   {},
    "error":          None,
}


def _safe_json(text: str) -> Optional[Any]:
    try:
        return json.loads(text)
    except Exception:
        return None


def _build_index() -> None:
    if not _GRIMOIRE_ROOT.exists():
        _state["error"]  = f"datadog-grimoire dir not present at {_GRIMOIRE_ROOT}"
        _state["loaded"] = True
        return

    fixtures:       List[Dict[str, Any]] = []
    by_provider:    Dict[str, List[Dict[str, Any]]] = {}
    by_technique:   Dict[str, List[Dict[str, Any]]] = {}

    # grimoire's detonators ship .json log-sample bundles. We walk every
    # *.json under the repo and pick out the ones whose path includes
    # 'detonators' (the real samples) — the rest are go fixtures that
    # don't carry CloudTrail records.
    for path in _GRIMOIRE_ROOT.rglob("*.json"):
        if not path.is_file() or path.stat().st_size > 200_000:
            continue
        try:
            rel = path.relative_to(_GRIMOIRE_ROOT).as_posix()
        except ValueError:
            rel = path.as_posix()
        if "detonator" not in rel.lower() and "ttp" not in rel.lower():
            continue
        try:
            doc = _safe_json(path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
        if not isinstance(doc, (dict, list)):
            continue

        # Stratus-style technique IDs are encoded in the file name or
        # the JSON `attack` field. Walk the file path components +
        # the JSON for matches.
        ttp_id = ""
        for part in path.parts:
            m = _PROVIDER_RE.match(part)
            if m:
                ttp_id = part
                break
        provider = ttp_id.split(".", 1)[0].lower() if ttp_id else ""
        if not ttp_id:
            ttp_id = path.stem

        # Capture a small slice of the log payload for prompt context.
        sample = doc if not isinstance(doc, list) else (doc[:2] if doc else [])
        sample_str = json.dumps(sample, separators=(",", ":"))[:1200]

        meta = {
            "technique_id":  ttp_id,
            "provider":      provider or "unknown",
            "path":          rel,
            "sample":        sample_str,
            "source":        "DataDog grimoire",
        }
        fixtures.append(meta)
        by_provider.setdefault(meta["provider"], []).append(meta)
        by_technique.setdefault(ttp_id, []).append(meta)

    _state["fixtures"]      = fixtures
    _state["by_provider"]   = by_provider
    _state["by_technique"]  = by_technique
    _state["loaded"]        = True
    _state["error"]         = None
    _log.info("datadog-grimoire loaded: %d fixtures | %d providers",
              len(fixtures), len(by_provider))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def samples_for_provider(provider: str,
                         max_results: int = 4) -> List[Dict[str, Any]]:
    _ensure_loaded()
    if not provider:
        return []
    rows = (_state.get("by_provider") or {}).get(provider.lower(), [])
    return rows[:max_results]


def samples_for_technique(ttp_id: str,
                          max_results: int = 3) -> List[Dict[str, Any]]:
    _ensure_loaded()
    if not ttp_id:
        return []
    rows = (_state.get("by_technique") or {}).get(ttp_id, [])
    return rows[:max_results]


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":      bool(_state["loaded"]),
        "fixtures":    len(_state.get("fixtures") or []),
        "providers":   list((_state.get("by_provider") or {}).keys()),
        "techniques":  len(_state.get("by_technique") or {}),
        "error":       _state.get("error"),
    }
