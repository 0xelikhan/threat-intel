"""
OASIS CACAO 2.0 playbook output adapter.

Source: https://docs.oasis-open.org/cacao/security-playbooks/v2.0/
(OASIS standard). CACAO ("Collaborative Automated Course of Action
Operations") is the JSON-schema standard for sharing incident-response
playbooks across SOAR platforms (Splunk SOAR, Tines, Torq, etc.).

This adapter converts RECON's response stage output (recommended_actions,
mitre_techniques, threat_actor, IOCs) into a CACAO 2.0 playbook JSON
that SOAR analysts can ingest and execute.

The CACAO schema:
  - playbook       — top-level container with type, name, description
  - workflow       — step graph (start_step, end_step, actions in between)
  - playbook_types — incident-response / detection / investigation
  - workflow_step  — single action with command, target, on_completion

For RECON's reactive triage workflow we emit:
  - type:           "playbook"
  - playbook_types: ["investigation","mitigation"]
  - workflow_start: the first recommended action
  - workflow:       chain of action steps, each referencing the MITRE
                    technique it counters

Output is a pure serializer — no IO, no LLM.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


_CACAO_SPEC_VERSION = "cacao-2.0"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _step_id() -> str:
    return f"action--{uuid.uuid4()}"


def _action_step(name: str, description: str,
                 technique_id: str = "",
                 on_completion_step: Optional[str] = None) -> Dict[str, Any]:
    step = {
        "type":               "action",
        "name":               name[:200],
        "description":        description[:600],
        "step_extensions":    {},
    }
    if technique_id:
        step["external_references"] = [{
            "source_name": "mitre-attack",
            "external_id":  technique_id,
            "url":          f"https://attack.mitre.org/techniques/"
                            f"{technique_id.replace('.', '/')}/",
        }]
    if on_completion_step:
        step["on_completion"] = on_completion_step
    return step


def to_cacao(response_summary: Dict[str, Any],
             investigation_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Convert a RECON response_summary + investigation_result dict into a
    CACAO 2.0 playbook. The response_summary's recommended_actions list
    becomes the workflow steps; threat_actor / verdict / IOCs become
    playbook metadata."""
    inv = investigation_result or {}
    now = _now_iso()

    verdict   = (response_summary or {}).get("threat_level") or inv.get("verdict") or "UNKNOWN"
    actor     = ""
    raw_actor = inv.get("threat_actor")
    if isinstance(raw_actor, dict):
        actor = raw_actor.get("name") or raw_actor.get("group") or ""
    elif isinstance(raw_actor, str):
        actor = raw_actor

    summary  = (response_summary or {}).get("summary") or ""
    actions  = (response_summary or {}).get("recommended_actions") or []
    if not isinstance(actions, list):
        actions = []

    techniques = inv.get("mitre_techniques") or []
    if not isinstance(techniques, list):
        techniques = []

    # Build the workflow step graph. Each recommended_action becomes one
    # CACAO action step; we chain them via on_completion pointers so a
    # SOAR engine can execute them sequentially.
    step_ids: List[str] = []
    workflow: Dict[str, Dict[str, Any]] = {}
    for idx, raw in enumerate(actions[:20]):
        if isinstance(raw, dict):
            name        = raw.get("title") or raw.get("name") or f"Action {idx + 1}"
            description = raw.get("description") or raw.get("text") or ""
            tid         = (raw.get("technique") or "").strip()
        else:
            name = f"Action {idx + 1}"
            description = str(raw)
            tid = ""
        sid = _step_id()
        step_ids.append(sid)
        workflow[sid] = _action_step(name, description, tid)

    # Wire on_completion chain — each step points at the next.
    for i, sid in enumerate(step_ids):
        nxt = step_ids[i + 1] if i + 1 < len(step_ids) else None
        if nxt:
            workflow[sid]["on_completion"] = nxt

    # Standard CACAO start + end markers.
    start_id = f"start--{uuid.uuid4()}"
    end_id   = f"end--{uuid.uuid4()}"
    workflow[start_id] = {"type": "start", "name": "start",
                           "on_completion": step_ids[0] if step_ids else end_id}
    workflow[end_id]   = {"type": "end",   "name": "end"}
    if step_ids:
        workflow[step_ids[-1]]["on_completion"] = end_id

    # MITRE references at the playbook level — surfaces every technique
    # the investigation flagged so SOAR engines can route by tactic.
    ext_refs: List[Dict[str, str]] = []
    for t in techniques[:12]:
        if not isinstance(t, str):
            continue
        tid = t.split(" ", 1)[0].strip()
        if tid.upper().startswith("T"):
            ext_refs.append({
                "source_name": "mitre-attack",
                "external_id":  tid,
                "url":          f"https://attack.mitre.org/techniques/"
                                f"{tid.replace('.', '/')}/",
            })

    playbook = {
        "type":              "playbook",
        "spec_version":      _CACAO_SPEC_VERSION,
        "id":                f"playbook--{uuid.uuid4()}",
        "name":              (f"RECON IR Playbook — {verdict}"
                              + (f" — {actor}" if actor else ""))[:240],
        "description":       (summary or
                              "Auto-generated RECON incident-response playbook.")[:1000],
        "playbook_types":    ["investigation", "mitigation"]
                             if verdict in ("MALICIOUS", "SUSPICIOUS")
                             else ["investigation"],
        "created_by":        "identity--00000000-0000-4000-8000-000000000000",
        "created":           now,
        "modified":          now,
        "valid_from":        now,
        "labels":            [verdict.lower()]
                              + ([actor.lower()] if actor else [])[:6],
        "external_references": ext_refs,
        "workflow_start":    start_id,
        "workflow":          workflow,
        "workflow_exception": end_id,
    }
    return playbook
