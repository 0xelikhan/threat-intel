"""
Attack Flow (STIX 2.1 extension) serializer.

Adapted from the Center for Threat-Informed Defense's Attack Flow project
(https://github.com/center-for-threat-informed-defense/attack-flow,
Apache-2.0). Attack Flow extends STIX 2.1 with three new SDOs that capture
the *sequence* of attacker techniques in an incident, not just the set:

  * attack-flow      — container, scope=incident/campaign/threat-actor
  * attack-action    — a single technique execution, with effect_refs that
                       link to the next action(s)
  * attack-asset     — what was acted upon (workstation, mailbox, account)

The existing `agents/response.py::_build_stix` already emits standard
attack-pattern objects from the investigation's MITRE list. This module
adds the Attack Flow overlay so the bundle can be opened directly in the
CTID Attack Flow Builder (https://center-for-threat-informed-defense.
github.io/attack-flow/builder/) and visualised as a sequenced graph.

The extension-definition UUID below is THE canonical one published by
CTID — every Attack Flow consumer recognises it. Do not regenerate it.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# CTID-canonical extension UUIDs (do not change).
_ATTACK_FLOW_EXT_ID  = "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4"
_ATTACK_FLOW_CREATOR = "identity--fb9c968a-745b-4ade-9b25-c324172197f4"

# Spec version of Attack Flow we're emitting. Bumped if/when we adopt a
# newer release of the extension.
_AF_SPEC_VERSION = "2.0.3"


# Map of MITRE tactic ID (TA####) → kill-chain phase name as required by
# attack-action SDOs. Lifted from the Mitre ATT&CK matrix; falls back to
# "unknown" when the technique's tactic can't be resolved (which is fine —
# attack-action's `tactic_ref` is optional).
_KILLCHAIN_PHASES = {
    "TA0001": "initial-access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege-escalation",
    "TA0005": "defense-evasion",
    "TA0006": "credential-access",
    "TA0007": "discovery",
    "TA0008": "lateral-movement",
    "TA0009": "collection",
    "TA0010": "exfiltration",
    "TA0011": "command-and-control",
    "TA0040": "impact",
    "TA0042": "resource-development",
    "TA0043": "reconnaissance",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ext_block() -> Dict[str, Any]:
    """The `extensions` block every Attack Flow SDO must carry so STIX
    parsers know to treat it as a new SDO type. Required by the spec."""
    return {_ATTACK_FLOW_EXT_ID: {"extension_type": "new-sdo"}}


def _extract_tid(label: str) -> Optional[str]:
    """Pull a MITRE technique ID out of 'T1059.001 - PowerShell' or just
    'T1059.001'. Returns None when no T-prefix is present."""
    if not isinstance(label, str):
        return None
    m = re.match(r"^\s*(T\d{4}(?:\.\d{3})?)\b", label)
    return m.group(1) if m else None


def _extract_name(label: str) -> Optional[str]:
    """Pull the human name out of 'T1059.001 - PowerShell'. Returns None
    when the label has no separator."""
    if not isinstance(label, str) or " - " not in label:
        return None
    return label.split(" - ", 1)[1].strip() or None


def build_attack_flow_objects(
    identity_id: str,
    technique_labels: List[str],
    attack_pattern_index: Dict[str, str],
    investigation: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Return a list of STIX objects implementing an Attack Flow overlay
    on top of the supplied techniques.

    Args:
        identity_id:           the bundle's identity SDO id ("identity--…").
                               Each attack-flow/action carries this as
                               created_by_ref so the bundle's provenance is
                               consistent.
        technique_labels:      ordered list of "Txxxx - Name" strings, as
                               produced by `agents/investigation.py`.
        attack_pattern_index:  map of technique_id → existing attack-pattern
                               SDO id, so attack-actions reference the same
                               attack-pattern objects already in the bundle
                               (no duplicate techniques in the bundle).
        investigation:         the investigation dict — used to surface
                               threat-actor name + verdict in the attack-flow
                               container's description.
    """
    if not technique_labels:
        return []

    now = _now_iso()
    objects: List[Dict[str, Any]] = []

    # 1) The extension-definition. Consumers reject unknown extension IDs,
    # so we declare it once per bundle. CTID's builder recognises this UUID.
    objects.append({
        "type":           "extension-definition",
        "id":             _ATTACK_FLOW_EXT_ID,
        "spec_version":   "2.1",
        "created":        now,
        "modified":       now,
        "name":           "Attack Flow",
        "description":    "Extends STIX 2.1 with SDOs for representing"
                          " sequenced attacker techniques (Attack Flow"
                          " by the Center for Threat-Informed Defense).",
        "created_by_ref": _ATTACK_FLOW_CREATOR,
        "schema":         "https://center-for-threat-informed-defense.github.io"
                          "/attack-flow/stix/attack-flow-schema-2.0.0.json",
        "version":        _AF_SPEC_VERSION,
        "extension_types": ["new-sdo"],
    })

    # 2) Build attack-action objects, one per technique, chained via
    # effect_refs so the next action becomes the effect of the previous one.
    # This gives the CTID Builder a linear sequence to render — analysts
    # who know the order was actually a branch can rewire it interactively.
    action_ids: List[str] = []
    actions: List[Dict[str, Any]] = []

    for idx, label in enumerate(technique_labels):
        tid = _extract_tid(label)
        if not tid:
            continue
        action_id = f"attack-action--{uuid.uuid4()}"
        action_ids.append(action_id)
        ap_id = attack_pattern_index.get(tid)  # link to the existing attack-pattern
        action: Dict[str, Any] = {
            "type":           "attack-action",
            "id":             action_id,
            "spec_version":   "2.1",
            "extensions":     _ext_block(),
            "created":        now,
            "modified":       now,
            "created_by_ref": identity_id,
            "name":           _extract_name(label) or tid,
            "technique_id":   tid,
            "description":    f"Technique observed in this incident: {label}",
        }
        if ap_id:
            action["technique_ref"] = ap_id
        actions.append(action)

    # Wire effect_refs (each action -> next action) to create the sequence.
    for i, action in enumerate(actions):
        if i + 1 < len(actions):
            action["effect_refs"] = [actions[i + 1]["id"]]

    objects.extend(actions)

    # 3) The attack-flow container. start_refs points at the first action
    # so the visualiser knows where the sequence begins.
    inv = investigation or {}
    actor   = (inv.get("threat_actor") or inv.get("actor") or "").strip()
    verdict = (inv.get("verdict") or inv.get("threat_level") or "").strip()
    flow_desc_bits: List[str] = []
    if verdict:
        flow_desc_bits.append(f"Verdict: {verdict}.")
    if actor:
        flow_desc_bits.append(f"Attributed actor: {actor}.")
    flow_desc_bits.append(
        "Sequence inferred from MITRE techniques surfaced during RECON's"
        " investigation stage. Open this bundle in the CTID Attack Flow"
        " Builder to refine the graph."
    )

    objects.insert(1, {  # right after the extension-definition
        "type":           "attack-flow",
        "id":             f"attack-flow--{uuid.uuid4()}",
        "spec_version":   "2.1",
        "extensions":     _ext_block(),
        "created":        now,
        "modified":       now,
        "created_by_ref": identity_id,
        "name":           "RECON-derived attack flow",
        "description":    " ".join(flow_desc_bits),
        "scope":          "incident",
        "start_refs":     action_ids[:1],
    })

    return objects
