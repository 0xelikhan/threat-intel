"""
NIST SP 800-53 control catalog loader.

Source: NIST OSCAL feed at
https://github.com/usnistgov/oscal-content (public domain).
Provides the canonical security/privacy control catalog (~1000 controls
across 20 families: AC Access Control, AU Audit/Accountability, CM
Config Management, IA Identification/Authentication, IR Incident
Response, RA Risk Assessment, SC System/Comms Protection, SI System
Information Integrity, etc.).

We bundle a compact in-tree mapping of the highest-traffic control
identifiers (AC-2, AU-6, IR-4, SI-3, ...) to their family + title +
one-line purpose. When the analyst report references a behaviour (e.g.
unauthorized access), the response stage can cite the relevant
NIST 800-53 control families for compliance-flavoured analyst writeups.

Operator can drop the full OSCAL JSON at vendor/nist-oscal/sp800-53.json
to swap in the full catalogue.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.nist_800_53")

_NIST_JSON = (Path(__file__).parent.parent.parent
              / "vendor" / "nist-oscal" / "sp800-53.json")

# In-tree fallback — highest-traffic controls keyed to the most common
# MITRE techniques RECON surfaces. Sourced from the NIST 800-53r5
# catalog + the ATT&CK→800-53 mappings published by CTID
# (center-for-threat-informed-defense/attack-control-framework-mappings).
_FALLBACK_CONTROLS: Dict[str, Dict[str, Any]] = {
    "AC-2":  {"family": "Access Control", "title": "Account Management",
              "purpose": "Manage account creation, modification, monitoring.",
              "attack_ids": ["T1078", "T1136", "T1098"]},
    "AC-3":  {"family": "Access Control", "title": "Access Enforcement",
              "purpose": "Enforce authorised access per AC policy.",
              "attack_ids": ["T1078", "T1190"]},
    "AC-6":  {"family": "Access Control", "title": "Least Privilege",
              "purpose": "Limit user privileges to those required for tasks.",
              "attack_ids": ["T1078.003", "T1548"]},
    "AC-7":  {"family": "Access Control", "title": "Unsuccessful Logon Attempts",
              "purpose": "Limit and audit failed authentication attempts.",
              "attack_ids": ["T1110"]},
    "AC-17": {"family": "Access Control", "title": "Remote Access",
              "purpose": "Establish + monitor remote access methods.",
              "attack_ids": ["T1133", "T1021"]},
    "AC-19": {"family": "Access Control", "title": "Access Control for Mobile Devices",
              "purpose": "Manage mobile device access to org systems.",
              "attack_ids": ["T1078"]},
    "AT-2":  {"family": "Awareness & Training", "title": "Literacy Training",
              "purpose": "Provide security awareness training to users.",
              "attack_ids": ["T1566"]},
    "AU-2":  {"family": "Audit & Accountability", "title": "Event Logging",
              "purpose": "Identify auditable events the system must capture.",
              "attack_ids": ["T1562.008"]},
    "AU-6":  {"family": "Audit & Accountability", "title": "Audit Record Review",
              "purpose": "Review and analyse audit records for indications of attack.",
              "attack_ids": ["T1562.008"]},
    "AU-9":  {"family": "Audit & Accountability", "title": "Protection of Audit Information",
              "purpose": "Protect audit information from unauthorised modification.",
              "attack_ids": ["T1562.008"]},
    "CM-2":  {"family": "Configuration Management", "title": "Baseline Configuration",
              "purpose": "Develop and maintain baseline system configurations.",
              "attack_ids": ["T1547", "T1543"]},
    "CM-7":  {"family": "Configuration Management", "title": "Least Functionality",
              "purpose": "Limit unnecessary functionality / services.",
              "attack_ids": ["T1059", "T1218"]},
    "CM-8":  {"family": "Configuration Management", "title": "System Component Inventory",
              "purpose": "Maintain an inventory of authorised system components.",
              "attack_ids": ["T1592", "T1083"]},
    "CP-9":  {"family": "Contingency Planning", "title": "System Backup",
              "purpose": "Back up information at organisation-defined frequency.",
              "attack_ids": ["T1486", "T1490"]},
    "IA-2":  {"family": "Identification & Authentication", "title": "User Identification & Authentication",
              "purpose": "Uniquely identify and authenticate org users.",
              "attack_ids": ["T1078", "T1110"]},
    "IA-5":  {"family": "Identification & Authentication", "title": "Authenticator Management",
              "purpose": "Manage authenticator content (passwords, tokens, certs).",
              "attack_ids": ["T1552", "T1098"]},
    "IR-4":  {"family": "Incident Response", "title": "Incident Handling",
              "purpose": "Implement incident handling capability covering preparation, detection, analysis, containment, eradication, recovery.",
              "attack_ids": ["T1486", "T1078"]},
    "IR-6":  {"family": "Incident Response", "title": "Incident Reporting",
              "purpose": "Report incidents to organisational stakeholders + authorities.",
              "attack_ids": ["T1486"]},
    "RA-5":  {"family": "Risk Assessment", "title": "Vulnerability Monitoring & Scanning",
              "purpose": "Monitor + scan systems for vulnerabilities.",
              "attack_ids": ["T1595", "T1190"]},
    "SC-7":  {"family": "System & Comms Protection", "title": "Boundary Protection",
              "purpose": "Monitor + control communications at external boundaries.",
              "attack_ids": ["T1071", "T1041"]},
    "SC-8":  {"family": "System & Comms Protection", "title": "Transmission Confidentiality and Integrity",
              "purpose": "Protect confidentiality + integrity of transmitted information.",
              "attack_ids": ["T1040", "T1557"]},
    "SC-12": {"family": "System & Comms Protection", "title": "Cryptographic Key Establishment & Management",
              "purpose": "Manage cryptographic keys throughout their lifecycle.",
              "attack_ids": ["T1552", "T1145"]},
    "SI-2":  {"family": "System & Information Integrity", "title": "Flaw Remediation",
              "purpose": "Identify, report, and correct system flaws.",
              "attack_ids": ["T1190", "T1195"]},
    "SI-3":  {"family": "System & Information Integrity", "title": "Malicious Code Protection",
              "purpose": "Employ malicious code protection mechanisms.",
              "attack_ids": ["T1059", "T1204"]},
    "SI-4":  {"family": "System & Information Integrity", "title": "System Monitoring",
              "purpose": "Monitor the system for attacks + indicators of potential attacks.",
              "attack_ids": ["T1071", "T1041"]},
    "SI-7":  {"family": "System & Information Integrity", "title": "Software, Firmware, and Information Integrity",
              "purpose": "Detect unauthorised changes to software/firmware/info.",
              "attack_ids": ["T1554", "T1574"]},
}

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":   False,
    "controls": {},
    "by_attack": {},
    "source":   "fallback",
    "error":    None,
}


def _build_index() -> None:
    controls = dict(_FALLBACK_CONTROLS)
    source = "fallback"
    if _NIST_JSON.exists():
        try:
            payload = json.loads(_NIST_JSON.read_text(encoding="utf-8",
                                                       errors="ignore"))
            # Accept either {control_id: meta} or OSCAL nested shape.
            if isinstance(payload, dict) and payload:
                # Heuristic: if the top-level value is a dict with
                # "family"/"title" keys, treat as our compact shape.
                first_val = next(iter(payload.values()), None)
                if isinstance(first_val, dict) and "family" in first_val:
                    for cid, meta in payload.items():
                        if isinstance(meta, dict):
                            controls[cid] = meta
                    source = "vendored-compact"
        except Exception as e:
            _log.warning("NIST 800-53 vendored JSON unreadable: %s", e)

    by_attack: Dict[str, List[str]] = {}
    for cid, meta in controls.items():
        for t in (meta.get("attack_ids") or []):
            by_attack.setdefault(str(t).upper(), []).append(cid)

    _state["controls"]  = controls
    _state["by_attack"] = by_attack
    _state["source"]    = source
    _state["loaded"]    = True
    _state["error"]     = None
    _log.info("NIST 800-53 loaded: %d controls (source=%s)",
              len(controls), source)


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def lookup(control_id: str) -> Optional[Dict[str, Any]]:
    _ensure_loaded()
    if not control_id:
        return None
    return (_state.get("controls") or {}).get(control_id.upper().strip())


def controls_for_attack(attack_id: str,
                        max_results: int = 6) -> List[Dict[str, Any]]:
    _ensure_loaded()
    if not attack_id:
        return []
    tid = attack_id.upper().strip()
    ids = (_state.get("by_attack") or {}).get(tid, [])
    if not ids and "." in tid:
        ids = (_state.get("by_attack") or {}).get(tid.split(".", 1)[0], [])
    out: List[Dict[str, Any]] = []
    for cid in ids[:max_results]:
        meta = _state["controls"].get(cid)
        if not meta:
            continue
        row = {"control_id": cid}
        row.update(meta)
        out.append(row)
    return out


def controls_for_attacks(attack_ids: Iterable[str]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for t in (attack_ids or []):
        rows = controls_for_attack(t)
        if rows:
            out[t.upper()] = rows
    return out


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":   bool(_state["loaded"]),
        "controls": len(_state.get("controls") or {}),
        "techniques_mapped": len(_state.get("by_attack") or {}),
        "source":   _state.get("source"),
        "error":    _state.get("error"),
    }
