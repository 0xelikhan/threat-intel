"""
CISA Cybersecurity Performance Goals (CPG) loader.

Source: https://www.cisa.gov/cpg (US gov, public domain). CISA published
the Cybersecurity Performance Goals as a baseline-and-essential tiered
control framework — a federal-government distillation of NIST CSF +
ATT&CK + critical infrastructure-sector experience.

Each CPG control is one of:
  - Baseline    — minimum recommended cybersecurity practice
  - Essential   — additional priority practice for critical-infra orgs
  - Enhanced    — stretch goals for mature organisations

Each is tagged with NIST CSF categories + (where applicable) ATT&CK
mitigation IDs. This module bundles a compact in-tree map of the
highest-traffic CPGs keyed to the ATT&CK techniques RECON commonly
sees. Pairs with intel/nist_800_53.py (which is broader) — CPG adds
the priority-tier signal NIST 800-53 doesn't carry.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.cisa_cpg")

_CPG_JSON = (Path(__file__).parent.parent.parent
             / "vendor" / "cisa-cpg" / "cpg.json")

# In-tree compact CPG → MITRE map. Each CPG has a stable identifier
# (e.g. "1.A" = Hardware/Software inventory; "2.A" = Changing default
# passwords; "2.F" = MFA enforcement). The tier ("Baseline" /
# "Essential" / "Enhanced") drives the analyst-priority surface.
_FALLBACK_CPGS: Dict[str, Dict[str, Any]] = {
    "1.A": {"name": "Asset Inventory",
            "tier": "Baseline",
            "purpose": "Maintain an inventory of all org IT/OT hardware and software.",
            "attack_ids": ["T1592", "T1083"]},
    "1.E": {"name": "Mitigating Known Vulnerabilities",
            "tier": "Essential",
            "purpose": "Patch known-exploited (KEV) vulnerabilities within CISA-defined SLAs.",
            "attack_ids": ["T1190", "T1195"]},
    "2.A": {"name": "Change Default Passwords",
            "tier": "Baseline",
            "purpose": "Reset default credentials on every device before deployment.",
            "attack_ids": ["T1078"]},
    "2.B": {"name": "Minimum Password Strength",
            "tier": "Baseline",
            "purpose": "Enforce password complexity / length minimums.",
            "attack_ids": ["T1110"]},
    "2.C": {"name": "Unique Credentials",
            "tier": "Baseline",
            "purpose": "Eliminate shared service / admin credentials.",
            "attack_ids": ["T1078"]},
    "2.E": {"name": "Separating User and Privileged Accounts",
            "tier": "Baseline",
            "purpose": "Disallow privileged users from using a privileged account for normal work.",
            "attack_ids": ["T1078.003", "T1548"]},
    "2.F": {"name": "Phishing-Resistant MFA",
            "tier": "Essential",
            "purpose": "Enforce phishing-resistant multi-factor authentication org-wide.",
            "attack_ids": ["T1110", "T1078", "T1556.006"]},
    "2.G": {"name": "Basic Cybersecurity Training",
            "tier": "Baseline",
            "purpose": "Provide periodic security awareness training to all employees.",
            "attack_ids": ["T1566"]},
    "2.H": {"name": "OT Cybersecurity Training",
            "tier": "Essential",
            "purpose": "OT-specific security training for personnel who operate ICS/OT.",
            "attack_ids": ["T1078"]},
    "2.I": {"name": "Strong and Agile Encryption",
            "tier": "Essential",
            "purpose": "Use modern, FIPS-validated encryption for data at rest + in transit.",
            "attack_ids": ["T1040", "T1557"]},
    "2.J": {"name": "Disable Macros by Default",
            "tier": "Baseline",
            "purpose": "Office macros disabled across the org; allow-list only when justified.",
            "attack_ids": ["T1059.005", "T1204.002"]},
    "2.K": {"name": "Signed Boot Process",
            "tier": "Essential",
            "purpose": "Enforce secure-boot / measured-boot on all systems.",
            "attack_ids": ["T1542"]},
    "2.M": {"name": "Network Segmentation",
            "tier": "Essential",
            "purpose": "Segment org networks; restrict OT systems from corporate IT.",
            "attack_ids": ["T1021", "T1210"]},
    "2.N": {"name": "Detection of Relevant Threats and TTPs",
            "tier": "Essential",
            "purpose": "Detect ATT&CK TTPs relevant to the org's threat model.",
            "attack_ids": ["T1071", "T1059"]},
    "2.O": {"name": "Document Device Configurations",
            "tier": "Baseline",
            "purpose": "Maintain baseline configuration documentation for all OT/IT assets.",
            "attack_ids": ["T1543"]},
    "2.P": {"name": "Centralized Logging",
            "tier": "Essential",
            "purpose": "Centrally collect + retain security-relevant logs.",
            "attack_ids": ["T1562.008"]},
    "2.Q": {"name": "Secure Log Storage",
            "tier": "Essential",
            "purpose": "Protect log storage from tampering / unauthorised modification.",
            "attack_ids": ["T1562.008"]},
    "2.R": {"name": "Asset Vulnerability Scanning",
            "tier": "Baseline",
            "purpose": "Regularly scan all IT/OT assets for vulnerabilities.",
            "attack_ids": ["T1595"]},
    "2.S": {"name": "Third-Party Validation of Cyber Practices",
            "tier": "Enhanced",
            "purpose": "Periodic independent security assessment.",
            "attack_ids": []},
    "2.U": {"name": "No Exploitable Internet-Exposed Services",
            "tier": "Essential",
            "purpose": "Eliminate or mitigate internet-exposed services with known CVEs.",
            "attack_ids": ["T1190", "T1133"]},
    "2.V": {"name": "Limit OT Connections to Public Internet",
            "tier": "Essential",
            "purpose": "OT systems should not be directly reachable from the public internet.",
            "attack_ids": ["T1190", "T1133"]},
    "2.W": {"name": "Email Security",
            "tier": "Essential",
            "purpose": "Enforce DMARC + SPF + DKIM and inbound email scanning.",
            "attack_ids": ["T1566"]},
    "2.X": {"name": "Document Network Topology",
            "tier": "Baseline",
            "purpose": "Maintain network diagrams covering trust boundaries + sensors.",
            "attack_ids": []},
    "3.A": {"name": "Backups",
            "tier": "Essential",
            "purpose": "Maintain isolated, tested backups of critical data.",
            "attack_ids": ["T1486", "T1490"]},
    "4.A": {"name": "Cyber Incident Reporting",
            "tier": "Essential",
            "purpose": "Document procedures for reporting incidents to CISA / sector-CSIRTs.",
            "attack_ids": []},
    "4.B": {"name": "Vulnerability Disclosure Program",
            "tier": "Enhanced",
            "purpose": "Run a coordinated VDP / safe-harbor for external researchers.",
            "attack_ids": ["T1595"]},
    "4.C": {"name": "Deploy Security.txt",
            "tier": "Enhanced",
            "purpose": "Publish security.txt with disclosure contact info.",
            "attack_ids": []},
}

_TIER_RANK = {"baseline": 1, "essential": 2, "enhanced": 3}

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":     False,
    "cpgs":       {},
    "by_attack":  {},
    "source":     "fallback",
    "error":      None,
}


def _build_index() -> None:
    cpgs = dict(_FALLBACK_CPGS)
    source = "fallback"
    if _CPG_JSON.exists():
        try:
            payload = json.loads(_CPG_JSON.read_text(encoding="utf-8",
                                                      errors="ignore"))
            if isinstance(payload, dict):
                first_val = next(iter(payload.values()), None)
                if isinstance(first_val, dict) and "tier" in first_val:
                    for cid, meta in payload.items():
                        if isinstance(meta, dict):
                            cpgs[cid] = meta
                    source = "vendored"
        except Exception as e:
            _log.warning("CISA CPG vendored JSON unreadable: %s", e)

    by_attack: Dict[str, List[str]] = {}
    for cid, meta in cpgs.items():
        for t in (meta.get("attack_ids") or []):
            by_attack.setdefault(str(t).upper(), []).append(cid)

    _state["cpgs"]      = cpgs
    _state["by_attack"] = by_attack
    _state["source"]    = source
    _state["loaded"]    = True
    _state["error"]     = None
    _log.info("CISA CPG loaded: %d controls (source=%s)",
              len(cpgs), source)


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def lookup(cpg_id: str) -> Optional[Dict[str, Any]]:
    _ensure_loaded()
    if not cpg_id:
        return None
    return (_state.get("cpgs") or {}).get(cpg_id.upper().strip())


def cpgs_for_attack(attack_id: str,
                    max_results: int = 8) -> List[Dict[str, Any]]:
    """Return CPGs that defend against the supplied ATT&CK technique,
    sorted by tier rank (Essential > Baseline > Enhanced)."""
    _ensure_loaded()
    if not attack_id:
        return []
    tid = attack_id.upper().strip()
    ids = (_state.get("by_attack") or {}).get(tid, [])
    if not ids and "." in tid:
        ids = (_state.get("by_attack") or {}).get(tid.split(".", 1)[0], [])
    out: List[Dict[str, Any]] = []
    for cid in ids:
        meta = _state["cpgs"].get(cid)
        if not meta:
            continue
        row = {"cpg_id": cid}
        row.update(meta)
        out.append(row)
    out.sort(key=lambda r: -_TIER_RANK.get((r.get("tier") or "").lower(), 0))
    return out[:max_results]


def cpgs_for_attacks(attack_ids: Iterable[str]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for t in (attack_ids or []):
        rows = cpgs_for_attack(t)
        if rows:
            out[t.upper()] = rows
    return out


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":   bool(_state["loaded"]),
        "controls": len(_state.get("cpgs") or {}),
        "techniques_mapped": len(_state.get("by_attack") or {}),
        "source":   _state.get("source"),
        "error":    _state.get("error"),
    }
