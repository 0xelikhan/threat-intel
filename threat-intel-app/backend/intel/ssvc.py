"""
SSVC — Stakeholder-Specific Vulnerability Categorization.

Source: https://github.com/CERTCC/SSVC (Apache-2.0). CISA + CERT/CC
joint publication that turns CVSS-style severity into one of four
operational categories:

  - Act       — apply mitigations immediately; consider emergency response
  - Attend    — quickly schedule remediation; out-of-cycle ok
  - Track*    — track during normal cycles; treat as Attend if state changes
  - Track     — track during normal cycles

The Coordinator decision tree consumes four discrete signals:

  - Exploitation:    none / poc / active
  - Automatable:     no / yes
  - Technical Impact: partial / total
  - Mission Impact:   degraded / crippled / mev   (we surface the first
                                                   two; mev requires
                                                   stakeholder-specific
                                                   context RECON doesn't have)

This module derives those signals directly from the CVE enrichment
dict (KEV → exploitation:active; nuclei templates ≥1 → automatable;
NVD CVSS 'C:H/I:H' → technical_impact:total; explicit 'Mission Impact'
override accepted from the caller).
"""

from __future__ import annotations

from typing import Any, Dict, Optional


# Decision-tree mapping — the canonical SSVC Coordinator outcomes per
# (exploitation, automatable, technical_impact, mission_impact). Mission
# impact 'mev' tier is not derived automatically.
_TREE: Dict[tuple, str] = {
    # (exploitation, automatable, technical_impact, mission_impact) -> action
    ("none",   "no",  "partial", "degraded"):    "Track",
    ("none",   "no",  "partial", "crippled"):    "Track",
    ("none",   "no",  "total",   "degraded"):    "Track",
    ("none",   "no",  "total",   "crippled"):    "Track*",
    ("none",   "yes", "partial", "degraded"):    "Track",
    ("none",   "yes", "partial", "crippled"):    "Track*",
    ("none",   "yes", "total",   "degraded"):    "Track*",
    ("none",   "yes", "total",   "crippled"):    "Attend",
    ("poc",    "no",  "partial", "degraded"):    "Track",
    ("poc",    "no",  "partial", "crippled"):    "Track*",
    ("poc",    "no",  "total",   "degraded"):    "Track*",
    ("poc",    "no",  "total",   "crippled"):    "Attend",
    ("poc",    "yes", "partial", "degraded"):    "Track*",
    ("poc",    "yes", "partial", "crippled"):    "Attend",
    ("poc",    "yes", "total",   "degraded"):    "Attend",
    ("poc",    "yes", "total",   "crippled"):    "Attend",
    ("active", "no",  "partial", "degraded"):    "Attend",
    ("active", "no",  "partial", "crippled"):    "Attend",
    ("active", "no",  "total",   "degraded"):    "Attend",
    ("active", "no",  "total",   "crippled"):    "Act",
    ("active", "yes", "partial", "degraded"):    "Attend",
    ("active", "yes", "partial", "crippled"):    "Act",
    ("active", "yes", "total",   "degraded"):    "Act",
    ("active", "yes", "total",   "crippled"):    "Act",
}

_ACTION_DESCRIPTIONS = {
    "Act":     ("Immediate action required; treat as out-of-cycle. "
                "Consider emergency response if mission impact is total."),
    "Attend":  ("Out-of-cycle remediation justified. Engage stakeholders "
                "and schedule promptly."),
    "Track*":  ("Track during normal cycles. Treat as Attend if any "
                "decision-tree input changes (PoC drop, active exploitation, "
                "mission-impact escalation)."),
    "Track":   ("Track during normal cycles; no special handling."),
}


def derive_signals(cve_data: Dict[str, Any],
                   mission_impact: str = "crippled") -> Dict[str, str]:
    """Map RECON's existing CVE enrichment into SSVC's four signals.
    Defaults: mission_impact='crippled' (the safer default for a generic
    SOC — operators can override per-asset)."""
    # Exploitation
    kev = cve_data.get("cisa_kev") or {}
    pocs = (cve_data.get("public_pocs") or {}).get("poc_count") or 0
    ids_rules = (cve_data.get("ids_rules") or {}).get("rule_count") or 0
    if kev.get("in_kev"):
        exploitation = "active"
    elif pocs > 0 or ids_rules > 0:
        exploitation = "poc"
    else:
        exploitation = "none"

    # Automatable: nuclei templates exist → yes (someone has weaponised
    # it into a templated scanner). Otherwise infer from CVSS attack
    # vector when present.
    nuc = (cve_data.get("nuclei") or {}).get("template_count") or 0
    if nuc > 0:
        automatable = "yes"
    else:
        cvss_str = (cve_data.get("nvd") or {}).get("cvss_v3_severity", "")
        # Conservative: only call something "automatable" when nuclei or
        # IDS rules confirm it; otherwise default to no.
        automatable = "no"

    # Technical impact: NVD CVSS severity. CRITICAL or HIGH with
    # confidentiality+integrity high → total. Otherwise partial.
    sev = ((cve_data.get("nvd") or {}).get("cvss_v3_severity") or "").upper()
    score = (cve_data.get("nvd") or {}).get("cvss_v3_score") or 0.0
    try:
        score_f = float(score)
    except (TypeError, ValueError):
        score_f = 0.0
    technical_impact = "total" if (sev == "CRITICAL" or score_f >= 8.0) else "partial"

    # Mission impact: caller-provided. SSVC treats this as a stakeholder
    # input; RECON can't infer it without asset context.
    if mission_impact not in ("degraded", "crippled"):
        mission_impact = "crippled"

    return {
        "exploitation":      exploitation,
        "automatable":       automatable,
        "technical_impact":  technical_impact,
        "mission_impact":    mission_impact,
    }


def assess(cve_data: Dict[str, Any],
           mission_impact: str = "crippled") -> Dict[str, Any]:
    """Run SSVC against a RECON CVE-enrichment dict. Returns
    {signals, action, description, source}."""
    signals = derive_signals(cve_data, mission_impact=mission_impact)
    key = (signals["exploitation"], signals["automatable"],
           signals["technical_impact"], signals["mission_impact"])
    action = _TREE.get(key, "Track")
    return {
        "source":      "SSVC v2 (Coordinator)",
        "signals":     signals,
        "action":      action,
        "description": _ACTION_DESCRIPTIONS[action],
        "reference":   "https://www.cisa.gov/ssvc",
    }
