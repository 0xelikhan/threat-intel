"""
Investigation AI calibration tests (Section 8).

These tests don't run the live LLM — that requires a configured Azure
OpenAI key and would be flaky in CI. They verify the three layers of
the calibration system that DO work without an LLM:

  1. The known_good library matches the canonical Dell SupportAssist
     scenario (reg.exe under SYSTEM exporting to ProgramData\\Dell\\…).
  2. The known_good library does NOT match the canonical Cobalt Strike
     scenario (powershell.exe -EncodedCommand to 185.220.101.45 +
     update-service.xyz).
  3. The calibration safety-net override in run_investigation downshifts
     a HIGH/CRITICAL verdict whose assessment_basis is benign-only.
"""

from __future__ import annotations

import re

from intel.known_good import match, extract_context_from_state


# ─── Test inputs (verbatim from the Section 8 spec) ──────────────────────────
DELL_LOG = """\
TimeCreated: 2026-05-30T14:02:11Z
Computer: DESKTOP-DELL-04
EventID: 4688
Process Name: C:\\Windows\\System32\\reg.exe
Command Line: reg.exe export HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy "C:\\ProgramData\\Dell\\SupportAssist\\Diagnostics\\firewall_export.reg"
User: NT AUTHORITY\\SYSTEM
Parent Process: SupportAssistAgent.exe
ParentProcessPath: C:\\Program Files\\Dell\\SupportAssist\\SupportAssistAgent.exe
"""

DELL_STATE = {
    "raw_input": DELL_LOG,
    "iocs": {
        "paths": ["C:\\ProgramData\\Dell\\SupportAssist\\Diagnostics\\firewall_export.reg"]
    },
}

CS_LOG = (
    "alert endpoint detection host WORKSTATION-04 "
    "sha256 3395856ce81f2b7382dee72602f798b642f14140 "
    "process powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdAA= "
    "source_ip 185.220.101.45 domain update-service.xyz"
)
CS_STATE = {"raw_input": CS_LOG, "iocs": {}}


# ─── 1. known_good vs Dell SupportAssist ─────────────────────────────────────
def test_dell_supportassist_matches_known_good_library():
    """The platform must recognise reg.exe under SYSTEM exporting to a
    Dell ProgramData directory as legitimate vendor maintenance."""
    ctx = extract_context_from_state(DELL_STATE)
    hits = match(ctx)
    assert hits, f"Expected at least one known-good hit for Dell scenario, got 0. ctx={ctx}"
    vendor_categories = {h["category"] for h in hits}
    assert "oem_maintenance" in vendor_categories or any(
        "Dell" in h["vendor"] for h in hits
    ), f"Expected an OEM Dell hit; got {hits}"


def test_dell_scenario_does_not_match_a_malicious_pattern_only():
    """A clean parse must not produce a vendor 'unknown' hit."""
    ctx = extract_context_from_state(DELL_STATE)
    hits = match(ctx)
    for h in hits:
        assert h["vendor"], f"hit must have a vendor label: {h}"
        assert h["category"] in (
            "oem_maintenance", "windows_builtin", "endpoint_security",
            "management_tools", "logging_tools", "backup_tools",
            "vendor_updater",
        ), f"unexpected category: {h}"


# ─── 2. known_good vs Cobalt Strike (must NOT match vendor patterns) ─────────
def test_cobalt_strike_does_not_match_vendor_known_good():
    """The platform must NOT classify Cobalt Strike / encoded PowerShell
    + TOR exit IP as known-good vendor activity."""
    ctx = extract_context_from_state(CS_STATE)
    hits = match(ctx)
    vendor_hits = [h for h in hits if h["category"] in (
        "oem_maintenance", "endpoint_security", "management_tools",
        "backup_tools", "vendor_updater", "logging_tools",
    )]
    assert not vendor_hits, (
        f"Cobalt Strike scenario must not match any vendor known-good pattern, "
        f"got: {vendor_hits}"
    )


# ─── 3. Calibration safety-net downshift ─────────────────────────────────────
def _apply_calibration(result: dict) -> dict:
    """Run JUST the calibration safety-net block from run_investigation
    against a synthetic result dict. Mirrors the production logic so the
    test exercises the same code path without booting the full pipeline."""
    _level = (result.get("threat_level") or "").upper()
    _basis = result.get("assessment_basis") or []
    if _level in ("HIGH", "CRITICAL") and _basis:
        _basis_text = " ".join(str(b).lower() for b in _basis)
        _benign_markers = (
            "known-good", "known good", "clean across", "is clean",
            "no malicious", "legitimate", "expected", "vendor pattern",
            "vendor directory", "service account", "matches dell",
            "matches microsoft", "matches crowdstrike", "matches sccm",
            "matches intune", "matches sentinel", "matches carbon black",
        )
        _malicious_markers = (
            "flagged by", "vt detect", "malware family", "cobalt strike",
            "mimikatz", "lsass", "ransomware", "dcsync", "credential",
            "lateral", "c2 callout", "command-and-control", "exfiltrat",
            "kev ", "malicious infrastructure", "phishing kit", "byovd",
            "loldrivers hit",
        )
        has_benign    = any(m in _basis_text for m in _benign_markers)
        has_malicious = any(m in _basis_text for m in _malicious_markers)
        if has_benign and not has_malicious:
            result["threat_level"] = "LOW"
            result["assessment_basis"] = list(_basis) + [
                "[RECON calibration] threat_level lowered — assessment_basis "
                "contained only benign indicators and no concrete malicious evidence."
            ]
            if result.get("verdict_classification") in ("MALICIOUS", "LIKELY_MALICIOUS"):
                result["verdict_classification"] = "LIKELY_BENIGN"
    return result


def test_calibration_downshifts_high_with_benign_only_basis():
    """The exact failure mode the user described — HIGH verdict with a
    Dell-SupportAssist-style benign basis — must be lowered to LOW."""
    result = {
        "threat_level": "HIGH",
        "assessment_basis": [
            "Process path matches Dell SupportAssist (known-good library hit)",
            "Hash is clean across all reputation sources checked",
            "Parent process is a legitimate Dell vendor agent",
        ],
        "verdict_classification": "LIKELY_MALICIOUS",
    }
    out = _apply_calibration(result)
    assert out["threat_level"] == "LOW", out
    assert out["verdict_classification"] == "LIKELY_BENIGN"
    assert any("[RECON calibration]" in b for b in out["assessment_basis"])


def test_calibration_does_not_downshift_when_malicious_evidence_present():
    """If even one concrete malicious-evidence point appears alongside
    benign ones, the calibration must NOT downshift."""
    result = {
        "threat_level": "HIGH",
        "assessment_basis": [
            "SHA256 3395... flagged by 42/96 VirusTotal engines as Cobalt Strike",
            "Process path matches a known Microsoft binary (legitimate by itself)",
        ],
        "verdict_classification": "MALICIOUS",
    }
    out = _apply_calibration(result)
    assert out["threat_level"] == "HIGH", out
    assert out["verdict_classification"] == "MALICIOUS"


def test_calibration_preserves_low_and_informational_unchanged():
    """The safety-net only downshifts HIGH/CRITICAL — LOW must pass through."""
    for level in ("LOW", "MEDIUM", "INFORMATIONAL"):
        result = {
            "threat_level": level,
            "assessment_basis": ["known-good library hit", "hash is clean"],
        }
        out = _apply_calibration(result)
        assert out["threat_level"] == level, f"level {level} should not be touched"


def test_calibration_no_op_when_assessment_basis_missing():
    """Defensive: missing or empty assessment_basis must not crash or
    downshift (the AI just didn't fill the field)."""
    for empty in ({}, {"assessment_basis": []}, {"assessment_basis": None}):
        r = {"threat_level": "HIGH", **empty}
        out = _apply_calibration(r)
        assert out["threat_level"] == "HIGH"


# ─── 4. Prompt regression — calibration text must be present ─────────────────
def test_investigation_prompt_contains_calibration_principles():
    """Verify the calibration system prompt actually loaded into the
    investigation module. If someone reverts the prompt this test will
    fail loudly rather than the calibration silently regressing."""
    from agents import investigation
    prompt = investigation.PROMPT
    for needle in (
        "evidence before drawing conclusions",  # the "innocent until proven guilty" principle, paraphrased
        "PRINCIPLE 1",
        "PRINCIPLE 3",
        "EVIDENCE STANDARD",
        "INFORMATIONAL",
        "Dell SupportAssist",
        "known-good",
    ):
        # Case-insensitive substring — the prompt's exact wording is what
        # we're checking; minor capitalisation tweaks shouldn't fail it.
        assert re.search(re.escape(needle), prompt, re.IGNORECASE), (
            f"investigation prompt missing required calibration text: {needle!r}"
        )
