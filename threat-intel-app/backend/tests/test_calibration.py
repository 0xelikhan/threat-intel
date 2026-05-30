"""Shared calibration module tests (intel/calibration.py)."""

from __future__ import annotations

from intel.calibration import (
    CALIBRATION_PRINCIPLES,
    VERDICT_LEVEL_GUIDE,
    EVIDENCE_STANDARD,
    benign_only_basis,
    downshift_if_benign_only,
    build_known_good_block_from_fields,
)


# ─── benign_only_basis classifier ────────────────────────────────────────────
def test_benign_only_basis_empty():
    assert benign_only_basis([]) is False
    assert benign_only_basis(None) is False


def test_benign_only_basis_pure_benign():
    assert benign_only_basis([
        "Process path matches Dell SupportAssist (known-good library hit)",
        "Hash is clean across every TI source",
        "Parent process is a legitimate vendor agent",
    ]) is True


def test_benign_only_basis_mixed_returns_false():
    """A single malicious indicator alongside benign ones must NOT trigger."""
    assert benign_only_basis([
        "Hash flagged by 42/96 VirusTotal engines as Cobalt Strike",
        "Process path matches a known Microsoft binary",
    ]) is False


def test_benign_only_basis_pure_malicious_returns_false():
    assert benign_only_basis([
        "SHA256 7c2f flagged by 60 VT engines",
        "LSASS access pattern observed",
    ]) is False


# ─── downshift_if_benign_only safety-net ─────────────────────────────────────
def test_downshift_high_with_benign_only_drops_to_low():
    result = {
        "threat_level": "HIGH",
        "assessment_basis": [
            "Matches Dell SupportAssist (known-good)",
            "Hash is clean across all sources",
        ],
        "verdict_classification": "LIKELY_MALICIOUS",
    }
    out = downshift_if_benign_only(result)
    assert out is result   # in-place
    assert out["threat_level"] == "LOW"
    assert out["verdict_classification"] == "LIKELY_BENIGN"
    assert any("[RECON calibration]" in b for b in out["assessment_basis"])


def test_downshift_preserves_medium_low_informational():
    for level in ("MEDIUM", "LOW", "INFORMATIONAL"):
        r = {"threat_level": level,
             "assessment_basis": ["known-good", "clean across"]}
        downshift_if_benign_only(r)
        assert r["threat_level"] == level


def test_downshift_preserves_high_with_malicious_evidence():
    r = {"threat_level": "HIGH",
         "assessment_basis": [
             "Hash flagged by 42 VT engines",
             "Process path matches a Microsoft binary",
         ],
         "verdict_classification": "MALICIOUS"}
    downshift_if_benign_only(r)
    assert r["threat_level"] == "HIGH"
    assert r["verdict_classification"] == "MALICIOUS"


def test_downshift_custom_keys():
    """Caller can override the field names (file_ai_analyst uses
    malware_classification.category instead of threat_level)."""
    r = {"severity": "CRITICAL",
         "evidence": ["known-good vendor pattern", "is clean across sources"]}
    downshift_if_benign_only(r, level_key="severity", basis_key="evidence")
    assert r["severity"] == "LOW"


def test_downshift_label_customisable():
    r = {"threat_level": "HIGH",
         "assessment_basis": ["known-good", "is clean"]}
    downshift_if_benign_only(r, label="file_ai_analyst")
    assert any("[file_ai_analyst]" in b for b in r["assessment_basis"])


# ─── known-good block builders ───────────────────────────────────────────────
def test_known_good_block_from_fields_dell():
    """The Dell SupportAssist scenario must produce a non-empty block."""
    block = build_known_good_block_from_fields(
        process="reg.exe",
        user_context="NT AUTHORITY\\SYSTEM",
        command_line="reg.exe export HKLM\\Foo bar.reg",
        destination_path="C:\\ProgramData\\Dell\\SupportAssist\\out.reg",
    )
    assert "Dell" in block
    assert "no known-good" not in block


def test_known_good_block_from_fields_no_match():
    block = build_known_good_block_from_fields(
        process="totally-random-binary.exe",
        path="C:\\Random\\Folder\\binary.exe",
    )
    assert "no known-good software patterns matched" in block


# ─── prompt blocks loaded ────────────────────────────────────────────────────
def test_calibration_blocks_are_nonempty():
    assert "CALIBRATION PRINCIPLES" in CALIBRATION_PRINCIPLES
    assert "INFORMATIONAL" in VERDICT_LEVEL_GUIDE
    assert "HIGH / CRITICAL" in EVIDENCE_STANDARD


def test_calibration_principles_cover_log_format_gotchas():
    """The shared calibration must explain that M365 UAL ResultStatus is
    audit-pipeline metadata, not the operation outcome. This was a real
    false-positive: the AI claimed 'log manipulation' on a normal
    UserLoginFailed record because ResultStatus showed Success."""
    for needle in (
        "ResultStatus",
        "audit",
        "LogonError",
        "50057",                  # account disabled error code
        "UserLoginFailed",
        "IsCompliant",
    ):
        assert needle in CALIBRATION_PRINCIPLES, (
            f"missing log-format gotcha: {needle!r} — the M365 UAL "
            f"'ResultStatus: Success' false-positive will reappear"
        )
