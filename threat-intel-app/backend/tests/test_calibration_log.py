"""Tests for the calibration override log."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_log():
    """Clear the in-memory ring buffer between tests so override counts
    don't leak across cases. The platform no longer persists overrides
    to disk; the records live in a process-local deque."""
    import intel.calibration_log as cl
    cl._RECORDS.clear()
    yield
    cl._RECORDS.clear()


def test_record_override_persists_and_returns_record():
    from intel.calibration_log import record_override, iter_records
    rec = record_override(
        raw_input            = "User logged in from new device",
        ai_threat_level      = "MEDIUM",
        ai_confidence        = 0.6,
        ai_summary           = "Possible session hijack",
        analyst_threat_level = "LOW",
        analyst_reason       = "Expected travel by user",
        alert_type           = "cloud_signin",
    )
    assert rec["ai_verdict"]["threat_level"]      == "MEDIUM"
    assert rec["analyst_verdict"]["threat_level"] == "LOW"
    assert rec["agreed"] is False
    assert rec["input_hash"] != "empty"
    # Held in the in-memory ring buffer
    persisted = iter_records()
    assert len(persisted) == 1
    assert persisted[0]["analyst_verdict"]["reason"] == "Expected travel by user"


def test_record_agreement_marks_agreed_true():
    from intel.calibration_log import record_override
    rec = record_override(
        raw_input            = "x",
        ai_threat_level      = "HIGH",
        ai_confidence        = 0.9,
        ai_summary           = "",
        analyst_threat_level = "HIGH",
    )
    assert rec["agreed"] is True


def test_record_normalises_threat_level_case():
    from intel.calibration_log import record_override
    rec = record_override("x", "medium", 0.5, "", "low")
    assert rec["ai_verdict"]["threat_level"]      == "MEDIUM"
    assert rec["analyst_verdict"]["threat_level"] == "LOW"


def test_input_hash_is_deterministic():
    from intel.calibration_log import input_hash
    a = input_hash("the same alert text")
    b = input_hash("the same alert text")
    c = input_hash("a different alert")
    assert a == b
    assert a != c
    assert len(a) == 64


def test_input_hash_handles_empty():
    from intel.calibration_log import input_hash
    assert input_hash("") == "empty"
    assert input_hash(None) == "empty"


def test_iter_records_returns_recorded_overrides():
    from intel.calibration_log import record_override, iter_records
    record_override("a", "HIGH",   0.9, "", "LOW")
    record_override("b", "MEDIUM", 0.6, "", "LOW")
    record_override("c", "HIGH",   0.8, "", "HIGH")
    recs = iter_records()
    assert len(recs) == 3
    assert sum(1 for r in recs if not r["agreed"]) == 2


def test_truncates_long_summary_and_reason():
    from intel.calibration_log import record_override
    long_summary = "x" * 500
    long_reason  = "y" * 1000
    rec = record_override("paste", "HIGH", 0.9, long_summary,
                          "LOW", long_reason)
    assert len(rec["ai_verdict"]["summary"])      <= 240
    assert len(rec["analyst_verdict"]["reason"])  <= 600


def test_prompt_version_returns_some_string():
    from intel.calibration_log import prompt_version
    v = prompt_version()
    assert isinstance(v, str) and v
