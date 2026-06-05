"""Tests for the calibration override log."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_log(monkeypatch):
    """Each test gets its own JSONL log file in a tempdir so we don't
    pollute the real backend/data/calibration_overrides.jsonl."""
    import intel.calibration_log as cl
    tmp = tempfile.NamedTemporaryFile(
        suffix=".jsonl", prefix="cal_test_", delete=False,
    )
    tmp.close()
    monkeypatch.setattr(cl, "_LOG_PATH", Path(tmp.name))
    yield
    try:
        os.unlink(tmp.name)
    except FileNotFoundError:
        pass


def test_record_override_persists_and_returns_record():
    from intel.calibration_log import record_override, _iter_records
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
    # Persisted to disk
    persisted = _iter_records()
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


def test_stats_empty_returns_zero_shape():
    from intel.calibration_log import stats
    s = stats()
    assert s["total_overrides"]   == 0
    assert s["agreement_rate"]    is None
    assert s["by_prompt_version"] == {}


def test_stats_counts_overrides_vs_agreements():
    from intel.calibration_log import record_override, stats
    # 2 disagreements, 1 agreement -> 33% override rate among 3 records
    record_override("a", "HIGH",   0.9, "", "LOW")
    record_override("b", "MEDIUM", 0.6, "", "LOW")
    record_override("c", "HIGH",   0.8, "", "HIGH")     # agreement
    s = stats()
    assert s["total_records"]      == 3
    assert s["total_overrides"]    == 2
    assert s["agreement_rate"]     == round(1 / 3, 3)


def test_stats_groups_by_prompt_version_and_level_pair():
    from intel.calibration_log import record_override, stats
    record_override("a", "HIGH",   0.9, "", "LOW")
    record_override("b", "MEDIUM", 0.6, "", "LOW")
    s = stats()
    pair = s["by_level_pair"]
    assert "HIGH->LOW"   in pair
    assert "MEDIUM->LOW" in pair
    # prompt_version should be present in the by_prompt_version dict
    assert len(s["by_prompt_version"]) >= 1


def test_truncates_long_summary_and_reason():
    from intel.calibration_log import record_override
    long_summary = "x" * 500
    long_reason  = "y" * 1000
    rec = record_override("paste", "HIGH", 0.9, long_summary,
                          "LOW", long_reason)
    assert len(rec["ai_verdict"]["summary"])      <= 240
    assert len(rec["analyst_verdict"]["reason"])  <= 600


def test_recent_is_capped_at_20():
    from intel.calibration_log import record_override, stats
    for i in range(30):
        record_override(f"alert-{i}", "HIGH", 0.9, "", "LOW")
    s = stats()
    assert len(s["recent"]) == 20


def test_prompt_version_returns_some_string():
    from intel.calibration_log import prompt_version
    v = prompt_version()
    assert isinstance(v, str) and v
