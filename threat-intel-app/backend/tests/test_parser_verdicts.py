"""Regression tests for the verdict-mapping audit pass.

Two bugs found while auditing every _p_* parser in agents/enrichment.py
after the GreyNoise RIOT misclassification:

  - AbuseIPDB:        score == 50 fell into UNKNOWN (off-by-one between
                      the > 50 SUSPICIOUS branch and the >= 0 catch-all).
  - Hybrid Analysis:  "suspicious" verdict was being mapped to MALICIOUS,
                      same severity-amplification pattern as GreyNoise
                      mapping RIOT-only matches to CLEAN.

Bucket every threshold here so future tweaks can't silently regress.
"""

from __future__ import annotations

from agents.enrichment import _p_abuse, _p_hybrid


# ─── AbuseIPDB ──────────────────────────────────────────────────────────────
def _abuse_blob(score: int, reports: int = 0):
    return {"data": {"abuseConfidenceScore": score, "totalReports": reports}}


def test_abuse_score_75_is_malicious():
    out = _p_abuse(_abuse_blob(75, 10))
    assert out["verdict"] == "MALICIOUS"
    out = _p_abuse(_abuse_blob(100, 10))
    assert out["verdict"] == "MALICIOUS"


def test_abuse_score_25_is_suspicious_per_abuseipdb_threshold():
    """AbuseIPDB's own API docs treat score >= 25 as the floor for
    actionable signal. The site colour-codes this range as yellow/
    orange. Previous mapping had the floor at 50, missing every
    25-49 IP that AbuseIPDB itself flagged."""
    for s in (25, 50, 74):
        out = _p_abuse(_abuse_blob(s, 5))
        assert out["verdict"] == "SUSPICIOUS", f"score {s} should be SUSPICIOUS"


def test_abuse_score_50_is_suspicious_not_unknown():
    """The original off-by-one bug case: score exactly 50 used to fall
    into UNKNOWN because the old SUSPICIOUS branch was `> 50`."""
    out = _p_abuse(_abuse_blob(50, 5))
    assert out["verdict"] == "SUSPICIOUS"


def test_abuse_score_zero_with_no_reports_is_clean():
    out = _p_abuse(_abuse_blob(0, 0))
    assert out["verdict"] == "CLEAN"


def test_abuse_score_zero_with_reports_is_unknown():
    out = _p_abuse(_abuse_blob(0, 3))
    assert out["verdict"] == "UNKNOWN"


def test_abuse_score_low_confidence_range_is_unknown():
    """1-24 is AbuseIPDB's low-confidence band — they explicitly say
    not to act on it, so we shouldn't surface it as SUSPICIOUS."""
    for s in (1, 10, 24):
        out = _p_abuse(_abuse_blob(s, 2))
        assert out["verdict"] == "UNKNOWN", f"score {s} should be UNKNOWN"


# ─── Hybrid Analysis ────────────────────────────────────────────────────────
def _hybrid_blob(verdict_raw: str):
    return [{"verdict": verdict_raw, "sha256": "a" * 64}]


def test_hybrid_malicious_stays_malicious():
    out = _p_hybrid(_hybrid_blob("malicious"))
    assert out["verdict"] == "MALICIOUS"


def test_hybrid_suspicious_does_not_amplify_to_malicious():
    """The bug case: HA's 'suspicious' verdict was being mapped to
    MALICIOUS — same severity-amplification pattern as GreyNoise."""
    out = _p_hybrid(_hybrid_blob("suspicious"))
    assert out["verdict"] == "SUSPICIOUS"
    assert out["verdict"] != "MALICIOUS"


def test_hybrid_no_specific_threat_is_clean():
    for raw in ("no specific threat", "no_specific_threat", "whitelisted"):
        out = _p_hybrid(_hybrid_blob(raw))
        assert out["verdict"] == "CLEAN", f"{raw!r} should be CLEAN"


def test_hybrid_unknown_verdict_is_unknown():
    for raw in ("unknown", "", "informational"):
        out = _p_hybrid(_hybrid_blob(raw))
        assert out["verdict"] == "UNKNOWN", f"{raw!r} should be UNKNOWN"


def test_hybrid_case_insensitive():
    out = _p_hybrid(_hybrid_blob("MALICIOUS"))
    assert out["verdict"] == "MALICIOUS"
    out = _p_hybrid(_hybrid_blob("Suspicious"))
    assert out["verdict"] == "SUSPICIOUS"


def test_hybrid_preserves_raw_for_audit():
    """The original verdict string must still be visible on the output
    so the analyst can audit how we interpreted it."""
    out = _p_hybrid(_hybrid_blob("suspicious"))
    assert out["verdict_raw"] == "suspicious"
