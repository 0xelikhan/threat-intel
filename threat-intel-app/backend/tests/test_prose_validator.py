"""Tests for the server-side prose validator.

Pulls duplicated content out of LLM-emitted investigation results
before they leave the backend - same semantic guarantee the frontend
de-dup gives, but enforced everywhere (MCP, email composer, API
consumers). Tracks the prose-bug regression catalogue from this week's
fixes.
"""

from __future__ import annotations

from intel.prose_validator import (
    token_overlap, drop_overlapping, cap_sentences,
    strip_forbidden_keys, validate_investigation_result,
)


# ─── token_overlap (mirrors the frontend helper) ────────────────────────
def test_token_overlap_identical_strings():
    s = "user x deleted file consolehost"
    assert token_overlap(s, s) > 0.9


def test_token_overlap_disjoint_strings():
    assert token_overlap("apple banana cherry", "truck mountain river") == 0


def test_token_overlap_paraphrased_dup_above_threshold():
    # The exact wording-shift duplicate the user reported.
    a = "User AGDRYER\\PTADMIN deleted consolehost_history.txt"
    b = "The deletion of consolehost_history.txt by user AGDRYER\\PTADMIN is not suspicious"
    assert token_overlap(a, b) > 0.5


def test_token_overlap_short_tokens_ignored():
    # 4-char minimum means "is" / "a" don't drive overlap up
    assert token_overlap("a is foo", "a is bar") == 0


def test_token_overlap_empty_returns_zero():
    assert token_overlap("", "anything") == 0
    assert token_overlap(None, "anything") == 0
    assert token_overlap(None, None) == 0


# ─── drop_overlapping ───────────────────────────────────────────────────
def test_drop_overlapping_filters_paraphrased_dupes():
    candidates = [
        "The deletion of file Y by user X is not suspicious",   # dup
        "AbuseIPDB reports 0 abuse history for the source IP",  # distinct
    ]
    corpus = "User X deleted file Y. Not malicious."
    out = drop_overlapping(candidates, corpus, threshold=0.4)
    assert len(out) == 1
    assert "AbuseIPDB" in out[0]


def test_drop_overlapping_keeps_all_when_corpus_empty():
    assert drop_overlapping(["a", "b"], "") == ["a", "b"]


def test_drop_overlapping_drops_falsy_entries():
    assert drop_overlapping(["", None, "real text"], "x", 0.5) == ["real text"]


def test_drop_overlapping_handles_list_corpus():
    out = drop_overlapping(
        ["the deletion of file consolehost was performed"],
        ["user deleted file consolehost from history"],
        threshold=0.4,
    )
    assert out == []


# ─── cap_sentences ──────────────────────────────────────────────────────
def test_cap_sentences_passes_through_short_text():
    s = "First sentence. Second one."
    assert cap_sentences(s, 2) == s


def test_cap_sentences_truncates_to_limit():
    s = "One. Two. Three. Four. Five."
    out = cap_sentences(s, 2)
    assert out == "One. Two."


def test_cap_sentences_handles_question_and_exclamation():
    s = "What? OK! Done. Continue. More."
    assert cap_sentences(s, 3) == "What? OK! Done."


def test_cap_sentences_handles_empty():
    assert cap_sentences("", 2) == ""
    assert cap_sentences(None, 2) == ""


# ─── strip_forbidden_keys ───────────────────────────────────────────────
def test_strip_forbidden_keys_removes_log_correlation():
    r = {"summary": "x", "log_correlation": {"events": []},
         "threat_level": "LOW"}
    strip_forbidden_keys(r)
    assert "log_correlation" not in r
    assert r["summary"] == "x"
    assert r["threat_level"] == "LOW"


def test_strip_forbidden_keys_noop_when_nothing_forbidden():
    r = {"summary": "x", "threat_level": "LOW"}
    assert strip_forbidden_keys(r) is r
    assert set(r.keys()) == {"summary", "threat_level"}


def test_strip_forbidden_keys_returns_input_for_non_dict():
    assert strip_forbidden_keys("string") == "string"
    assert strip_forbidden_keys(None) is None


# ─── validate_investigation_result (end-to-end) ─────────────────────────
def test_validate_caps_summary_at_two_sentences():
    r = {"summary": "One. Two. Three. Four."}
    out = validate_investigation_result(r)
    # cap_sentences uses a conservative split that requires capital
    # / quote / paren after; so "One. Two." is the result.
    assert out["summary"].count(".") == 2


def test_validate_drops_analysis_that_paraphrases_summary():
    """The bug-shape from the user's PowerShell deletion case."""
    r = {
        "summary": "User AGDRYER\\PTADMIN deleted consolehost_history.txt. Routine admin cleanup.",
        "confirmed_facts": [],
        "analysis_assessment": [
            "The deletion of consolehost_history.txt by user AGDRYER\\PTADMIN is not inherently suspicious.",
            "AbuseIPDB reports no malicious activity for the source IP.",
        ],
    }
    out = validate_investigation_result(r)
    # First analysis sentence overlaps the summary heavily — should be
    # dropped. Second is distinct — should be kept.
    assert len(out["analysis_assessment"]) == 1
    assert "AbuseIPDB" in out["analysis_assessment"][0]


def test_validate_drops_key_findings_that_restate_confirmed_facts():
    r = {
        "summary": "x",
        "confirmed_facts": [
            "User AGDRYER\\PTADMIN deleted consolehost_history.txt at 16:27 UTC",
        ],
        "key_findings": [
            "User AGDRYER\\PTADMIN deleted consolehost_history.txt",   # dup
            "AbuseIPDB confidence score 0 for the source IP",          # distinct
        ],
    }
    out = validate_investigation_result(r)
    assert len(out["key_findings"]) == 1
    assert "AbuseIPDB" in out["key_findings"][0]


def test_validate_clears_redundant_analyst_notes():
    r = {
        "summary": "Routine admin cleanup of PowerShell history.",
        "analysis_assessment": ["Pattern matches expected admin workflow."],
        "analyst_notes": "The PowerShell history cleanup is part of the routine admin workflow.",
    }
    out = validate_investigation_result(r)
    # analyst_notes paraphrases the existing prose -> blanked.
    assert out["analyst_notes"] == ""


def test_validate_preserves_distinct_analyst_notes():
    r = {
        "summary": "User deleted PowerShell history.",
        "analysis_assessment": [],
        "analyst_notes": "Customer has documented this exact account as their RMM service principal; the workflow is sanctioned per the change request on 2026-05-10.",
    }
    out = validate_investigation_result(r)
    assert out["analyst_notes"] != ""
    assert "service principal" in out["analyst_notes"]


def test_validate_strips_forbidden_log_correlation():
    r = {
        "summary": "x", "threat_level": "LOW",
        "log_correlation": {"events": [1, 2, 3]},
    }
    out = validate_investigation_result(r)
    assert "log_correlation" not in out


def test_validate_handles_non_dict_input_safely():
    assert validate_investigation_result(None) is None
    assert validate_investigation_result("string") == "string"
    assert validate_investigation_result([]) == []


def test_validate_is_idempotent():
    """Running the validator twice produces the same output as once."""
    r = {
        "summary": "User deleted PowerShell history. Routine cleanup.",
        "confirmed_facts": ["User X deleted file Y"],
        "analysis_assessment": [
            "User X's deletion of file Y is routine cleanup.",   # dup
            "AbuseIPDB shows 0 abuse confidence.",               # distinct
        ],
        "key_findings": ["AbuseIPDB returns 0 abuse confidence (source: AbuseIPDB)"],
    }
    once = validate_investigation_result(dict(r))   # copy so we can compare
    twice = validate_investigation_result(dict(once))
    assert once == twice
