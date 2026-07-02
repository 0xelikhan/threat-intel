"""Round-17 tests — signal_priority framework + disposition safety net.

The core failure mode we're catching: the LLM produces a summary that
correctly identifies a nation-state actor + upstream high-risk marker,
then recommends CLEAR based on public-TI reputation being "clean".
These tests pin the deterministic tier extraction + the auto-override
that stops that contradiction from reaching production.
"""

from __future__ import annotations


# ─── Tier extraction ───────────────────────────────────────────────────────

def test_tier1_named_actor_in_log_blocks_clear():
    from intel.signal_priority import extract_tier_signals, should_block_clear
    state = {
        "raw_input": (
            "Gareth Fawke signed in from an IP address associated with a "
            "nation-state actor, STORM-3052, indicating a potential security "
            "risk. The action was flagged as high risk."
        ),
        "enrichments": {"ips": {"43.130.98.43": {
            "virustotal": {"malicious": 0},
            "abuseipdb":  {"abuseScore": 0},
        }}},
    }
    t = extract_tier_signals(state)
    assert t["tier_1"], f"expected TIER 1 named-actor + high-risk match, got: {t}"
    assert t["verdict_floor"] == "HIGH"
    assert t["block_clear"] is True
    blocked, reason = should_block_clear(state)
    assert blocked is True
    assert "TIER 1" in reason or "signals fired" in reason


def test_tier1_upstream_high_risk_marker_blocks_clear():
    from intel.signal_priority import extract_tier_signals
    state = {
        "raw_input": "Sign-in event · Risk Level: High · impossible travel detected",
        "enrichments": {},
    }
    t = extract_tier_signals(state)
    assert t["tier_1"]
    assert t["block_clear"] is True


def test_tier1_apt_and_g_intrusion_set_match():
    from intel.signal_priority import extract_tier_signals
    state = {"raw_input": "This activity overlaps with APT29 (G0016) tradecraft."}
    t = extract_tier_signals(state)
    assert t["tier_1"]


def test_tier1_named_malware_family_from_investigation():
    from intel.signal_priority import extract_tier_signals
    state = {
        "raw_input": "Endpoint alert on host WORKSTATION-04.",
        "response_summary": {"malware_family": "LockBit"},
    }
    t = extract_tier_signals(state)
    assert any("malware family" in s["signal"] for s in t["tier_1"])
    assert t["block_clear"] is True


def test_tier1_vt_5_plus_engines():
    from intel.signal_priority import extract_tier_signals
    state = {
        "raw_input": "hash lookup",
        "enrichments": {"hashes": {"deadbeef": {
            "virustotal": {"malicious": 12},
        }}},
    }
    t = extract_tier_signals(state)
    assert any("5 engines" in s["signal"] for s in t["tier_1"])


def test_tier2_vt_2_4_engines_alone_does_not_block_clear():
    from intel.signal_priority import extract_tier_signals
    state = {
        "raw_input": "hash lookup",
        "enrichments": {"hashes": {"deadbeef": {
            "virustotal": {"malicious": 3},
        }}},
    }
    t = extract_tier_signals(state)
    assert t["tier_2"]
    assert not t["tier_1"]
    # single TIER 2 → MEDIUM floor. block_clear depends on downweight.
    assert t["verdict_floor"] == "MEDIUM"


def test_tier2_pair_blocks_clear():
    from intel.signal_priority import extract_tier_signals
    state = {
        "raw_input": "IP + hash under investigation",
        "enrichments": {
            "ips":    {"1.2.3.4":  {"abuseipdb": {"abuseScore": 90}}},
            "hashes": {"deadbeef": {"virustotal": {"malicious": 3}}},
        },
    }
    t = extract_tier_signals(state)
    assert len(t["tier_2"]) >= 2
    assert t["block_clear"] is True


def test_downweight_misp_warninglist_only_does_not_block_clear():
    from intel.signal_priority import extract_tier_signals
    state = {
        "raw_input": "IP 8.8.8.8 looked up.",
        "suppressed_iocs": {"ips": ["8.8.8.8"]},
        "enrichments": {"ips": {"9.9.9.9": {
            "virustotal": {"malicious": 0},
            "abuseipdb":  {"abuseScore": 0},
        }}},
    }
    t = extract_tier_signals(state)
    assert t["downweight"]
    assert t["block_clear"] is False


# ─── Correlation prose ─────────────────────────────────────────────────────

def test_correlation_prose_mentions_tier1_when_actor_present():
    from intel.signal_priority import (extract_tier_signals,
                                        format_signal_correlation)
    state = {"raw_input": "Sign-in from Storm-3052 marked High risk."}
    t = extract_tier_signals(state)
    prose = format_signal_correlation(state, t)
    assert "TIER 1" in prose
    assert "CLEAR is BLOCKED" in prose
    assert "verdict floor" in prose.lower()


def test_correlation_prose_empty_when_no_signals():
    from intel.signal_priority import format_signal_correlation
    prose = format_signal_correlation({"raw_input": "hi", "enrichments": {}})
    assert prose == ""


# ─── Feedback loop guard ───────────────────────────────────────────────────

def test_actor_detection_ignores_ai_generated_summary():
    """Regression guard: the actor detection must NOT read the AI's own
    summary — otherwise the AI recognises an actor once and every future
    disposition on unrelated alerts inherits the block. Only the raw log
    input is authoritative for TIER 1 actor detection."""
    from intel.signal_priority import extract_tier_signals
    state = {
        "raw_input":     "Ordinary sign-in event, no attribution here.",
        "response_summary": {
            "summary": "The AI mistakenly wrote 'this is Storm-3052' here.",
        },
    }
    t = extract_tier_signals(state)
    # No TIER 1 actor fires because the raw log is clean.
    assert not any("actor" in s["signal"] for s in t["tier_1"])
