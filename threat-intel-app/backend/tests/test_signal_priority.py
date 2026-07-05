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

def test_threatlocker_builtin_policy_fires_downweight_signals():
    """Real ThreatLocker allowlist audit event — Chromium ChatGPT
    extension permitted by a BUILT-IN policy under a Google-signed
    chrome.exe. Should be INFORMATIONAL, block_clear=False, with two
    strong DOWNWEIGHT signals so the LLM confidently picks CLEAR."""
    from intel.signal_priority import extract_tier_signals
    log = (
        "Date: Jul 2, 2026, 6:56:46 AM\n"
        "User: AZUREAD\\STUARTCHOAK\n"
        "Policy Name: Chromium Ext Chat GPT (Built-In)\n"
        "Action Type: Execute\n"
        "Action: Permit\n"
        "Process Path : c:\\program files\\google\\chrome\\application\\chrome.exe\n"
        "Application Name : Chromium Ext Chat GPT for Chrome (Built-In)\n"
        "Monitor Only : true\n"
        "SHA256 : 9376139fba3a19836f1776c62ea2d5d6d476dc226d6aaa936d3c6110b0dc473c\n"
        "Effective Action : Permitted\n"
        "Parent Process Certificate : cn=google llc, o=google llc, l=mountain view\n"
    )
    t = extract_tier_signals({"raw_input": log})
    assert not t["tier_1"]
    assert not t["tier_2"]
    assert t["verdict_floor"] == "INFORMATIONAL"
    assert t["block_clear"] is False
    dw_signals = [s["signal"] for s in t["downweight"]]
    assert any("known-good" in s or "signed" in s for s in dw_signals), dw_signals
    assert any("permitted" in s.lower() for s in dw_signals), dw_signals


def test_chrome_msedge_firefox_process_paths_are_downweight():
    from intel.signal_priority import extract_tier_signals
    for path in (
        r"c:\program files\google\chrome\application\chrome.exe",
        r"c:\program files (x86)\microsoft\edge\application\msedge.exe",
        r"c:\program files\mozilla firefox\firefox.exe",
    ):
        t = extract_tier_signals({"raw_input": f"Process: {path}"})
        assert any("known-good" in s["signal"] or "signed" in s["signal"]
                   for s in t["downweight"]), (path, t)


def test_tenant_permit_alone_not_downweight_needs_two_markers():
    """Just 'Action: Permit' without other permit markers shouldn't
    trigger the tenant policy downweight — we want at least two of
    (Action:Permit, Effective Action:Permitted, Monitor Only:true)
    firing together to avoid false positives on generic permit logs."""
    from intel.signal_priority import extract_tier_signals
    t = extract_tier_signals({"raw_input": "Action: Permit"})
    perm_hits = [s for s in t["downweight"]
                 if "permitted" in s["signal"].lower()]
    assert not perm_hits, perm_hits


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


def test_pua_family_is_tier2_not_tier1():
    """Regression guard: `malware_family` values prefixed with PUA:,
    PUABundler:, HackTool:, Tool:, Adware:, Bundler:, Misleading:,
    Riskware: must NOT fire the TIER 1 `named malware family
    attributed` signal — those are Microsoft's unwanted-software
    categorizations, not traditional malware families. They should
    fire as TIER 2 `PUA / HackTool family attributed` instead."""
    from intel.signal_priority import extract_tier_signals
    for fam in ("PUA:Win32/AskToolbar", "PUABundler:Win32/OfferCore",
                 "HackTool:Script/AutoKMS!AMTB", "Adware:Win32/InstallCore",
                 "Riskware:Win32/CoinMiner"):
        state = {"raw_input": f"Defender detected {fam}",
                  "malware_family": fam}
        t = extract_tier_signals(state)
        # Must NOT be in TIER 1
        assert not any("named malware family" in s["signal"] for s in t["tier_1"]), \
            f"{fam} incorrectly fired TIER 1 malware family"
        # MUST be in TIER 2
        assert any("PUA / HackTool family" in s["signal"] for s in t["tier_2"]), \
            f"{fam} should fire TIER 2 PUA / HackTool family"


def test_real_malware_family_still_fires_tier1():
    """Regression guard: real malware family names (LockBit, Emotet,
    TrickBot, etc.) must still fire the TIER 1 signal. Only the
    Microsoft PUA/HackTool prefixes are gated out."""
    from intel.signal_priority import extract_tier_signals
    for fam in ("LockBit", "Emotet", "TrickBot", "Cobalt Strike beacon",
                 "BlackCat", "Conti"):
        state = {"raw_input": f"Confirmed {fam} activity",
                  "malware_family": fam}
        t = extract_tier_signals(state)
        assert any("named malware family" in s["signal"] for s in t["tier_1"]), \
            f"{fam} should still fire TIER 1"
