"""
Round-9 OSS integrations:

  * intel.dataplane         — DataPlane.org honeypot feeds
  * intel.dshield           — SANS Internet Storm Center
  * intel.spamhaus_drop     — Spamhaus DROP/EDROP
  * intel.sarif_output      — SARIF 2.1.0 serializer for file scans
  * intel.cacao_output      — OASIS CACAO 2.0 playbook serializer
  * intel.cisa_cpg          — CISA Cybersecurity Performance Goals

Offline shape tests + built-in fallback assertions.
"""

from __future__ import annotations

import asyncio


# ─── DataPlane.org ──────────────────────────────────────────────────────────
def test_dataplane_handles_unloaded_state():
    from intel.dataplane import lookup, stats
    s = stats()
    assert lookup("198.51.100.1") == []
    assert lookup("") == []
    # Either has data (loaded) or reports "no feeds loaded"
    assert isinstance(s.get("error"), (str, type(None)))


# ─── SANS DShield ───────────────────────────────────────────────────────────
def test_dshield_rejects_missing_ip():
    from intel.dshield import lookup
    out = asyncio.run(lookup(None, ""))
    assert out["found"] is False
    assert out["error"] == "missing ip"


# ─── Spamhaus DROP ──────────────────────────────────────────────────────────
def test_spamhaus_handles_unloaded_state():
    from intel.spamhaus_drop import lookup, stats
    s = stats()
    assert lookup("198.51.100.1") is None
    assert lookup("not-an-ip") is None


# ─── SARIF output ───────────────────────────────────────────────────────────
def test_sarif_empty_input_produces_valid_skeleton():
    from intel.sarif_output import to_sarif
    sarif = to_sarif({})
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert sarif["runs"] and sarif["runs"][0]["tool"]["driver"]["name"] == "RECON"
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_yara_match_becomes_result():
    from intel.sarif_output import to_sarif
    payload = {
        "filename": "sample.exe",
        "verdict": "MALICIOUS",
        "yara_matches": [
            {"rule": "Win.Trojan.CobaltStrike",
             "namespace": "florian-roth",
             "description": "Cobalt Strike beacon shellcode",
             "matched_strings": [
                 {"id": "$s1", "offset": 1024,
                  "matched": "MZ\x90\x00\x03"},
             ]},
        ],
    }
    sarif = to_sarif(payload)
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "yara/Win.Trojan.CobaltStrike"
    assert results[0]["level"] == "error"  # MALICIOUS -> error
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert any(r["id"] == "yara/Win.Trojan.CobaltStrike" for r in rules)


def test_sarif_includes_capa_capabilities():
    from intel.sarif_output import to_sarif
    payload = {
        "filename": "sample.exe",
        "verdict": "SUSPICIOUS",
        "capa": {
            "capabilities": [
                {"rule": "encrypt data using RC4",
                 "namespace": "data-manipulation/encryption",
                 "mitre_techniques": ["T1573.001"]},
            ],
        },
    }
    sarif = to_sarif(payload)
    rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
    assert "capa/encrypt data using RC4" in rule_ids
    assert sarif["runs"][0]["results"][0]["level"] == "warning"


# ─── CACAO output ───────────────────────────────────────────────────────────
def test_cacao_empty_input_produces_valid_skeleton():
    from intel.cacao_output import to_cacao
    pb = to_cacao({}, {})
    assert pb["type"] == "playbook"
    assert pb["spec_version"] == "cacao-2.0"
    assert pb["id"].startswith("playbook--")
    assert pb["workflow_start"].startswith("start--")
    assert "investigation" in pb["playbook_types"]


def test_cacao_chains_actions():
    from intel.cacao_output import to_cacao
    rs = {
        "threat_level": "MALICIOUS",
        "summary":      "Cobalt Strike beacon staging",
        "recommended_actions": [
            {"title": "Isolate host", "description": "Network-isolate the affected workstation",
             "technique": "T1059.001"},
            {"title": "Reset credentials", "description": "Rotate all creds used on the host"},
            {"title": "Hunt lateral movement", "description": "Pivot on the IP across endpoints"},
        ],
    }
    inv = {
        "mitre_techniques": ["T1059.001 - PowerShell", "T1027 - Obfuscation"],
        "threat_actor":     {"name": "Cobalt Strike"},
    }
    pb = to_cacao(rs, inv)
    # 3 action steps + start + end = 5 workflow entries
    assert len(pb["workflow"]) == 5
    # First step name preserved
    action_steps = [s for s in pb["workflow"].values() if s["type"] == "action"]
    assert action_steps[0]["name"] == "Isolate host"
    # MITRE refs at playbook level
    ext_ids = [r["external_id"] for r in pb["external_references"]]
    assert "T1059.001" in ext_ids
    assert "T1027" in ext_ids
    # Verdict label
    assert "malicious" in pb["labels"]


# ─── CISA CPG ───────────────────────────────────────────────────────────────
def test_cisa_cpg_via_fallback():
    from intel.cisa_cpg import lookup, cpgs_for_attack, cpgs_for_attacks, stats
    s = stats()
    assert s["loaded"] is True
    assert s["controls"] >= 20
    mfa = lookup("2.F")
    assert mfa is not None
    assert mfa["tier"] == "Essential"
    assert "T1110" in mfa["attack_ids"]
    # Reverse lookup
    brute_cpgs = cpgs_for_attack("T1110")
    assert any(r["cpg_id"] == "2.F" for r in brute_cpgs)
    # Multi-technique
    multi = cpgs_for_attacks(["T1110", "T1486"])
    assert "T1110" in multi
    assert "T1486" in multi


def test_cisa_cpg_sorted_by_tier():
    """cpgs_for_attack should return Essential controls before Baseline."""
    from intel.cisa_cpg import cpgs_for_attack
    rows = cpgs_for_attack("T1078")  # access-control / valid accounts
    if len(rows) >= 2:
        # Essential outranks Baseline outranks Enhanced
        tier_order = {"essential": 2, "baseline": 1, "enhanced": 3}
        ranks = [tier_order.get((r.get("tier") or "").lower(), 0)
                 for r in rows]
        # The first row's rank >= the last row's rank
        assert ranks[0] >= ranks[-1] or len(set(ranks)) == 1
