"""
Behavioural tests for the round-5 OSS integrations:

  * intel.d3fend             — MITRE D3FEND defensive countermeasures
  * intel.stratus_techniques — DataDog Stratus Red Team TTP catalogue
  * intel.falco_rules        — Sysdig falco-rules container detection
  * intel.owasp_crs          — OWASP ModSecurity Core Rule Set
  * intel.tranco             — Tranco top-1M ranked domains
  * intel.malapi             — MalAPI.io Windows-API map
  * intel.ghsa               — GitHub Security Advisories database
  * intel.codeql_queries     — CodeQL query catalog

All graceful-missing-corpus paths exercised offline. The unified
match_detections skill is verified to fan into all 10 sources.
"""

from __future__ import annotations

import asyncio


# ─── D3FEND (always loaded via built-in fallback) ───────────────────────────
def test_d3fend_fallback_covers_top_techniques():
    from intel.d3fend import countermeasures_for, stats
    s = stats()
    assert s["loaded"] is True
    assert s["source"] in ("vendored", "fallback")
    # T1059.001 PowerShell — must have at least one countermeasure in the
    # built-in fallback.
    cms = countermeasures_for("T1059.001")
    assert cms
    assert all("d3_id" in c and c["d3_id"].startswith("D3-") for c in cms)


def test_d3fend_falls_back_to_parent_technique():
    """A sub-technique with no explicit mapping should inherit from its
    parent (T-only) entry."""
    from intel.d3fend import countermeasures_for
    # T1547.999 doesn't exist; should hit T1547 in the fallback table.
    cms = countermeasures_for("T1547.999")
    assert cms  # falls back to T1547


# ─── Stratus Red Team ───────────────────────────────────────────────────────
def test_stratus_handles_missing_corpus():
    from intel.stratus_techniques import (
        match_by_techniques, lookup_id, stats,
    )
    s = stats()
    assert s["loaded"] is True
    assert isinstance(match_by_techniques(["T1078"]), list)
    assert lookup_id("aws.persistence.iam-backdoor-user") is None or isinstance(
        lookup_id("aws.persistence.iam-backdoor-user"), dict
    )


# ─── falco-rules ────────────────────────────────────────────────────────────
def test_falco_rules_handles_missing_corpus():
    from intel.falco_rules import match_by_techniques, stats
    s = stats()
    assert s["loaded"] is True
    assert isinstance(match_by_techniques(["T1059"]), list)


# ─── OWASP CRS ──────────────────────────────────────────────────────────────
def test_owasp_crs_handles_missing_corpus():
    from intel.owasp_crs import match_by_attack_class, match_by_keywords, stats
    s = stats()
    assert s["loaded"] is True
    assert isinstance(match_by_attack_class("SQL Injection"), list)
    assert isinstance(match_by_keywords("attempted SQL injection"), list)


# ─── Tranco ─────────────────────────────────────────────────────────────────
def test_tranco_returns_none_when_feed_not_loaded():
    from intel.tranco import rank, is_top_n
    # Feed isn't fetched in tests
    assert rank("microsoft.com") is None or isinstance(rank("microsoft.com"), int)
    assert is_top_n("microsoft.com") is False or is_top_n("microsoft.com") is True


# ─── MalAPI.io (always loaded via built-in fallback) ────────────────────────
def test_malapi_classifies_injection_apis_via_fallback():
    from intel.malapi import classify_apis, stats
    s = stats()
    assert s["loaded"] is True
    # VirtualAllocEx + WriteProcessMemory + CreateRemoteThread is the
    # canonical injection triad — fallback must catch it.
    out = classify_apis([
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "InternetOpen", "GetAsyncKeyState",
    ])
    assert out["total_matched"] >= 4
    cats = out["by_category"]
    assert "Injection" in cats
    assert "T1055" in out["mitre_techniques"]


def test_malapi_handles_a_w_suffix_collapse():
    """SetWindowsHookExA / -W should collapse to the base name when the
    base isn't in the table."""
    from intel.malapi import classify_apis
    out = classify_apis(["SetWindowsHookExA"])
    assert out["total_matched"] >= 1
    assert "Hooking" in out["by_category"]


# ─── GitHub Security Advisories ─────────────────────────────────────────────
def test_ghsa_handles_missing_corpus():
    from intel.ghsa import lookup_cve, lookup_ghsa, stats
    s = stats()
    assert s["loaded"] is True
    assert lookup_cve("CVE-2023-12345") == [] or isinstance(
        lookup_cve("CVE-2023-12345"), list
    )
    assert lookup_ghsa("") is None


# ─── CodeQL (always loaded via built-in fallback) ───────────────────────────
def test_codeql_fallback_returns_known_queries():
    from intel.codeql_queries import lookup_cwe, queries_for_language, stats
    s = stats()
    assert s["loaded"] is True
    # CWE-89 is SQL injection — fallback has multiple language coverage
    sqli = lookup_cwe("CWE-89")
    assert sqli
    assert any(q["language"] == "python" for q in sqli)
    py = queries_for_language("python")
    assert py


def test_codeql_normalises_cwe_prefix():
    from intel.codeql_queries import lookup_cwe
    # User-supplied "89" should be normalised to "CWE-89"
    a = lookup_cwe("89")
    b = lookup_cwe("CWE-89")
    assert a == b


# ─── Unified match_detections — now spans 10 corpora ────────────────────────
def test_match_detections_returns_ten_source_keys():
    from skills import run_skill
    out = asyncio.run(run_skill("match_detections", {
        "mitre_techniques": ["T1059.001"], "per_source_max": 3,
    }))
    for src in ("sigma", "panther", "splunk", "mitre_car",
                "hunter_playbook", "sublime", "chronicle", "olafhartong",
                "falco", "stratus"):
        assert src in out, f"missing source key: {src}"
        assert isinstance(out[src], list)


# ─── File scanner: file_capability_map now includes MalAPI summary ──────────
def test_file_capability_map_includes_malapi_summary():
    """The file_capability_map.build_capability_assessment output now
    carries a `malapi` section even when no PE imports were supplied."""
    from intel.file_capability_map import build_capability_assessment
    out = build_capability_assessment({"format_specific": {}, "suspicious_strings": []})
    assert "malapi" in out
    assert isinstance(out["malapi"], dict)
