"""
Behavioural tests for the round-3 OSS integrations:

  * intel.malcontent_rules     — chainguard malcontent capability buckets
  * intel.eset_families        — ESET malware-ioc family IOC corpus
  * intel.panther_rules        — panther-analysis cloud detections
  * intel.splunk_content       — Splunk security_content
  * intel.mitre_car            — MITRE CAR analytics
  * intel.emulation_plans      — CTID Adversary Emulation Library
  * intel.hunter_playbook      — OTRF ThreatHunter-Playbook
  * intel.ads_framework        — Palantir ADS Framework (always loaded)
  * intel.forensic_artifacts   — ForensicArtifacts/artifacts
  * intel.cloud_fixtures       — DataDog grimoire
  * intel.phishing_db          — Phishing.Database (live feed)
  * skills.match_detections    — unified detection-corpora fan-out
  * skills.classify_capabilities — malcontent capability classification

All graceful-missing-corpus paths are exercised. The corpora are
operator-fetched via scripts/fetch_*.sh; tests just confirm the
loaders don't blow up when the dir is missing and that the public
API surface is stable.
"""

from __future__ import annotations

import asyncio

import pytest


# ─── ADS framework (always loaded — no corpus to fetch) ─────────────────────
def test_ads_framework_has_nine_sections():
    from intel.ads_framework import ADS_SECTIONS, ads_section_outline, ads_headings
    assert len(ADS_SECTIONS) == 9
    headings = ads_headings()
    assert "Goal" in headings
    assert "Validation" in headings
    assert "Response" in headings
    outline = ads_section_outline()
    assert "## Alerting & Detection Strategy" in outline
    assert "- **Goal**" in outline


# ─── malcontent (graceful missing + classify shape) ─────────────────────────
def test_malcontent_handles_missing_corpus():
    from intel.malcontent_rules import stats, classify
    s = stats()
    assert s["loaded"] is True
    out = classify(["SomeRuleName"])
    assert out["total_matched"] == 0
    assert isinstance(out["unmatched"], list)
    assert isinstance(out["by_bucket"], dict)


def test_classify_capabilities_skill_shape():
    """Skill returns the schema-declared keys even when corpus is empty."""
    from skills import run_skill
    out = asyncio.run(run_skill("classify_capabilities", {
        "rule_names": ["nonexistent_rule"],
    }))
    for k in ("by_bucket", "bucket_counts", "tactics",
              "unmatched", "total_matched"):
        assert k in out


# ─── ESET malware-ioc (graceful missing) ────────────────────────────────────
def test_eset_families_handles_missing_corpus():
    from intel.eset_families import lookup_hash, lookup_domain, lookup_ip, stats
    s = stats()
    assert s["loaded"] is True
    assert lookup_hash("0" * 64) is None
    assert lookup_domain("example.com") is None
    assert lookup_ip("198.51.100.1") is None


# ─── panther-analysis (graceful missing + index shape) ──────────────────────
def test_panther_handles_missing_corpus():
    from intel.panther_rules import match_by_techniques, stats, match_by_log_type
    s = stats()
    assert s["loaded"] is True
    assert match_by_techniques(["T1059.001"]) == [] or s["rules"] > 0
    assert match_by_log_type("Okta.SystemLog") == [] or s["rules"] > 0


# ─── Splunk security_content (graceful missing) ─────────────────────────────
def test_splunk_content_handles_missing_corpus():
    from intel.splunk_content import match_by_techniques, stats
    s = stats()
    assert s["loaded"] is True
    out = match_by_techniques(["T1059.001"])
    assert isinstance(out, list)


# ─── MITRE CAR (graceful missing) ───────────────────────────────────────────
def test_mitre_car_handles_missing_corpus():
    from intel.mitre_car import match_by_techniques, stats
    s = stats()
    assert s["loaded"] is True
    out = match_by_techniques(["T1059"])
    assert isinstance(out, list)


# ─── CTID Adversary Emulation Library (graceful missing) ────────────────────
def test_emulation_plans_handles_missing_corpus():
    from intel.emulation_plans import lookup_actor, stats
    s = stats()
    assert s["loaded"] is True
    assert lookup_actor("APT29") is None or isinstance(lookup_actor("APT29"), dict)
    assert lookup_actor("") is None


# ─── OTRF ThreatHunter-Playbook (graceful missing) ──────────────────────────
def test_hunter_playbook_handles_missing_corpus():
    from intel.hunter_playbook import match_by_techniques, stats
    s = stats()
    assert s["loaded"] is True
    out = match_by_techniques(["T1059.001"])
    assert isinstance(out, list)


# ─── ForensicArtifacts (graceful missing) ───────────────────────────────────
def test_forensic_artifacts_handles_missing_corpus():
    from intel.forensic_artifacts import evidence_for_techniques, stats
    s = stats()
    assert s["loaded"] is True
    out = evidence_for_techniques(["Persistence"], host_os="Windows")
    assert isinstance(out, list)


# ─── DataDog grimoire (graceful missing) ────────────────────────────────────
def test_cloud_fixtures_handles_missing_corpus():
    from intel.cloud_fixtures import samples_for_provider, samples_for_technique, stats
    s = stats()
    assert s["loaded"] is True
    assert samples_for_provider("aws") == [] or s["fixtures"] > 0
    assert samples_for_technique("aws.persistence.iam-backdoor-user") == [] \
            or s["fixtures"] > 0
    assert samples_for_provider("") == []


# ─── Phishing.Database (no network in test) ─────────────────────────────────
def test_phishing_db_is_known_phish_is_false_when_not_loaded():
    from intel.phishing_db import is_known_phish
    assert is_known_phish("microsoft.com") is False
    assert is_known_phish("") is False


# ─── Unified match_detections skill ─────────────────────────────────────────
def test_match_detections_returns_all_five_source_keys():
    """The skill should always return the five source keys + corpus_stats,
    even when several corpora aren't loaded."""
    from skills import run_skill
    out = asyncio.run(run_skill("match_detections", {
        "mitre_techniques": ["T1059.001", "T1027"],
        "per_source_max":   3,
    }))
    for src in ("sigma", "panther", "splunk", "mitre_car", "hunter_playbook"):
        assert src in out
        assert isinstance(out[src], list)
    assert isinstance(out["corpus_stats"], dict)
    # SigmaHQ is bundled, so we should get at least one hit on T1059.001.
    assert len(out["sigma"]) >= 1


def test_match_detections_handles_empty_techniques():
    from skills import run_skill
    out = asyncio.run(run_skill("match_detections", {
        "mitre_techniques": [], "per_source_max": 3,
    }))
    assert out["total"] == 0
    for src in ("sigma", "panther", "splunk", "mitre_car", "hunter_playbook"):
        assert out[src] == []


# ─── Skill registry coverage ────────────────────────────────────────────────
def test_skill_registry_includes_round3_skills():
    from skills import SKILL_REGISTRY
    for name in ("classify_capabilities", "match_detections",
                 "match_sigma_rules", "analyze_capabilities"):
        assert name in SKILL_REGISTRY
