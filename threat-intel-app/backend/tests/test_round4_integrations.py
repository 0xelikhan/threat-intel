"""
Behavioural tests for the round-4 OSS integrations sourced from
deep-walks of awesome-yara and awesome-threat-detection:

  * intel.sublime_rules        — Sublime email detection corpus
  * intel.chronicle_rules      — Google Chronicle YARA-L corpus
  * intel.olafhartong_th       — olafhartong/ThreatHunting + sentinel-attack
                                  KQL/Sentinel rules
  * intel.attack_datasets      — Splunk attack_data labelled fixtures
                                  (mordor surfaced but skipped on GPL-3.0)

All loaders exercise their graceful-missing-corpus path. The unified
match_detections skill is verified to fan out across the eight bundled
corpora and return every expected source key.
"""

from __future__ import annotations

import asyncio


# ─── Sublime email detection rules ──────────────────────────────────────────
def test_sublime_rules_handles_missing_corpus():
    from intel.sublime_rules import (
        match_by_techniques, match_by_attack_type, stats,
    )
    s = stats()
    assert s["loaded"] is True
    assert isinstance(match_by_techniques(["T1566", "T1566.001"]), list)
    assert isinstance(match_by_attack_type("Phishing"), list)


# ─── Chronicle YARA-L corpus ────────────────────────────────────────────────
def test_chronicle_rules_handles_missing_corpus():
    from intel.chronicle_rules import match_by_techniques, stats
    s = stats()
    assert s["loaded"] is True
    assert isinstance(match_by_techniques(["T1059.001"]), list)


# ─── olafhartong KQL / Sentinel ─────────────────────────────────────────────
def test_olafhartong_handles_missing_corpus():
    from intel.olafhartong_th import match_by_techniques, stats
    s = stats()
    assert s["loaded"] is True
    out = match_by_techniques(["T1059.001"])
    assert isinstance(out, list)


# ─── attack_data labelled fixtures ──────────────────────────────────────────
def test_attack_datasets_handles_missing_corpus():
    from intel.attack_datasets import samples_for_technique, stats
    s = stats()
    assert s["loaded"] is True
    # Mordor is GPL-3.0 — even if present, we never ingest it
    assert "mordor_skipped" in s
    out = samples_for_technique("T1059.001")
    assert isinstance(out, list)
    assert samples_for_technique("") == []


# ─── Unified match_detections — now spans 8 corpora ─────────────────────────
def test_match_detections_returns_eight_source_keys():
    from skills import run_skill
    out = asyncio.run(run_skill("match_detections", {
        "mitre_techniques": ["T1059.001"], "per_source_max": 3,
    }))
    for src in ("sigma", "panther", "splunk", "mitre_car",
                "hunter_playbook", "sublime", "chronicle", "olafhartong"):
        assert src in out, f"missing source key: {src}"
        assert isinstance(out[src], list)
    assert isinstance(out["corpus_stats"], dict)
    assert "sublime" in out["corpus_stats"]
    assert "chronicle" in out["corpus_stats"]


# ─── YARA scanner now references 20 RULE_SOURCES ────────────────────────────
def test_yara_scanner_rule_sources_extended():
    from intel.yara_scanner import RULE_SOURCES
    labels = [label for label, _ in RULE_SOURCES]
    # Original 3 + 7 round-2 + 13 round-4 = 23 labels, but malcontent +
    # the 3 pre-existing make it 23 total (verify a few known additions).
    assert "ditekshen detection" in labels
    assert "delivr-to detections" in labels
    assert "Google Chronicle GCTI" in labels
    assert "Intezer Labs" in labels
    assert "CyStack stealer-fingerprints" in labels
    assert len(RULE_SOURCES) >= 20
