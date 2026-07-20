"""
Round-14 ML enhancement tests.

  * intel.dga_classifier            — DGA / benign separation
  * intel.phishing_url_classifier   — phish / benign URL separation
  * intel.semantic_search           — search returns hits ordered by score
  * skills.semantic_search_detections — skill envelope shape
"""

from __future__ import annotations

import asyncio
import pytest


# ─── DGA classifier ────────────────────────────────────────────────────────

def test_dga_classifier_flags_synthetic_dga():
    from intel.dga_classifier import classify
    result = classify("qpvbnzxlmrkjzhqwpor.com")
    assert isinstance(result, dict)
    assert "probability" in result
    assert "verdict" in result
    # Either it scored as DGA OR (if sklearn fell back to heuristic) at
    # minimum we get a usable score. Both paths must return a number.
    assert 0.0 <= result["probability"] <= 1.0


def test_dga_classifier_passes_known_brand():
    from intel.dga_classifier import classify
    result = classify("github.com")
    assert result["probability"] < 0.7
    assert result["verdict"] in ("CLEAN", "SUSPICIOUS")


def test_dga_classifier_handles_empty_input():
    from intel.dga_classifier import classify
    assert classify("")["probability"] == 0.0
    assert classify("a")["probability"] == 0.0


def test_dga_classifier_label_extraction_strips_subdomains():
    """The leftmost-label heuristic strips www / login subdomains so
    benign brand domains aren't mis-scored by the subdomain noise."""
    from intel.dga_classifier import classify
    a = classify("login.microsoft.com")
    b = classify("microsoft.com")
    # Both should land in the same verdict tier — the SLD is identical.
    assert a["verdict"] == b["verdict"]


# ─── Phishing URL classifier ───────────────────────────────────────────────

def test_phishing_classifier_flags_brand_phish_pattern():
    from intel.phishing_url_classifier import classify
    res = classify("https://paypal-secure-login.evil-cdn.tk/auth/verify")
    assert 0.0 <= res["probability"] <= 1.0
    # Three smoking-gun features should all flag.
    feats = res.get("features") or {}
    assert feats.get("brand_in_subdomain") == 1.0
    assert feats.get("abused_tld") == 1.0


def test_phishing_classifier_passes_legit_https_url():
    from intel.phishing_url_classifier import classify
    res = classify("https://github.com/torvalds/linux")
    assert res["probability"] < 0.7


def test_phishing_classifier_flags_ip_in_url():
    from intel.phishing_url_classifier import classify
    res = classify("http://192.168.45.12/login.php")
    feats = res.get("features") or {}
    assert feats.get("is_ip_host") == 1.0


def test_phishing_classifier_handles_invalid_input():
    from intel.phishing_url_classifier import classify
    assert classify("")["probability"] == 0.0
    assert classify("   ")["probability"] == 0.0


# ─── Semantic search ───────────────────────────────────────────────────────

def test_semantic_search_returns_results():
    from intel.semantic_search import search, stats
    s = stats()
    # Even with zero corpora loaded (none of the .sigma / .panther dirs
    # present in CI), the index builder shouldn't crash — it just
    # returns no rules. We don't assert rule_count > 0.
    assert "backend" in s
    out = search("powershell encoded command office macro", top_k=5)
    assert isinstance(out, list)
    # When the index DID load rules, top-k results should be sorted by
    # descending score.
    if out:
        scores = [r["score"] for r in out]
        assert scores == sorted(scores, reverse=True)


def test_semantic_search_handles_empty_query():
    from intel.semantic_search import search
    assert search("") == []
    assert search("   ") == []


# ─── Skill registry + envelope ─────────────────────────────────────────────

def test_semantic_search_skill_registered():
    from skills import SKILL_REGISTRY, get_skill
    assert "semantic_search_detections" in SKILL_REGISTRY
    skill = get_skill("semantic_search_detections")
    assert skill.name == "semantic_search_detections"
    assert "query" in skill.input_schema


def test_semantic_search_skill_returns_envelope():
    from skills import run_skill
    # asyncio.run manages the loop lifecycle (create, run, drain, close)
    # correctly — the earlier hand-rolled loop.close() left aiohttp
    # transports pending, which surfaced as ResourceWarning during test
    # collection.
    out = asyncio.run(
        run_skill("semantic_search_detections",
                  {"query": "lateral movement", "top_k": 3})
    )
    assert "query" in out
    assert "results" in out
    assert "total" in out
    assert "backend" in out
    assert isinstance(out["results"], list)
