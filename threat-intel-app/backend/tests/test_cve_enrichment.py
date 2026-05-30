"""Tests for the per-CVE enrichment sources."""

from __future__ import annotations

from intel.cve_enrichment import extract_cves, _parse_nvd, _parse_epss
from agents.investigation import _src_flagged_malicious
from gti_score import score_cve


# ─── extract_cves ────────────────────────────────────────────────────────────
def test_extract_cves_basic():
    text = "Vulnerability CVE-2024-1234 was exploited and CVE-2023-50001 was patched."
    out = extract_cves(text)
    assert "CVE-2024-1234" in out
    assert "CVE-2023-50001" in out


def test_extract_cves_case_insensitive_dedup():
    text = "cve-2024-1234 and CVE-2024-1234 and Cve-2024-1234"
    out = extract_cves(text)
    assert out == ["CVE-2024-1234"]


def test_extract_cves_rejects_invalid_year():
    text = "Old CVE-1995-001 and future CVE-2099-99999 — both nonsense"
    out = extract_cves(text)
    assert out == []


def test_extract_cves_handles_empty():
    assert extract_cves("") == []
    assert extract_cves("no cves here") == []
    assert extract_cves(None) == []  # type: ignore[arg-type]


def test_extract_cves_seven_digit_number():
    """CVE numbering supports 4-7 digits after the year."""
    out = extract_cves("CVE-2024-1234567 — a huge CVE number")
    assert out == ["CVE-2024-1234567"]


# ─── NVD parser ──────────────────────────────────────────────────────────────
def test_nvd_parser_not_found():
    out = _parse_nvd({"vulnerabilities": []}, "CVE-2099-9999")
    assert out["found"] is False
    assert "no record" in out["summary"].lower()


def test_nvd_parser_critical_cve():
    payload = {"vulnerabilities": [{"cve": {
        "descriptions": [{"lang": "en", "value": "A critical RCE vulnerability."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {
            "baseScore": 9.8, "baseSeverity": "CRITICAL",
        }}]},
        "configurations": [{"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
        ]}]}],
        "published": "2024-01-01T00:00:00.000",
    }}]}
    out = _parse_nvd(payload, "CVE-2024-1234")
    assert out["cvss_v3_score"] == 9.8
    assert out["cvss_v3_severity"] == "CRITICAL"
    assert out["verdict"] == "MALICIOUS"
    assert "vendor product" in out["affected_products"]


def test_nvd_parser_handles_errors():
    out = _parse_nvd({"error": "unreachable", "error_type": "unreachable"}, "CVE-X")
    assert out["source"] == "nvd"
    assert out["error"] == "unreachable"


# ─── EPSS parser ─────────────────────────────────────────────────────────────
def test_epss_high_probability_malicious():
    out = _parse_epss({"data": [{"epss": "0.85", "percentile": "0.99",
                                  "date": "2026-05-30"}]}, "CVE-2024-1234")
    assert out["score"] == 0.85
    assert out["verdict"] == "MALICIOUS"
    assert out["score_pct"] == 85.0


def test_epss_low_probability_clean():
    out = _parse_epss({"data": [{"epss": "0.001", "percentile": "0.1"}]},
                      "CVE-2024-1234")
    assert out["verdict"] == "CLEAN"


def test_epss_not_found():
    out = _parse_epss({"data": []}, "CVE-2099-9999")
    assert out["found"] is False


# ─── _src_flagged_malicious for CVE sources ──────────────────────────────────
def test_cisa_kev_flagged_when_in_kev():
    assert _src_flagged_malicious("cisa_kev", {"in_kev": True}) is True
    assert _src_flagged_malicious("cisa_kev", {"in_kev": False}) is False


def test_nvd_critical_high_flagged():
    assert _src_flagged_malicious("nvd", {"cvss_v3_severity": "CRITICAL"}) is True
    assert _src_flagged_malicious("nvd", {"cvss_v3_severity": "HIGH"}) is True
    assert _src_flagged_malicious("nvd", {"cvss_v3_severity": "MEDIUM"}) is False


def test_epss_seventy_percent_flagged():
    assert _src_flagged_malicious("epss", {"score": 0.75}) is True
    assert _src_flagged_malicious("epss", {"score": 0.5}) is False


def test_urlhaus_any_hit_flagged():
    assert _src_flagged_malicious("urlhaus_url", {"verdict": "MALICIOUS"}) is True
    assert _src_flagged_malicious("urlhaus_payload", {"signature": "Emotet"}) is True


# ─── CVE GTI scoring ─────────────────────────────────────────────────────────
def test_cve_score_kev_match_is_malicious():
    """KEV match alone is the highest-confidence signal — MALICIOUS verdict."""
    out = score_cve({"cisa_kev": {"in_kev": True, "date_added": "2024-05-01",
                                  "ransomware_use": True}}, label="CVE-2024-1234")
    assert out.verdict == "MALICIOUS"
    assert out.score >= 70


def test_cve_score_high_cvss_alone_is_suspicious():
    out = score_cve({"nvd": {"found": True, "cvss_v3_severity": "HIGH",
                              "cvss_v3_score": 7.5}}, label="CVE-X")
    assert out.verdict == "SUSPICIOUS"


def test_cve_score_combined_signals():
    """KEV + CRITICAL CVSS + high EPSS should max-out the score."""
    out = score_cve({
        "cisa_kev": {"in_kev": True, "date_added": "2024-01-01",
                     "ransomware_use": True},
        "nvd":      {"found": True, "cvss_v3_severity": "CRITICAL", "cvss_v3_score": 9.8},
        "epss":     {"found": True, "score": 0.95},
    }, label="CVE-2024-1234")
    assert out.verdict == "MALICIOUS"
    assert out.score == 100   # capped
