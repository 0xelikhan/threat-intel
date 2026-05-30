"""Tests for the breach-database + paste-site enrichment sources."""

from __future__ import annotations

from intel.breach_sources import (
    _parse_hibp, _parse_dehashed, _parse_intelx,
    _parse_criminal_ip, _parse_urlscan_screenshot,
)
from agents.investigation import _src_flagged_malicious, compute_enrichment_summary


# ─── HIBP ────────────────────────────────────────────────────────────────────
def test_hibp_clean_when_no_breaches():
    """404 from HIBP means 'no breaches found' — surface as CLEAN, not error."""
    out = _parse_hibp({"error": "404 Not Found", "error_type": "http_error"},
                      "clean@example.com")
    assert out["breach_count"] == 0
    assert out["verdict"] == "CLEAN"
    assert out["source"] == "hibp"


def test_hibp_one_breach_is_suspicious():
    breaches = [{"Name": "LinkedIn", "Title": "LinkedIn", "BreachDate": "2012-05-05",
                 "PwnCount": 164_611_595, "DataClasses": ["Emails", "Passwords"]}]
    out = _parse_hibp(breaches, "u@example.com")
    assert out["breach_count"] == 1
    assert out["verdict"] == "SUSPICIOUS"


def test_hibp_fifteen_breaches_is_malicious():
    """User spec: an email in 15 data breaches is a strong indicator of
    a compromised account — must verdict MALICIOUS."""
    breaches = [
        {"Name": f"Breach{i}", "Title": f"Breach {i}", "BreachDate": "2023-01-01",
         "PwnCount": 1000, "DataClasses": ["Emails", "Passwords"]}
        for i in range(15)
    ]
    out = _parse_hibp(breaches, "compromised@example.com")
    assert out["breach_count"] == 15
    assert out["verdict"] == "MALICIOUS"


def test_hibp_summary_lists_total_pwn_count():
    breaches = [{"Name": "A", "Title": "A", "BreachDate": "2020-01-01",
                 "PwnCount": 1_000_000, "DataClasses": ["Emails"]}]
    out = _parse_hibp(breaches, "u@e.com")
    assert "1,000,000" in out["summary"]


def test_hibp_caps_breach_list_at_twenty():
    breaches = [{"Name": f"B{i}", "Title": f"B{i}", "BreachDate": "2023-01-01",
                 "PwnCount": 1, "DataClasses": []} for i in range(30)]
    out = _parse_hibp(breaches, "u@e.com")
    assert out["breach_count"] == 30
    assert len(out["breaches"]) == 20


# ─── Dehashed ────────────────────────────────────────────────────────────────
def test_dehashed_no_hits_clean():
    out = _parse_dehashed({"total": 0, "entries": []}, "u@e.com")
    assert out["verdict"] == "CLEAN"
    assert out["total"] == 0


def test_dehashed_strips_plaintext_passwords():
    """Dehashed returns plaintext passwords — we MUST never surface them.
    Only the has_password / has_hash booleans go into the UI."""
    entries = {"total": 1, "entries": [{
        "database_name": "Leak1", "email": "u@e.com",
        "password": "hunter2-secret-do-not-leak", "hashed_password": "abc"
    }]}
    out = _parse_dehashed(entries, "u@e.com")
    hit = out["hits"][0]
    assert hit["has_password"] is True
    assert hit["has_hash"] is True
    assert "password" not in hit
    assert "hunter2" not in str(out)


def test_dehashed_ten_hits_malicious():
    entries = {"total": 12, "entries": [{"database_name": "x"}] * 12}
    out = _parse_dehashed(entries, "u@e.com")
    assert out["verdict"] == "MALICIOUS"


# ─── IntelX ──────────────────────────────────────────────────────────────────
def test_intelx_no_records_clean():
    out = _parse_intelx({"records": []}, "domain.example")
    assert out["count"] == 0
    assert out["verdict"] == "CLEAN"


def test_intelx_buckets_deduped_and_sorted():
    records = {"records": [
        {"bucket": "pastes",    "name": "p1"},
        {"bucket": "darkweb",   "name": "d1"},
        {"bucket": "pastes",    "name": "p2"},
        {"bucket": "leaks",     "name": "l1"},
    ]}
    out = _parse_intelx(records, "x")
    assert out["buckets"] == sorted(["pastes", "darkweb", "leaks"])
    assert out["count"] == 4


# ─── Criminal IP ─────────────────────────────────────────────────────────────
def test_criminal_ip_dangerous_inbound_is_malicious():
    payload = {"score": {"inbound": "dangerous", "outbound": "safe"},
               "issues": {"is_tor": True, "is_vpn": False}}
    out = _parse_criminal_ip(payload, "1.2.3.4")
    assert out["verdict"] == "MALICIOUS"
    assert out["is_tor"] is True


def test_criminal_ip_safe_safe_is_clean():
    out = _parse_criminal_ip(
        {"score": {"inbound": "safe", "outbound": "safe"}, "issues": {}},
        "1.1.1.1",
    )
    assert out["verdict"] == "CLEAN"


def test_criminal_ip_moderate_is_suspicious():
    out = _parse_criminal_ip(
        {"score": {"inbound": "moderate", "outbound": "low"}, "issues": {}},
        "1.2.3.4",
    )
    assert out["verdict"] == "SUSPICIOUS"


# ─── URLScan screenshot ──────────────────────────────────────────────────────
def test_urlscan_screenshot_not_found_returns_clear_shape():
    out = _parse_urlscan_screenshot({"results": []}, "http://nope.example")
    assert out["found"] is False
    assert "screenshot_url" not in out or not out.get("screenshot_url")


def test_urlscan_screenshot_returns_thumbnail_url_when_found():
    results = {"results": [{
        "_id": "abc-uuid-123",
        "task": {"time": "2026-01-01T12:00:00Z", "uuid": "abc-uuid-123"},
        "page": {"country": "US", "ip": "1.2.3.4"},
        "verdicts": {"overall": {"malicious": False, "score": 0}},
    }]}
    out = _parse_urlscan_screenshot(results, "http://example.com")
    assert out["found"] is True
    assert out["screenshot_url"] == "https://urlscan.io/screenshots/abc-uuid-123.png"
    assert out["scan_url"] == "https://urlscan.io/result/abc-uuid-123/"


def test_urlscan_screenshot_malicious_flagged():
    results = {"results": [{
        "_id": "bad-uuid",
        "task": {"time": "2026-01-01"},
        "verdicts": {"overall": {"malicious": True, "score": 92}},
        "page": {},
    }]}
    out = _parse_urlscan_screenshot(results, "http://evil.example")
    assert out["verdict"] == "MALICIOUS"
    assert _src_flagged_malicious("urlscan_screenshot", out) is True


# ─── Enrichment-summary integration ──────────────────────────────────────────
def test_enrichment_summary_counts_email_breach_sources():
    """The enrichment-summary line should reflect email-IOC sources too."""
    enr = {"emails": {"u@e.com": {
        "hibp":     {"breach_count": 15, "verdict": "MALICIOUS"},
        "dehashed": {"total": 5, "verdict": "SUSPICIOUS"},
        "intelx":   {"count": 1, "verdict": "CLEAN"},
    }}}
    s = compute_enrichment_summary(enr)
    assert s["returned_count"] == 3
    assert s["flagged_count"] == 2     # HIBP + Dehashed flagged
    assert "u@e.com" in s["flagged_iocs"]
    assert "hibp" in s["flagged_per_ioc"]["u@e.com"]
    assert "dehashed" in s["flagged_per_ioc"]["u@e.com"]


def test_enrichment_summary_three_breaches_meets_flag_threshold():
    """HIBP threshold for 'flagged' in the enrichment summary is 3 breaches
    (the per-source verdict threshold for MALICIOUS is 10)."""
    enr = {"emails": {"u@e.com": {
        "hibp": {"breach_count": 3, "verdict": "SUSPICIOUS"},
    }}}
    s = compute_enrichment_summary(enr)
    assert s["flagged_count"] == 1


def test_enrichment_summary_two_breaches_does_not_flag():
    """Below threshold — must NOT count as a flagged source."""
    enr = {"emails": {"u@e.com": {
        "hibp": {"breach_count": 2, "verdict": "SUSPICIOUS"},
    }}}
    s = compute_enrichment_summary(enr)
    assert s["flagged_count"] == 0
