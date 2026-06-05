"""Tests for the paste-site + asset enrichment sources."""

from __future__ import annotations

from intel.breach_sources import (
    _parse_criminal_ip, _parse_urlscan_screenshot,
)
from agents.investigation import _src_flagged_malicious


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
