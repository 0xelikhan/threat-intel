"""Tests for the known-good baseline short-circuit."""

from __future__ import annotations

from intel.known_good_baseline import (
    lookup_ip, lookup_domain, lookup_hash, lookup_ioc, stats,
)


def test_google_dns_ipv4_hits():
    h = lookup_ip("8.8.8.8")
    assert h is not None
    assert h["verdict"] == "CLEAN"
    assert h["category"] == "public_dns"
    assert h["source"] == "known_good_baseline"


def test_cloudflare_dns_hits():
    for ip in ("1.1.1.1", "1.0.0.1", "1.1.1.2"):
        h = lookup_ip(ip)
        assert h is not None, f"{ip} should hit baseline"
        assert h["category"] == "public_dns"


def test_google_dns_ipv6_hits():
    h = lookup_ip("2001:4860:4860::8888")
    assert h is not None
    assert "Google" in h["name"]


def test_cloudflare_cidr_range_hits():
    # 104.16.123.96 (used in earlier tests) is inside 104.16.0.0/12
    h = lookup_ip("104.16.123.96")
    assert h is not None
    assert h["category"] == "cdn"
    assert "Cloudflare" in h["name"]


def test_random_public_ip_misses():
    assert lookup_ip("185.220.101.45") is None
    assert lookup_ip("45.61.169.99")  is None


def test_private_ip_returns_none():
    # Private space isn't in the baseline — that's a different concern
    # (handled by triage's _is_private_ip filter).
    assert lookup_ip("192.168.1.1") is None
    assert lookup_ip("10.0.0.1")    is None


def test_invalid_ip_returns_none():
    assert lookup_ip("not-an-ip") is None
    assert lookup_ip("")           is None
    assert lookup_ip(None)         is None


def test_microsoft_domain_exact_hits():
    h = lookup_domain("login.microsoftonline.com")
    assert h is not None
    assert h["category"] == "ms_auth"


def test_microsoft_domain_subdomain_hits_via_suffix():
    # sts.login.microsoftonline.com is a real Entra subdomain.
    h = lookup_domain("sts.login.microsoftonline.com")
    assert h is not None
    assert h["category"] == "ms_auth"


def test_google_apis_subdomain_hits():
    h = lookup_domain("oauth2.googleapis.com")
    assert h is not None
    assert "Google" in h["name"]


def test_domain_lookup_is_case_insensitive():
    a = lookup_domain("Login.MicrosoftOnline.COM")
    b = lookup_domain("login.microsoftonline.com")
    assert a is not None and b is not None
    assert a["name"] == b["name"]


def test_unknown_domain_misses():
    assert lookup_domain("totally-random-attacker-domain.xyz") is None
    assert lookup_domain("") is None
    assert lookup_domain(None) is None


def test_hash_baseline_returns_none_by_default():
    # Empty by design — CIRCL hashlookup handles known-good hashes.
    assert lookup_hash("d" * 64) is None


def test_lookup_ioc_dispatches():
    assert lookup_ioc("ip",     "8.8.8.8")["verdict"] == "CLEAN"
    assert lookup_ioc("domain", "google.com")["verdict"] == "CLEAN"
    assert lookup_ioc("hash",   "abc") is None
    assert lookup_ioc("url",    "http://x") is None  # unsupported type


def test_stats_returns_counts():
    s = stats()
    assert s["ip_exact"] > 10
    assert s["domain_exact"] > 10
    assert "ip_cidr" in s
