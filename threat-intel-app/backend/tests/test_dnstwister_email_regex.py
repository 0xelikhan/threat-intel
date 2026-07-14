"""Regression tests for round-18 fixes:

  1. Email extraction — iocextract was gluing preceding tokens onto the
     local-part ('from ceo@x.com' -> 'fromceo@x.com'). Added a
     word-boundary check against the source text before accepting.
  2. DNSTwister — new intel/dnstwister.py using the free /api/fuzz/
     endpoint + local DNS resolution to identify registered typos.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

from agents.triage import extract_iocs
from intel import dnstwister


class _null_session:
    async def __aenter__(self): return self
    async def __aexit__(self, *_a): return False


# ─── Email regex regression ──────────────────────────────────────────
def test_extract_iocs_rejects_iocextract_prefix_glue():
    """The bug: extractor produced both 'ceo@x.com' AND
    'fromceo@x.com' from 'from ceo@x.com'. Only the clean address
    should survive after the word-boundary filter."""
    text = ("Inbound email from ceo-support@paypal-security-verify.com "
            "to cfo@corp.example asking to update wire transfer routing.")
    emails = set((extract_iocs(text).get("emails") or []))
    assert "ceo-support@paypal-security-verify.com" in emails
    assert "cfo@corp.example" in emails
    # Glued versions must not survive.
    assert "fromceo-support@paypal-security-verify.com" not in emails
    assert "tocfo@corp.example" not in emails


def test_extract_iocs_keeps_defanged_and_at_variants():
    """iocextract earns its keep by catching defanged forms — the
    word-boundary filter must not accidentally drop those. `@` after a
    space, `[at]`, `(at)` are the common defang variants."""
    text = ("Contact user1[at]example.com or user2 (at) example.org "
            "for details. Regular: user3@example.net")
    emails = set((extract_iocs(text).get("emails") or []))
    # The regular one always makes it via the raw regex.
    assert "user3@example.net" in emails


# ─── DNSTwister ──────────────────────────────────────────────────────
def test_dnstwister_returns_empty_on_invalid_domain():
    async def _run():
        async with _null_session() as s:
            return await dnstwister.enrich(s, "not-a-domain")
    assert asyncio.run(_run()) == {}


def test_dnstwister_flags_registered_typos_as_suspicious():
    """DNSTwister returns a fuzz list; local DNS resolution is patched
    so we can assert the shape without hitting the internet."""
    fake_fuzz = {
        "domain": "stripe.com",
        "fuzzy_domains": [
            {"domain": "stripe.com",   "fuzzer": "Original*"},
            {"domain": "5tripe.com",   "fuzzer": "Bitsquatting"},
            {"domain": "ctripe.com",   "fuzzer": "Bitsquatting"},
            {"domain": "wtripe.com",   "fuzzer": "Bitsquatting"},
        ],
    }
    # Two of the three permutations resolve.
    resolved = {"5tripe.com": "13.248.169.48",
                "ctripe.com": "103.224.182.243",
                "wtripe.com": None}

    def _fake_resolve(host):
        return resolved.get(host)

    async def _run():
        async with _null_session() as s:
            with patch("agents.enrichment._get", return_value=fake_fuzz), \
                 patch("intel.dnstwister._resolve_sync", side_effect=_fake_resolve):
                return await dnstwister.enrich(s, "stripe.com", max_perms=10)
    r = asyncio.run(_run())
    assert r["found"] is True
    assert r["verdict"] == "SUSPICIOUS"
    assert r["resolving_count"] == 2
    resolving_domains = {e["domain"] for e in r["resolving"]}
    assert resolving_domains == {"5tripe.com", "ctripe.com"}
    assert "Bitsquatting" in r["fuzzers"]
    # Seed domain never appears in the resolving set.
    assert "stripe.com" not in resolving_domains


def test_dnstwister_reports_clean_when_no_permutations_resolve():
    fake_fuzz = {"domain": "example.com",
                 "fuzzy_domains": [
                     {"domain": "example.com",  "fuzzer": "Original*"},
                     {"domain": "eexample.com", "fuzzer": "Insertion"},
                     {"domain": "xample.com",   "fuzzer": "Omission"},
                 ]}

    async def _run():
        async with _null_session() as s:
            with patch("agents.enrichment._get", return_value=fake_fuzz), \
                 patch("intel.dnstwister._resolve_sync", return_value=None):
                return await dnstwister.enrich(s, "example.com", max_perms=10)
    r = asyncio.run(_run())
    assert r["found"] is False
    assert r["perms_checked"] == 2   # seed excluded
    assert "none currently registered" in r["summary"]


def test_dnstwister_surfaces_upstream_error():
    async def _run():
        async with _null_session() as s:
            with patch("agents.enrichment._get",
                       return_value={"error": "HTTP 502", "error_type": "http_error"}):
                return await dnstwister.enrich(s, "example.com")
    r = asyncio.run(_run())
    assert r["error"] == "HTTP 502"
    assert r["error_type"] == "http_error"
