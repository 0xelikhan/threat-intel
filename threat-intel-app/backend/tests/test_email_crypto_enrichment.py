"""Coverage tests for the email + crypto enrichment additions.

Two new IOC buckets landed together:
  - `crypto` extracted from ransom-note text, enriched via Ransomwhe.re +
    OFAC SDN sanctioned-address list (both offline).
  - `emails` enriched via OFAC SDN + HIBP breach-by-domain.

These tests hit only the offline / mocked paths so they don't need
internet or the OFAC / Ransomwhere vendor files. The point is that the
extractor + enricher + fan-out plumbing all agree on the same bucket
names and shapes.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

from agents.enrichment import enrich_email, enrich_crypto, run_enrichment
from agents.triage import extract_iocs, score_iocs, derive_alert_type
from agents.orchestrator import _route_triage


def test_extract_crypto_addresses_from_ransom_note():
    text = (
        "Your files are encrypted. Pay 5 BTC to "
        "bc1q9h6mvfdz9vt9qmzk8n2p7xvyrn8y92xh5r7lkq or "
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2. "
        "ETH also accepted: 0x8589427373d6d84e98730d7795d8f6f8731fdb8d. "
        "Contact operator@bad.example if you need help paying."
    )
    iocs = extract_iocs(text)
    crypto = set(iocs.get("crypto") or [])
    assert "bc1q9h6mvfdz9vt9qmzk8n2p7xvyrn8y92xh5r7lkq" in crypto
    assert "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" in crypto
    assert "0x8589427373d6d84e98730d7795d8f6f8731fdb8d" in crypto
    # Emails still land in their own bucket.
    assert "operator@bad.example" in (iocs.get("emails") or [])


def test_crypto_addresses_bump_triage_score_and_route_to_enrichment():
    iocs = {"crypto": ["bc1q9h6mvfdz9vt9qmzk8n2p7xvyrn8y92xh5r7lkq"]}
    # score_iocs contribution is 0.30 per crypto (capped at 0.60).
    assert score_iocs(iocs) >= 0.30
    # Crypto payments imply ransomware.
    assert derive_alert_type(iocs, {}) == "ransomware"
    # The routing gate must send crypto-bearing alerts to enrichment,
    # not straight to investigation.
    state = {"iocs": iocs, "triage_score": 0.5, "should_proceed": True}
    assert _route_triage(state) == "enrichment"


def test_enrich_email_flags_ofac_sanctioned_address():
    async def _run():
        async with _null_session() as s:
            with patch("intel.ofac_sdn.lookup_email",
                       return_value={"entity": "Sanctioned Person",
                                     "programs": ["CYBER2"],
                                     "list_type": "Individual"}):
                return await enrich_email(s, "bad@sanctioned.example", {})
    out = asyncio.run(_run())
    assert out["ofac_sdn"]["verdict"] == "MALICIOUS"
    assert "Sanctioned Person" in out["ofac_sdn"]["entity"]


def test_enrich_email_rejects_non_email_input():
    async def _run():
        async with _null_session() as s:
            return await enrich_email(s, "not-an-email", {})
    out = asyncio.run(_run())
    assert out.get("error") == "invalid email"


def test_enrich_email_skips_hibp_on_public_mail_provider():
    """Free HIBP breach-by-domain adds noise for public providers —
    every gmail / yahoo / hotmail address 'is in' every breach on the
    internet. Provider list is hardcoded; the request should not fire."""
    async def _run():
        async with _null_session() as s:
            called = {"n": 0}

            async def _fail(*_a, **_k):
                called["n"] += 1
                raise AssertionError("HIBP should not be called for gmail.com")

            with patch("agents.enrichment._get", new=_fail), \
                 patch("intel.ofac_sdn.lookup_email", return_value=None):
                out = await enrich_email(s, "user@gmail.com", {})
            return out, called
    out, called = asyncio.run(_run())
    assert called["n"] == 0
    assert "hibp_breaches" not in out


def test_enrich_crypto_flags_ransomwhere_family():
    async def _run():
        async with _null_session() as s:
            with patch("intel.ransomwhere.lookup",
                       return_value={"family": "LockBit",
                                     "first_seen": "2022-01-15",
                                     "last_seen":  "2024-08-01",
                                     "blockchain": "btc"}), \
                 patch("intel.ofac_sdn.lookup_crypto", return_value=None):
                return await enrich_crypto(
                    s, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", {})
    out = asyncio.run(_run())
    assert out["chain"] == "btc"
    assert out["ransomwhere"]["family"] == "LockBit"
    assert out["ransomwhere"]["verdict"] == "MALICIOUS"


def test_enrich_crypto_detects_eth_chain():
    async def _run():
        async with _null_session() as s:
            with patch("intel.ransomwhere.lookup", return_value=None), \
                 patch("intel.ofac_sdn.lookup_crypto",
                       return_value={"entity": "Lazarus Wallet",
                                     "programs": ["DPRK"],
                                     "list_type": "Individual"}):
                return await enrich_crypto(
                    s, "0x8589427373d6d84e98730d7795d8f6f8731fdb8d", {})
    out = asyncio.run(_run())
    assert out["chain"] == "eth"
    assert out["ofac_sdn"]["verdict"] == "MALICIOUS"
    assert "Lazarus Wallet" in out["ofac_sdn"]["entity"]


def test_run_enrichment_wires_new_buckets_end_to_end():
    """Both new buckets travel through the fan-out orchestration:
    extract → run_enrichment → verdicts summary. Stubs every enricher so
    this test is offline + no-key."""
    async def _stub(_s, _v, _k):
        return {"verdict": "UNKNOWN"}

    state = {
        "iocs": {
            "ips": [], "domains": [], "hashes": [], "urls": [], "cves": [],
            "emails": ["victim@example.com"],
            "crypto": ["bc1q9h6mvfdz9vt9qmzk8n2p7xvyrn8y92xh5r7lkq"],
        },
        "agent_trace": [],
    }

    with patch("agents.enrichment.enrich_ip",     new=_stub), \
         patch("agents.enrichment.enrich_domain", new=_stub), \
         patch("agents.enrichment.enrich_hash",   new=_stub), \
         patch("agents.enrichment.enrich_url",    new=_stub), \
         patch("agents.enrichment.enrich_cve",    new=_stub), \
         patch("agents.enrichment.enrich_email",  new=_stub), \
         patch("agents.enrichment.enrich_crypto", new=_stub):
        out = asyncio.run(run_enrichment(state))

    totals = out["enrichment_summary"]["totals"]
    assert totals["emails"] == 1
    assert totals["crypto"] == 1
    verdicts = out["enrichment_summary"]["verdicts_per_ioc"]
    assert "emails" in verdicts and "crypto" in verdicts


class _null_session:
    """aiohttp.ClientSession stand-in. The offline enrichers never call
    it directly (only through _get which we patch), so a bare async
    context manager is enough for the type slot."""
    async def __aenter__(self): return self
    async def __aexit__(self, *_a): return False
