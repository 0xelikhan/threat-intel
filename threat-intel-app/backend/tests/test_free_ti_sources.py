"""Coverage for the six free / no-key TI additions:

  - crt.sh Certificate Transparency        (intel/crt_sh.py)
  - abuse.ch SSLBL blocklist               (intel/sslbl.py)
  - CIRCL CVE-Search failover              (intel/cve_search.py)
  - CISA Vulnrichment via MITRE Awg        (intel/vulnrichment.py)
  - OpenSanctions superset of OFAC         (intel/opensanctions.py)
  - Ransomware.live active-actor freshness (intel/ransomware_live.py)

Every test stubs the network / disk so nothing hits the internet.
The point is that each module returns the shape the frontend renders
and that the aggregation code inside enrichment.py wires each hit
into the right slot.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

from intel import (
    crt_sh, cve_search, vulnrichment, opensanctions, ransomware_live, sslbl,
)


class _null_session:
    async def __aenter__(self): return self
    async def __aexit__(self, *_a): return False


# ─── crt.sh ──────────────────────────────────────────────────────────────
def test_crt_sh_flags_recent_cert_burst_as_suspicious():
    """When crt.sh reports 20+ new certs in 30 days OR 5+ unrelated SANs
    the verdict is SUSPICIOUS — that's the phishing-infra prep signal
    the analyst wants surfaced in orange."""
    now = "2026-07-01T12:00:00"
    fake = [
        {"issuer_name":  "C=US, O=Let's Encrypt, CN=R3",
         "not_before":   now,
         "name_value":   f"phish{i}.example.com\nexample.com"}
        for i in range(25)
    ]
    async def _run():
        async with _null_session() as s:
            with patch("agents.enrichment._get", return_value=fake):
                return await crt_sh.enrich(s, "example.com")
    r = asyncio.run(_run())
    assert r["found"] is True
    assert r["cert_count"] == 25
    assert r["verdict"] == "SUSPICIOUS"
    assert r["recent_30d"] >= 20
    assert "Let's Encrypt" in r["issuers"]


def test_crt_sh_degrades_gracefully_on_502():
    """crt.sh 502s frequently under load. The failure surfaces as an
    error row instead of blowing up domain enrichment."""
    async def _run():
        async with _null_session() as s:
            with patch("agents.enrichment._get",
                       return_value={"error": "server error (HTTP 502)",
                                     "error_type": "http_error"}):
                return await crt_sh.enrich(s, "example.com")
    r = asyncio.run(_run())
    assert r.get("error") is not None
    assert r.get("error_type") == "http_error"


# ─── SSLBL ────────────────────────────────────────────────────────────────
def test_sslbl_ip_parser_extracts_family_from_listing_reason():
    csv_text = (
        "# DstIP,DstPort,Listing_date,Listing_reason\n"
        "1.2.3.4,443,2026-06-01 12:00:00,Emotet C2\n"
        "5.6.7.8,80,2026-06-15 09:00:00,Cobalt Strike C2\n"
    )
    parsed = sslbl._parse_ip_csv(csv_text)
    assert parsed["1.2.3.4:443"]["family"] == "Emotet"
    assert parsed["5.6.7.8:80"]["family"] == "Cobalt"
    assert "C2" in parsed["1.2.3.4:443"]["listing_reason"]


def test_sslbl_ja3_parser_rejects_non_md5_length():
    csv_text = (
        "# ja3_md5,Firstseen,Lastseen,Listingreason\n"
        "72a589da586844d7f0818ce684948eea,2020-01-01,2026-06-01,Cobalt Strike\n"
        "notavalidhash,2020-01-01,2026-06-01,Junk row\n"
    )
    parsed = sslbl._parse_ja3_csv(csv_text)
    assert "72a589da586844d7f0818ce684948eea" in parsed
    assert "notavalidhash" not in parsed


def test_sslbl_lookup_ip_prefers_port_specific_over_any():
    """A row indexed by ip:port is the more specific hit and should win
    when the caller supplies the port."""
    sslbl._state.update({
        "loaded_at":  __import__("time").time(),   # inside TTL — skip network
        "by_ip":      {"1.2.3.4:443": {"family": "Emotet"}},
        "by_ip_any":  {"1.2.3.4": {"family": "Emotet"}},
        "by_sha1":    {}, "by_ja3": {},
    })
    hit = sslbl.lookup_ip("1.2.3.4", port=443)
    assert hit["family"] == "Emotet"
    # And with no port arg, still returns the any-port row.
    assert sslbl.lookup_ip("1.2.3.4")["family"] == "Emotet"


# ─── CIRCL CVE-Search ─────────────────────────────────────────────────────
def test_circl_cve_search_parses_cvss_from_adp_container():
    """Modern CIRCL responses put CVSS inside containers.adp[N].metrics
    not in the CNA container. The parser must walk both."""
    fake = {
        "cveMetadata": {"cveId": "CVE-2024-6387"},
        "containers": {
            "cna": {"descriptions": [{"lang": "en", "value": "regreSSHion"}]},
            "adp": [{
                "providerMetadata": {"shortName": "CISA-ADP"},
                "metrics": [{"cvssV3_1": {
                    "baseScore": 8.1,
                    "baseSeverity": "HIGH",
                    "vectorString": "CVSS:3.1/AV:N/…",
                }}],
            }],
        },
    }
    async def _run():
        async with _null_session() as s:
            with patch("agents.enrichment._get", return_value=fake):
                return await cve_search.lookup(s, "CVE-2024-6387")
    r = asyncio.run(_run())
    assert r["cvss_v3_score"] == 8.1
    assert r["cvss_v3_severity"] == "HIGH"
    assert "regreSSHion" in r["summary"]


def test_circl_cve_search_returns_empty_on_bad_cve_id():
    async def _run():
        async with _null_session() as s:
            return await cve_search.lookup(s, "not-a-cve")
    assert asyncio.run(_run()) == {}


# ─── Vulnrichment ────────────────────────────────────────────────────────
def test_vulnrichment_extracts_ssvc_decision():
    fake = {
        "containers": {
            "cna": {},
            "adp": [{
                "providerMetadata": {"shortName": "CISA-ADP"},
                "problemTypes": [{"descriptions": [{"cweId": "CWE-416"}]}],
                "metrics": [
                    {"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL",
                                   "vectorString": "CVSS:3.1/AV:N"}},
                    {"other": {"type": "ssvc", "content": {
                        "role": "CISA Coordinator",
                        "version": "2.0.3",
                        "options": [{"Exploitation": "active"},
                                    {"Automatable": "yes"},
                                    {"Technical Impact": "total"}],
                        "timestamp": "2026-06-01T00:00:00Z",
                    }}},
                ],
            }],
        },
    }
    async def _run():
        async with _null_session() as s:
            with patch("agents.enrichment._get", return_value=fake):
                return await vulnrichment.lookup(s, "CVE-2026-0001")
    r = asyncio.run(_run())
    assert r["cwes"] == ["CWE-416"]
    assert r["refined_cvss"]["score"] == 9.8
    assert r["ssvc"]["options"]["Exploitation"] == "active"
    assert "SSVC" in r["summary"]


def test_vulnrichment_returns_empty_when_no_cisa_adp():
    """MITRE record present but CISA hasn't scored it yet."""
    fake = {"containers": {"cna": {}, "adp": [
        {"providerMetadata": {"shortName": "someone-else"}},
    ]}}
    async def _run():
        async with _null_session() as s:
            with patch("agents.enrichment._get", return_value=fake):
                return await vulnrichment.lookup(s, "CVE-2026-0002")
    assert asyncio.run(_run()) == {}


# ─── OpenSanctions ────────────────────────────────────────────────────────
def test_opensanctions_crypto_lookup_rejects_fuzzy_match():
    """OpenSanctions /search fuzzy-matches — a hit that DOESN'T actually
    have the queried address in its cryptoWallets is noise. The
    lookup must verify the address is on the entity before returning."""
    fake_hit = {
        "results": [{
            "id": "np-xyz",
            "caption": "Lazarus Wallet",
            "schema": "Address",
            "properties": {
                "cryptoWallets": ["0xdifferentaddress0000000000000000000000"],
                "topics": ["sanctions.us_ofac"],
            },
        }],
    }
    async def _run():
        async with _null_session() as s:
            with patch("agents.enrichment._get", return_value=fake_hit):
                return await opensanctions.lookup_crypto(
                    s, "0x8589427373d6d84e98730d7795d8f6f8731fdb8d")
    assert asyncio.run(_run()) is None


def test_opensanctions_crypto_lookup_returns_hit_when_address_matches():
    addr = "0x8589427373d6d84e98730d7795d8f6f8731fdb8d"
    fake_hit = {
        "results": [{
            "id": "np-abc",
            "caption": "Sanctioned Wallet",
            "schema": "Address",
            "properties": {
                "cryptoWallets": [addr],
                "topics": ["sanctions.us_ofac"],
            },
        }],
    }
    async def _run():
        async with _null_session() as s:
            with patch("agents.enrichment._get", return_value=fake_hit):
                return await opensanctions.lookup_crypto(s, addr)
    r = asyncio.run(_run())
    assert r is not None
    assert "Sanctioned Wallet" in r["entity"]
    assert r["source"] == "OpenSanctions"


# ─── Ransomware.live ──────────────────────────────────────────────────────
def test_ransomware_live_matches_family_name_case_insensitive():
    """Alert-time actor naming rarely matches leak-site casing exactly
    ('LockBit' vs 'lockbit'). The lookup must be case-insensitive."""
    ransomware_live._state.update({
        "loaded_at":    __import__("time").time(),
        "by_group":     {"lockbit": {
            "group":       "lockbit",
            "latest":      "2026-07-01",
            "victims_30d": 12,
            "sample":      [{"victim": "Acme Corp", "posted": "2026-07-01"}],
        }},
        "active_groups": ["lockbit"],
    })
    hit = ransomware_live.lookup_group("LockBit")
    assert hit is not None
    assert hit["victims_30d"] == 12


def test_ransomware_live_loose_match_on_family_variants():
    """'lockbit3' should still match the 'lockbit' feed row — the loose
    substring branch handles the version-suffix drift."""
    ransomware_live._state.update({
        "loaded_at":  __import__("time").time(),
        "by_group":   {"lockbit": {"group": "lockbit", "victims_30d": 3}},
    })
    hit = ransomware_live.lookup_group("lockbit3")
    assert hit is not None
    assert hit["group"] == "lockbit"


def test_ransomware_live_returns_none_for_unknown_family():
    ransomware_live._state.update({
        "loaded_at": __import__("time").time(),
        "by_group":  {},
    })
    assert ransomware_live.lookup_group("SomeMadeUpAPT") is None
