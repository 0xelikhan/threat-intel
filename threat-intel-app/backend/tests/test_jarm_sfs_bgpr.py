"""Coverage for round-17 free/no-key TI additions:

  - intel/jarm.py               curated JARM known-bad list
  - intel/stopforumspam.py      IP + email spam-source lookup
  - intel/osint_extra.bgp_ranking updated to CIRCL's current 2-call API
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch, AsyncMock

from intel import jarm, stopforumspam
from intel.osint_extra import bgp_ranking


class _null_session:
    async def __aenter__(self): return self
    async def __aexit__(self, *_a): return False


# ─── JARM ─────────────────────────────────────────────────────────────
def test_jarm_lookup_matches_case_insensitive():
    sample = jarm.KNOWN_BAD[0]
    hit = jarm.lookup(sample["jarm"].upper())
    assert hit is not None
    assert hit["framework"] == sample["framework"]


def test_jarm_lookup_rejects_invalid_length():
    """JARM values are always 62 hex chars. Anything shorter is not a
    valid fingerprint and must not return a false-positive match."""
    assert jarm.lookup("07d14d16d21d21d0") is None       # 16 chars
    assert jarm.lookup(None) is None                       # type: ignore[arg-type]
    assert jarm.lookup("") is None
    assert jarm.lookup("z" * 62) is None                   # right length, no match


def test_jarm_get_for_alert_type_returns_only_relevant():
    """A 'ransomware' alert type should return every entry whose
    alert_types include 'ransomware' — but not the pure banking or
    exfiltration-only rows."""
    hits = jarm.get_for_alert_type("ransomware")
    assert len(hits) > 0
    for h in hits:
        assert "ransomware" in " ".join(h["alert_types"]) or "malware" in " ".join(h["alert_types"])


def test_jarm_get_for_mitre_returns_all_on_c2_technique():
    """T1071 (Application Layer Protocol) is a C2 technique; every
    known-bad JARM in the list is a plausible C2 candidate so all
    should surface."""
    all_hits = jarm.get_for_mitre(["T1071.001"])
    assert len(all_hits) == len(jarm.KNOWN_BAD)


def test_jarm_get_for_mitre_returns_empty_on_non_c2_technique():
    """T1078 (Valid Accounts) has nothing to do with TLS fingerprinting.
    The list should stay empty so the analyst isn't shown noise."""
    assert jarm.get_for_mitre(["T1078"]) == []


# ─── StopForumSpam ────────────────────────────────────────────────────
def test_sfs_ip_returns_malicious_when_high_confidence():
    """SFS response with `appears=1` + `confidence>=80` maps to
    MALICIOUS. Frequency and torexit surface as extra chips."""
    fake = {"success": 1, "ip": {
        "value": "1.2.3.4", "appears": 1, "frequency": 42,
        "confidence": 92.5, "torexit": 1, "asn": 12345, "country": "us",
        "lastseen": "2026-06-01 12:00:00",
    }}
    async def _run():
        async with _null_session() as s:
            with patch("agents.enrichment._get", return_value=fake):
                return await stopforumspam.lookup_ip(s, "1.2.3.4")
    r = asyncio.run(_run())
    assert r["verdict"] == "MALICIOUS"
    assert r["frequency"] == 42
    assert r["torexit"] is True
    assert "95% confidence" in r["summary"] or "92" in r["summary"]


def test_sfs_ip_returns_suspicious_for_mid_confidence():
    fake = {"success": 1, "ip": {
        "value": "1.2.3.4", "appears": 1, "frequency": 3,
        "confidence": 60.0,
    }}
    async def _run():
        async with _null_session() as s:
            with patch("agents.enrichment._get", return_value=fake):
                return await stopforumspam.lookup_ip(s, "1.2.3.4")
    r = asyncio.run(_run())
    assert r["verdict"] == "SUSPICIOUS"


def test_sfs_ip_returns_found_false_when_no_reports():
    fake = {"success": 1, "ip": {"value": "8.8.8.8", "appears": 0, "frequency": 0}}
    async def _run():
        async with _null_session() as s:
            with patch("agents.enrichment._get", return_value=fake):
                return await stopforumspam.lookup_ip(s, "8.8.8.8")
    r = asyncio.run(_run())
    assert r["found"] is False
    assert "no spam reports" in r["summary"]


def test_sfs_email_flags_high_frequency_as_malicious():
    fake = {"success": 1, "email": {
        "value": "spammer@example.com", "appears": 1, "frequency": 25,
    }}
    async def _run():
        async with _null_session() as s:
            with patch("agents.enrichment._get", return_value=fake):
                return await stopforumspam.lookup_email(s, "spammer@example.com")
    r = asyncio.run(_run())
    assert r["verdict"] == "MALICIOUS"
    assert r["frequency"] == 25


def test_sfs_rejects_non_email_input():
    async def _run():
        async with _null_session() as s:
            return await stopforumspam.lookup_email(s, "not-an-email")
    assert asyncio.run(_run()) == {}


# ─── CIRCL BGP Ranking (2-call flow) ──────────────────────────────────
def test_bgp_ranking_walks_ipasn_then_asn_rank():
    """The current CIRCL API needs two POSTs: IP → ASN, then ASN → rank.
    The old bgpranking-ng endpoint was retired — the module was
    silently 404ing before this fix."""
    step1 = {"meta": {"ip": "8.8.8.8"},
             "response": {"2026-07-04T12:00:00": {
                 "asn": "15169", "prefix": "8.8.8.0/24", "source": "caida",
             }}}
    step2 = {"meta": {"asn": "15169"},
             "response": {
                 "asn_description": "GOOGLE, US",
                 "ranking": {"rank": 0.00017, "position": 8984,
                             "total_known_asns": 13677},
             }}

    class _fake_ctx:
        def __init__(self, payload, status=200):
            self._payload = payload
            self.status = status
        async def __aenter__(self): return self
        async def __aexit__(self, *_a): return False
        async def json(self): return self._payload
        async def text(self): return ""

    class _fake_session:
        def __init__(self):
            self.calls = 0
        def post(self, url, **kw):
            self.calls += 1
            return _fake_ctx(step1 if self.calls == 1 else step2)

    async def _run():
        sess = _fake_session()
        r = await bgp_ranking(sess, "8.8.8.8")
        return sess.calls, r
    calls, r = asyncio.run(_run())
    assert calls == 2
    assert r["asn"] == "15169"
    assert r["asn_description"] == "GOOGLE, US"
    assert r["ranking_position"] == 8984
    assert r["total_known_asns"] == 13677


def test_bgp_ranking_surfaces_error_on_no_asn_for_ip():
    """CIRCL's ipasn_history returns an empty response.response when it
    can't map the IP to an ASN. That must surface as an error rather
    than crashing the second call with `asn=""`."""
    step1 = {"meta": {"ip": "127.0.0.1"}, "response": {}}

    class _fake_ctx:
        def __init__(self, payload):
            self._payload = payload
            self.status = 200
        async def __aenter__(self): return self
        async def __aexit__(self, *_a): return False
        async def json(self): return self._payload
        async def text(self): return ""

    class _fake_session:
        def post(self, url, **kw):
            return _fake_ctx(step1)

    async def _run():
        return await bgp_ranking(_fake_session(), "127.0.0.1")
    r = asyncio.run(_run())
    assert r["error"] == "no ASN found for IP"
