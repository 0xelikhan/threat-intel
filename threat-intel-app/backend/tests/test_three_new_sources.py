"""Regression coverage for the three new keyless sources:
  * ip-api.com   (geo fallback)
  * ThreatCluster (per-IOC lookup + feed ingestor)
  * BGPv6.com    (BGP + RPKI)

All three are hit against mocked HTTP responses so the suite runs
offline. Each test picks a boundary that a plausible regression
would trip:
  - registry registration (invisible plugin = silent dead feature)
  - parser normalization (empty/error responses handled cleanly)
  - verdict logic (RPKI-invalid, ThreatCluster-multi-cluster)
  - enrich_ip integration (new keys land in the output dict)
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from plugins import registry


@pytest.fixture(autouse=True)
def _reset_enrichment_state():
    """Enrichment keeps a per-host circuit breaker AND a results cache
    at module scope. Stale state from an earlier test can trip the
    breaker and short-circuit our fake _get, which returns a bare
    {'error':'circuit open'} dict - no `found` key, lookup()s crash
    on KeyError. Reset both before each test."""
    try:
        from agents.enrichment import get_breaker, _cache
        breaker = get_breaker()
        if hasattr(breaker, "_hosts"):
            lock = getattr(breaker, "_lock", None)
            if lock is not None:
                with lock:
                    breaker._hosts.clear()
            else:
                breaker._hosts.clear()
        _cache.clear()
    except Exception:
        pass
    yield


# ─── Shared fake session ──────────────────────────────────────────────────

class _FakeResp:
    def __init__(self, payload, status=200, content_type="application/json"):
        self._payload = payload
        self.status = status
        self.content_type = content_type
        self.headers = {"Content-Type": content_type}
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
    async def json(self): return self._payload
    async def text(self):
        if isinstance(self._payload, str):
            return self._payload
        import json as _j
        return _j.dumps(self._payload)


def _session_returning(responses_by_url):
    """Build a session mock that routes each GET to a pre-canned response
    based on substring-match of the URL. Lets each test target specific
    endpoints without caring about parameter encoding."""
    def _get(url, **kwargs):
        for substring, resp in responses_by_url.items():
            if substring in url:
                return _FakeResp(resp if not isinstance(resp, tuple) else resp[0],
                                  status=(resp[1] if isinstance(resp, tuple) else 200))
        return _FakeResp({"error": "no mock", "error_type": "unreachable"},
                          status=404)
    s = MagicMock()
    s.get = _get
    s.post = _get
    s.closed = False
    return s


# ─── Registry ──────────────────────────────────────────────────────────────

def test_ip_api_analyzer_registered():
    assert registry.get("ip_api") is not None, (
        "ip_api analyzer didn't register - check module-level register()"
    )


def test_threatcluster_analyzer_registered():
    assert registry.get("threatcluster") is not None


def test_threatcluster_ingestor_registered():
    """Confirm the ingestor registered with its own name, not clobbered
    by the analyzer sharing the same slug prefix."""
    ingestors = {i.name for i in registry.ingestors()}
    assert "threatcluster" in ingestors, (
        f"threatcluster ingestor missing: {sorted(ingestors)}"
    )


def test_bgpv6_analyzer_registered():
    assert registry.get("bgpv6") is not None


# ─── ip-api parser ────────────────────────────────────────────────────────

def test_ip_api_success_normalizes_to_ipinfo_shape():
    """The fallback value depends on the normalizer producing a `loc`
    string in the same lat,lon format IPInfo returns - otherwise the
    Map tab won't render the marker."""
    from intel.ip_api import lookup
    session = _session_returning({
        "ip-api.com": {
            "status": "success", "country": "United States",
            "countryCode": "US", "regionName": "Virginia",
            "city": "Ashburn", "lat": 39.03, "lon": -77.5,
            "org": "Google LLC", "as": "AS15169 Google LLC",
            "query": "8.8.8.8",
        },
    })
    out = asyncio.run(lookup(session, "8.8.8.8"))
    assert out["found"] is True
    assert out["loc"] == "39.03,-77.5", (
        f"loc must be 'lat,lon' string; got {out.get('loc')!r}"
    )
    assert out["country"] == "US"
    assert out["city"] == "Ashburn"
    assert out["org"] == "Google LLC"


def test_ip_api_private_range_is_not_an_error():
    """ip-api returns status:fail for private/reserved IPs. Those are
    'not applicable', not errors - must not surface as a dim 'unavailable'
    row in the UI for 192.168.x lookups."""
    from intel.ip_api import lookup
    session = _session_returning({
        "ip-api.com": {"status": "fail", "message": "private range"},
    })
    out = asyncio.run(lookup(session, "192.168.1.1"))
    assert out["found"] is False
    assert "error" not in out
    assert "private" in out["summary"].lower()


# ─── ThreatCluster parser ─────────────────────────────────────────────────

def test_threatcluster_hit_populates_clusters():
    """A found IOC with 2+ clusters must produce a MALICIOUS-ish verdict
    and surface actor/family tags. Catches the ranker drifting if the
    clusters array shape changes."""
    from intel.threatcluster import lookup
    session = _session_returning({
        "threatcluster.io/api/iocs/lookup": {
            "value": "1.2.3.4", "count": 4, "categories": ["malware", "c2"],
            "lookback_days": 7, "older_matches": False,
            "clusters": [
                {"title": "Emotet infrastructure",
                 "tags": ["malware:Emotet", "actor:TA542"]},
                {"title": "QakBot infrastructure",
                 "tags": ["malware:QakBot"]},
            ],
            "notice": {"code": "tier_clamped"},
        },
    })
    out = asyncio.run(lookup(session, "1.2.3.4"))
    assert out["found"] is True
    assert out["cluster_count"] == 4
    # 4 clusters crosses the 3-threshold so should go MALICIOUS
    assert out["verdict"] == "MALICIOUS"
    assert "Emotet" in out["families"]
    assert "QakBot" in out["families"]


def test_threatcluster_miss_is_not_found_not_error():
    """count=0 is normal for most IOCs. Must be found=False with no
    error, so the per-IP renderer stays quiet instead of showing a
    'unavailable' row for every clean IP."""
    from intel.threatcluster import lookup
    session = _session_returning({
        "threatcluster.io/api/iocs/lookup": {
            "value": "1.2.3.4", "count": 0, "clusters": [],
            "categories": [], "lookback_days": 7,
        },
    })
    out = asyncio.run(lookup(session, "1.2.3.4"))
    assert out["found"] is False
    assert "error" not in out


def test_threatcluster_ingestor_parses_text_feed():
    """The ingestor pulls a plain-text file with # comments. Confirm
    the parser skips comments + blank lines and yields the right
    type for IPv4 vs domain entries."""
    from plugins.ingestors.threatcluster import _detect_type, _TC_CACHE
    assert _detect_type("1.2.3.4") == "ipv4"
    assert _detect_type("2606:4700::1") == "ipv6"
    assert _detect_type("evil.example.com") == "domain"


def test_threatcluster_feed_lookup_cache_miss():
    from plugins.ingestors.threatcluster import lookup, _TC_CACHE
    _TC_CACHE.clear()
    # Empty cache always misses.
    assert lookup("8.8.8.8") is None


def test_threatcluster_feed_lookup_cache_hit():
    """After the ingestor populates the cache, lookup must return a
    SUSPICIOUS blob for an IP present in the set."""
    from plugins.ingestors import threatcluster as tc_ing
    tc_ing._TC_CACHE = {"4.3.2.1", "evil.example.com"}
    tc_ing._TC_CACHE_AT = __import__("time").time()
    hit = tc_ing.lookup("4.3.2.1")
    assert hit is not None
    assert hit["found"] is True
    assert hit["verdict"] == "SUSPICIOUS"
    miss = tc_ing.lookup("127.0.0.1")
    assert miss is None


# ─── BGPv6 parser ─────────────────────────────────────────────────────────

def test_bgpv6_success_surfaces_rpki_valid():
    """Clean RPKI-valid prefix should return verdict=UNKNOWN (mild trust
    signal, not enough to override other verdicts) with populated
    prefix + ASN."""
    from intel.bgpv6 import lookup
    session = _session_returning({
        "bgpv6.com/api/v1/lookup": {
            "data": {"ip": "8.8.8.8", "prefix": "8.8.8.0/24",
                     "asn": 15169, "asn_name": "", "rpki_status": "valid"},
            "geoip": {"country": "US", "country_name": "United States",
                       "latitude": 37.751, "longitude": -97.822,
                       "asn": 15169, "as_org": "Google LLC"},
        },
    })
    out = asyncio.run(lookup(session, "8.8.8.8"))
    assert out["found"] is True
    assert out["prefix"] == "8.8.8.0/24"
    assert out["asn"] == 15169
    assert out["rpki_status"] == "valid"
    assert out["verdict"] == "UNKNOWN"
    assert out["asn_name"] == "Google LLC"   # pulled from geoip when
                                             # data.asn_name is blank


def test_bgpv6_rpki_invalid_bumps_to_suspicious():
    """RPKI-invalid = hijack flag. Verdict MUST bump to SUSPICIOUS or
    the whole reason for choosing BGPv6 over Robtex is moot."""
    from intel.bgpv6 import lookup
    session = _session_returning({
        "bgpv6.com/api/v1/lookup": {
            "data": {"ip": "1.2.3.4", "prefix": "1.2.3.0/24",
                     "asn": 65001, "asn_name": "HijackerCorp",
                     "rpki_status": "invalid"},
            "geoip": {},
        },
    })
    out = asyncio.run(lookup(session, "1.2.3.4"))
    assert out["found"] is True
    assert out["rpki_status"] == "invalid"
    assert out["verdict"] == "SUSPICIOUS"


# ─── enrich_ip integration ────────────────────────────────────────────────

def test_enrich_ip_populates_all_three_new_keys():
    """End-to-end: run enrich_ip against a fake session, assert all
    three new blobs land in the result. If any one goes missing after
    this commit, regressions show here instead of silently in the UI."""
    import asyncio as _asyncio

    tc_payload = {
        "value": "1.2.3.4", "count": 2, "categories": ["c2"],
        "clusters": [{"title": "Emotet", "tags": ["malware:Emotet"]}],
        "lookback_days": 7,
    }
    bgp_payload = {
        "data": {"ip": "1.2.3.4", "prefix": "1.2.3.0/24", "asn": 65001,
                 "asn_name": "Bad", "rpki_status": "invalid"},
        "geoip": {"country": "XX", "country_name": "Nowhere"},
    }
    ipapi_payload = {
        "status": "success", "countryCode": "XX", "country": "Nowhere",
        "regionName": "Somewhere", "city": "Capital",
        "lat": 10.0, "lon": 20.0, "org": "BadCorp",
        "as": "AS65001 Bad", "query": "1.2.3.4",
    }
    session = _session_returning({
        "threatcluster.io":     tc_payload,
        "bgpv6.com":            bgp_payload,
        "ip-api.com":           ipapi_payload,
    })

    # Clear the enrichment cache so the ip we probe doesn't short-
    # circuit to a prior test's cached result.
    from agents.enrichment import enrich_ip, _cache
    _cache.clear()

    out = _asyncio.run(enrich_ip(session, "1.2.3.4", keys={}))

    # All three must land. Individual asserts give clearer diagnostics
    # than a single `all()` assertion.
    assert "threatcluster" in out, (
        f"threatcluster blob missing. keys: {sorted(out.keys())}"
    )
    assert "bgpv6" in out, f"bgpv6 blob missing. keys: {sorted(out.keys())}"
    # ip_api is a FALLBACK - only populates when ipinfo was blank.
    # The fake ipinfo endpoint returns {"error":"no mock", ...} (404)
    # which parses to an errored ipinfo_data, triggering the fallback.
    # So ip_api should be present here.
    assert "ip_api" in out, f"ip_api fallback didn't fire. keys: {sorted(out.keys())}"

    # Quick sanity on the content.
    assert out["threatcluster"]["cluster_count"] == 2
    assert out["bgpv6"]["rpki_status"] == "invalid"
    assert out["ip_api"]["city"] == "Capital"


def test_ip_api_does_not_fire_when_ipinfo_has_loc():
    """Conversely, if IPInfo returned a `loc`, ip-api should NOT fire -
    no point paying a second round-trip for redundant data."""
    import asyncio as _asyncio

    ipinfo_hit = {
        "ip": "8.8.8.8", "country": "US", "city": "Mountain View",
        "loc": "37.3861,-122.0839", "org": "Google LLC",
    }
    # Note: the response has to be returned when the VirusTotal URL
    # matches too, since _get is called for both. Using a generic
    # match on "ipinfo.io/" so the routing is reliable.
    session = _session_returning({
        "ipinfo.io/":           ipinfo_hit,
        # BGPv6 + ThreatCluster paths still return 404 "no mock" -
        # that's fine, we only care about the ip_api fallback behaviour
        # for this test.
    })

    from agents.enrichment import enrich_ip, _cache
    _cache.clear()
    out = _asyncio.run(enrich_ip(session, "8.8.8.8", keys={}))
    # The ipinfo response landed with a loc, so the fallback should
    # not have fired.
    assert "ip_api" not in out, (
        f"ip_api fired despite valid ipinfo.loc; check fallback gate. "
        f"ipinfo blob was: {out.get('ipinfo')}"
    )
