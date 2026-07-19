"""Coverage for round-18 additions + fixes:

  - intel/tor_exits.py            Onionoo Tor exit-relay index
  - intel/threatview_c2.py        High-confidence CS C2 IP list
  - intel/viriback.py             Malware C2 panel index (family attribution)
  - intel/typosquat.py            First-party brand-domain allowlist
                                   (regression: onmicrosoft.com flagged as
                                    Microsoft typosquat before fix)

Every test stubs the network / disk path so nothing hits the internet.
"""

from __future__ import annotations

import copy
import time

import pytest

from intel import tor_exits, threatview_c2, viriback, typosquat


@pytest.fixture(autouse=True)
def _snapshot_module_state():
    """Snapshot + restore module-level `_state` on every test in this
    file. Tests mutate _state directly to inject fixture data; without
    the restore they leak into whatever test runs next (order-dependent
    failures under pytest-randomly + parallel runs)."""
    saved = {
        tor_exits:     copy.deepcopy(tor_exits._state),
        threatview_c2: copy.deepcopy(threatview_c2._state),
        viriback:      copy.deepcopy(viriback._state),
    }
    yield
    for mod, snapshot in saved.items():
        mod._state.clear()
        mod._state.update(snapshot)
    # typosquat uses lru_cache — clear so an allowlist test result
    # can't linger and mask a subsequent negative test.
    typosquat.check_domain.cache_clear()


# ─── Tor exit index ─────────────────────────────────────────────────
def test_tor_exit_index_normalises_or_addresses_and_indexes_both_ip_fields():
    tor_exits._state.update({
        "loaded_at":    time.time(),
        "by_ip":        {},
        "total_relays": 0,
    })
    # Simulate one relay with an IPv4 or_addr with :port and an
    # IPv6 or_addr with brackets, plus a distinct exit_address.
    fake_payload = {"relays": [{
        "fingerprint":         "AB" * 20,
        "or_addresses":        ["1.2.3.4:9001", "[2001:db8::1]:9001"],
        "exit_addresses":      ["5.6.7.8"],
        "as_number":           "AS12345",
        "as_name":              "Example Exit LLC",
        "country":             "us",
        "verified_host_names": ["exit1.example.com"],
        "last_seen":           "2026-07-14 12:00:00",
    }]}
    import json
    from unittest.mock import patch, MagicMock
    fake_resp = MagicMock()
    fake_resp.read.return_value = json.dumps(fake_payload).encode()
    fake_resp.__enter__ = lambda s: s
    fake_resp.__exit__ = lambda s, *a: False
    with patch("urllib.request.urlopen", return_value=fake_resp):
        tor_exits._refresh_sync()
    assert tor_exits.lookup("1.2.3.4") is not None      # or_addr IPv4 :port
    assert tor_exits.lookup("5.6.7.8") is not None      # exit_addresses
    assert tor_exits.lookup("2001:db8::1") is not None  # IPv6 bracketed
    assert tor_exits.lookup("9.9.9.9") is None          # unlisted IP


def test_tor_exit_lookup_returns_verified_hostname_and_asn():
    tor_exits._state.update({
        "loaded_at": time.time(),
        "by_ip":     {"1.1.1.1": {"fingerprint": "F" * 40,
                                    "as_number": "AS64500",
                                    "as_name": "Test Relay",
                                    "verified_host_names": ["tor.example.org"],
                                    "last_seen": "2026-07-14 00:00:00",
                                    "matched_field": "exit_addresses"}},
    })
    hit = tor_exits.lookup("1.1.1.1")
    assert hit["fingerprint"] == "F" * 40
    assert hit["as_name"] == "Test Relay"
    assert "tor.example.org" in hit["verified_host_names"]


# ─── ThreatView CS C2 ────────────────────────────────────────────────
def test_threatview_flags_listed_ip_as_cobalt_strike():
    threatview_c2._state.update({
        "loaded_at":       time.time(),
        "ips":             {"1.2.3.4", "5.6.7.8"},
        "generated_note":  "Feed generated 2026-07-16 by Proactive Hunter",
    })
    hit = threatview_c2.lookup("1.2.3.4")
    assert hit is not None
    assert hit["framework"] == "Cobalt Strike"
    assert hit["verdict"] == "MALICIOUS"
    assert "high-confidence" in hit["summary"].lower()


def test_threatview_returns_none_for_unlisted_ip():
    threatview_c2._state.update({
        "loaded_at": time.time(),
        "ips":       {"1.2.3.4"},
    })
    assert threatview_c2.lookup("9.9.9.9") is None
    assert threatview_c2.lookup("") is None
    assert threatview_c2.lookup(None) is None   # type: ignore[arg-type]


# ─── ViriBack ────────────────────────────────────────────────────────
def test_viriback_ip_returns_latest_family_and_hit_count():
    """Multiple observations of the same IP across different dates —
    ViriBack should surface the newest family attribution and expose
    the historical count."""
    viriback._state.update({
        "loaded_at": time.time(),
        "by_ip":     {"1.2.3.4": [
            {"family": "Amadey", "url": "http://1.2.3.4/old.php",
             "ip": "1.2.3.4", "first_seen": "01-06-2026"},
            {"family": "RedLine", "url": "http://1.2.3.4/new.php",
             "ip": "1.2.3.4", "first_seen": "09-07-2026"},
        ]},
        "by_url":    {},
    })
    hit = viriback.lookup_ip("1.2.3.4")
    assert hit is not None
    assert hit["family"] == "RedLine"
    assert hit["hit_count"] == 2
    assert set(hit["all_families"]) == {"Amadey", "RedLine"}


def test_viriback_url_lookup_returns_family():
    viriback._state.update({
        "loaded_at": time.time(),
        "by_ip":     {},
        "by_url":    {"http://1.2.3.4/panel/login.php": {
            "family": "Lumma", "url": "http://1.2.3.4/panel/login.php",
            "ip": "1.2.3.4", "first_seen": "10-07-2026",
        }},
    })
    hit = viriback.lookup_url("http://1.2.3.4/panel/login.php")
    assert hit["family"] == "Lumma"
    assert hit["verdict"] == "MALICIOUS"


# ─── typosquat first-party allowlist ─────────────────────────────────
def test_onmicrosoft_com_not_flagged_as_microsoft_typosquat():
    """Regression: 'microsoft' is a proper substring of 'onmicrosoft'
    so the substring matcher inside looks_like_brand fired on every
    M365 tenant domain. That surfaced in a real analyst report on an
    email-forwarding-rule log — onmicrosoft.com was called a typosquat.
    Assert the whole first-party matrix stays clean."""
    for d in ("onmicrosoft.com", "contoso.onmicrosoft.com",
              "login.microsoftonline.com", "microsoftonline.com",
              "microsoft365.com", "sharepoint.com",
              "storage.googleapis.com", "googleusercontent.com",
              "docs.googleusercontent.com",
              "amazonaws.com", "cloudfront.net",
              "githubusercontent.com", "docusign.net"):
        # Bust the lru_cache so the assertion actually re-runs the
        # gate we changed.
        typosquat.check_domain.cache_clear()
        assert typosquat.check_domain(d) is None, (
            f"{d} was incorrectly flagged as a typosquat"
        )


def test_real_typosquats_still_flagged():
    """Belt-and-braces — the allowlist must not swallow real squats."""
    for d in ("micros0ft.com", "micrsoft.com", "microsoftonlme.com",
              "paypa1.com", "g00gle.com"):
        typosquat.check_domain.cache_clear()
        assert typosquat.check_domain(d) is not None, (
            f"{d} should have been flagged as a typosquat"
        )
