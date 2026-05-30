"""IPv6 IOC extraction regression tests.

Pre-fix: an impossible-travel alert with two IPv6 source IPs silently
skipped enrichment because `_valid_octets(ip)` did `ip.split('.')` +
`int(part)` and rejected every v6 input on ValueError. No IPs in the
result → no enrichment fan-out → no Geolocation map.

These tests pin the v6 extraction path so the regression cannot
return.
"""

from __future__ import annotations

import asyncio

from agents.triage import (
    extract_iocs,
    _is_private_ip,
    _valid_ip,
    _valid_octets,
)
from skills import get_skill


# The exact alert the user pasted (trimmed to the IP-bearing fields).
IMPOSSIBLE_TRAVEL_ALERT = """\
Operation : UserLoggedIn
Workload : AzureActiveDirectory
RiskType : Impossible Travel
FirstLoginIp : 2a13:9243:4890:692:b5c9:ba7b:ad9e:4427
SecondLoginIp : 2607:fb90:efa3:4d9:404a:e81a:706b:ebf6
AddressPair : 2a13:9243:4890:692:b5c9:ba7b:ad9e:4427,2607:fb90:efa3:4d9:404a:e81a:706b:ebf6
SourceIp : 2a13:9243:4890:692:b5c9:ba7b:ad9e:4427
City : New York City
Country : United States
"""


def test_impossible_travel_ipv6_addresses_extracted():
    out = extract_iocs(IMPOSSIBLE_TRAVEL_ALERT)
    assert set(out["ips"]) == {
        "2a13:9243:4890:692:b5c9:ba7b:ad9e:4427",
        "2607:fb90:efa3:4d9:404a:e81a:706b:ebf6",
    }, f"missing IPv6: {out['ips']}"


def test_ipv6_compressed_form_extracted():
    out = extract_iocs("Connection to 2606:4700::1111 succeeded")
    assert "2606:4700::1111" in out["ips"]


def test_ipv6_substring_dedup():
    """Both '2606:4700::' (regex trailing-:: branch) and the longer
    '2606:4700::1111' get matched. Only the longer survives."""
    out = extract_iocs("traffic to 2606:4700::1111 then to 2a00:1450:4001:81b::200e")
    assert "2606:4700::1111" in out["ips"]
    assert "2a00:1450:4001:81b::200e" in out["ips"]
    assert "2606:4700::" not in out["ips"]
    assert "2a00:1450:4001:81b::" not in out["ips"]


def test_ipv6_private_loopback_link_local_rejected():
    """Private / loopback / link-local / ULA must be filtered out; public
    IPv6 (not in BENIGN_IPS) must survive."""
    out = extract_iocs(
        "loopback ::1 link-local fe80::1 ULA fd00::abcd "
        "public 2a13:9243:4890:692:b5c9:ba7b:ad9e:4427"
    )
    assert out["ips"] == ["2a13:9243:4890:692:b5c9:ba7b:ad9e:4427"]


def test_ipv6_well_known_resolvers_in_benign_list():
    """Cloudflare + Google public DNS v6 are in BENIGN_IPS — should be
    dropped same as their v4 counterparts."""
    out = extract_iocs("DNS lookup to 2606:4700:4700::1111 and to 8.8.8.8")
    assert "2606:4700:4700::1111" not in out["ips"]
    assert "8.8.8.8" not in out["ips"]


def test_ipv6_mixed_with_ipv4():
    out = extract_iocs("TOR exit 185.220.101.45 then v6 callout 2a00:1450:4001:81b::200e")
    assert "185.220.101.45" in out["ips"]
    assert "2a00:1450:4001:81b::200e" in out["ips"]


# ─── helper functions ────────────────────────────────────────────────────────
def test_valid_ip_accepts_both_v4_and_v6():
    assert _valid_ip("8.8.8.8") is True
    assert _valid_ip("2606:4700:4700::1111") is True
    assert _valid_ip("::1") is True
    assert _valid_ip("not-an-ip") is False
    assert _valid_ip("") is False


def test_valid_octets_back_compat_alias():
    """_valid_octets is the historical name; it must still resolve and
    must accept v6 now (the bug was that v6 returned False)."""
    assert _valid_octets is _valid_ip
    assert _valid_octets("2606:4700:4700::1111") is True


def test_is_private_ip_handles_both_families():
    # v4 private / loopback / link-local
    assert _is_private_ip("192.168.1.1") is True
    assert _is_private_ip("10.0.0.5") is True
    assert _is_private_ip("127.0.0.1") is True
    assert _is_private_ip("169.254.169.254") is True
    # v6 private / loopback / link-local / ULA / multicast
    assert _is_private_ip("::1") is True
    assert _is_private_ip("fe80::1") is True
    assert _is_private_ip("fd00::abcd") is True
    assert _is_private_ip("ff02::1") is True
    # public
    assert _is_private_ip("8.8.8.8") is False
    assert _is_private_ip("2606:4700:4700::1111") is False
    assert _is_private_ip("2a00:1450:4001:81b::200e") is False
    # garbage
    assert _is_private_ip("not-an-ip") is False
    assert _is_private_ip("") is False


# ─── skill path ──────────────────────────────────────────────────────────────
def test_skill_extract_iocs_handles_ipv6():
    sk = get_skill("extract_iocs")
    out = asyncio.run(sk.execute({"raw_text": IMPOSSIBLE_TRAVEL_ALERT}, provider=None))
    seen = set(out["ips"]) | {s["ioc"] for s in out["suppressed_iocs"]["ips"]}
    assert "2a13:9243:4890:692:b5c9:ba7b:ad9e:4427" in seen
    assert "2607:fb90:efa3:4d9:404a:e81a:706b:ebf6" in seen
