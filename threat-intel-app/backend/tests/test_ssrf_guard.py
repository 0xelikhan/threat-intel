"""SSRF-guard regression test for /api/scan/url.

Catches two specific failure modes that the unit suite previously missed:

1. aiohttp's AbstractResolver export moved between releases. In aiohttp
   3.14 the top-level `aiohttp.AbstractResolver` re-export was removed,
   and the `_PinnedResolver` class definition in main.py crashed at
   endpoint-eval time — every POST to /api/scan/url returned a blanket
   500 BEFORE the SSRF guard could even run. The integration audit caught
   it; nothing in the unit suite did. Pin the resolver location here so
   any future re-export change fails loudly in CI instead of silently in
   prod.

2. The address-classification logic must reject every range an SSRF
   attacker could meaningfully pivot through, including ones Python's
   own ipaddress module does NOT flag as private — CGNAT (100.64.0.0/10)
   contains Alibaba Cloud's metadata endpoint, IPv4-mapped IPv6 hides
   loopback behind `::ffff:127.0.0.1`, decimal/hex/octal forms hide the
   octets entirely. The previous guard let CGNAT through (verified live
   during the audit).
"""

from __future__ import annotations

import os
import sys

import pytest

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)


# ─── 1. aiohttp's AbstractResolver must be importable from a stable path ──
def test_aiohttp_abstract_resolver_importable():
    # main.py subclasses this. If aiohttp ever moves it again, that
    # subclass eval would crash at request time and every /api/scan/url
    # call would return a blanket 500. Pin the path here.
    from aiohttp.abc import AbstractResolver
    assert AbstractResolver is not None
    # main.py uses the same import path; if this drifts, /api/scan/url breaks.
    import inspect
    src = inspect.getsource(__import__("main"))
    assert "from aiohttp.abc import AbstractResolver" in src, (
        "main.py no longer pins aiohttp.abc.AbstractResolver — when aiohttp "
        "next renames it, the SSRF guard's _PinnedResolver class definition "
        "will crash at request time."
    )


# ─── 2. Internal-IP classification must reject every SSRF pivot range ────
# The classifier is defined inside the scan_url_endpoint closure, so we
# re-implement the exact same predicate here (same ranges, same logic)
# and assert that nothing slips through. When main.py's _ip_is_internal
# is updated, mirror it here.
def _ip_is_internal_under_test(ip_str: str) -> bool:
    import ipaddress
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
        return True
    extras = tuple(ipaddress.ip_network(c) for c in (
        "100.64.0.0/10", "198.18.0.0/15", "192.0.0.0/24",
        "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
        "fd00:ec2::/64", "2001:db8::/32", "100::/64",
    ))
    for net in extras:
        if ip.version == net.version and ip in net:
            return True
    return False


# Each entry: (ip, should_be_blocked)
@pytest.mark.parametrize("ip,should_block", [
    # Classic private / loopback / link-local
    ("127.0.0.1",          True),
    ("127.1.2.3",          True),     # entire 127/8 is loopback
    ("10.0.0.5",           True),
    ("172.16.0.1",         True),
    ("192.168.1.1",        True),
    ("169.254.1.1",        True),
    ("169.254.169.254",    True),     # AWS / Azure / GCP IMDS

    # Unspecified / multicast / reserved
    ("0.0.0.0",            True),
    ("224.0.0.1",          True),
    ("240.0.0.1",          True),

    # CGNAT — Python's is_private says False, but it IS internal-ish and
    # contains Alibaba Cloud's metadata IP at 100.100.100.200.
    ("100.64.0.5",         True),
    ("100.100.100.200",    True),     # Alibaba metadata
    ("100.127.255.255",    True),

    # Benchmark / TEST-NET / IANA special use
    ("198.18.0.5",         True),
    ("192.0.0.5",          True),
    ("192.0.2.1",          True),
    ("198.51.100.1",       True),
    ("203.0.113.1",        True),

    # IPv6 internal
    ("::1",                True),
    ("fe80::1",            True),     # link-local
    ("fc00::1",            True),     # ULA
    ("::",                 True),     # unspecified
    ("::ffff:127.0.0.1",   True),     # IPv4-mapped loopback

    # IPv6 cloud-metadata / documentation / discard
    ("fd00:ec2::254",      True),     # AWS IPv6 metadata
    ("2001:db8::1",        True),     # docs
    ("100::1",             True),     # discard

    # Malformed inputs — fail closed
    ("",                   True),
    ("not.an.ip",          True),
    ("999.999.999.999",    True),

    # Legitimate public addresses — must NOT be blocked.
    ("1.1.1.1",            False),    # Cloudflare DNS
    ("8.8.8.8",            False),    # Google DNS
    ("93.184.216.34",      False),    # example.com (historic)
    ("2606:4700:4700::1111", False),  # Cloudflare DNS IPv6
])
def test_internal_ip_classification(ip, should_block):
    assert _ip_is_internal_under_test(ip) is should_block, (
        f"{ip!r}: classifier said {_ip_is_internal_under_test(ip)!r}, "
        f"expected {should_block!r}"
    )


# ─── 3. Sanity-check that main.py's actual classifier matches this one ───
# We can't easily import the closure-local _ip_is_internal directly, but
# we can assert main.py contains the same set of extra ranges so the
# table here doesn't drift from the production guard.
def test_main_pinned_extra_internal_nets_in_source():
    import inspect
    src = inspect.getsource(__import__("main"))
    # Every range in this list must appear verbatim in main.py.
    for cidr in (
        '"100.64.0.0/10"', '"198.18.0.0/15"', '"192.0.0.0/24"',
        '"192.0.2.0/24"', '"198.51.100.0/24"', '"203.0.113.0/24"',
        '"fd00:ec2::/64"', '"2001:db8::/32"', '"100::/64"',
    ):
        assert cidr in src, (
            f"main.py's SSRF guard no longer pins {cidr} — the regression "
            f"table in tests/test_ssrf_guard.py expects it. Either reinstate "
            f"the range or update the test table."
        )
