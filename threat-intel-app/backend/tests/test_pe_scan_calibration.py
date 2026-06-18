"""Regression tests for the file-scanner verdict calibration fixes
discovered during the live `/api/scan/file` audit:

  1. Authenticode-signed PEs that don't trip the capability map's
     MALICIOUS elevator must not land at MALICIOUS purely from raw YARA
     match count. A real signed `python.exe` was returning MALICIOUS
     verdict / 80 confidence because the YARA library shipped 17
     generic PE-characteristic rules (IsPE64, HasOverlay, anti_dbg,
     HasRichSignature, ...) and the verdict synthesizer added 70 points
     for the match count.

  2. Dotted-quad IP extraction must drop version-shaped values
     (6.0.0.0, 5.1.2600.0, 10.0.19041.0) and any IP with an octet
     > 255 — they appear constantly in PE binary strings.

  3. URL extraction must drop trailing junk that PE binaries embed
     immediately after OCSP URLs (`http://ocsp.digicert.com0A` etc.)
     — the DER ASN.1 length+tag bytes following the URL happen to
     spell printable ASCII that the old `[^\\s'\"<>]` regex captured.
"""

from __future__ import annotations

import os
import sys

import pytest

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)


# ─── 1. Verdict calibration for Authenticode-signed binaries ────────────
def test_signed_pe_with_generic_yara_does_not_land_at_malicious():
    """The live audit: python.exe (a legitimate signed Python
    interpreter) returned MALICIOUS with confidence 80. Reproduce the
    same shape via the public _synthesize_verdict path and assert the
    new cap holds."""
    from intel.file_analyzer import _synthesize_verdict
    # Shape mirrors what file_analyzer produces for a Python interpreter:
    # 17 vendor YARA matches (all generic), capabilities verdict
    # SUSPICIOUS (2 mid-tier techniques), Authenticode signature present.
    result = {
        "yara_matches": [{"rule": f"generic_{i}", "source": "vendor"}
                         for i in range(17)],
        "type":         {"mismatch": False},
        "entropy":      {"flag": None, "overall": 6.5},
        "suspicious_strings": [],
        "capabilities": {"verdict": "SUSPICIOUS",
                         "mitre_techniques": [{"id": "T1106"}, {"id": "T1497"}]},
        "format_specific": {"pe": {"signature": {"present": True}}},
    }
    verdict, score = _synthesize_verdict(result)
    assert verdict in ("LOW", "SUSPICIOUS"), (
        f"signed PE with generic YARA matches should not land at "
        f"MALICIOUS — got {verdict!r} / {score}"
    )


def test_unsigned_pe_with_same_yara_still_lands_at_malicious():
    """Verify the cap only applies when Authenticode is present. The
    same 17-match shape on an UNSIGNED binary should still escalate —
    we don't want to make it harder to flag unsigned commodity loaders."""
    from intel.file_analyzer import _synthesize_verdict
    result = {
        "yara_matches": [{"rule": f"generic_{i}", "source": "vendor"}
                         for i in range(17)],
        "type":         {"mismatch": False},
        "entropy":      {"flag": None, "overall": 6.5},
        "suspicious_strings": [],
        "capabilities": {"verdict": "SUSPICIOUS",
                         "mitre_techniques": [{"id": "T1106"}, {"id": "T1497"}]},
        "format_specific": {"pe": {"signature": {"present": False}}},
    }
    verdict, score = _synthesize_verdict(result)
    assert verdict == "MALICIOUS", (
        f"unsigned PE with the same 17-match shape should still land "
        f"at MALICIOUS — got {verdict!r} / {score}"
    )


def test_signed_pe_with_capability_malicious_still_escalates():
    """Critical: a SIGNED binary that the capability map flagged as
    MALICIOUS (e.g., Cobalt Strike beacon signed with a stolen cert,
    or a malware that picked up T1055 + T1105) must still be reported
    MALICIOUS. The Authenticode downgrade is only for the
    weak-capability case."""
    from intel.file_analyzer import _synthesize_verdict
    result = {
        "yara_matches": [{"rule": "Cobalt_Strike_Beacon", "source": "vendor"}],
        "type":         {"mismatch": False},
        "entropy":      {"flag": "elevated_entropy"},
        "suspicious_strings": [],
        "capabilities": {"verdict": "MALICIOUS",
                         "mitre_techniques": [{"id": "T1055"}, {"id": "T1105"}]},
        "format_specific": {"pe": {"signature": {"present": True}}},
    }
    verdict, score = _synthesize_verdict(result)
    assert verdict == "MALICIOUS", (
        f"signed PE with capabilities.verdict=MALICIOUS must still "
        f"escalate — got {verdict!r} / {score}"
    )


# ─── 2. Version-shaped IPv4 filter ───────────────────────────────────────
@pytest.mark.parametrize("ip,should_filter", [
    # Version-shaped — PE binaries emit these constantly. Should filter.
    ("6.0.0.0",          True),    # Windows SDK
    ("5.0.0.0",          True),    # generic 5.X assembly
    ("1.0.0.0",          True),    # generic 1.0 assembly
    ("10.0.19041.0",     True),    # Windows 10 build
    ("5.1.2600.0",       True),    # Windows XP build
    ("4.0.30319.0",      True),    # .NET runtime
    # Defender / Microsoft signature versions with octet > 255 — same shape
    # as the version strings the original Defender 1116 fix dropped.
    ("1.451.195.0",      True),    # Defender AV signature version
    # Real IPs — must NOT filter.
    ("1.1.1.1",          False),   # Cloudflare
    ("8.8.8.8",          False),   # Google DNS
    ("185.220.101.45",   False),   # something
    ("192.168.1.1",      False),   # RFC1918 (caller decides)
])
def test_version_shaped_ip_filter(ip, should_filter):
    from intel.file_analyzer import _is_version_shaped_ip
    assert _is_version_shaped_ip(ip) is should_filter, (
        f"{ip!r}: filter said {_is_version_shaped_ip(ip)!r}, "
        f"expected {should_filter!r}"
    )


def test_pe_binary_ioc_extraction_drops_version_strings():
    """End-to-end: a PE binary string containing 6.0.0.0 and other
    version artifacts must not have them appear in iocs.ips."""
    from intel.file_analyzer import _extract_iocs_from_text
    # Synthetic PE-binary-style string corpus: version artifacts + legit IPs.
    corpus = (
        "FileVersion 6.0.0.0\n"
        "ProductVersion 10.0.19041.0\n"
        "DotNetVersion 4.0.30319.0\n"
        "ScannerSignature 1.451.195.0\n"
        "OriginalIP 185.220.101.45\n"
        "AnotherIP 8.8.8.8\n"
    )
    iocs = _extract_iocs_from_text(corpus)
    # version artifacts must be filtered
    for v in ("6.0.0.0", "10.0.19041.0", "4.0.30319.0", "1.451.195.0"):
        assert v not in iocs["ips"], f"version artifact {v!r} leaked into iocs.ips"
    # real IPs must survive
    assert "185.220.101.45" in iocs["ips"]
    assert "8.8.8.8" in iocs["ips"]


# ─── 3. URL extraction filter for DER/X.509 trailing junk ────────────────
@pytest.mark.parametrize("url,should_pass", [
    # Real URLs — must pass.
    ("https://google.com/search",                 True),
    ("http://example.com/",                       True),
    ("https://api.virustotal.com/api/v3/files/x", True),
    ("http://abuseipdb.com",                      True),
    # IP-based URLs — common for C2 / lab / pentest setups. The Nim
    # shellcode loader test in test_source_code_analysis.py uses
    # http://192.168.174.128:4443/... and must pass — my first version
    # of the netloc validator rejected these because the "TLD" of an
    # IP address is a number, not alphabetic. Regression cover.
    ("http://192.168.174.128:4443/screenconnect/id?=64545", True),
    ("http://10.0.0.5/payload",                            True),
    ("https://1.1.1.1/cdn-cgi/trace",                      True),
    ("http://[2001:db8::1]:8080/x",                        True),  # IPv6 with brackets
    # OCSP-with-DER-junk — must NOT pass.
    ("http://ocsp.digicert.com0A",                False),
    ("http://ocsp.digicert.com0C",                False),
    ("http://ocsp.digicert.com0X",                False),
    ("http://crl.thawte.com.crl0\\",              False),
    # Bare scheme — must NOT pass.
    ("http://",                                   False),
    ("https://",                                  False),
])
def test_url_netloc_validation(url, should_pass):
    from intel.file_analyzer import _is_valid_url_netloc
    assert _is_valid_url_netloc(url) is should_pass, (
        f"{url!r}: validator said {_is_valid_url_netloc(url)!r}, "
        f"expected {should_pass!r}"
    )


def test_pe_binary_ioc_extraction_drops_der_junk_urls():
    """End-to-end: a PE binary that embedded `http://ocsp.digicert.com0A`
    immediately followed by `0\\x03` in DER encoding must NOT have that
    junk URL in iocs.urls."""
    from intel.file_analyzer import _extract_iocs_from_text
    corpus = (
        "Some text http://ocsp.digicert.com0A more stuff\n"
        "Real URL https://google.com/search?q=test\n"
        "Another junk: http://crl.thawte.com.crl0\\\\ more stuff\n"
    )
    iocs = _extract_iocs_from_text(corpus)
    for junk in ("http://ocsp.digicert.com0A", "http://crl.thawte.com.crl0\\"):
        assert junk not in iocs["urls"], f"DER-junk URL leaked: {junk!r}"
    assert "https://google.com/search?q=test" in iocs["urls"]
