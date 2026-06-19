"""Regression tests for the Defender-1116 version-vs-IP confusion the
user reported 2026-06-19 against a PUABundler:FileZilla alert.

Two leaks were stacked:

  1. The SIEM auto-populated `Source IP: 1[.]453[.]161[.]0` from the
     Defender Security Intelligence Version field (octet 453 > 255 so
     it is not a valid IPv4). The triage strip didn't blank labeled
     IP fields, so the value reached the LLM prompt and the model
     parroted "the source IP for this event is 1.453.161.0" into the
     analyst-facing narrative.

  2. iocextract's URL extractor refangs `1[.]453[.]161[.]0` to
     `http://1.453.161.0`, and the URL extraction path had no host
     octet-validity gate. The fake URL therefore landed in iocs[urls]
     and got shipped to enrichment, which surfaced it again in the
     analyst report.

Both paths are exercised below using the exact alert shape from the
user's repro.
"""
from __future__ import annotations

import os
import sys

import pytest

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)


# Exact shape of the reported alert. Defanged `1[.]453[.]161[.]0` plus
# the inline AV/AS/NIS Security Intelligence Version that drove the
# SIEM to mis-label it.
_DEFENDER_ALERT = (
    "User: SYSTEM\n"
    r"File path: C:\Users\user1\AppData\Local\Microsoft\OneDrive\OneDrive.exe"
    "\n"
    "Detection: PUABundler:Win32/FileZilla_BundleInstaller\n"
    "Source IP: 1[.]453[.]161[.]0\n"
    "Time: Jun 19, 2026, 8:33:59 AM\n"
    "EventLog Source ID: 1116\n"
    "Message: Microsoft Defender Antivirus has detected malware or other "
    "potentially unwanted software. ID: 311942 Severity: Low "
    "Security intelligence Version: AV: 1.453.161.0, AS: 1.453.161.0, "
    "NIS: 1.453.161.0 Engine Version: AM: 1.1.26050.11, NIS: 1.1.26050.11\n"
)


def test_extract_iocs_drops_iocextract_url_fabrication():
    """iocextract refangs `1[.]453[.]161[.]0` into `http://1.453.161.0`
    and the URL host octet gate must drop it. The bug surfaced as a
    fake URL IOC in the analyst report."""
    from agents.triage import extract_iocs

    iocs = extract_iocs(_DEFENDER_ALERT)
    urls = iocs.get("urls", [])

    assert not any("1.453.161.0" in u for u in urls), (
        f"iocextract URL fabrication leaked into IOCs: {urls!r}. "
        "The URL host octet-validity gate must drop fake "
        "http://<invalid-quad> URLs that iocextract synthesizes from "
        "defanged dotted-quad shapes."
    )

    # And no IP either — _valid_ipv4_octets backstops the regex too.
    assert "1.453.161.0" not in iocs.get("ips", []), (
        f"version 1.453.161.0 leaked into IP IOCs: {iocs.get('ips')!r}"
    )


def test_clean_for_analysis_wipes_labeled_invalid_ip_fields():
    """The LLM prompt must not see `Source IP: 1.453.161.0` or any
    labeled IP field whose value isn't a valid 0-255 quad. clean_for_analysis
    is the single chokepoint feeding every triage / investigation / response
    LLM call."""
    from agents.triage import clean_for_analysis

    cleaned = clean_for_analysis(_DEFENDER_ALERT)

    assert "1.453.161.0" not in cleaned, (
        f"Defender version 1.453.161.0 survived the LLM-prompt scrub. "
        f"Cleaned text was:\n{cleaned!r}"
    )
    assert "<invalid>" in cleaned, (
        "The labeled-IP scrub must replace the bad value with the "
        f"sentinel <invalid> so the alert structure stays grep-able. "
        f"Cleaned text:\n{cleaned!r}"
    )
    # The actual triggering filename + detection name MUST survive —
    # those are the bits the analyst needs to see.
    assert "FileZilla_BundleInstaller" in cleaned
    assert "OneDrive.exe" in cleaned


def test_clean_for_analysis_preserves_legitimate_source_ips():
    """The scrub must not touch real source IPs. Impossible-travel
    and brute-force alerts depend on the labeled IP field surfacing
    the attacker's address."""
    from agents.triage import clean_for_analysis

    real_alert = (
        "Sign-in failed for user@corp.example\n"
        "Source IP: 185.220.101.45\n"
        "Client IP: 203.0.113.42\n"
        "Remote IP Address: 2001:db8::1\n"
        "Outcome: failure\n"
    )
    cleaned = clean_for_analysis(real_alert)
    assert "185.220.101.45" in cleaned
    assert "203.0.113.42" in cleaned
    assert "<invalid>" not in cleaned, (
        f"Real IPs were wrongly wiped:\n{cleaned!r}"
    )


@pytest.mark.parametrize("url,is_invalid", [
    ("http://1.453.161.0",            True),
    ("https://1.453.161.0:8080/path", True),
    ("http://10.0.19041.0/x",         True),
    ("http://8.8.8.8",                False),
    ("https://1.2.3.4",               False),
    ("https://example.com/path",      False),
    ("http://[::1]/",                 False),
])
def test_url_host_invalid_quad_gate(url, is_invalid):
    from agents.triage import _url_host_is_invalid_quad
    assert _url_host_is_invalid_quad(url) is is_invalid


def test_url_host_octet_gate_catches_defanged_fabrications():
    """The URL gate must catch every shape iocextract emits when it
    refangs defanged quads — different ports, paths, trailing query
    strings — so none reach iocs[urls]."""
    from agents.triage import extract_iocs

    samples = [
        # All defanged forms iocextract can refang into http://<invalid-quad>
        "phishing target Source IP 1[.]453[.]161[.]0 connection",
        "saw 1(.)453(.)161(.)0 in the log",
        "endpoint 1(dot)453(dot)161(dot)0 ratelimited",
    ]
    for sample in samples:
        iocs = extract_iocs(sample)
        assert not any("1.453.161.0" in u for u in iocs.get("urls", [])), (
            f"defanged form {sample!r} leaked as URL IOC: "
            f"{iocs.get('urls')!r}"
        )
        assert "1.453.161.0" not in iocs.get("ips", []), (
            f"defanged form {sample!r} leaked as IP IOC: "
            f"{iocs.get('ips')!r}"
        )
