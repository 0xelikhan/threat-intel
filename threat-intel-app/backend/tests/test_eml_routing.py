"""Regression tests for the EML mis-routing bug surfaced by the live
file-scanner audit:

  * A phishing-shaped .eml POSTed to /api/scan/file came back with
    file_type=source_code and file_type_label="Source Code source code"
    (doubled wording). The source-code heuristic in _detect_source_code
    triggered on the RFC822 message because EMLs are >95% printable
    ASCII with no binary magic — the negative path needed an explicit
    "known non-source extension" branch.
  * EML files also fell into category=binary (the dispatcher in
    file_analyzer_formats had no `email` branch), so format_specific
    came back empty. Even before a dedicated EML deep-analyzer lands,
    the category should be `email` so future hooks have somewhere to go.
"""

from __future__ import annotations

import os
import sys

import pytest

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)


# A phishing-shaped EML. Matches the live audit fixture shape.
_EML_BODY = (
    b"From: attacker@evil.example\n"
    b"To: victim@victim.example\n"
    b"Subject: Urgent: Account verification\n"
    b"Date: Sun, 18 Jun 2026 10:00:00 +0000\n"
    b"Authentication-Results: spf=fail (sender IP is 185.220.101.45) "
    b"dkim=fail dmarc=fail\n"
    b"Received: from mail.evil.example ([185.220.101.45])\n"
    b"Content-Type: text/html\n"
    b"\n"
    b"<html><body>\n"
    b'Click <a href="http://phishing-portal.evil.example/login?id=victim">'
    b"here</a>\n"
    b"to verify your account.\n"
    b"</body></html>\n"
)


def test_eml_not_classified_as_source_code():
    """The .eml extension MUST trigger the early-out non-source branch
    so the printable-ASCII heuristic doesn't catch it."""
    from intel.file_analyzer import _detect_source_code
    is_source, lang = _detect_source_code(_EML_BODY, "eml", "message/rfc822")
    assert not is_source, (
        f"EML wrongly classified as source code (lang={lang!r}). "
        "RFC822 messages are plain ASCII headers + body — the .eml "
        "extension branch must short-circuit before the printable ratio."
    )


def test_extensionless_email_headers_not_classified_as_source_code():
    """An EML pasted without the .eml extension still needs to bypass
    the source-code heuristic — the header sniff catches it."""
    from intel.file_analyzer import _detect_source_code
    is_source, lang = _detect_source_code(_EML_BODY, "", "")
    assert not is_source, (
        f"Extensionless RFC822 message wrongly classified as source code "
        f"(lang={lang!r}). The header sniff in _detect_source_code must "
        "reject content that opens with email headers."
    )


def test_eml_category_is_email():
    """File category for EML must be 'email' so a future dedicated
    EML analyzer in file_analyzer_formats has a category to hook on.
    Previously fell into 'binary' (no MIME match) which meant the
    dispatcher silently did nothing."""
    from intel.file_analyzer import _category_from_mime
    assert _category_from_mime("message/rfc822", "eml") == "email"
    assert _category_from_mime("message/rfc822", "") == "email"
    assert _category_from_mime("", "eml") == "email"


def test_eml_end_to_end_through_analyze_file():
    """End-to-end: an EML through analyze_file gets the right top-level
    fields and extracts the phishing IOCs the analyst cares about."""
    from intel.file_analyzer import analyze_file
    result = analyze_file(_EML_BODY, "phish.eml")
    # File-type fields must NOT say source code.
    assert result["file_type"] != "source_code", (
        f"file_type wrongly set to source_code for an EML: "
        f"{result['file_type']!r}"
    )
    # Specifically the doubled "Source Code source code" label must be gone.
    assert "source code source code" not in (result.get("file_type_label") or "").lower()
    # The IOCs the analyst expects from this phishing message must surface.
    iocs = result.get("iocs") or {}
    assert "185.220.101.45" in (iocs.get("ips") or [])
    assert "phishing-portal.evil.example" in (iocs.get("domains") or [])
    assert any("phishing-portal.evil.example" in u for u in (iocs.get("urls") or []))
    assert "attacker@evil.example" in (iocs.get("emails") or [])


# ─── Source-code label dedup ────────────────────────────────────────────
def test_generic_source_code_label_does_not_double():
    """When the source-code language detector falls back to the generic
    "Source Code" label, the file_type_label must say "source code"
    (one phrase), not "Source Code source code" (doubled)."""
    from intel.file_analyzer import analyze_file
    # A printable-ASCII blob with no extension, no source-specific signals.
    # Falls into the heuristic source-code path with the generic label.
    plain = b"This is some printable text with no language signal.\n" * 30
    result = analyze_file(plain, "notes")
    if result.get("file_type") == "source_code":
        label = (result.get("file_type_label") or "").lower()
        assert label == "source code", (
            f"generic source label wrongly doubled: {label!r}"
        )
        banner = (result.get("file_type_banner") or "")
        assert "Source Code source code" not in banner, (
            f"banner wrongly doubled: {banner!r}"
        )
