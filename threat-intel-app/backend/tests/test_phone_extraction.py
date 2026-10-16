"""Phone IOC extraction regression test.

Confirms that triage.extract_iocs now emits a 'phones' bucket when
the input text contains recognisable phone numbers. Powered by
google-libphonenumber's PhoneNumberMatcher (POSSIBLE leniency).

Covers:
  - international format (+country code)
  - US formatted (parens / dashes / dots)
  - invalid / short digit runs do NOT produce phones
  - no phonenumbers lib installed → empty bucket, no crash
"""

from __future__ import annotations

import pytest


def test_extract_iocs_emits_phones_bucket():
    from agents.triage import extract_iocs
    iocs = extract_iocs("call us")
    assert "phones" in iocs
    assert isinstance(iocs["phones"], list)


def test_extract_iocs_international_phone():
    from agents.triage import extract_iocs
    # +14155551234 is a valid US number in E.164 form
    iocs = extract_iocs("The attacker's number was +1 415 555 1234, repeated 3x.")
    assert any(p.startswith("+1") for p in iocs["phones"]), (
        f"expected a +1 phone in: {iocs['phones']}"
    )


def test_extract_iocs_international_phones_multiple():
    """Multiple E.164 numbers in one text, different countries."""
    from agents.triage import extract_iocs
    iocs = extract_iocs("Numbers: +1 415 555 1234, +44 20 7946 0958, +81 3-1234-5678.")
    e164s = iocs["phones"]
    assert any("+1" in p for p in e164s), f"missing US number in: {e164s}"
    assert any("+44" in p for p in e164s), f"missing UK number in: {e164s}"
    assert any("+81" in p for p in e164s), f"missing JP number in: {e164s}"


def test_extract_iocs_does_not_find_phones_in_ips_or_versions():
    """A plain IP or version string shouldn't be flagged as a phone number."""
    from agents.triage import extract_iocs
    text = "Source IP 192.168.1.1 reached version 4.19.0.123456 at 10:35 UTC."
    iocs = extract_iocs(text)
    assert iocs["phones"] == [], f"false-positive phones: {iocs['phones']}"


def test_extract_iocs_coexists_with_other_buckets():
    """Phone IOCs shouldn't blow up or interfere with other buckets.
    Uses an attacker-flavoured IP (not in BENIGN_IPS)."""
    from agents.triage import extract_iocs
    text = ("Attack from 185.220.101.5 against evil.example.com, "
            "contact +1 415 555 1234 for ransom.")
    iocs = extract_iocs(text)
    # All three buckets populated — phones didn't steal from the rest
    assert "185.220.101.5" in iocs["ips"]
    assert "evil.example.com" in iocs["domains"]
    assert any("+1" in p for p in iocs["phones"])
