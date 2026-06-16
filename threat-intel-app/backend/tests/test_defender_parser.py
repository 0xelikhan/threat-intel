"""Regression tests for intel.defender_parser — focus on the inline-Message
export shape (Event-Forwarding / Sentinel) that the original line-anchored
patterns missed.

Reproduces the real log from a misparse where the email composer reported
the legitimate OUTLOOK.EXE as the malicious file, the audit-subject SYSTEM
as the affected user, and the AV signature version 1.453.121.0 as a source
IP.
"""

import os
import sys

import pytest


_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from intel.defender_parser import parse_defender_event  # noqa: E402
from agents.triage import extract_iocs                  # noqa: E402


# Defender 1116 export with every field crammed onto the Message line —
# the form emitted by Windows Event Forwarding / Sentinel ingestion. Earlier
# parser versions ignored every Message-body field and matched only the
# top-level "User : SYSTEM" line.
_DEFENDER_INLINE_LOG = (
    "Date: Jun 16, 2026, 10:09:35 AM\n"
    "User: SYSTEM\n"
    "Action Type: OS Event Log\n"
    "Transport Layer : none\n"
    "Effective Action : None\n"
    "EventLog Source ID : 1116\n"
    "EventLog Description : Microsoft-Windows-Windows Defender\n"
    "Message : Microsoft Defender Antivirus has detected malware or other "
    "potentially unwanted software. For more information please see the "
    "following: https://go.microsoft.com/fwlink/?linkid=37020"
    "&name=Trojan:Win32/Leonem!rfn&threatid=2147827561&enterprise=0 "
    "Name: Trojan:Win32/Leonem!rfn "
    "ID: 2147827561 "
    "Severity: Severe "
    "Category: Trojan "
    "Path: file:_C:\\Users\\josee.landry\\AppData\\Local\\Microsoft\\Windows\\"
    "INetCache\\Content.Outlook\\VY5U7HNH\\Agricultural Alliance of NB Series Docs.pdf "
    "Detection Origin: Internet "
    "Detection Type: Concrete "
    "Detection Source: Real-Time Protection "
    "User: COLLEGE\\Josee.Landry "
    "Process Name: C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE "
    "Security intelligence Version: AV: 1.453.121.0, AS: 1.453.121.0, NIS: 1.453.121.0 "
    "Engine Version: AM: 1.1.26050.11, NIS: 1.1.26050.11\n"
    "Log Name : Microsoft-Windows-Windows Defender/Operational\n"
    "Level : Warning\n"
)


@pytest.fixture(scope="module")
def parsed():
    p = parse_defender_event(_DEFENDER_INLINE_LOG)
    assert p is not None, "looks_like_defender_log() rejected a known Defender 1116 input"
    return p


def test_malware_name_from_message_body(parsed):
    assert parsed["malware_name"] == "Trojan:Win32/Leonem!rfn"


def test_threat_id_is_numeric(parsed):
    assert parsed["threat_id"] == "2147827561"


def test_severity_and_category_from_message_body(parsed):
    assert parsed["severity"] == "Severe"
    assert parsed["category"] == "Trojan"


def test_infected_path_is_the_pdf_not_outlook(parsed):
    # file:_ prefix stripped; trailing fields don't bleed in.
    assert parsed["infected_path"].endswith(
        "INetCache\\Content.Outlook\\VY5U7HNH\\Agricultural Alliance of NB Series Docs.pdf"
    )
    assert not parsed["infected_path"].lower().startswith("file:")
    # Critical: the legitimate process must not be reported as the malicious file.
    assert "OUTLOOK.EXE" not in parsed["infected_path"]


def test_affected_user_overrides_top_level_system(parsed):
    # Top-level "User : SYSTEM" is audit-pipeline metadata. The
    # Message-body "User : COLLEGE\\Josee.Landry" is the actual victim
    # and must win.
    assert parsed["affected_user"] == "COLLEGE\\Josee.Landry"


def test_process_name_kept_separate_from_infected_path(parsed):
    assert parsed["process_name"].endswith("OUTLOOK.EXE")
    assert parsed["process_name"] != parsed["infected_path"]


def test_detection_origin_and_type_and_source(parsed):
    assert parsed["detection_origin"] == "Internet"
    assert parsed["detection_type"] == "Concrete"
    assert parsed["detection_source"] == "Real-Time Protection"


def test_security_intelligence_version_captured(parsed):
    # The whole comma-separated AV/AS/NIS list comes through, bounded
    # before the Engine Version field.
    assert "1.453.121.0" in parsed["security_intelligence_version"]
    assert "AV:" in parsed["security_intelligence_version"]
    assert "NIS:" in parsed["security_intelligence_version"]
    assert "Engine" not in parsed["security_intelligence_version"]


def test_engine_version_captured(parsed):
    assert "1.1.26050.11" in parsed["engine_version"]


def test_summary_line_names_the_pdf_and_real_user(parsed):
    s = parsed["summary_line"]
    assert "Trojan:Win32/Leonem!rfn" in s
    assert ".pdf" in s.lower()
    assert "Josee.Landry" in s
    # Must NOT name OUTLOOK.EXE as the threat or SYSTEM as the user.
    assert "OUTLOOK.EXE" not in s
    assert "SYSTEM" not in s


def test_ioc_extractor_does_not_extract_version_string_as_ip():
    # Independent integration check: the AV/AS/NIS dotted numbers are
    # software version strings, not IPs. The _DEFENDER_AV_KV_RE scrubber
    # plus the _valid_ipv4_octets gate both backstop this.
    iocs = extract_iocs(_DEFENDER_INLINE_LOG)
    assert "1.453.121.0" not in iocs.get("ips", [])
    assert "1.1.26050.11" not in iocs.get("ips", [])
