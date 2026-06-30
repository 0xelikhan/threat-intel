"""Round-15 tests — cti-expert integrations.

Covers the four new backend modules + their wire-points:

  * intel/admin_endpoint_classifier.py — pure-function classifier
  * intel/m365_tenant_recon.py         — gate + module shape (no live HTTP)
  * intel/maltego_export.py            — GraphML serialiser
  * intel/case_score.py                — case-level rollup
  * /api/export/maltego/{run_id}       — HTTP endpoint covered via TestClient

The M365 module's actual HTTP probes hit Microsoft endpoints, so we
only test the shape + gate function here. End-to-end M365 verification
requires a real internet-connected lab.
"""

from __future__ import annotations

import os
import sys

import bcrypt
import pytest

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)


# ─── admin_endpoint_classifier ─────────────────────────────────────────────

def test_admin_classifier_flags_subdomain_prefix():
    from intel.admin_endpoint_classifier import classify
    r = classify("https://kefu.example.com/")
    assert r["is_admin"] is True
    assert r["indicator"].startswith("subdomain:")
    assert r["verdict"] in ("SUSPICIOUS", "MALICIOUS")


def test_admin_classifier_flags_path_segment():
    from intel.admin_endpoint_classifier import classify
    r = classify("https://example.com/admin/login.php")
    assert r["is_admin"] is True
    assert r["indicator"].startswith("path:/admin")


def test_admin_classifier_localised_keyword():
    from intel.admin_endpoint_classifier import classify
    r = classify("https://example.com/管理")
    assert r["is_admin"] is True
    assert r["indicator"] == "keyword:cn-admin"


def test_admin_classifier_scam_tld_amplifier_alone():
    from intel.admin_endpoint_classifier import classify
    r = classify("https://example.top/page")
    # scam-TLD by itself is SUSPICIOUS but NOT is_admin
    assert r["is_admin"] is False
    assert r["verdict"] == "SUSPICIOUS"
    assert r["indicator"].startswith("scam_tld:")


def test_admin_classifier_admin_plus_scam_tld_is_malicious():
    from intel.admin_endpoint_classifier import classify
    r = classify("https://admin.shady.top/login")
    assert r["is_admin"] is True
    assert r["verdict"] == "MALICIOUS"


def test_admin_classifier_clean_url():
    from intel.admin_endpoint_classifier import classify
    r = classify("https://github.com/torvalds/linux")
    assert r["is_admin"] is False
    assert r["verdict"] == "CLEAN"


def test_admin_classifier_ignores_non_http_schemes():
    from intel.admin_endpoint_classifier import classify
    r = classify("android://com.example.app/admin")
    assert r["is_admin"] is False


def test_admin_classifier_handles_empty():
    from intel.admin_endpoint_classifier import classify
    assert classify("")["verdict"] == "CLEAN"
    assert classify(None)["verdict"] == "CLEAN"  # type: ignore[arg-type]


# ─── m365_tenant_recon ─────────────────────────────────────────────────────

def test_m365_gate_picks_up_outlook_protection_in_whois():
    from intel.m365_tenant_recon import is_m365_candidate
    payload = {"whois": {"mx": "tenant-com.mail.protection.outlook.com"}}
    assert is_m365_candidate(payload) is True


def test_m365_gate_picks_up_onmicrosoft_in_payload():
    from intel.m365_tenant_recon import is_m365_candidate
    payload = {"shodan": {"banner": "contoso.onmicrosoft.com responded with..."}}
    assert is_m365_candidate(payload) is True


def test_m365_gate_skips_non_microsoft_domain():
    from intel.m365_tenant_recon import is_m365_candidate
    payload = {"whois": {"mx": "alt1.aspmx.l.google.com"}}
    assert is_m365_candidate(payload) is False


def test_m365_gate_handles_empty_payload():
    from intel.m365_tenant_recon import is_m365_candidate
    assert is_m365_candidate({}) is False
    assert is_m365_candidate(None) is False  # type: ignore[arg-type]


def test_m365_stats_shape():
    from intel.m365_tenant_recon import stats
    s = stats()
    assert s["loaded"] is True
    assert s["endpoints_probed"] == 4


# ─── case_score ────────────────────────────────────────────────────────────

def test_case_score_clean_state_grades_low():
    from intel.case_score import compute
    out = compute({})
    assert 0 <= out["score"] <= 30
    assert out["tier"] in ("CLEAR", "MONITOR")
    assert out["grade"].startswith(("A", "B"))


def test_case_score_kev_active_amplifies():
    from intel.case_score import compute
    state = {
        "cross_refs": {"kev": [{"cve": "CVE-2024-1234", "ransomware_use": True}]},
        "response_summary": {"malware_family": "Lockbit"},
        "behavioral_indicators": {"categories": {"credential_access": [1]}},
    }
    out = compute(state)
    assert out["score"] >= 70
    assert out["tier"] in ("ESCALATE", "CRITICAL")
    # active-compromise multiplier should have fired
    assert out["multipliers"]["active_compromise"] > 1.0


def test_case_score_grade_letter_format():
    from intel.case_score import compute
    out = compute({})
    assert len(out["grade"]) == 2
    assert out["grade"][0] in "ABCDF"
    assert out["grade"][1].isdigit()


def test_case_score_drivers_listed():
    from intel.case_score import compute
    out = compute({"cross_refs": {"kev": [{"cve": "x"}]}})
    assert any(d["driver"] == "kev_active" for d in out["drivers"])


# ─── maltego_export ────────────────────────────────────────────────────────

def test_maltego_export_empty_state_returns_minimal_graphml():
    from intel.maltego_export import to_graphml
    g = to_graphml({})
    assert g.startswith('<?xml version="1.0"')
    assert "<graphml" in g
    assert "</graphml>" in g
    # Root recon node + verdict node always emitted
    assert g.count("<node") >= 2


def test_maltego_export_ioc_nodes_and_edges():
    from intel.maltego_export import to_graphml
    state = {
        "runId": "test-run-001",
        "iocs": {
            "ips":     ["1.2.3.4"],
            "domains": ["evil.example.com"],
            "urls":    ["https://evil.example.com/login.php"],
            "hashes":  ["abc123" * 10][:1],  # one fake hash
        },
        "enrichments": {
            "domains": {"evil.example.com": {"whois": {"resolved": "1.2.3.4"}}},
            "ips":     {"1.2.3.4": {"virustotal": {"malicious": 7}}},
        },
        "response_summary": {
            "threat_level": "HIGH",
            "summary":      "evil.example.com hosts a credential phish",
        },
    }
    g = to_graphml(state)
    assert "evil.example.com" in g
    assert "1.2.3.4" in g
    # Domain → resolves_to → IP edge should appear
    assert "resolves_to" in g
    # URL → on_domain → Domain edge should appear
    assert "on_domain" in g
    # Verdict edge from root
    assert 'relationship">verdict' in g


def test_maltego_export_is_valid_xml():
    """Defensive parse — the GraphML output must round-trip through an
    XML parser without raising."""
    from intel.maltego_export import to_graphml
    import xml.etree.ElementTree as ET
    g = to_graphml({
        "runId": "x",
        "iocs": {"domains": ["foo.com", "bar.com"]},
        "response_summary": {"threat_level": "LOW"},
    })
    ET.fromstring(g)


# ─── /api/export/maltego/{run_id} HTTP endpoint ───────────────────────────

_USER = "round15-test"
_PW   = "round15-test-pw"


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    import main as _main
    from intel import auth as _auth

    _auth._USERNAME      = _USER
    _auth._PASSWORD_HASH = bcrypt.hashpw(
        _PW.encode(), bcrypt.gensalt(rounds=4))

    c = TestClient(_main.app)
    r = c.post("/api/auth/login",
               json={"username": _USER, "password": _PW})
    assert r.status_code == 200, f"login failed: {r.text}"
    return c, _main


def test_maltego_endpoint_404_for_missing_run(client):
    c, _ = client
    r = c.get("/api/export/maltego/does-not-exist")
    assert r.status_code == 404


def test_maltego_endpoint_returns_graphml(client):
    c, _main = client
    # Seed a run in the bounded store the endpoint reads from.
    run_id = "round15-maltego-test"
    _main._results[run_id] = {
        "runId": run_id,
        "iocs": {"domains": ["example.com"]},
        "response_summary": {"threat_level": "LOW"},
    }
    r = c.get(f"/api/export/maltego/{run_id}")
    assert r.status_code == 200
    assert r.headers.get("content-type", "").startswith("application/graphml+xml")
    body = r.text
    assert "<graphml" in body
    assert "example.com" in body
    # Filename header
    assert "graphml" in (r.headers.get("content-disposition") or "")
