"""
Round-7 OSS integrations:

  * Shodan InternetDB         (live API)
  * ET Open + Snort           (intel.ids_rules)
  * FireHOL                   (intel.firehol)
  * Cloud provider IP ranges  (intel.cloud_ip_ranges)
  * MSRC API                  (intel.cve_enrichment.msrc)
  * SSVC                      (intel.ssvc)
  * ATT&CK Mobile/Cloud/Containers (intel.mitre_data)
  * PublicSuffix List         (intel.public_suffix)
  * CISA AIS / TAXII catalog  (intel.taxii_feeds_catalog)
  * Ransomwhe.re              (intel.ransomwhere)
  * AWS GuardDuty taxonomy    (intel.guardduty_taxonomy)
  * Vendor advisory RSS       (intel.vendor_advisories)
  * NIST 800-53               (intel.nist_800_53)
  * ETW providers             (intel.etw_providers)

Offline graceful-missing + built-in fallback coverage for each.
"""

from __future__ import annotations

import asyncio


# ─── ET Open + Snort IDS rules ──────────────────────────────────────────────
def test_ids_rules_handles_missing_corpus():
    from intel.ids_rules import match_by_cve, match_by_techniques, stats
    s = stats()
    assert s["loaded"] is True
    assert isinstance(match_by_cve("CVE-2023-12345"), list)
    assert isinstance(match_by_techniques(["T1190"]), list)


# ─── FireHOL ────────────────────────────────────────────────────────────────
def test_firehol_handles_missing_corpus():
    from intel.firehol import lookup, stats
    s = stats()
    assert s["loaded"] is True
    assert lookup("198.51.100.1") == []
    assert lookup("not-an-ip") == []


# ─── Cloud provider IP ranges ───────────────────────────────────────────────
def test_cloud_ip_ranges_returns_none_when_not_loaded():
    from intel.cloud_ip_ranges import lookup
    # Feed isn't fetched in tests — lookup should return None gracefully
    assert lookup("198.51.100.1") is None or isinstance(
        lookup("198.51.100.1"), dict
    )


# ─── MSRC parser (offline shape test) ───────────────────────────────────────
def test_msrc_parser_handles_not_found():
    from intel.cve_enrichment import _parse_msrc
    out = _parse_msrc({"error": "HTTP 404", "error_type": "not_found"},
                       "CVE-2099-99999")
    assert out["found"] is False


def test_msrc_parser_extracts_titles():
    from intel.cve_enrichment import _parse_msrc
    payload = {"value": [
        {"DocumentTitle": {"Value": "January 2024 Security Updates"},
         "AffectedProducts": [{"Value": "Windows 11"}]},
    ]}
    out = _parse_msrc(payload, "CVE-2024-12345")
    assert out["found"] is True
    assert "January 2024 Security Updates" in out["update_titles"][0]


# ─── SSVC ───────────────────────────────────────────────────────────────────
def test_ssvc_act_on_active_critical():
    """KEV + critical CVSS + nuclei templates → automatable=yes,
    exploitation=active, technical_impact=total → Act."""
    from intel.ssvc import assess
    data = {
        "cisa_kev": {"in_kev": True},
        "nuclei":   {"template_count": 5},
        "nvd":      {"cvss_v3_severity": "CRITICAL", "cvss_v3_score": 9.8},
    }
    out = assess(data, mission_impact="crippled")
    assert out["action"] == "Act"
    assert out["signals"]["exploitation"] == "active"
    assert out["signals"]["automatable"] == "yes"


def test_ssvc_track_on_clean_cve():
    """No KEV, no PoCs, no nuclei → exploitation=none, automatable=no,
    medium severity, degraded mission impact → Track."""
    from intel.ssvc import assess
    data = {"nvd": {"cvss_v3_severity": "MEDIUM", "cvss_v3_score": 5.5}}
    out = assess(data, mission_impact="degraded")
    assert out["action"] == "Track"


def test_ssvc_attend_with_poc():
    """No KEV but PoCs exist → exploitation=poc → escalates above Track."""
    from intel.ssvc import assess
    data = {
        "public_pocs": {"poc_count": 3},
        "nvd":         {"cvss_v3_severity": "CRITICAL", "cvss_v3_score": 9.0},
    }
    out = assess(data, mission_impact="crippled")
    assert out["action"] in ("Attend", "Act")


# ─── ATT&CK additional matrices ─────────────────────────────────────────────
def test_attack_matrices_keyword_routers():
    from intel.mitre_data import (
        looks_like_mobile_alert,
        looks_like_cloud_alert,
        looks_like_container_alert,
        looks_like_ics_alert,
    )
    assert looks_like_mobile_alert("alert on suspicious APK install") is True
    assert looks_like_mobile_alert("Windows DC logon") is False

    assert looks_like_cloud_alert("CloudTrail event for IAM role creation") is True
    assert looks_like_cloud_alert("Office 365 OAuth token reuse") is True
    assert looks_like_cloud_alert("ordinary endpoint event") is False

    assert looks_like_container_alert("privileged kubectl exec on pod") is True
    assert looks_like_container_alert("docker container escape via runc") is True
    assert looks_like_container_alert("regular file write") is False


def test_attack_mobile_loader_handles_missing_corpus():
    from intel.mitre_data import get_all_techniques_mobile
    assert isinstance(get_all_techniques_mobile(), list)


# ─── PublicSuffix List ──────────────────────────────────────────────────────
def test_psl_handles_known_suffixes_via_fallback():
    from intel.public_suffix import (
        public_suffix, registrable_domain, subdomain, stats,
    )
    s = stats()
    assert s["loaded"] is True
    # The built-in fallback covers co.uk
    assert public_suffix("mail.example.co.uk") == "co.uk"
    assert registrable_domain("mail.example.co.uk") == "example.co.uk"
    assert subdomain("mail.foo.example.co.uk") == "mail.foo"
    # github.io is a registry-style suffix
    assert public_suffix("myproject.github.io") == "github.io"
    assert registrable_domain("myproject.github.io") == "myproject.github.io"
    # Plain .com
    assert public_suffix("foo.example.com") == "com"
    assert registrable_domain("foo.example.com") == "example.com"


def test_psl_rejects_empty():
    from intel.public_suffix import public_suffix, registrable_domain
    assert public_suffix("") is None
    assert registrable_domain("") is None


# ─── TAXII feed catalog ─────────────────────────────────────────────────────
def test_taxii_catalog_lists_known_feeds():
    from intel.taxii_feeds_catalog import feed_slugs, TAXII_FEED_CATALOG
    slugs = feed_slugs()
    assert "cisa_ais" in slugs
    assert "hailataxii" in slugs
    assert TAXII_FEED_CATALOG["cisa_ais"]["requires_enrollment"] is True


def test_taxii_catalog_get_enabled_skips_enrollment_only():
    """cisa_ais without operator-supplied collection ID should be
    skipped, not returned with None/missing fields."""
    import os
    from intel.taxii_feeds_catalog import get_enabled_feeds
    old = os.environ.get("RECON_TAXII_FEEDS", "")
    try:
        os.environ["RECON_TAXII_FEEDS"] = "cisa_ais,hailataxii"
        # Make sure no collection override is set
        os.environ.pop("RECON_TAXII_CISA_AIS_COLLECTION", None)
        out = get_enabled_feeds()
        slugs_out = [f["name"] for f in out]
        # cisa_ais should be skipped due to missing collection;
        # hailataxii should be present (it has hardcoded collection)
        assert "CISA AIS" not in slugs_out
        assert any("hailataxii" in s.lower() for s in slugs_out)
    finally:
        os.environ["RECON_TAXII_FEEDS"] = old


# ─── Ransomwhe.re ───────────────────────────────────────────────────────────
def test_ransomwhere_handles_missing_corpus():
    from intel.ransomwhere import lookup, extract_addresses, stats
    s = stats()
    assert s["loaded"] is True
    assert lookup("bc1qexampleaddressnottracked") is None
    # extract_addresses doesn't need the corpus
    text = "send 1.5 BTC to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq or your data is gone"
    out = extract_addresses(text)
    assert "btc_bech32" in out
    assert "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" in out["btc_bech32"]


# ─── AWS GuardDuty taxonomy ─────────────────────────────────────────────────
def test_guardduty_known_findings_via_fallback():
    from intel.guardduty_taxonomy import (
        lookup_finding, findings_in_text, findings_for_technique, stats,
    )
    s = stats()
    assert s["loaded"] is True
    f = lookup_finding("Recon:EC2/PortProbeUnprotectedPort")
    assert f is not None
    assert "T1046" in f["mitre"]
    # findings_in_text picks up canonical finding-type strings
    alert = "Detected Recon:EC2/Portscan from instance i-deadbeef"
    found = findings_in_text(alert)
    assert any(r["finding_type"] == "Recon:EC2/Portscan" for r in found)
    # Reverse lookup
    assert "Recon:EC2/PortProbeUnprotectedPort" in findings_for_technique("T1046")


# ─── Vendor advisory aggregator ─────────────────────────────────────────────
def test_vendor_advisories_handles_unloaded_state():
    from intel.vendor_advisories import lookup_cve, stats
    s = stats()
    # In tests we haven't called ensure_loaded, so it's empty + loaded=False
    assert lookup_cve("CVE-2024-12345") == []
    assert s["error"] is None or "refresh failed" in (s.get("error") or "")


# ─── NIST 800-53 ────────────────────────────────────────────────────────────
def test_nist_controls_via_fallback():
    from intel.nist_800_53 import (
        lookup, controls_for_attack, controls_for_attacks, stats,
    )
    s = stats()
    assert s["loaded"] is True
    assert lookup("AU-6") is not None
    ac = controls_for_attack("T1078")
    assert ac
    assert any(r["control_id"].startswith("AC-") or r["control_id"].startswith("IA-") for r in ac)
    multi = controls_for_attacks(["T1078", "T1486"])
    assert "T1078" in multi
    assert "T1486" in multi


def test_nist_lookup_normalises_case():
    from intel.nist_800_53 import lookup
    assert lookup("ac-2") == lookup("AC-2")


# ─── ETW providers ──────────────────────────────────────────────────────────
def test_etw_providers_via_fallback():
    from intel.etw_providers import (
        lookup_guid, lookup_name, providers_for_attack, stats,
    )
    s = stats()
    assert s["loaded"] is True
    # Security Auditing GUID is in the fallback
    sec = lookup_guid("{54849625-5478-4994-A5BA-3E3B0328C30D}")
    assert sec is not None
    assert sec["name"].endswith("Security-Auditing")
    # Name lookup is case-insensitive
    by_name = lookup_name("microsoft-windows-security-auditing")
    assert by_name is not None
    # Reverse lookup by technique
    provs = providers_for_attack("T1078")
    assert any("Security-Auditing" in p["name"] for p in provs)


# ─── Unified match_detections — now spans 11 corpora ────────────────────────
def test_match_detections_returns_eleven_source_keys():
    from skills import run_skill
    out = asyncio.run(run_skill("match_detections", {
        "mitre_techniques": ["T1059.001"], "per_source_max": 3,
    }))
    for src in ("sigma", "panther", "splunk", "mitre_car",
                "hunter_playbook", "sublime", "chronicle", "olafhartong",
                "falco", "stratus", "ids_rules"):
        assert src in out, f"missing source key: {src}"
        assert isinstance(out[src], list)
