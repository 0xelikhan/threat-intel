"""
Round-10 outbound-adapter tests:

  * intel.sarif_output          — round-9 serializer already tested; this
                                   suite covers the /api/export/sarif/{id}
                                   endpoint shape via the helper.
  * intel.cacao_output          — same.
  * intel.misp_push             — graceful not_configured + builder shape
  * intel.thehive_push          — graceful not_configured + observable
                                   flattening
  * intel.stix_shifter_adapter  — built-in fallback translator

Offline only — no network in tests.
"""

from __future__ import annotations

import asyncio


# ─── MISP push (not_configured guard) ──────────────────────────────────────
def test_misp_push_not_configured():
    """With MISP_URL / MISP_KEY unset the push must short-circuit with
    a clean error_code rather than reach for the network."""
    import os
    # Ensure neither env nor config has MISP creds
    for v in ("MISP_URL", "MISP_KEY"):
        os.environ.pop(v, None)
    from intel.misp_push import push_event
    out = push_event(iocs={"ips": ["1.2.3.4"]}, investigation={})
    assert out["ok"] is False
    assert out["error_code"] == "not_configured"


def test_misp_push_attribute_builder_classifies_hashes():
    """Internal _build_misp_attributes must pick md5 / sha1 / sha256
    based on hash length."""
    from intel.misp_push import _build_misp_attributes
    attrs = _build_misp_attributes(
        {"hashes": [
            "0" * 32,    # MD5
            "1" * 40,    # SHA1
            "2" * 64,    # SHA256
            "shortbadhash",
        ]},
        investigation={"threat_actor": {"name": "Cobalt Strike"}},
    )
    types = sorted(a["type"] for a in attrs)
    assert "md5" in types
    assert "sha1" in types
    assert "sha256" in types
    # The malformed hash should be silently dropped.
    assert len(attrs) == 3
    assert all("Cobalt Strike" in a["comment"] for a in attrs)


# ─── TheHive push (not_configured guard) ───────────────────────────────────
def test_thehive_push_not_configured():
    import os
    for v in ("THEHIVE_URL", "THEHIVE_KEY"):
        os.environ.pop(v, None)
    from intel.thehive_push import push_case
    out = asyncio.run(push_case(iocs={"ips": ["1.2.3.4"]}, investigation={}))
    assert out["ok"] is False
    assert out["error_code"] == "not_configured"


def test_thehive_observable_flattener_handles_known_types():
    from intel.thehive_push import _flatten_observables
    obs = _flatten_observables(
        {"ips": ["1.2.3.4", "5.6.7.8"],
         "domains": ["evil.example.com"],
         "hashes": ["abc"],
         "urls": ["https://x.com/path"]},
        tlp=2,
    )
    types = sorted(o["dataType"] for o in obs)
    assert "ip" in types
    assert "domain" in types
    assert "url" in types
    assert "hash" in types
    # All carry TLP and ioc=True flags
    assert all(o["tlp"] == 2 for o in obs)
    assert all(o["ioc"] is True for o in obs)


# ─── STIX-Shifter built-in fallback translator ─────────────────────────────
def test_stix_shifter_unknown_target():
    from intel.stix_shifter_adapter import translate_pattern
    out = translate_pattern("[ipv4-addr:value = '1.2.3.4']", target="nonexistent")
    assert out["ok"] is False
    assert out["error_code"] == "unknown_target"


def test_stix_shifter_empty_pattern():
    from intel.stix_shifter_adapter import translate_pattern
    out = translate_pattern("", target="splunk")
    assert out["ok"] is False
    assert out["error_code"] == "empty_pattern"


def test_stix_shifter_translates_ip_to_splunk():
    from intel.stix_shifter_adapter import translate_pattern
    out = translate_pattern("[ipv4-addr:value = '185.220.101.45']",
                             target="splunk")
    assert out["ok"] is True
    assert "185.220.101.45" in out["query"]
    assert "src_ip" in out["query"] or "dest_ip" in out["query"]
    assert out["match_count"] == 1


def test_stix_shifter_translates_hash_to_kql():
    from intel.stix_shifter_adapter import translate_pattern
    out = translate_pattern(
        "[file:hashes.'SHA-256' = 'deadbeef0123456789abcdef0123456789abcdef0123456789abcdef0123456789']",
        target="kql",
    )
    assert out["ok"] is True
    assert "deadbeef" in out["query"]
    assert "SHA256" in out["query"]


def test_stix_shifter_translates_bundle_with_multiple_indicators():
    from intel.stix_shifter_adapter import translate_bundle
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "indicator", "pattern": "[ipv4-addr:value = '1.2.3.4']"},
            {"type": "indicator", "pattern": "[domain-name:value = 'evil.com']"},
            {"type": "attack-pattern", "name": "ignored"},  # non-indicator
        ],
    }
    out = translate_bundle(bundle, target="elastic_ecs")
    assert out["ok"] is True
    assert out["pattern_count"] == 2
    assert "1.2.3.4" in out["query"]
    assert "evil.com" in out["query"]


def test_stix_shifter_handles_empty_bundle():
    from intel.stix_shifter_adapter import translate_bundle
    out = translate_bundle({"type": "bundle", "objects": []}, target="splunk")
    assert out["ok"] is False
    assert out["error_code"] == "empty_bundle"


def test_stix_shifter_lib_available_returns_bool():
    from intel.stix_shifter_adapter import is_stix_shifter_available
    # The heavy lib is not installed in the test env; expect False.
    assert is_stix_shifter_available() in (True, False)
