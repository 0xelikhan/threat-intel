"""Tests for the MISP galaxy lookup module.

These tests rely on the galaxy JSON files being downloaded under
backend/intel/misp_galaxy/. In CI the Dockerfile fetches them at build
time; locally the developer runs the same curl loop. If the cluster
files are missing the tests skip rather than fail (so a fresh checkout
without network access still passes pytest).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from intel.misp_galaxies import (
    lookup_actor, lookup_malware, _normalize, stats,
)

_GALAXY_DIR = Path(__file__).resolve().parents[1] / "intel" / "misp_galaxy"


def _has(cluster: str) -> bool:
    return (_GALAXY_DIR / cluster).exists()


def test_normalize_collapses_punctuation_and_case():
    assert _normalize("LockBit 3.0") == "lockbit30"
    assert _normalize("APT-28") == "apt28"
    assert _normalize("  Cozy Bear ") == "cozybear"


@pytest.mark.skipif(not _has("threat-actor.json"),
                    reason="MISP galaxy threat-actor.json not downloaded")
def test_threat_actor_canonical_and_alias_resolve_to_same_record():
    canon = lookup_actor("APT28")
    via_alias = lookup_actor("Fancy Bear")
    assert canon is not None
    assert via_alias is not None
    assert canon["name"] == via_alias["name"] == "APT28"
    assert canon["country"] == "RU"
    assert any("Sofacy" in a for a in canon.get("aliases", []))


@pytest.mark.skipif(not _has("threat-actor.json"),
                    reason="MISP galaxy threat-actor.json not downloaded")
def test_threat_actor_is_case_insensitive():
    a = lookup_actor("LAZARUS GROUP")
    b = lookup_actor("lazarus group")
    assert a is not None and b is not None
    assert a["name"] == b["name"] == "Lazarus Group"
    assert a["country"] == "KP"


@pytest.mark.skipif(not _has("ransomware.json"),
                    reason="MISP galaxy ransomware.json not downloaded")
def test_malware_lookup_alphv_resolves_via_alias():
    # ALPHV is an alias for BlackCat in the malpedia cluster.
    r = lookup_malware("ALPHV")
    assert r is not None
    assert "BlackCat" in r["name"] or "ALPHV" in r["name"]
    assert r["cluster"] in ("Malpedia", "Ransomware Group")


@pytest.mark.skipif(not _has("malpedia.json"),
                    reason="MISP galaxy malpedia.json not downloaded")
def test_malware_lookup_well_known_families():
    for fam in ("Cobalt Strike", "Emotet", "TrickBot"):
        r = lookup_malware(fam)
        assert r is not None, f"{fam} should be in malpedia"
        assert r["name"]
        assert r["description"]


def test_lookup_returns_none_for_unknown():
    assert lookup_actor("definitely-not-an-apt-12345") is None
    assert lookup_malware("not-a-real-malware-family-zzz") is None
    assert lookup_actor("") is None
    assert lookup_actor(None) is None


def test_stats_returns_expected_shape():
    s = stats()
    assert "actor_index_size" in s
    assert "malware_index_size" in s
    assert "cluster_files" in s
    assert isinstance(s["cluster_files"], dict)
