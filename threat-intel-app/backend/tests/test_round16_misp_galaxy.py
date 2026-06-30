"""Round-16 tests — MISP Galaxy depth + cross-walk attribution.

Covers the three new actor-flavour clusters + cross_walk_actor + the
existing fuzzy lookups still functioning. We don't pin specific
actor names (the upstream MISP catalog changes) — instead we exercise
shapes + the cross-walk behaviour against known long-lived names.
"""

from __future__ import annotations


def test_galaxy_stats_includes_new_clusters():
    from intel.misp_galaxies import stats
    s = stats()
    assert s["actor_index_size"] >= 100, s
    # The malware index now spans the 5 malware-flavour catalogs.
    assert s["malware_index_size"] >= 1500, s
    # actor_by_tier should expose three tiers when the three clusters
    # are present. Tests should still pass when only the community
    # cluster is bundled (CI without the fetch script).
    tiers = s.get("actor_tiers") or {}
    assert "community" in tiers


def test_lookup_actor_returns_canonical_shape():
    from intel.misp_galaxies import lookup_actor
    a = lookup_actor("APT29")
    if a is None:
        # Older bundle doesn't include the threat-actor cluster — OK to skip.
        import pytest
        pytest.skip("threat-actor cluster not bundled")
    assert isinstance(a, dict)
    for k in ("name", "aliases", "cluster", "source_tier"):
        assert k in a, f"missing field {k}: {a}"


def test_cross_walk_actor_high_confidence_when_multi_source():
    """APT29 / Cozy Bear is documented in MITRE intrusion-set (G0016)
    AND community threat-actor — when both are present, confidence
    should be 'high'."""
    from intel.misp_galaxies import cross_walk_actor
    walk = cross_walk_actor("APT29")
    if walk is None:
        import pytest
        pytest.skip("MITRE intrusion-set cluster not bundled")
    assert "tiers_hit" in walk
    if len(walk["tiers_hit"]) >= 2:
        assert walk["confidence"] == "high", walk
    elif len(walk["tiers_hit"]) == 1:
        assert walk["confidence"] == "medium", walk


def test_cross_walk_actor_returns_none_for_unknown():
    from intel.misp_galaxies import cross_walk_actor
    assert cross_walk_actor("definitely-not-a-real-threat-actor-xyz") is None
    assert cross_walk_actor("") is None
    assert cross_walk_actor(None) is None  # type: ignore[arg-type]


def test_cross_walk_actor_attaches_mitre_id_when_mitre_match():
    """For an actor that appears in mitre-intrusion-set, the cross-walk
    record should expose its G#### id."""
    from intel.misp_galaxies import cross_walk_actor
    # APT29 = G0016 in MITRE intrusion-set. Use the friendly name so
    # the fuzzy lookup hits.
    walk = cross_walk_actor("APT29")
    if walk is None:
        import pytest
        pytest.skip("MITRE intrusion-set cluster not bundled")
    if walk.get("matches", {}).get("mitre"):
        assert walk["mitre_id"] and walk["mitre_id"].startswith("G")


def test_list_sectors_present_when_bundled():
    from intel.misp_galaxies import list_sectors
    sectors = list_sectors()
    if not sectors:
        import pytest
        pytest.skip("sector.json not bundled")
    assert isinstance(sectors, list)
    assert all(isinstance(s, str) for s in sectors)


def test_list_countries_present_when_bundled():
    from intel.misp_galaxies import list_countries
    cs = list_countries()
    if not cs:
        import pytest
        pytest.skip("target-information.json not bundled")
    assert isinstance(cs, list)
    assert all(isinstance(c, dict) for c in cs)
    assert all("name" in c for c in cs[:5])


def test_response_match_actors_attaches_cross_walk():
    """End-to-end: response._match_actors should add a `cross_walk`
    dict to each matched actor when MISP-galaxy has data."""
    from agents.response import _match_actors
    # Pick a technique list that has historical actor coverage (T1059
    # PowerShell, T1003 OS credential dumping, T1486 ransomware).
    matched = _match_actors(["T1059", "T1003", "T1486"])
    if not matched:
        import pytest
        pytest.skip("no actors matched — actor_data fallback empty")
    # Every match either has cross_walk (when MISP galaxy fired) OR
    # at least the original fields preserved (when cross_walk_actor
    # returned None for that name).
    for a in matched:
        assert "name" in a
        if "cross_walk" in a:
            cw = a["cross_walk"]
            assert "confidence" in cw
            assert "tiers_hit" in cw
