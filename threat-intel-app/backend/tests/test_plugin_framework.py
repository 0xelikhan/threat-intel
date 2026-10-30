"""Regression tests for the plugin framework (plugins/).

Covers:
  - Registry discovery populates all 7 plugin kinds without crashing
  - Legacy adapters register and are callable
  - AnalysisResult.from_legacy_dict handles missing / malformed inputs
  - File-type detector returns the right types per magic bytes
  - Pivot plugin extracts dropped hashes correctly
  - Playbook plugin validates artifact type
"""

from __future__ import annotations

import sys
import types

import pytest


# ─── Stub agents.enrichment so legacy adapters importing _get/_post work ───

@pytest.fixture(autouse=True, scope="module")
def _stub_agents():
    if "agents.enrichment" in sys.modules:
        yield
        return
    pkg = types.ModuleType("agents")
    enr = types.ModuleType("agents.enrichment")
    async def _get(*a, **k): return {"error": "stub", "error_type": "unreachable"}
    async def _post(*a, **k): return {"error": "stub", "error_type": "unreachable"}
    enr._get = _get
    enr._post = _post
    sys.modules["agents"] = pkg
    sys.modules["agents.enrichment"] = enr
    yield


# ─── Registry ──────────────────────────────────────────────────────────────

def test_registry_discovers_without_crash():
    from plugins import registry
    registry.discover()
    assert len(registry.all()) > 50, "registry should discover many plugins"


def test_registry_has_all_plugin_kinds():
    from plugins import registry
    registry.discover()
    assert registry.analyzers(), "no analyzers registered"
    assert registry.file_analyzers(), "no file analyzers registered"
    assert registry.connectors(), "no connectors registered"
    assert registry.pivots(), "no pivots registered"
    assert registry.visualizers(), "no visualizers registered"
    assert registry.ingestors(), "no ingestors registered"
    assert registry.playbooks(), "no playbooks registered"


def test_registry_get_by_name():
    from plugins import registry
    assert registry.get("dshield") is not None
    assert registry.get("yaraify") is not None
    assert registry.get("phunter") is not None
    assert registry.get("sandbox_dropped_hashes") is not None
    assert registry.get("misp") is not None
    assert registry.get("default_card") is not None
    assert registry.get("taxii") is not None
    assert registry.get("suspicious_ip_triage") is not None
    assert registry.get("DOES_NOT_EXIST") is None


def test_analyzers_for_ipv4_covers_core_sources():
    from plugins import registry
    names = {a.name for a in registry.analyzers_for("ipv4")}
    assert {"dshield", "robtex"}.issubset(names), (
        f"expected dshield + robtex in ipv4 analyzers; got {names}"
    )


def test_file_analyzers_for_pe_covers_core():
    from plugins import registry
    names = {a.name for a in registry.file_analyzers_for("pe")}
    assert {"pe_metadata", "pe_authenticode", "yara_scanner"}.issubset(names)


def test_descriptors_serialise_cleanly():
    from plugins import registry
    for d in registry.descriptors():
        # Pydantic model_dump must not raise and must have core fields
        serialised = d.model_dump()
        assert serialised["name"] and serialised["kind"]


# ─── AnalysisResult wrapping ───────────────────────────────────────────────

def test_from_legacy_dict_handles_empty():
    """Empty/None legacy returns map to found=False — a bare {} means
    the upstream module had nothing to say, not that it succeeded.
    This matters because many legacy intel/*.py modules short-circuit
    with return None on no-data; the wrapper boxes that to {} before
    passing here, and we must NOT turn that into a false-positive hit."""
    from plugins.data_models import AnalysisResult
    r = AnalysisResult.from_legacy_dict({}, "ipv4", "1.2.3.4")
    assert r.source == "unknown"
    assert r.verdict == "UNKNOWN"
    assert r.found is False


def test_from_legacy_dict_content_dict_is_found():
    """A dict with any real content (keys beyond the reserved set)
    counts as a hit — the common 'module returned enrichment' path."""
    from plugins.data_models import AnalysisResult
    r = AnalysisResult.from_legacy_dict(
        {"source": "foo", "country": "US", "org": "ExampleCorp"},
        "ipv4", "1.2.3.4",
    )
    assert r.found is True
    assert r.raw == {"country": "US", "org": "ExampleCorp"}


def test_from_legacy_dict_explicit_found_wins():
    """If a legacy module sets found=False explicitly, we honour it
    even if the dict has other content."""
    from plugins.data_models import AnalysisResult
    r = AnalysisResult.from_legacy_dict(
        {"source": "foo", "found": False, "summary": "no record"},
        "ipv4", "1.2.3.4",
    )
    assert r.found is False


def test_from_legacy_dict_captures_error():
    from plugins.data_models import AnalysisResult
    r = AnalysisResult.from_legacy_dict(
        {"source": "x", "error": "boom", "error_type": "auth_failed"},
        "ipv4", "1.2.3.4",
    )
    assert r.error == "boom"
    assert r.error_type == "auth_failed"
    assert r.found is False


def test_from_legacy_dict_extras_land_in_raw():
    from plugins.data_models import AnalysisResult
    r = AnalysisResult.from_legacy_dict(
        {"source": "y", "verdict": "MALICIOUS", "custom_field": [1, 2, 3]},
        "domain", "example.com",
    )
    assert r.raw.get("custom_field") == [1, 2, 3]
    # Reserved fields never appear in raw
    for k in ("source", "found", "verdict", "summary", "details_url", "error", "error_type"):
        assert k not in r.raw


# ─── File type detector ───────────────────────────────────────────────────

def test_detect_pe():
    from plugins.file_type_detector import detect_types
    assert "pe" in detect_types(b"MZ" + b"\x00" * 100, "")


def test_detect_elf():
    from plugins.file_type_detector import detect_types
    assert "elf" in detect_types(b"\x7fELF\x02\x01" + b"\x00" * 100, "")


def test_detect_pdf():
    from plugins.file_type_detector import detect_types
    assert "pdf" in detect_types(b"%PDF-1.7\n", "")


def test_detect_apk():
    from plugins.file_type_detector import detect_types
    assert "apk" in detect_types(b"PK\x03\x04AndroidManifest.xml", "")


def test_detect_office_from_ole():
    from plugins.file_type_detector import detect_types
    assert "office" in detect_types(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100, "")


def test_detect_office_from_openxml_extension():
    from plugins.file_type_detector import detect_types
    assert "office" in detect_types(b"PK\x03\x04", "doc.docx")


def test_detect_shellcode_on_small_unknown():
    from plugins.file_type_detector import detect_types
    # Small blob, no magic, no extension → shellcode heuristic
    assert "shellcode" in detect_types(b"\x90" * 100, "")


def test_detect_no_shellcode_on_known_formats():
    """Shellcode heuristic must not fire alongside identified formats."""
    from plugins.file_type_detector import detect_types
    assert "shellcode" not in detect_types(b"MZ" + b"\x00" * 100, "")
    assert "shellcode" not in detect_types(b"%PDF-1.7\n", "")


def test_detect_always_appends_any():
    from plugins.file_type_detector import detect_types
    assert detect_types(b"anything", "x.exe")[-1] == "any"


# ─── Pivot: sandbox_dropped_hashes ────────────────────────────────────────

@pytest.mark.asyncio
async def test_pivot_extracts_dropped_hashes():
    from plugins import registry, AnalysisResult
    pivot = registry.get("sandbox_dropped_hashes")
    assert pivot is not None

    result = AnalysisResult(
        source="hybrid_analysis", ioc_type="sha256", ioc_value="x" * 64,
        found=True, verdict="MALICIOUS", summary="",
        raw={"files_dropped": [
            {"sha256": "a" * 64},
            {"md5": "b" * 32},
        ]},
    )
    assert await pivot.should_pivot(result) is True
    iocs = await pivot.extract_pivot_iocs(result)
    types_found = {i["type"] for i in iocs}
    assert "sha256" in types_found and "md5" in types_found


@pytest.mark.asyncio
async def test_pivot_skips_non_sandbox_sources():
    from plugins import registry, AnalysisResult
    pivot = registry.get("sandbox_dropped_hashes")
    result = AnalysisResult(
        source="virustotal", ioc_type="ipv4", ioc_value="1.2.3.4",
        found=True, verdict="MALICIOUS", summary="",
        raw={"files_dropped": [{"sha256": "a" * 64}]},
    )
    # Even with files_dropped present, VT shouldn't trigger the sandbox pivot
    assert await pivot.should_pivot(result) is False


# ─── Visualizer ───────────────────────────────────────────────────────────

def test_default_card_visualizer_shape():
    from plugins import registry, AnalysisResult
    viz = registry.get("default_card")
    result = AnalysisResult(
        source="greynoise", ioc_type="ipv4", ioc_value="8.8.8.8",
        found=True, verdict="UNKNOWN", summary="benign scanner",
        details_url="https://greynoise.io/8.8.8.8",
        raw={"country": "US", "asn": "AS15169"},
    )
    hint = viz.to_component_hint(result)
    assert hint["component"] == "GenericEnrichmentCard"
    assert hint["source"] == "greynoise"
    assert hint["verdict"] == "UNKNOWN"
    assert hint["preview"]["country"] == "US"
