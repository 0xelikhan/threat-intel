"""Regression test: every LegacyAnalyzerAdapter in the registry can
be invoked without crashing.

The adapter maps a formal Analyzer plugin to an existing intel/*.py
module via importlib + getattr. Common failure modes this test
catches:
  - typo in module_import_path or lookup_fn_name
  - module imports a dependency that's not installed
  - the module raises on malformed input instead of returning a dict

Each adapter is called with a benign dummy IOC + a fake API key (if
required). We assert the return is an AnalysisResult — the content
is irrelevant for this test; we only care that no exception reaches
the orchestrator.
"""

from __future__ import annotations

import sys
import types

import pytest


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


# Representative IOC per type
_DUMMY = {
    "ipv4":   "8.8.8.8",
    "ipv6":   "2606:4700:4700::1111",
    "domain": "example.com",
    "url":    "http://example.com/",
    "md5":    "d41d8cd98f00b204e9800998ecf8427e",
    "sha1":   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "cve":    "CVE-2024-0001",
    "email":  "test@example.com",
    "crypto": "0x0000000000000000000000000000000000000000",
    "phone":  "+14155551234",
}


@pytest.mark.asyncio
async def test_every_legacy_adapter_returns_analysis_result():
    """Call every LegacyAnalyzerAdapter and confirm it doesn't blow up."""
    from plugins import registry, AnalysisResult, LegacyAnalyzerAdapter
    registry.discover()

    adapters = [a for a in registry.analyzers()
                 if isinstance(a, LegacyAnalyzerAdapter)]
    assert adapters, "no legacy adapters registered"

    # Pass a fake value for every required key so the adapter has
    # something to send through.
    import aiohttp
    async with aiohttp.ClientSession() as session:
        keys = {k: "FAKE_KEY_FOR_TESTS"
                for a in adapters for k in (a.required_keys + a.optional_keys)}

        failures = []
        for a in adapters:
            # Pick the first supported IOC type the adapter advertises.
            if not a.supported_ioc_types:
                failures.append(f"{a.name}: no supported_ioc_types declared")
                continue
            ioc_type = a.supported_ioc_types[0]
            value = _DUMMY.get(ioc_type, "test")
            try:
                r = await a.analyze(session, ioc_type, value, keys)
            except Exception as e:
                failures.append(f"{a.name}: raised {type(e).__name__}: {e}")
                continue
            if not isinstance(r, AnalysisResult):
                failures.append(f"{a.name}: returned {type(r).__name__} not AnalysisResult")

        assert not failures, "Legacy adapter failures:\n" + "\n".join(failures)
