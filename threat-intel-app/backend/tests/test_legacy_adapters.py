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
async def test_every_analyzer_returns_analysis_result():
    """Call every registered Analyzer plugin's `analyze()` and confirm
    it doesn't crash (the legacy_registrations table has since been
    drained — the sweep now exercises every formal plugin file under
    plugins/analyzers/, which is a stricter check since each file can
    diverge from the shared adapter pattern)."""
    from plugins import registry, AnalysisResult
    registry.discover()

    analyzers = registry.analyzers()
    assert analyzers, "no analyzers registered"

    import aiohttp
    async with aiohttp.ClientSession() as session:
        # Fake every required/optional key the registered set declares
        all_keys = set()
        for a in analyzers:
            all_keys.update(getattr(a, "required_keys", []) or [])
            all_keys.update(getattr(a, "optional_keys", []) or [])
        keys = {k: "FAKE_KEY_FOR_TESTS" for k in all_keys}

        failures = []
        for a in analyzers:
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

        assert not failures, (
            f"{len(failures)} analyzer failure{'s' if len(failures) != 1 else ''}:\n"
            + "\n".join(failures)
        )
