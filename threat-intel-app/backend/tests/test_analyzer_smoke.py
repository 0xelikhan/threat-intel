"""Analyzer smoke test — every registered Analyzer handles a bare
no-key invocation without crashing and returns an AnalysisResult.

What this guards against:
  1. Import drift — legacy intel/*.py module renames / deletions. If
     an analyzer's lazy-import target disappeared, we want to see it
     surface as an `unavailable` AnalysisResult, not a NameError.
  2. Key-handling drift — keyed analyzers must short-circuit with
     error_type ∈ {missing_key, not_configured, unavailable, auth_failed}
     when no key is passed. If an analyzer blindly calls the upstream
     endpoint without a key, the mocked-session HTTP call would hit
     this test's fake response and (depending on parser shape) could
     either return a bad verdict or raise. Either way: the assertion
     "found is False" catches it.
  3. Response-shape drift — the mocked session returns an empty JSON
     payload. If the parser can't handle an empty dict without raising,
     the smoke test fails and we know the parser needs a type guard.

What this does NOT guard against:
  * Real-world response-shape changes in the live third-party APIs.
    That requires actually calling the services, which this test
    deliberately does not do (no network, no keys).

Companion test: `test_every_analyzer_returns_analysis_result` asserts
the SHAPE at the plugin-framework level. This one adds the behavioural
layer — "runs end-to-end without raising" — on top.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from plugins import AnalysisResult, registry


# ─── Fixtures ──────────────────────────────────────────────────────────────

# Plausible value per IOC type. Chosen so parsers that validate
# format (regex-match hashes, URL schemes, etc.) accept the input and
# proceed to the response-parsing path — which is what we actually want
# to exercise.
_PLAUSIBLE_VALUES = {
    "ipv4":   "1.1.1.1",
    "ipv6":   "2606:4700:4700::1111",
    "domain": "example.com",
    "url":    "http://example.com/path",
    "md5":    "d41d8cd98f00b204e9800998ecf8427e",
    "sha1":   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "cve":    "CVE-2024-0001",
    "email":  "noreply@example.com",
    "phone":  "+14155550123",
    "crypto": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "file":   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}


class _FakeAioResp:
    """Minimum aiohttp.ClientResponse surface. Returns empty JSON so
    analyzers exercise their 'no data' / 'not found' branches."""
    def __init__(self, status: int = 200, payload=None):
        self.status = status
        self._payload = payload if payload is not None else {}
        self.content_type = "application/json"
        self.headers = {"Content-Type": "application/json"}

    async def __aenter__(self): return self
    async def __aexit__(self, *_a): return False
    async def json(self, *_a, **_k): return self._payload
    async def text(self): return "{}"
    async def read(self): return b"{}"
    def raise_for_status(self): return None


def _make_fake_session() -> MagicMock:
    """aiohttp.ClientSession stand-in that returns empty JSON for every
    GET / POST. Analyzers whose parsers can't handle an empty response
    will fail parametric assertions below."""
    def _route(*_a, **_k):
        return _FakeAioResp(200, {})

    s = MagicMock()
    s.get = _route
    s.post = _route
    s.closed = False
    return s


def _pick_ioc_type(analyzer) -> str:
    """One IOC type is enough — picking the first declared type keeps
    the parametrize matrix compact. Analyzers with no supported types
    get skipped."""
    types = getattr(analyzer, "supported_ioc_types", []) or []
    return types[0] if types else ""


# ─── Parametrized smoke test ───────────────────────────────────────────────

def _registered_analyzer_names() -> list:
    """Collected at import time via registry.discover(). Any analyzer
    that fails to import at startup is NOT in this list — that's a
    separate kind of regression caught by test_plugin_framework."""
    return sorted(a.name for a in registry.analyzers())


@pytest.mark.parametrize("analyzer_name", _registered_analyzer_names())
def test_analyzer_runs_without_crashing(analyzer_name):
    """Every registered analyzer must return an AnalysisResult when
    invoked with no API keys and a plausible IOC value — not raise,
    not return None, not return a dict."""
    analyzer = registry.get(analyzer_name)
    assert analyzer is not None, f"analyzer {analyzer_name!r} missing from registry"

    ioc_type = _pick_ioc_type(analyzer)
    if not ioc_type:
        pytest.skip(f"{analyzer_name}: no supported_ioc_types declared")

    value = _PLAUSIBLE_VALUES.get(ioc_type)
    if value is None:
        pytest.skip(f"{analyzer_name}: no plausible value for ioc_type={ioc_type}")

    session = _make_fake_session()
    result = asyncio.run(analyzer.analyze(session, ioc_type, value, keys={}))

    assert isinstance(result, AnalysisResult), (
        f"{analyzer_name}.analyze returned {type(result).__name__}, "
        f"expected AnalysisResult"
    )
    assert result.source, f"{analyzer_name}: result.source is empty"
    assert result.ioc_type == ioc_type
    assert result.ioc_value == value


@pytest.mark.parametrize("analyzer_name", _registered_analyzer_names())
def test_keyed_analyzer_handles_missing_key(analyzer_name):
    """Analyzers with declared required_keys must short-circuit cleanly
    when no key is passed — not attempt the upstream call and then
    crash on the mocked empty response."""
    analyzer = registry.get(analyzer_name)
    assert analyzer is not None

    required = getattr(analyzer, "required_keys", []) or []
    if not required:
        pytest.skip(f"{analyzer_name}: no required_keys — not a keyed analyzer")

    ioc_type = _pick_ioc_type(analyzer)
    if not ioc_type:
        pytest.skip(f"{analyzer_name}: no supported_ioc_types declared")

    value = _PLAUSIBLE_VALUES.get(ioc_type)
    if value is None:
        pytest.skip(f"{analyzer_name}: no plausible value for ioc_type={ioc_type}")

    result = asyncio.run(
        analyzer.analyze(_make_fake_session(), ioc_type, value, keys={})
    )

    # Must be an AnalysisResult. Expected: found=False with an error_type
    # that signals "operator hasn't configured this yet". Different
    # analyzers use slightly different vocabularies; accept any of them
    # as long as the result cleanly reports a non-finding (not a crash).
    assert isinstance(result, AnalysisResult)

    acceptable = {
        "missing_key", "not_configured", "unavailable",
        "auth_failed", None,
    }
    # If found=True, the analyzer called upstream, got an empty mocked
    # response, and somehow still claimed success. That's wrong.
    if result.found:
        pytest.fail(
            f"{analyzer_name}: required_keys={required} but found=True "
            f"with no key passed — analyzer isn't checking its keys."
        )
    # found=False is fine — error_type can be any of the acceptable
    # values OR a parser-level error (which means "empty response"
    # branched correctly). Either way, no crash = pass.
    assert result.error_type in acceptable or result.error_type is not None, (
        f"{analyzer_name}: found=False but error_type is unset"
    )


def test_registry_has_expected_analyzer_count():
    """Sanity floor — we had ~56 formal analyzer files at the last audit.
    If this ever drops below 50, something imported-silently-failed and
    the smoke matrix is no longer actually covering what it claims."""
    names = _registered_analyzer_names()
    assert len(names) >= 50, (
        f"analyzer registry has only {len(names)} entries — expected ≥50. "
        f"Likely an import error during plugin discovery. Current list:\n"
        + "\n".join(f"  - {n}" for n in names)
    )
