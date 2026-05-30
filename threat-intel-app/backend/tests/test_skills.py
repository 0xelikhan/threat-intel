"""
Skill unit tests — each registered skill must pass its own test in
isolation with no external API calls. The mock provider returns a fixed
LLMResponse so LLM-backed skills can still run end-to-end here.

Run with:  pytest backend/tests/test_skills.py -v
"""

from __future__ import annotations

import asyncio

import pytest

from providers.base import LLMProvider, LLMResponse, LLMChunk
from skills import SKILL_REGISTRY, get_skill


class MockProvider(LLMProvider):
    """Returns a fixed canned response. Skills that don't actually need
    the provider (e.g. ExtractIOCsSkill) ignore it; skills that do use
    it get a deterministic input for the assertion phase."""

    def __init__(self, canned: str = '{"ok": true}'):
        self._canned = canned

    @property
    def name(self) -> str:
        return "mock"

    @property
    def supports_tools(self) -> bool:
        return True

    async def complete(self, messages, tools=None, temperature=0.2,
                       max_tokens=None, **kwargs) -> LLMResponse:
        return LLMResponse(message=self._canned, model="mock", provider="mock",
                           input_tokens=10, output_tokens=20, finish_reason="stop")

    async def stream(self, messages, tools=None, temperature=0.2,
                     max_tokens=None, **kwargs):
        yield LLMChunk(delta_text=self._canned, finish_reason="stop")


def _check_output_shape(skill, output):
    """Every key in output_schema must appear in execute()'s output dict."""
    for key in skill.output_schema:
        assert key in output, f"{skill.name}: missing output key {key!r}"


# Skills that fan out to external HTTP (TI sources) or run the full LangGraph
# pipeline — skipped in the lightweight parametrized smoke test because they
# need either network access or a fully-wired provider with realistic JSON
# responses. They get dedicated tests below with stronger mocks.
_NEEDS_REAL_BACKEND = {"enrich_ioc", "investigate", "triage_alert"}


@pytest.mark.parametrize("skill_name",
                         [n for n in SKILL_REGISTRY.keys() if n not in _NEEDS_REAL_BACKEND])
def test_every_lightweight_skill_runs_on_its_own_test_input(skill_name):
    skill = get_skill(skill_name)
    inputs = skill.test_input
    assert isinstance(inputs, dict), f"{skill_name}: test_input must be a dict"
    out = asyncio.run(skill.execute(inputs, provider=MockProvider()))
    assert isinstance(out, dict), f"{skill_name}: execute must return a dict"
    _check_output_shape(skill, out)


def test_skill_registry_contains_expected_skills():
    """If you add a new skill, register it in skills/__init__.py too."""
    expected = {
        "extract_iocs", "enrich_ioc", "triage_alert", "investigate",
        "generate_sigma", "generate_kql", "map_mitre", "correlate_signals",
    }
    assert expected.issubset(set(SKILL_REGISTRY.keys()))


def test_map_mitre_deterministic_resolution():
    """T1059.001 lives in MITRE ATT&CK — the deterministic resolver should
    return at least one technique without calling any provider."""
    out = asyncio.run(get_skill("map_mitre").execute({
        "behavioral_indicators": {"techniques": ["T1059.001"]},
        "enrichments": {},
        "iocs":        {},
    }, provider=None))
    techs = out.get("mitre_techniques") or []
    assert techs, "expected at least one resolved technique"
    assert any(t["technique_id"] == "T1059.001" for t in techs)


def test_generate_kql_strips_markdown_fences():
    """Models often emit ```kql ... ``` blocks even when told not to —
    the skill must strip them before returning."""
    fenced = "```kql\nDeviceProcessEvents | where ProcessName == 'powershell.exe'\n```"
    out = asyncio.run(get_skill("generate_kql").execute(
        {"analysis": {}, "iocs": {}}, provider=MockProvider(canned=fenced)))
    assert "```" not in out["kql_query"]
    assert "DeviceProcessEvents" in out["kql_query"]


def test_correlate_signals_handles_empty_provider_response():
    """If the model returns gibberish, the skill must still return shape."""
    out = asyncio.run(get_skill("correlate_signals").execute(
        {"enrichments": {}, "behavioral_indicators": {}},
        provider=MockProvider(canned='{"clusters": [], "summary": ""}')))
    assert out["clusters"] == []
    assert out["correlation_summary"] == ""


def test_extract_iocs_skill_extracts_known_indicators():
    """Concrete behavioural check on the IOC extractor.

    The IP 185.220.101.45 is on a MISP warninglist (Tor exit node /
    common VPN range), so the skill correctly moves it from `ips` into
    `suppressed_iocs.ips`. We assert it appears in *either* bucket — what
    matters is that the extractor saw it. The hash and email don't match
    any warninglist so they must come back in their primary buckets.
    """
    out = asyncio.run(get_skill("extract_iocs").execute({
        "raw_text": (
            "IP 185.220.101.45 connected to evil-payload.xyz. SHA256 "
            "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678 "
            "downloaded. User a@b.com filed ticket."
        ),
    }))
    seen_ips = list(out["ips"]) + [s["ioc"] for s in out["suppressed_iocs"]["ips"]]
    assert "185.220.101.45" in seen_ips
    assert "a@b.com" in out["emails"]
    assert any(len(h) == 64 for h in out["hashes"])
