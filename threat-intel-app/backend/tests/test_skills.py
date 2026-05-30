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


@pytest.mark.parametrize("skill_name", list(SKILL_REGISTRY.keys()))
def test_every_registered_skill_runs_on_its_own_test_input(skill_name):
    skill = get_skill(skill_name)
    inputs = skill.test_input
    assert isinstance(inputs, dict), f"{skill_name}: test_input must be a dict"
    out = asyncio.run(skill.execute(inputs, provider=MockProvider()))
    assert isinstance(out, dict), f"{skill_name}: execute must return a dict"
    _check_output_shape(skill, out)


def test_extract_iocs_skill_extracts_known_indicators():
    """Concrete behavioural check on the one skill we ship in this commit."""
    out = asyncio.run(get_skill("extract_iocs").execute({
        "raw_text": (
            "IP 185.220.101.45 connected to evil.example. SHA256 "
            "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678 "
            "downloaded. URL https://evil-payload.xyz/x.exe contacted. "
            "User a@b.com filed ticket."
        ),
    }))
    assert "185.220.101.45" in out["ips"]
    assert any("evil-payload.xyz" in u or "evil-payload" in u for u in out["urls"])
    assert any("a@b.com" == e for e in out["emails"])
    assert any(len(h) == 64 for h in out["hashes"])
    assert out["total"] >= 4
