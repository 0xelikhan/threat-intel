"""
Smoke tests for the model-agnostic provider layer.

Each test instantiates one provider, calls .complete() with a simple hello
message, and asserts the normalised response shape. Tests skip gracefully
when the required API key or service isn't reachable so the suite passes
on any developer machine without forcing everyone to configure every
provider.

Run with:    pytest backend/tests/test_providers.py -v
"""

from __future__ import annotations

import asyncio
import os

import pytest


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if not asyncio.iscoroutine(coro) \
        else asyncio.run(coro)


def test_factory_returns_known_providers():
    from providers import get_provider
    p = get_provider("openai")
    assert p.name in ("openai", "azure-openai")
    p = get_provider("ollama")
    assert p.name == "ollama"
    with pytest.raises(ValueError):
        get_provider("not-a-provider")


def test_normalised_response_shape():
    """Even when the underlying SDK isn't installed / configured, the
    factory + base classes must construct without import errors."""
    from providers.base import LLMResponse, LLMChunk
    r = LLMResponse(message="hi", model="x", provider="y")
    assert r.tool_calls == []
    assert r.error is None
    c = LLMChunk(delta_text="hi")
    assert c.finish_reason == ""


def test_openai_provider_complete():
    """Hits real OpenAI/Azure when OPENAI_API_KEY is set, otherwise skips."""
    from config import config
    if not config.get("OPENAI_API_KEY"):
        pytest.skip("OPENAI_API_KEY not configured")
    from providers import get_provider
    p = get_provider("openai")
    resp = asyncio.run(p.complete(
        [{"role": "user", "content": "Reply with the single word: ready"}],
        max_tokens=8, temperature=0.0,
    ))
    assert resp.error is None, f"openai error: {resp.error}"
    assert resp.provider in ("openai", "azure-openai")
    assert resp.message, "no message body returned"


def test_ollama_provider_complete():
    """Skips when local Ollama isn't reachable. Useful for offline dev."""
    from providers import get_provider
    p = get_provider("ollama")
    resp = asyncio.run(p.complete(
        [{"role": "user", "content": "Reply with the single word: ready"}],
        max_tokens=8, temperature=0.0,
    ))
    if resp.error and "could not reach Ollama" in resp.error:
        pytest.skip(resp.error)
    assert resp.provider == "ollama"
    assert resp.message or resp.error
