"""Provider-abstraction regression tests that don't need network or keys.

The existing test_providers.py probes hit real APIs and skip when no key
is set — so in any default-dev environment the entire provider layer goes
untested. That's how the aiohttp 3.14 compat break in /api/scan/url and
the AnthropicProvider __init__ cache-attribute issue both escaped CI.

These tests pin the contracts that matter even when offline:

  1. The factory returns a singleton per provider name.
  2. Every provider can be constructed without errors (no AttributeError
     from missing __init__ initialisation of cache fields, no ImportError
     at construct time for optional SDKs).
  3. .complete() never raises bare — it must return an LLMResponse with
     .error populated when something fails (missing key, missing SDK,
     network down).
  4. The normalised LLMResponse / LLMChunk shape holds.
"""

from __future__ import annotations

import asyncio
import os

import pytest


# ─── Factory contract ─────────────────────────────────────────────────────
def test_factory_singletons_per_name():
    from providers.factory import get_provider, _cache
    _cache.clear()
    a = get_provider("openai")
    b = get_provider("openai")
    assert a is b, "factory must return the same instance for repeated calls"


def test_factory_rejects_unknown_provider_name():
    from providers.factory import get_provider
    with pytest.raises(ValueError):
        get_provider("not-a-real-provider")


def test_factory_normalises_azure_aliases():
    from providers.factory import get_provider
    from providers.openai_provider import OpenAIProvider
    for alias in ("openai", "azure", "azure-openai", "azureopenai"):
        p = get_provider(alias)
        assert isinstance(p, OpenAIProvider), f"alias {alias!r} should map to OpenAIProvider"


# ─── Construction must not raise on any provider ──────────────────────────
def test_openai_provider_constructs_clean():
    from providers.openai_provider import OpenAIProvider
    p = OpenAIProvider()
    # The cache attributes the cached_client checks against must be
    # initialised in __init__ so any code path that reads them directly
    # doesn't AttributeError.
    assert p._cached_client is None
    assert p._cached_key is None
    assert isinstance(p._configured_model, str)


def test_anthropic_provider_constructs_clean():
    # This is the regression test for the bug fixed in commit 336d0ea —
    # AnthropicProvider.__init__ used to leave _cached_client / _cached_key
    # unset, relying on getattr(..., None) sentinel reads. Any caller that
    # accessed the attributes directly would AttributeError.
    from providers.anthropic_provider import AnthropicProvider
    p = AnthropicProvider()
    assert p._cached_client is None
    assert p._cached_key is None
    assert isinstance(p._configured_model, str)


def test_ollama_provider_constructs_clean():
    from providers.ollama_provider import OllamaProvider
    p = OllamaProvider()
    assert isinstance(p._configured_model, str)
    assert p._base.startswith("http")


# ─── .complete() never raises bare — always returns LLMResponse ─────────
def test_openai_complete_returns_envelope_when_unauthorised():
    """Force an auth failure by giving the OpenAI SDK a bogus key. The
    response must come back as an LLMResponse with .error populated, not
    as an uncaught exception."""
    from providers.openai_provider import OpenAIProvider
    from providers.base import LLMResponse
    p = OpenAIProvider()
    # Stash and restore so the test doesn't leak into the global config.
    from config import config as _cfg
    prior_key = _cfg.get("OPENAI_API_KEY")
    _cfg._config["OPENAI_API_KEY"] = "sk-clearly-not-a-real-key-XXXXXXXX"
    try:
        resp = asyncio.run(p.complete(
            messages=[{"role": "user", "content": "hi"}],
            max_tokens=4, temperature=0.0,
        ))
    finally:
        if prior_key is not None:
            _cfg._config["OPENAI_API_KEY"] = prior_key
        else:
            _cfg._config.pop("OPENAI_API_KEY", None)
    assert isinstance(resp, LLMResponse), f"got {type(resp).__name__}, expected LLMResponse"
    assert resp.error, "auth failure must populate .error, not return success"
    assert resp.provider in ("openai", "azure-openai")


def test_ollama_complete_returns_envelope_when_unreachable():
    """Point Ollama at a port that's not listening — complete() must come
    back with .error rather than raising aiohttp.ClientConnectorError."""
    from providers.ollama_provider import OllamaProvider
    from providers.base import LLMResponse
    p = OllamaProvider()
    # Override base to an almost-certainly-unbound localhost port.
    p._base = "http://127.0.0.1:9"
    resp = asyncio.run(p.complete(
        messages=[{"role": "user", "content": "hi"}],
        max_tokens=4, temperature=0.0,
    ))
    assert isinstance(resp, LLMResponse)
    assert resp.error, "unreachable Ollama must populate .error, not raise"
    assert resp.provider == "ollama"


def test_anthropic_complete_returns_envelope_without_sdk_key():
    """Even when the anthropic SDK is installed but no key is configured,
    .complete() must come back with .error rather than raise."""
    from providers.anthropic_provider import AnthropicProvider
    from providers.base import LLMResponse
    p = AnthropicProvider()
    # Wipe the key so the SDK rejects auth.
    prior_env = os.environ.pop("ANTHROPIC_API_KEY", None)
    from config import config as _cfg
    prior_cfg = _cfg.get("ANTHROPIC_API_KEY")
    _cfg._config.pop("ANTHROPIC_API_KEY", None)
    try:
        resp = asyncio.run(p.complete(
            messages=[{"role": "user", "content": "hi"}],
            max_tokens=4, temperature=0.0,
        ))
    finally:
        if prior_env is not None:
            os.environ["ANTHROPIC_API_KEY"] = prior_env
        if prior_cfg:
            _cfg._config["ANTHROPIC_API_KEY"] = prior_cfg
    # Either the SDK isn't installed (error string includes "anthropic
    # package not installed") OR the SDK is installed but rejects auth.
    # Either way the result MUST be an LLMResponse, not a raised exception.
    assert isinstance(resp, LLMResponse)
    assert resp.error, f"missing-key call must populate .error, got {resp!r}"
    assert resp.provider == "anthropic"


# ─── Normalised type shape ────────────────────────────────────────────────
def test_llm_response_defaults():
    from providers.base import LLMResponse
    r = LLMResponse()
    assert r.message == ""
    assert r.tool_calls == []
    assert r.error is None
    assert r.input_tokens == 0
    assert r.output_tokens == 0


def test_llm_chunk_defaults():
    from providers.base import LLMChunk
    c = LLMChunk()
    assert c.delta_text == ""
    assert c.tool_call_delta is None
    assert c.finish_reason == ""
    assert c.error is None


# ─── provider_configured contract ────────────────────────────────────────
def test_provider_configured_per_active_llm():
    from providers.factory import provider_configured
    from config import config

    saved = os.environ.get("LLM_PROVIDER")
    try:
        # ollama always reports configured (locally-hosted, no key needed)
        os.environ["LLM_PROVIDER"] = "ollama"
        assert provider_configured(config) is True

        # openai/azure check OPENAI_API_KEY
        os.environ["LLM_PROVIDER"] = "openai"
        # Whatever the operator has in the dev config — just assert the
        # call returns a bool without raising.
        assert isinstance(provider_configured(config), bool)

        # anthropic checks ANTHROPIC_API_KEY
        os.environ["LLM_PROVIDER"] = "anthropic"
        assert isinstance(provider_configured(config), bool)
    finally:
        if saved is None:
            os.environ.pop("LLM_PROVIDER", None)
        else:
            os.environ["LLM_PROVIDER"] = saved
