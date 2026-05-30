"""
Single entry point for selecting which LLM provider to use at runtime.

Reads LLM_PROVIDER env (default 'openai') and returns the matching
instance. Instances are constructed on first call and cached so subsequent
get_provider() calls are O(1) — the SDK clients inside the providers
manage their own connection pooling.
"""

from __future__ import annotations

import os
from typing import Dict

from .base               import LLMProvider
from .openai_provider    import OpenAIProvider
from .anthropic_provider import AnthropicProvider
from .ollama_provider    import OllamaProvider


_cache: Dict[str, LLMProvider] = {}


def get_provider(name: str | None = None) -> LLMProvider:
    """Return the configured (or explicitly-named) provider instance.
    `name` overrides LLM_PROVIDER when set — useful for skills that want
    to force a specific provider (e.g. a vision skill that requires
    OpenAI even when the default is Ollama)."""
    selected = (name or os.environ.get("LLM_PROVIDER") or "openai").strip().lower()
    if selected in _cache:
        return _cache[selected]
    if selected in ("openai", "azure", "azure-openai", "azureopenai"):
        provider: LLMProvider = OpenAIProvider()
    elif selected == "anthropic":
        provider = AnthropicProvider()
    elif selected == "ollama":
        provider = OllamaProvider()
    else:
        raise ValueError(
            f"unknown LLM_PROVIDER={selected!r} — supported: openai, azure, "
            f"anthropic, ollama"
        )
    _cache[selected] = provider
    return provider


def list_providers() -> list[str]:
    """The names get_provider() will accept."""
    return ["openai", "azure", "anthropic", "ollama"]
