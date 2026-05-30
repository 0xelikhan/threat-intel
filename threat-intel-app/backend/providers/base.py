"""
Abstract LLMProvider interface + normalised response/chunk dataclasses.

All adapters (OpenAI, Anthropic, Ollama) translate to/from these shapes
so callers never see vendor-specific structures. Adding a new provider
means: subclass LLMProvider, implement complete() and stream(), register
in providers/factory.py.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, List, Optional


# ─── normalised types ─────────────────────────────────────────────────────────
Message = Dict[str, Any]
Tool    = Dict[str, Any]
ToolCall = Dict[str, Any]


@dataclass
class LLMResponse:
    """Normalised completion response. Every adapter returns one of these."""
    message:        str                      = ""
    tool_calls:     List[ToolCall]           = field(default_factory=list)
    model:          str                      = ""
    provider:       str                      = ""
    input_tokens:   int                      = 0
    output_tokens:  int                      = 0
    finish_reason:  str                      = ""
    error:          Optional[str]            = None   # populated when call failed
    raw:            Optional[Any]            = None   # vendor response, for debugging only


@dataclass
class LLMChunk:
    """Normalised streaming chunk. delta_text accumulates the visible content,
    tool_call_delta carries partial tool calls when the model is invoking
    one, finish_reason is set on the final chunk."""
    delta_text:       str                = ""
    tool_call_delta:  Optional[ToolCall] = None
    finish_reason:    str                = ""
    error:            Optional[str]      = None


# ─── interface ────────────────────────────────────────────────────────────────
class LLMProvider(ABC):
    """Concrete adapters must subclass this and implement complete + stream.
    Adapters should read their own config (API keys, base URLs, models) in
    __init__ so the factory can construct them without per-call setup."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short stable identifier — 'openai', 'azure-openai', 'anthropic',
        'ollama'. Used in audit log + LLMResponse.provider."""

    @property
    def supports_tools(self) -> bool:
        """True when the adapter can pass `tools=` to complete()/stream()
        and surface tool_calls back. Ollama defaults False (most local
        models lack native tool calling)."""
        return False

    @abstractmethod
    async def complete(
        self,
        messages:    List[Message],
        tools:       Optional[List[Tool]] = None,
        temperature: float = 0.2,
        max_tokens:  Optional[int] = None,
        **kwargs,
    ) -> LLMResponse:
        """One-shot completion. Returns a normalised LLMResponse."""

    @abstractmethod
    def stream(
        self,
        messages:    List[Message],
        tools:       Optional[List[Tool]] = None,
        temperature: float = 0.2,
        max_tokens:  Optional[int] = None,
        **kwargs,
    ) -> AsyncIterator[LLMChunk]:
        """Streaming completion. Returns an async generator yielding
        LLMChunk objects until the final one (finish_reason set)."""
