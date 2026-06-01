"""
Anthropic Claude adapter.

Translates the normalised message format (role + content) into Anthropic's
{role, content} format with the `system` parameter split out (Anthropic
expects system as a top-level kwarg, not a role in messages). Tool calls
come back as `tool_use` content blocks; we flatten them into the
normalised tool_calls list. Streaming converts Anthropic events
(content_block_delta / message_delta) into LLMChunks.

The `anthropic` package is imported lazily so the codebase doesn't hard-
depend on it when LLM_PROVIDER != anthropic.
"""

from __future__ import annotations

import json
import os
from typing import AsyncIterator, List, Optional, Tuple

from .base import LLMProvider, LLMResponse, LLMChunk, Message, Tool


_DEFAULT_MODEL = "claude-sonnet-4-20250514"


def _clean_sdk_err(e: BaseException) -> str:
    """Anthropic SDK exceptions usually have a useful `.message`; prefer
    that. Fall back to a humanised class name so the analyst doesn't see
    a raw `APIError(...)` repr."""
    msg = (getattr(e, "message", None) or "").strip()
    if msg:
        return msg[:200]
    cls = type(e).__name__
    return (cls.replace("Error", " error")
               .replace("Exception", " exception")
               .strip().lower()) or "unknown LLM error"


def _split_system(messages: List[Message]) -> Tuple[Optional[str], List[Message]]:
    """Pop the leading system message into a single string (Anthropic takes
    system as a separate kwarg). Preserves order of the rest."""
    system_parts: List[str] = []
    rest: List[Message] = []
    for m in messages:
        if m.get("role") == "system":
            c = m.get("content", "")
            system_parts.append(c if isinstance(c, str) else json.dumps(c))
        else:
            rest.append(m)
    sys = "\n\n".join(s for s in system_parts if s) or None
    return sys, rest


def _to_anthropic_tools(tools: Optional[List[Tool]]) -> Optional[list]:
    """Convert OpenAI-style tool dicts ({type, function:{name, description,
    parameters}}) into Anthropic-style ({name, description, input_schema})."""
    if not tools:
        return None
    out = []
    for t in tools:
        if t.get("type") == "function" and "function" in t:
            f = t["function"]
            out.append({
                "name":         f.get("name", ""),
                "description":  f.get("description", ""),
                "input_schema": f.get("parameters") or {"type": "object", "properties": {}},
            })
        else:
            out.append(t)   # already Anthropic shape
    return out


class AnthropicProvider(LLMProvider):
    def __init__(self, model: Optional[str] = None):
        self._configured_model = model or os.environ.get("ANTHROPIC_MODEL") or _DEFAULT_MODEL

    @property
    def name(self) -> str:
        return "anthropic"

    @property
    def supports_tools(self) -> bool:
        return True

    def _client(self):
        try:
            from anthropic import AsyncAnthropic
        except ImportError as e:
            raise RuntimeError(
                "anthropic package not installed — `pip install anthropic` "
                "or switch LLM_PROVIDER to openai/ollama"
            ) from e
        key = os.environ.get("ANTHROPIC_API_KEY") or ""
        return AsyncAnthropic(api_key=key, timeout=60.0, max_retries=1)

    async def complete(
        self,
        messages:    List[Message],
        tools:       Optional[List[Tool]] = None,
        temperature: float = 0.2,
        max_tokens:  Optional[int] = None,
        **kwargs,
    ) -> LLMResponse:
        model = kwargs.get("model") or self._configured_model
        sys, rest = _split_system(messages)
        try:
            client = self._client()
        except RuntimeError as e:
            return LLMResponse(model=model, provider=self.name, error=str(e))
        try:
            req: dict = {
                "model":       model,
                "messages":    rest,
                "temperature": temperature,
                "max_tokens":  max_tokens or 1024,
            }
            if sys:    req["system"] = sys
            if tools:  req["tools"]  = _to_anthropic_tools(tools)
            resp = await client.messages.create(**req)
        except Exception as e:
            return LLMResponse(model=model, provider=self.name, error=_clean_sdk_err(e))

        text_parts: List[str] = []
        tool_calls = []
        for block in (resp.content or []):
            btype = getattr(block, "type", None)
            if btype == "text":
                text_parts.append(getattr(block, "text", ""))
            elif btype == "tool_use":
                tool_calls.append({
                    "id":        getattr(block, "id", ""),
                    "name":      getattr(block, "name", ""),
                    "arguments": getattr(block, "input", {}) or {},
                })
        usage = getattr(resp, "usage", None)
        return LLMResponse(
            message="".join(text_parts),
            tool_calls=tool_calls,
            model=model,
            provider=self.name,
            input_tokens=getattr(usage, "input_tokens", 0) or 0,
            output_tokens=getattr(usage, "output_tokens", 0) or 0,
            finish_reason=getattr(resp, "stop_reason", "") or "",
            raw=resp,
        )

    async def stream(
        self,
        messages:    List[Message],
        tools:       Optional[List[Tool]] = None,
        temperature: float = 0.2,
        max_tokens:  Optional[int] = None,
        **kwargs,
    ) -> AsyncIterator[LLMChunk]:
        model = kwargs.get("model") or self._configured_model
        sys, rest = _split_system(messages)
        try:
            client = self._client()
        except RuntimeError as e:
            yield LLMChunk(error=str(e), finish_reason="error")
            return
        try:
            req: dict = {
                "model":       model,
                "messages":    rest,
                "temperature": temperature,
                "max_tokens":  max_tokens or 1024,
                "stream":      True,
            }
            if sys:    req["system"] = sys
            if tools:  req["tools"]  = _to_anthropic_tools(tools)
            async with client.messages.stream(**req) as stream:
                async for event in stream:
                    etype = getattr(event, "type", "")
                    if etype == "content_block_delta":
                        delta = getattr(event, "delta", None)
                        text = getattr(delta, "text", "") if delta else ""
                        if text:
                            yield LLMChunk(delta_text=text)
                    elif etype == "message_stop":
                        yield LLMChunk(finish_reason="stop")
        except Exception as e:
            yield LLMChunk(error=_clean_sdk_err(e), finish_reason="error")
