"""
OpenAI / Azure OpenAI adapter.

Detects Azure when OPENAI_BASE_URL contains "openai.azure.com" and routes
through AsyncAzureOpenAI with api_version 2024-02-01; otherwise uses
AsyncOpenAI against base_url or the default endpoint. Tool definitions
and tool_calls are already in the OpenAI shape (the codebase historically
matched OpenAI's format), so translation is mostly pass-through.
"""

from __future__ import annotations

import json
from typing import AsyncIterator, List, Optional

from config import config

from .base import LLMProvider, LLMResponse, LLMChunk, Message, Tool


class OpenAIProvider(LLMProvider):
    def __init__(self, model: Optional[str] = None):
        self._configured_model = model or config.get("AI_MODEL") or "gpt-4o-mini"

    @property
    def name(self) -> str:
        base = (config.get("OPENAI_BASE_URL") or "").lower()
        return "azure-openai" if "openai.azure.com" in base else "openai"

    @property
    def supports_tools(self) -> bool:
        return True

    def _client_and_model(self, override_model: Optional[str] = None):
        from openai import AsyncAzureOpenAI, AsyncOpenAI
        key      = config.get("OPENAI_API_KEY") or ""
        base_url = config.get("OPENAI_BASE_URL") or ""
        model    = override_model or self._configured_model
        if "openai.azure.com" in base_url.lower():
            return AsyncAzureOpenAI(
                api_key=key,
                azure_endpoint=base_url.rstrip("/"),
                api_version="2024-02-01",
                timeout=60.0,
                max_retries=1,
            ), model
        return AsyncOpenAI(
            api_key=key,
            base_url=base_url or "https://api.openai.com/v1",
            timeout=60.0,
            max_retries=1,
        ), model

    async def complete(
        self,
        messages:    List[Message],
        tools:       Optional[List[Tool]] = None,
        temperature: float = 0.2,
        max_tokens:  Optional[int] = None,
        **kwargs,
    ) -> LLMResponse:
        client, model = self._client_and_model(kwargs.get("model"))
        try:
            req: dict = {
                "model":       model,
                "messages":    messages,
                "temperature": temperature,
            }
            if max_tokens:           req["max_tokens"]      = max_tokens
            if tools:                req["tools"]           = tools
            if "tool_choice" in kwargs: req["tool_choice"] = kwargs["tool_choice"]
            if "response_format" in kwargs:
                req["response_format"] = kwargs["response_format"]
            resp = await client.chat.completions.create(**req)
        except Exception as e:
            return LLMResponse(model=model, provider=self.name, error=str(e)[:300])

        choice = resp.choices[0] if resp.choices else None
        if not choice:
            return LLMResponse(model=model, provider=self.name, error="empty response")
        msg = choice.message
        tool_calls = []
        for tc in (msg.tool_calls or []):
            try:
                args = json.loads(tc.function.arguments or "{}")
            except Exception:
                args = {}
            tool_calls.append({"id": tc.id, "name": tc.function.name, "arguments": args})
        usage = getattr(resp, "usage", None)
        return LLMResponse(
            message=msg.content or "",
            tool_calls=tool_calls,
            model=model,
            provider=self.name,
            input_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            output_tokens=getattr(usage, "completion_tokens", 0) or 0,
            finish_reason=choice.finish_reason or "",
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
        client, model = self._client_and_model(kwargs.get("model"))
        try:
            req: dict = {
                "model":       model,
                "messages":    messages,
                "temperature": temperature,
                "stream":      True,
            }
            if max_tokens: req["max_tokens"] = max_tokens
            if tools:      req["tools"]      = tools
            resp = await client.chat.completions.create(**req)
        except Exception as e:
            yield LLMChunk(error=str(e)[:300], finish_reason="error")
            return
        async for chunk in resp:
            if not chunk.choices:
                continue
            choice = chunk.choices[0]
            d = choice.delta
            tc_delta = None
            for tc in (getattr(d, "tool_calls", None) or []):
                tc_delta = {
                    "id":        getattr(tc, "id", None),
                    "name":      getattr(getattr(tc, "function", None), "name", None),
                    "arguments": getattr(getattr(tc, "function", None), "arguments", "") or "",
                }
            yield LLMChunk(
                delta_text=getattr(d, "content", "") or "",
                tool_call_delta=tc_delta,
                finish_reason=choice.finish_reason or "",
            )
