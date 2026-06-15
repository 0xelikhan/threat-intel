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
import logging
import os
from typing import AsyncIterator, List, Optional

from config import config

_log = logging.getLogger("recon.providers.openai")

from .base import LLMProvider, LLMResponse, LLMChunk, Message, Tool


def _clean_sdk_err(e: BaseException) -> str:
    """Strip OpenAI SDK exception noise. Most SDK errors have a useful
    `.message` (the server's human-readable string), so prefer that.
    Class name fallback maps APIConnectionError → 'connection error',
    AuthenticationError → 'auth failed', etc."""
    msg = (getattr(e, "message", None) or "").strip()
    if msg:
        # The SDK's .message is usually one sentence — trim hard.
        return msg[:200]
    # Fall back to a short class-name phrase rather than the raw repr.
    cls = type(e).__name__
    return (cls.replace("Error", " error")
               .replace("Exception", " exception")
               .strip().lower()) or "unknown LLM error"


class OpenAIProvider(LLMProvider):
    def __init__(self, model: Optional[str] = None):
        self._configured_model = model or config.get("AI_MODEL") or "gpt-4o-mini"
        # Reuse the SDK client across calls so the underlying httpx pool
        # (DNS cache, keep-alive sockets, TLS sessions) survives. Rebuilt
        # when the config tuple (key / base_url / api_version) changes,
        # which lets a Settings-UI key rotation take effect on the next
        # call without a restart. The previous code constructed a fresh
        # AsyncOpenAI every complete() — fine in tests, but in production
        # an investigation that fires 3 parallel synthesis calls + a
        # tool-call loop spent real time on TLS handshakes that should
        # have been pooled.
        self._cached_client = None
        self._cached_key:  Optional[tuple] = None

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
        is_azure = "openai.azure.com" in base_url.lower()
        # api_version can be overridden via OPENAI_API_VERSION when an
        # operator needs a newer Azure surface (preview features,
        # gpt-5-class deployments). Default tracks the latest stable GA
        # preview at time of writing.
        api_version = (config.get("OPENAI_API_VERSION")
                       or os.environ.get("OPENAI_API_VERSION")
                       or "2024-10-21")
        cache_key = (is_azure, key, base_url.rstrip("/"), api_version)
        if self._cached_client is not None and self._cached_key == cache_key:
            return self._cached_client, model

        if is_azure:
            client = AsyncAzureOpenAI(
                api_key=key,
                azure_endpoint=base_url.rstrip("/"),
                api_version=api_version,
                timeout=60.0,
                max_retries=0,
            )
        else:
            client = AsyncOpenAI(
                api_key=key,
                base_url=base_url or "https://api.openai.com/v1",
                timeout=60.0,
                max_retries=0,
            )
        self._cached_client = client
        self._cached_key    = cache_key
        return client, model

    async def complete(
        self,
        messages:    List[Message],
        tools:       Optional[List[Tool]] = None,
        temperature: float = 0.2,
        max_tokens:  Optional[int] = None,
        **kwargs,
    ) -> LLMResponse:
        # The SDK is now constructed with max_retries=0 so the manual
        # rate-limit retry loop below is the ONLY retry layer. The
        # previous setup (SDK max_retries=1 + manual for attempt in
        # (0,1)) compounded to up to 4 attempts on a transient 429 —
        # each one billing tokens. The manual layer is the spec-faithful
        # one (deterministic 2s wait + one retry); the SDK's was opaque
        # and amplified, not parallel.
        import asyncio as _asyncio
        client, model = self._client_and_model(kwargs.get("model"))
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

        # Manual rate-limit retry on top of the SDK's built-in (the
        # built-in's backoff is opaque; on 429 we want a deterministic
        # 2-second wait + one retry per the spec).
        last_err: Optional[Exception] = None
        for attempt in (0, 1):
            try:
                resp = await client.chat.completions.create(**req)
                break
            except Exception as e:
                last_err = e
                msg = str(e).lower()
                # 401 / 403 / invalid_api_key — no point retrying.
                if any(s in msg for s in ("invalid_api_key", "incorrect api key",
                                          "invalid authentication", "401", "403",
                                          "unauthorized", "permission")):
                    return LLMResponse(
                        model=model, provider=self.name,
                        error="LLM authentication failed — check your API key in /settings",
                    )
                # Rate limit — wait then retry once.
                if attempt == 0 and any(s in msg for s in ("rate limit", "429", "too many requests")):
                    await _asyncio.sleep(2.0)
                    continue
                # 5xx server error — retry once immediately.
                if attempt == 0 and any(s in msg for s in ("500", "502", "503", "504",
                                                            "internal server", "bad gateway",
                                                            "service unavailable", "gateway timeout")):
                    continue
                # Anything else — give up after this attempt.
                return LLMResponse(model=model, provider=self.name,
                                   error=_clean_sdk_err(e))
        else:
            # Both attempts exhausted with retryable errors.
            return LLMResponse(model=model, provider=self.name,
                               error=_clean_sdk_err(last_err) if last_err else "unknown error")

        choice = resp.choices[0] if resp.choices else None
        if not choice:
            return LLMResponse(model=model, provider=self.name, error="empty response")
        msg = choice.message
        tool_calls = []
        for tc in (msg.tool_calls or []):
            raw = tc.function.arguments or "{}"
            try:
                args = json.loads(raw)
            except Exception as _e:
                # Used to silently swap in {} which made the tool run with
                # whatever its defaults were. Log it so a recurring parse
                # failure (model misbehaviour, schema drift) is visible.
                _log.warning("tool args JSON parse failed for %s: %s (raw=%r)",
                             tc.function.name, _e, raw[:200])
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
            yield LLMChunk(error=_clean_sdk_err(e), finish_reason="error")
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
