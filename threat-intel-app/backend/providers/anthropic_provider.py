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
import logging
import os
from typing import AsyncIterator, List, Optional, Tuple

_log = logging.getLogger("recon.providers.anthropic")

from .base import LLMProvider, LLMResponse, LLMChunk, Message, Tool


# Claude Sonnet 4.6 — the current Sonnet release.  The previous default
# (claude-sonnet-4-20250514) reached end-of-life on 2026-06-15; deploys
# that hadn't overridden ANTHROPIC_MODAL via Settings would have started
# getting model-deprecated errors from the API on the 16th.  This file's
# unit tests now trip the same deprecation warning loudly so the next
# rollover is caught locally instead of in production.
_DEFAULT_MODEL = "claude-sonnet-4-6"


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
    system as a separate kwarg) AND translate OpenAI-shape tool messages
    into Anthropic content-block format.

    OpenAI uses:
      - assistant turn with `tool_calls=[{id, function:{name, arguments}}]`
      - tool result turn with `{role:"tool", tool_call_id, content}`
    Anthropic uses content arrays:
      - assistant with `[{type:"text"...}, {type:"tool_use", id, name, input}]`
      - user with `[{type:"tool_result", tool_use_id, content}]`

    The codebase emits OpenAI-shape messages everywhere, so the
    translation lives here in the adapter (where the abstraction belongs)
    rather than each caller learning Anthropic's shape.
    """
    system_parts: List[str] = []
    rest: List[Message] = []
    for m in messages:
        role = m.get("role")
        if role == "system":
            c = m.get("content", "")
            system_parts.append(c if isinstance(c, str) else json.dumps(c))
            continue
        if role == "tool":
            # OpenAI tool-result → Anthropic user/tool_result block
            rest.append({
                "role": "user",
                "content": [{
                    "type":        "tool_result",
                    "tool_use_id": m.get("tool_call_id", ""),
                    "content":     m.get("content", "") or "",
                }],
            })
            continue
        if role == "assistant" and m.get("tool_calls"):
            blocks: list = []
            text = m.get("content")
            if isinstance(text, str) and text.strip():
                blocks.append({"type": "text", "text": text})
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function") or {}
                args_raw = fn.get("arguments") or "{}"
                try:
                    args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
                except Exception:
                    args = {}
                blocks.append({
                    "type":  "tool_use",
                    "id":    tc.get("id", ""),
                    "name":  fn.get("name", ""),
                    "input": args if isinstance(args, dict) else {},
                })
            rest.append({"role": "assistant", "content": blocks})
            continue
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
        # Same precedence story as the API key: prefer Settings/config
        # over env so operators can switch Claude model deployments
        # without redeploying the container.
        try:
            from config import config as _cfg
            cfg_model = _cfg.get("ANTHROPIC_MODEL") or ""
        except Exception:
            cfg_model = ""
        self._configured_model = (model or cfg_model
                                  or os.environ.get("ANTHROPIC_MODEL")
                                  or _DEFAULT_MODEL)
        # Mirror the OpenAI provider — initialise the cache fields up
        # front so any code path that reads them directly (without going
        # through `getattr(..., None)`) doesn't AttributeError on the
        # first call.
        self._cached_client = None
        self._cached_key:  Optional[str] = None

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
        # Prefer the Settings-stored config.json key for symmetry with
        # the OpenAI provider (which also reads from config). Fall back
        # to the env var so existing Docker / CI deployments that
        # already export ANTHROPIC_API_KEY keep working.
        try:
            from config import config as _cfg
            key = (_cfg.get("ANTHROPIC_API_KEY")
                   or os.environ.get("ANTHROPIC_API_KEY") or "")
        except Exception:
            key = os.environ.get("ANTHROPIC_API_KEY") or ""
        # Cache the SDK client across calls so its underlying httpx pool
        # (DNS + keep-alive + TLS session reuse) survives. Same rationale
        # as the OpenAI provider — a single analyze fires multiple
        # concurrent LLM calls and shouldn't pay TLS handshake cost on
        # every one. Rebuilt when the key rotates.
        cached_key = getattr(self, "_cached_key", None)
        if cached_key == key and getattr(self, "_cached_client", None) is not None:
            return self._cached_client
        self._cached_client = AsyncAnthropic(api_key=key, timeout=60.0, max_retries=1)
        self._cached_key    = key
        return self._cached_client

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
                # Anthropic delivers tool args as a parsed dict on
                # `input`. If it's missing or None we used to silently
                # swap in {} and execute the tool with no args; log it
                # so a model-side regression is visible.
                args = getattr(block, "input", None)
                if not isinstance(args, dict) or not args:
                    _log.warning("tool_use block missing input for %s",
                                 getattr(block, "name", "?"))
                    args = {} if not isinstance(args, dict) else args
                tool_calls.append({
                    "id":        getattr(block, "id", ""),
                    "name":      getattr(block, "name", ""),
                    "arguments": args,
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
