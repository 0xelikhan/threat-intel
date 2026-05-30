"""
Local Ollama adapter — POSTs to /api/chat on OLLAMA_BASE_URL (default
http://localhost:11434). Designed for local dev / air-gapped use.

Most local models don't support function calling natively, so
supports_tools defaults False. If `tools=` is passed anyway we serialise
them into the system prompt as a description and trust the model to
produce JSON tool_calls in text form (best-effort, no guarantees —
that's why supports_tools is False).

Connection errors return a clear LLMResponse.error rather than raising
so callers can fall back gracefully when Ollama isn't running.
"""

from __future__ import annotations

import json
import os
from typing import AsyncIterator, List, Optional

import aiohttp

from .base import LLMProvider, LLMResponse, LLMChunk, Message, Tool


_DEFAULT_MODEL = "llama3.2"


class OllamaProvider(LLMProvider):
    def __init__(self, model: Optional[str] = None):
        self._configured_model = model or os.environ.get("OLLAMA_MODEL") or _DEFAULT_MODEL
        self._base = (os.environ.get("OLLAMA_BASE_URL") or "http://localhost:11434").rstrip("/")

    @property
    def name(self) -> str:
        return "ollama"

    @property
    def supports_tools(self) -> bool:
        # Per-model, but most local models can't reliably do tool calls.
        # Skills that need tools should branch on this and degrade.
        return False

    async def complete(
        self,
        messages:    List[Message],
        tools:       Optional[List[Tool]] = None,
        temperature: float = 0.2,
        max_tokens:  Optional[int] = None,
        **kwargs,
    ) -> LLMResponse:
        model = kwargs.get("model") or self._configured_model
        payload = {
            "model":   model,
            "messages": messages,
            "stream":  False,
            "options": {"temperature": temperature},
        }
        if max_tokens:
            payload["options"]["num_predict"] = max_tokens
        if tools:
            # Inline tool descriptions in a system note — Ollama doesn't
            # natively support tools so this is best-effort.
            tool_doc = "Available tools (call by returning JSON " \
                       "`{\"tool\": <name>, \"args\": {...}}`):\n" + \
                       json.dumps(tools, indent=2)
            payload["messages"] = [
                {"role": "system", "content": tool_doc},
                *messages,
            ]
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=120),
            ) as session:
                async with session.post(f"{self._base}/api/chat", json=payload) as r:
                    if r.status != 200:
                        body = await r.text()
                        return LLMResponse(
                            model=model, provider=self.name,
                            error=f"ollama HTTP {r.status}: {body[:200]}",
                        )
                    data = await r.json()
        except aiohttp.ClientConnectorError:
            return LLMResponse(
                model=model, provider=self.name,
                error=f"could not reach Ollama at {self._base} — is it running?",
            )
        except Exception as e:
            return LLMResponse(model=model, provider=self.name, error=str(e)[:300])

        msg = (data.get("message") or {}).get("content", "")
        return LLMResponse(
            message=msg,
            model=model,
            provider=self.name,
            input_tokens=int(data.get("prompt_eval_count", 0) or 0),
            output_tokens=int(data.get("eval_count", 0) or 0),
            finish_reason="stop",
            raw=data,
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
        payload = {
            "model":   model,
            "messages": messages,
            "stream":  True,
            "options": {"temperature": temperature},
        }
        if max_tokens:
            payload["options"]["num_predict"] = max_tokens
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=300),
            ) as session:
                async with session.post(f"{self._base}/api/chat", json=payload) as r:
                    if r.status != 200:
                        body = await r.text()
                        yield LLMChunk(error=f"ollama HTTP {r.status}: {body[:200]}",
                                       finish_reason="error")
                        return
                    async for raw in r.content:
                        line = raw.decode("utf-8", errors="ignore").strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                        except Exception:
                            continue
                        msg = (data.get("message") or {}).get("content", "")
                        done = bool(data.get("done"))
                        yield LLMChunk(
                            delta_text=msg,
                            finish_reason="stop" if done else "",
                        )
                        if done:
                            return
        except aiohttp.ClientConnectorError:
            yield LLMChunk(error=f"could not reach Ollama at {self._base}",
                           finish_reason="error")
        except Exception as e:
            yield LLMChunk(error=str(e)[:300], finish_reason="error")
