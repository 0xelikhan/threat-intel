"""
Model-agnostic LLM provider layer.

Every place in the codebase that needs to call an LLM goes through this
module instead of importing a vendor SDK directly. Provider is selected
at runtime via the LLM_PROVIDER env var (openai / azure / anthropic /
ollama). Callers stay vendor-neutral; swapping models is a config
change.

Public API:
    from providers import get_provider
    p = get_provider()                       # default from LLM_PROVIDER
    resp = await p.complete(messages, tools=...)
    async for chunk in p.stream(messages):
        ...

Normalised message format:
    {"role": "system" | "user" | "assistant", "content": str | [blocks]}

Normalised tool-call format (returned in resp.tool_calls):
    {"id": str, "name": str, "arguments": dict}
"""

from .base    import LLMProvider, LLMResponse, LLMChunk
from .factory import get_provider

__all__ = ["LLMProvider", "LLMResponse", "LLMChunk", "get_provider"]
