"""
Skill abstract base class.

A Skill is a self-contained, individually-testable unit of capability —
"extract IOCs from text," "enrich one IOC against TI sources," "ask the
AI to generate a Sigma rule," etc. Every skill exposes a uniform shape
(name, description, input_schema, output_schema, execute, test_input)
so the orchestrator + the test harness can iterate without per-skill
glue code.

Hard rule: `execute()` must NEVER import or call a vendor SDK directly.
LLM access goes exclusively through the `provider` parameter (an
LLMProvider instance from providers/factory.py). That keeps every skill
swappable across providers and unit-testable with a mock.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from providers.base import LLMProvider


class Skill(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Short stable identifier, e.g. "extract_iocs"."""

    @property
    @abstractmethod
    def description(self) -> str:
        """One-line plain-English explanation of what the skill does."""

    @property
    @abstractmethod
    def input_schema(self) -> Dict[str, Any]:
        """Dict describing the expected `inputs` keys and their types.
        Example: {"raw_text": "str"}. Used by tests + future Skill UI."""

    @property
    @abstractmethod
    def output_schema(self) -> Dict[str, Any]:
        """Dict describing the returned dict keys and their types. Tests
        assert every key in this schema is present in the execute() output."""

    @property
    @abstractmethod
    def test_input(self) -> Dict[str, Any]:
        """A representative `inputs` dict the unit test can hand to
        execute() without touching real API services."""

    @abstractmethod
    async def execute(
        self,
        inputs:   Dict[str, Any],
        provider: Optional[LLMProvider] = None,
    ) -> Dict[str, Any]:
        """Run the skill. Returns a dict whose keys match output_schema.
        Skills that don't need an LLM can ignore `provider`."""
