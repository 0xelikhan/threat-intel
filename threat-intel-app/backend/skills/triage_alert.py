"""
TriageAlertSkill — wraps the existing run_triage agent.

Builds a synthetic state object so the agent's state-driven contract still
holds, then surfaces the fields skills callers expect.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from providers.base import LLMProvider

from .base import Skill


class TriageAlertSkill(Skill):
    @property
    def name(self) -> str:
        return "triage_alert"

    @property
    def description(self) -> str:
        return ("Run heuristic + AI triage over raw alert text. Returns a "
                "triage score (0-1), proceed/skip decision, extracted IOCs, "
                "behavioral indicators, and the AI's short reasoning string.")

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {"raw_input": "str"}

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "triage_score":          "float",
            "should_proceed":        "bool",
            "iocs":                  "dict",
            "behavioral_indicators": "dict",
            "triage_reasoning":      "str",
            "alert_type":            "str",
        }

    @property
    def test_input(self) -> Dict[str, Any]:
        return {"raw_input": "alert: endpoint detection host WORKSTATION-04"}

    async def execute(
        self,
        inputs:   Dict[str, Any],
        provider: Optional[LLMProvider] = None,
    ) -> Dict[str, Any]:
        raw = (inputs or {}).get("raw_input") or ""
        try:
            from agents.triage import run_triage
        except Exception as e:
            return {
                "triage_score": 0.0, "should_proceed": True, "iocs": {},
                "behavioral_indicators": {}, "triage_reasoning": f"unavailable: {e}",
                "alert_type": "unknown",
            }
        state = {"raw_input": raw, "agent_trace": []}
        out = await run_triage(state)

        trace = out.get("agent_trace") or []
        triage_trace = next((t for t in trace if t.get("agent") == "triage"), {})
        return {
            "triage_score":          float(out.get("triage_score") or triage_trace.get("score") or 0.0),
            "should_proceed":        bool(out.get("should_proceed", True)),
            "iocs":                  out.get("iocs") or {},
            "behavioral_indicators": out.get("behavioral_indicators") or {},
            "triage_reasoning":      triage_trace.get("summary") or "",
            "alert_type":            triage_trace.get("alert_type") or "unknown",
        }
