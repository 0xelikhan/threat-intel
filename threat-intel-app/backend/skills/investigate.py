"""
InvestigateSkill — wraps the full agents.investigation.run_investigation.

This is the heaviest skill. Run_investigation already routes through the
provider abstraction (after the call-site migration in 464828d), so this
wrapper just shapes inputs and returns the response_summary the analyze
pipeline normally builds.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from providers.base import LLMProvider

from .base import Skill


class InvestigateSkill(Skill):
    @property
    def name(self) -> str:
        return "investigate"

    @property
    def description(self) -> str:
        return ("Full AI investigation over an enriched alert: correlates "
                "every TI signal, calls additional MITRE/KEV/actor tools "
                "as needed, and produces the structured assessment "
                "(threat_level, summary, key_findings, mitre_techniques, "
                "ioc_assessments, recommended_actions, clarifying_questions, "
                "confidence, probing_questions).")

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "raw_input":   "str",
            "iocs":        "dict",
            "enrichments": "dict",
            # Optional: cross_refs, behavioral_indicators, confidence_scores,
            # analyst_answers — passed straight through if present.
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "threat_level":          "str",
            "summary":               "str",
            "key_findings":          "list",
            "mitre_techniques":      "list",
            "ioc_assessments":       "list",
            "recommended_actions":   "list",
            "clarifying_questions":  "list",
            "confidence":            "float",
            "probing_questions":     "list",
            "raw":                   "dict",
        }

    @property
    def test_input(self) -> Dict[str, Any]:
        return {
            "raw_input":   "alert: endpoint detection host WORKSTATION-04",
            "iocs":        {"ips": [], "domains": [], "hashes": []},
            "enrichments": {},
        }

    async def execute(
        self,
        inputs:   Dict[str, Any],
        provider: Optional[LLMProvider] = None,
    ) -> Dict[str, Any]:
        try:
            from agents.investigation import run_investigation
        except Exception as e:
            return self._empty(error=str(e))

        state = {
            "raw_input":              (inputs or {}).get("raw_input") or "",
            "iocs":                   (inputs or {}).get("iocs") or {},
            "enrichments":            (inputs or {}).get("enrichments") or {},
            "cross_refs":             (inputs or {}).get("cross_refs") or {},
            "behavioral_indicators":  (inputs or {}).get("behavioral_indicators") or {},
            "confidence_scores":      (inputs or {}).get("confidence_scores") or {},
            "analyst_answers":        (inputs or {}).get("analyst_answers") or {},
            "email_analysis":         (inputs or {}).get("email_analysis") or {},
            "agent_trace":            [],
            "triage_score":           float((inputs or {}).get("triage_score") or 0.5),
        }
        out = await run_investigation(state)
        result = out.get("investigation") or out
        return {
            "threat_level":         result.get("threat_level", "UNKNOWN"),
            "summary":              result.get("summary", ""),
            "key_findings":         result.get("key_findings") or [],
            "mitre_techniques":     result.get("mitre_techniques") or [],
            "ioc_assessments":      result.get("ioc_assessments") or [],
            "recommended_actions":  result.get("recommended_actions") or [],
            "clarifying_questions": result.get("clarifying_questions") or [],
            "confidence":           float(result.get("confidence") or 0.0),
            "probing_questions":    result.get("probing_questions") or [],
            "raw":                  result,
        }

    @staticmethod
    def _empty(error: str = "") -> Dict[str, Any]:
        return {
            "threat_level": "UNKNOWN", "summary": error, "key_findings": [],
            "mitre_techniques": [], "ioc_assessments": [], "recommended_actions": [],
            "clarifying_questions": [], "confidence": 0.0, "probing_questions": [],
            "raw": {},
        }
