"""
ClassifyCapabilitiesSkill — group YARA matches by Chainguard malcontent
capability buckets (anti-behavior, c2, credential, exec, exfil, persist,
privesc, etc.) so the analyst report gets a structured "what does this
sample DO" view alongside the raw rule list.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from providers.base import LLMProvider

from .base import Skill


class ClassifyCapabilitiesSkill(Skill):
    @property
    def name(self) -> str:
        return "classify_capabilities"

    @property
    def description(self) -> str:
        return ("Group a set of YARA rule matches by Chainguard malcontent "
                "capability bucket (anti-behavior, c2, credential, exec, "
                "exfil, persist, privesc, etc.).")

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {"rule_names": "list[str]"}

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "by_bucket":       "dict[bucket, list[rule]]",
            "bucket_counts":   "dict[bucket, int]",
            "tactics":         "dict[MITRE-tactic, int]",
            "unmatched":       "list[str]",
            "total_matched":   "int",
        }

    @property
    def test_input(self) -> Dict[str, Any]:
        return {"rule_names": []}

    async def execute(
        self,
        inputs:   Dict[str, Any],
        provider: Optional[LLMProvider] = None,
    ) -> Dict[str, Any]:
        from intel.malcontent_rules import classify
        names = list((inputs or {}).get("rule_names") or [])
        return classify(names)
