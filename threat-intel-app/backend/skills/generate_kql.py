"""
GenerateKQLSkill — produce a Microsoft Sentinel KQL query for the analysis.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from providers.base import LLMProvider

from .base import Skill


_KQL_PROMPT = """You are a Sentinel detection engineer. Write ONE KQL query
that would surface the activity described below in a Microsoft Sentinel
workspace.

Hard requirements:
* Pick the most specific table (DeviceProcessEvents / DeviceNetworkEvents /
  DeviceFileEvents / SecurityEvent / SigninLogs / etc.) — never reach for
  union when one table covers it.
* Filter on the actual IOC values (IP/domain/hash) using `in (...)` or
  `has_any (...)`.
* Use `| project` to surface the columns an analyst would triage on.
* Include an inline `// ...` comment line at the top stating what the
  query detects in one sentence.

Output the KQL only — no markdown fences, no commentary outside the query.
"""


class GenerateKQLSkill(Skill):
    @property
    def name(self) -> str:
        return "generate_kql"

    @property
    def description(self) -> str:
        return ("Generate a Microsoft Sentinel KQL query that surfaces the "
                "activity described in the analysis using the supplied IOCs.")

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {"analysis": "dict", "iocs": "dict"}

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {"kql_query": "str"}

    @property
    def test_input(self) -> Dict[str, Any]:
        return {
            "analysis": {"threat_level": "HIGH",
                         "summary": "Outbound C2 beaconing"},
            "iocs":     {"ips": ["185.220.101.45"], "domains": ["update-service.xyz"]},
        }

    async def execute(
        self,
        inputs:   Dict[str, Any],
        provider: Optional[LLMProvider] = None,
    ) -> Dict[str, Any]:
        if provider is None:
            from providers import get_provider
            provider = get_provider()

        analysis = (inputs or {}).get("analysis") or {}
        iocs     = (inputs or {}).get("iocs") or {}
        resp = await provider.complete(
            messages=[
                {"role": "system", "content": _KQL_PROMPT},
                {"role": "user",   "content":
                    "## Analysis\n" + json.dumps(analysis, indent=2)[:2500] +
                    "\n\n## IOCs\n"  + json.dumps(iocs, indent=2)[:1500]},
            ],
            temperature=0.1,
            max_tokens=600,
        )
        kql = "" if resp.error else (resp.message or "").strip()
        # Strip any stray fences the model produces despite the rule.
        if kql.startswith("```"):
            kql = kql.split("\n", 1)[1] if "\n" in kql else kql[3:]
            if kql.rstrip().endswith("```"):
                kql = kql.rstrip()[:-3]
        return {"kql_query": kql.strip()}
