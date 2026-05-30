"""
CorrelateSignalsSkill — group IOCs into related clusters.

Takes a dict of per-IOC enrichments and the behavioral_indicators and asks
the provider to identify infrastructure overlaps (same ASN / registrar),
malware-family overlaps, threat-actor overlaps, and TTP overlaps. Output
is a list of clusters + a one-line per-cluster summary.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from providers.base import LLMProvider

from .base import Skill


_PROMPT = """You are correlating threat-intel signals across several IOCs.
Given the per-IOC enrichments and the behavioral indicators, identify
relationships and group IOCs that share:
* the same ASN / registrar / hosting infrastructure,
* the same malware family or named tool (Cobalt Strike, Emotet, etc.),
* attribution to the same threat actor,
* the same MITRE technique cluster (e.g. all credential-access TTPs).

Output strict JSON:
{
  "clusters": [
    {
      "label":       "<short cluster name>",
      "members":     ["<ioc>", ...],
      "shared":      ["<thing 1 they share>", "<thing 2>"],
      "relationship": "<one-line summary of why these IOCs are grouped>"
    }
  ],
  "summary": "<2-3 sentence rollup of the strongest cross-IOC relationship>"
}

Empty clusters list when nothing meaningful correlates. No commentary,
no markdown fences.
"""


class CorrelateSignalsSkill(Skill):
    @property
    def name(self) -> str:
        return "correlate_signals"

    @property
    def description(self) -> str:
        return ("Group IOCs into clusters that share infrastructure, malware "
                "family, threat actor, or MITRE TTPs. Returns a per-cluster "
                "summary so the analyst sees relationships the per-IOC view "
                "doesn't surface.")

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "enrichments":           "dict",
            "behavioral_indicators": "dict",
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "clusters":            "list[dict]",
            "correlation_summary": "str",
        }

    @property
    def test_input(self) -> Dict[str, Any]:
        return {
            "enrichments":           {"ips": {"1.1.1.1": {"asn": "AS13335"}}},
            "behavioral_indicators": {"categories": {}},
        }

    async def execute(
        self,
        inputs:   Dict[str, Any],
        provider: Optional[LLMProvider] = None,
    ) -> Dict[str, Any]:
        if provider is None:
            from providers import get_provider
            provider = get_provider()

        enr = (inputs or {}).get("enrichments") or {}
        bi  = (inputs or {}).get("behavioral_indicators") or {}
        try:
            resp = await provider.complete(
                messages=[
                    {"role": "system", "content": _PROMPT},
                    {"role": "user",   "content":
                        "## Enrichments (compressed)\n" +
                        json.dumps(enr, indent=2, default=str)[:6000] +
                        "\n\n## Behavioral indicators\n" +
                        json.dumps(bi, indent=2, default=str)[:2500]},
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=900,
            )
            if resp.error or not resp.message:
                return {"clusters": [], "correlation_summary": ""}
            parsed = json.loads(resp.message)
            return {
                "clusters":            (parsed.get("clusters") or [])[:8],
                "correlation_summary": parsed.get("summary") or "",
            }
        except Exception:
            return {"clusters": [], "correlation_summary": ""}
