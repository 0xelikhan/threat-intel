"""
GenerateHypothesisSkill — produce testable threat-hunting hypotheses
from a completed RECON analysis (triage + enrichment + investigation).

Prompt adapted from Cisco Talos PEAK-Assistant
(`peak_assistant/hypothesis_assistant/hypothesis_assistant_cli.py`,
MIT licensed; copyright 2025 Cisco Systems, Inc.).

RECON's existing pipeline is reactive (paste alert → verdict). This
skill shifts left: given the verdict + IOCs + MITRE coverage from a run,
emit 3-5 specific, behaviour-focused hypotheses an analyst can take into
a hunt. The prompt enforces PEAK's "describe what adversaries ARE DOING,
not what detection might show" framing.

Runs on the fast model tier (FAST_AI_MODEL) — it's a single short call.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from providers.base import LLMProvider

from .base import Skill


_HYPOTHESIS_PROMPT = """You are a threat hunting hypothesis generator. Based on the
provided RECON analysis (verdict, IOCs, MITRE coverage, behavioural indicators),
generate 3-5 specific, testable threat hunting hypotheses.

## Requirements
Each hypothesis must be:
- Specific: include concrete technique names, tool names, protocols, target systems, or file patterns
- Testable: can be proven or disproven through data analysis
- Achievable: investigable with common security tools and logs
- Relevant: grounded in the techniques and behaviours surfaced by the analysis
- Behavioural: describes what adversaries ARE DOING, not what detection might show

## DO
- State what adversaries / attackers / threat actors "may be", "are", or "might be" DOING
- Describe observable adversary actions (process execution, file creation, network traffic, authentication attempts)
- Include 3-5 specific technical details per hypothesis
- Focus on 1-2 related behaviours per hypothesis
- Keep each hypothesis under 35 words

## DO NOT
- Use detection-focused language ("could indicate", "might suggest", "may reveal", "evidence of")
- Describe investigation activities ("hunt for", "search for", "cross-reference", "systematic review")
- Include time windows ("in the last 30 days", "during off-hours")
- Specify data sources or log types ("Sysmon EventID 1", "Windows Event 4688")
- Mention detection products ("Splunk", "Zeek", "CrowdStrike", "QRadar")
- Use vague terms ("suspicious activity", "anomalous behavior", "unusual patterns", "various methods")
- Number or label hypotheses

## Output format
Return ONLY the hypotheses, one per line. No introductory text, no numbering, no
explanations, no conclusions. If you cannot generate any valid hypotheses,
respond only with: "No hypotheses could be generated"

## Examples of GOOD hypotheses
Threat actors may be using PowerShell Empire to establish persistence through scheduled tasks on domain-joined Windows endpoints
Adversaries may be dumping LSASS process memory using built-in Windows utilities such as rundll32.exe or comsvcs.dll to harvest credentials
Threat actors may be exfiltrating sensitive data through DNS tunneling using encoded queries to external resolvers
Attackers may be leveraging WMI for lateral movement between workstations by executing remote commands via DCOM

## Examples of BAD hypotheses (DO NOT produce these)
Threat actors may be active in the last 30 days using PowerShell           [time window]
Evidence of PowerShell Empire in EDR logs could indicate persistence       [detection-focused]
Check Cisco ASA firewall logs for suspicious traffic to known C2 servers   [data source + task]
Hunt for signs of credential dumping using Mimikatz                        [hunting task, not behaviour]
Unusual spikes in authentication failures might suggest brute force        [vague + detection-focused]
"""


class GenerateHypothesisSkill(Skill):
    @property
    def name(self) -> str:
        return "generate_hypothesis"

    @property
    def description(self) -> str:
        return ("Generate 3-5 testable threat-hunting hypotheses from a completed "
                "RECON analysis (verdict, IOCs, MITRE coverage, behavioural indicators).")

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {"analysis": "dict", "iocs": "dict"}

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {"hypotheses": "list[str]"}

    @property
    def test_input(self) -> Dict[str, Any]:
        return {
            "analysis": {
                "threat_level":    "HIGH",
                "summary":         "PowerShell EncodedCommand staging Cobalt Strike beacon",
                "mitre_techniques": ["T1059.001", "T1027"],
                "malware_family":  "Cobalt Strike",
            },
            "iocs": {
                "ips":     ["185.220.101.45"],
                "domains": ["update-service.xyz"],
                "hashes":  ["3395856ce81f2b7382dee72602f798b642f14140"],
            },
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
        user_msg = (
            "## Analysis\n" + json.dumps(analysis, indent=2)[:3000] +
            "\n\n## IOCs\n"  + json.dumps(iocs, indent=2)[:2000]
        )

        model = _fast_model()
        kwargs = {"model": model} if model else {}
        resp = await provider.complete(
            messages=[
                {"role": "system", "content": _HYPOTHESIS_PROMPT},
                {"role": "user",   "content": user_msg},
            ],
            temperature=0.3,
            max_tokens=700,
            **kwargs,
        )
        if resp.error or not (resp.message or "").strip():
            return {"hypotheses": []}

        lines = [_clean_line(l) for l in resp.message.splitlines()]
        hypotheses = [l for l in lines if _looks_like_hypothesis(l)]
        return {"hypotheses": hypotheses[:5]}


def _fast_model() -> Optional[str]:
    """Resolve FAST_AI_MODEL via config without making it a hard dependency
    when config isn't importable (e.g. early tests)."""
    try:
        from config import config  # noqa: WPS433
        if hasattr(config, "get_model"):
            return config.get_model(fast=True) or None
        return config.get("FAST_AI_MODEL") or config.get("AI_MODEL") or None
    except Exception:
        return None


def _clean_line(s: str) -> str:
    s = (s or "").strip()
    # Strip leading bullets / numbers the model sometimes adds despite the prompt.
    for prefix in ("- ", "* ", "• "):
        if s.startswith(prefix):
            s = s[len(prefix):].strip()
            break
    if s[:3].rstrip(".)").isdigit():
        # "1. ", "10) ", etc.
        for sep in (". ", ") "):
            if sep in s[:5]:
                s = s.split(sep, 1)[1].strip()
                break
    return s


def _looks_like_hypothesis(s: str) -> bool:
    if len(s) < 20 or len(s) > 400:
        return False
    if s.lower().startswith(("based on", "here are", "the following", "no hypotheses")):
        return False
    return True
