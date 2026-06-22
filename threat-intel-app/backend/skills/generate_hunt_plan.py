"""
GenerateHuntPlanSkill — synthesise a structured threat-hunting plan
(time frame, ABLE recap, data sources, hunt procedure with KQL/SPL/Sigma
hints) for a given hypothesis + RECON analysis.

Prompts adapted from Cisco Talos PEAK-Assistant
(`peak_assistant/planning_assistant/__init__.py`, MIT licensed; copyright
2025 Cisco Systems, Inc.).

PEAK uses an autogen RoundRobinGroupChat between a planner and a critic
that emits a termination token when the plan is good enough. We use the
same idea via `providers/critic_loop.py` so we don't pull in autogen.
Runs on the smart model tier (AI_MODEL) — the output is the most complex
of the three new skills and benefits from the better reasoning model.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from providers.base import LLMProvider
from providers.critic_loop import run_critic_loop

from .base import Skill


_PLANNER_PROMPT = """You are an expert in cybersecurity threat hunting. Produce a
comprehensive hunt plan based on the provided hypothesis, RECON analysis (the
threat verdict, IOCs, MITRE coverage, behavioural indicators), and ABLE table.

Use generic SIEM-platform hints — RECON ships KQL (Microsoft Sentinel /
Defender) and Splunk SPL examples by default. Do NOT assume a specific
deployment of either.

## Output format (Markdown — first character must be `#`, no code fences around the whole document)

# Threat Hunt Plan: <short technique / behaviour name>

## Hypothesis
<restate the hypothesis verbatim>

## Recommended Time Frame
<one short paragraph — examples: "Previous 30 days", "7 days", "Year-to-date".
If no specific window applies, write "No specific time window recommended" and
briefly say why.>

## ABLE Recap
<concise restatement of the ABLE table in the same | Actor | Behavior |
Location | Evidence | format — fill in cells with one-paragraph descriptions>

## Data Sources
| Source | Why it matters | Key fields |
|---|---|---|
| <e.g. Defender for Endpoint > DeviceProcessEvents> | <relevance> | <field list> |

## Hunt Procedure

Number each step. For each step include: what you're looking for, ONE example
KQL or SPL query in a fenced code block, and how to interpret the result.

1. **<step name>** — <what you're hunting for in this step>
   ```kql
   <KQL query, scoped to the relevant table + fields>
   ```
   Interpretation: <how to read the output and what would indicate the hypothesis is true>

2. **<next step>** …

## Pivot / Follow-up
<short bullet list of next hunts or escalation actions if the hypothesis is confirmed>

Do not wrap the entire document in code fences. Do not include any text before
the title.
"""


_PLAN_CRITIC_PROMPT = """You are an expert threat-hunting critic. Evaluate the
hunt plan against these criteria:

1. The plan restates the hypothesis accurately.
2. Recommended Time Frame is stated (specific window or explicit "no specific window").
3. ABLE recap is present with all four cells filled.
4. Data Sources table has at least one row with relevant key fields named.
5. Hunt Procedure has numbered steps, each with at least one concrete KQL or SPL
   query and an interpretation paragraph.
6. Queries are syntactically plausible for the platform (KQL = pipe-separated
   operators against a table; SPL = search command pipeline). Reject obviously
   malformed queries.
7. The plan does not refer to detection products or deployments RECON does not
   support (no Zeek-specific output formats, no CrowdStrike Falcon platform
   internals, etc.).
8. No code fence wraps the entire document.

If every criterion is met, respond with exactly:

YYY-TERMINATE-YYY

Otherwise, respond with a short bulleted list of the specific changes the
planner should make. Do not rewrite the plan yourself — only give feedback.
"""


class GenerateHuntPlanSkill(Skill):
    @property
    def name(self) -> str:
        return "generate_hunt_plan"

    @property
    def description(self) -> str:
        return ("Generate a structured PEAK-style threat hunt plan (time frame, "
                "ABLE recap, data sources, hunt procedure with example queries) "
                "via a generator+critic loop.")

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "hypothesis":    "str",
            "able_markdown": "str",
            "analysis":      "dict",
            "iocs":          "dict",
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "hunt_plan_markdown":   "str",
            "iterations":           "int",
            "critic_approved":      "bool",
        }

    @property
    def test_input(self) -> Dict[str, Any]:
        return {
            "hypothesis": ("Threat actors may be using PowerShell EncodedCommand to "
                           "stage Cobalt Strike beacons on Windows endpoints"),
            "able_markdown": (
                "# PEAK ABLE Table: PowerShell EncodedCommand Cobalt Strike staging\n\n"
                "*Hypothesis: Threat actors may be using PowerShell EncodedCommand "
                "to stage Cobalt Strike beacons on Windows endpoints*\n\n"
                "| ABLE Element | Detail |\n|---|---|\n"
                "| Actor | Unattributed; Cobalt Strike is widely abused by ransomware affiliates. |\n"
                "| Behavior | PowerShell.exe invoked with -EncodedCommand decoding a base64 payload. |\n"
                "| Location | End-user workstations and Windows servers with PowerShell available. |\n"
                "| Evidence | Process creation logs with base64-encoded command lines. |\n"
            ),
            "analysis": {
                "threat_level":     "HIGH",
                "summary":          "PowerShell EncodedCommand staging Cobalt Strike beacon",
                "mitre_techniques": ["T1059.001", "T1027"],
                "malware_family":   "Cobalt Strike",
            },
            "iocs": {
                "ips":     ["185.220.101.45"],
                "domains": ["update-service.xyz"],
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

        hypothesis    = (inputs or {}).get("hypothesis") or ""
        able_markdown = (inputs or {}).get("able_markdown") or ""
        analysis      = (inputs or {}).get("analysis") or {}
        iocs          = (inputs or {}).get("iocs") or {}

        if not hypothesis.strip():
            return {
                "hunt_plan_markdown": "",
                "iterations":         0,
                "critic_approved":    False,
            }

        user_msg = (
            f"## Hypothesis\n{hypothesis}\n\n"
            f"## ABLE Table\n{able_markdown}\n\n"
            f"## RECON Analysis\n{json.dumps(analysis, indent=2)[:3000]}\n\n"
            f"## IOCs\n{json.dumps(iocs, indent=2)[:1500]}"
        )

        result = await run_critic_loop(
            provider=provider,
            generator_system=_PLANNER_PROMPT,
            critic_system=_PLAN_CRITIC_PROMPT,
            user_content=user_msg,
            max_iters=2,
            temperature=0.2,
            max_tokens=1600,
            model=_smart_model(),
        )

        return {
            "hunt_plan_markdown": _strip_fences(result.output),
            "iterations":         result.iterations,
            "critic_approved":    result.terminated_cleanly,
        }


def _smart_model() -> Optional[str]:
    try:
        from config import config  # noqa: WPS433
        if hasattr(config, "get_model"):
            return config.get_model() or None
        return config.get("AI_MODEL") or None
    except Exception:
        return None


def _strip_fences(s: str) -> str:
    s = (s or "").strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[1] if "\n" in s else s[3:]
        if s.rstrip().endswith("```"):
            s = s.rstrip()[:-3]
    return s.strip()
