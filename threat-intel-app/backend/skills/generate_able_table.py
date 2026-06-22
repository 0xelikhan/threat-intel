"""
GenerateAbleTableSkill — produce a PEAK ABLE (Actor, Behavior, Location,
Evidence) table for a given hunt hypothesis.

Prompt adapted from Cisco Talos PEAK-Assistant
(`peak_assistant/able_assistant/__init__.py`, MIT licensed; copyright
2025 Cisco Systems, Inc.).

ABLE is a hunt-scoping schema richer than MITRE alone: it captures who
you're looking for, what behaviour, where in the network, and what data
would prove it. RECON's analyst report already has MITRE coverage; this
adds the L (Location) and E (Evidence) dimensions an analyst needs to
turn a verdict into a hunt.

Runs on the fast model tier.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from providers.base import LLMProvider

from .base import Skill


_ABLE_PROMPT = """You are an expert in cybersecurity threat hunting, specifically
the PEAK Threat Hunting Framework's ABLE method. ABLE captures the four critical
pieces of a hunt:

  - Actor: The threat actor (or general type) you're looking for. Many behaviours
    are not tied to a specific actor; leave the cell descriptive in that case.
  - Behavior: The specific TTP being hunted, focused on 1-2 related techniques.
  - Location: The part(s) of the network where this behaviour is expected
    (e.g., "end-user desktops", "internet-facing web servers", "domain controllers").
  - Evidence: Which data sources you'd need and what the activity looks like in them.

Given the hypothesis and the RECON analysis below, produce a single PEAK ABLE
table in Markdown.

## Output format (Markdown — start with the title, nothing before it)

# PEAK ABLE Table: <short common name for the technique>

*Hypothesis: <restate the hypothesis verbatim>*

| ABLE Element | Detail |
|---|---|
| Actor | <one-paragraph description, or "Not actor-attributed" if generic> |
| Behavior | <one-paragraph description of the specific TTP> |
| Location | <one-paragraph description of network locations> |
| Evidence | <one-paragraph description of data sources + expected indicators> |

Optionally, append a "## Notes" section with bullet points ONLY if you have
genuinely useful caveats. Omit the section if there are no notes.

Never wrap the output in code fences. The first character of your response must
be the `#` of the title.
"""


class GenerateAbleTableSkill(Skill):
    @property
    def name(self) -> str:
        return "generate_able_table"

    @property
    def description(self) -> str:
        return ("Generate a PEAK ABLE (Actor, Behavior, Location, Evidence) table "
                "for a hunt hypothesis using the RECON analysis as research context.")

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {"hypothesis": "str", "analysis": "dict", "iocs": "dict"}

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {"able_markdown": "str"}

    @property
    def test_input(self) -> Dict[str, Any]:
        return {
            "hypothesis": ("Threat actors may be using PowerShell EncodedCommand to "
                           "stage Cobalt Strike beacons on Windows endpoints"),
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

        hypothesis = (inputs or {}).get("hypothesis") or ""
        analysis   = (inputs or {}).get("analysis") or {}
        iocs       = (inputs or {}).get("iocs") or {}
        if not hypothesis.strip():
            return {"able_markdown": ""}

        user_msg = (
            f"## Hypothesis\n{hypothesis}\n\n"
            f"## Analysis\n{json.dumps(analysis, indent=2)[:3000]}\n\n"
            f"## IOCs\n{json.dumps(iocs, indent=2)[:1500]}"
        )

        model = _fast_model()
        kwargs = {"model": model} if model else {}
        resp = await provider.complete(
            messages=[
                {"role": "system", "content": _ABLE_PROMPT},
                {"role": "user",   "content": user_msg},
            ],
            temperature=0.2,
            max_tokens=900,
            **kwargs,
        )
        if resp.error:
            return {"able_markdown": ""}

        markdown = _strip_fences((resp.message or "").strip())
        return {"able_markdown": markdown}


def _fast_model() -> Optional[str]:
    try:
        from config import config  # noqa: WPS433
        if hasattr(config, "get_model"):
            return config.get_model(fast=True) or None
        return config.get("FAST_AI_MODEL") or config.get("AI_MODEL") or None
    except Exception:
        return None


def _strip_fences(s: str) -> str:
    s = (s or "").strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[1] if "\n" in s else s[3:]
        if s.rstrip().endswith("```"):
            s = s.rstrip()[:-3]
    return s.strip()
