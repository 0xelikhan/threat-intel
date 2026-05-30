"""
GenerateSigmaSkill — produce a Sigma detection rule for the analysis.

Reuses agents.response.validate_sigma_rule for sigma-cli validation. The
generation prompt is local to keep the skill self-contained.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from providers.base import LLMProvider

from .base import Skill


_SIGMA_PROMPT = """You are a senior detection engineer. Produce ONE Sigma rule
in YAML 1.2 syntax that fires on the threat described below. The rule must:
* declare logsource with category + product (where known)
* use detection.selection with concrete field=value pairs derived from the
  IOCs / behavioral indicators provided
* end with `condition: selection`
* include `falsepositives`, `level`, and `tags` (use MITRE technique IDs
  in tags when available, e.g. `attack.t1059.001`)

Output the YAML only — no surrounding markdown fences, no commentary.
"""


class GenerateSigmaSkill(Skill):
    @property
    def name(self) -> str:
        return "generate_sigma"

    @property
    def description(self) -> str:
        return ("Generate a Sigma detection rule for the supplied analysis + "
                "IOCs and validate it with sigma-cli. One retry on validation "
                "failure.")

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {"analysis": "dict", "iocs": "dict"}

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "sigma_rule":   "str",
            "sigma_valid":  "bool",
            "sigma_errors": "list[str]",
        }

    @property
    def test_input(self) -> Dict[str, Any]:
        return {
            "analysis": {"threat_level": "HIGH",
                         "summary": "PowerShell EncodedCommand staging Cobalt Strike beacon"},
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
        user_msg = (
            "## Analysis\n" + json.dumps(analysis, indent=2)[:2500] +
            "\n\n## IOCs\n"  + json.dumps(iocs, indent=2)[:1500]
        )

        async def _gen() -> str:
            resp = await provider.complete(
                messages=[
                    {"role": "system", "content": _SIGMA_PROMPT},
                    {"role": "user",   "content": user_msg},
                ],
                temperature=0.1,
                max_tokens=900,
            )
            return "" if resp.error else (resp.message or "").strip()

        sigma = await _gen()
        sigma = _strip_fences(sigma)
        valid, err = _validate(sigma)
        errors: List[str] = [] if valid else [err]
        if not valid:
            sigma2 = await _gen()
            sigma2 = _strip_fences(sigma2)
            v2, e2 = _validate(sigma2)
            if v2:
                sigma, valid, errors = sigma2, True, []
            else:
                errors.append(e2)

        return {
            "sigma_rule":   sigma,
            "sigma_valid":  valid,
            "sigma_errors": errors,
        }


def _strip_fences(s: str) -> str:
    s = (s or "").strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[1] if "\n" in s else s[3:]
        if s.rstrip().endswith("```"):
            s = s.rstrip()[:-3]
    return s.strip()


def _validate(yaml_content: str):
    try:
        from agents.response import validate_sigma_rule
        return validate_sigma_rule(yaml_content)
    except Exception as e:
        return False, f"validator unavailable: {e}"
