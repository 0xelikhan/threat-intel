"""
MapMITRESkill — map findings to MITRE ATT&CK techniques.

Layered approach:
  1. Pull deterministic technique IDs out of the behavioral_indicators
     (the behavior_extractor already emits MITRE-tagged hits).
  2. Resolve human-readable names + tactic via intel.mitre_data
     (mitreattack-python over enterprise-attack.json — loaded once,
     cached at module level).
  3. If a provider is available, ask it to add any techniques the
     deterministic pass missed (it sees iocs + behavioral_indicators
     and returns extra technique IDs with one-line evidence).

Output is a flat list[dict] of {technique_id, technique_name, tactic,
confidence, evidence}.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from providers.base import LLMProvider

from .base import Skill


_AUGMENT_PROMPT = """You are mapping security findings to MITRE ATT&CK
techniques. The deterministic extractor already produced the techniques
in `existing`. Read the supplied IOCs + behavioral indicators and return
ONLY ADDITIONAL techniques the deterministic pass missed.

Output strict JSON: {"additions": [
  {"technique_id": "Txxxx[.yyy]", "evidence": "<1-line why>"}
]}. Empty list when the deterministic pass already covered everything.
No commentary. No markdown.
"""


def _resolve(tech_ids: List[str]) -> List[Dict[str, Any]]:
    """Look up name + tactic for each technique id via mitre_data."""
    if not tech_ids:
        return []
    try:
        from intel.mitre_data import get_all_techniques
    except Exception:
        return [{"technique_id": tid, "technique_name": tid, "tactic": "Unknown",
                 "confidence": 0.5, "evidence": ""} for tid in tech_ids]
    catalog = {t["id"]: t for t in (get_all_techniques() or [])}
    out: List[Dict[str, Any]] = []
    seen = set()
    for tid in tech_ids:
        norm = (tid or "").strip().upper()
        if not norm or norm in seen:
            continue
        seen.add(norm)
        c = catalog.get(norm) or {}
        out.append({
            "technique_id":   norm,
            "technique_name": c.get("name") or norm,
            "tactic":         c.get("tactic") or "Unknown",
            "confidence":     0.85,   # deterministic = high
            "evidence":       "behavior_extractor pattern match",
        })
    return out


class MapMITRESkill(Skill):
    @property
    def name(self) -> str:
        return "map_mitre"

    @property
    def description(self) -> str:
        return ("Map behavioral indicators + IOCs to MITRE ATT&CK techniques. "
                "Combines deterministic regex mapping (high confidence) with "
                "an optional LLM augmentation pass for techniques the regex "
                "missed.")

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "behavioral_indicators": "dict",
            "enrichments":           "dict",
            "iocs":                  "dict",
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {"mitre_techniques": "list[dict]"}

    @property
    def test_input(self) -> Dict[str, Any]:
        return {
            "behavioral_indicators": {
                "techniques": ["T1059.001"],
                "categories": {"powershell": [{"name": "PowerShell EncodedCommand"}]},
            },
            "enrichments": {},
            "iocs":        {"ips": [], "domains": [], "hashes": []},
        }

    async def execute(
        self,
        inputs:   Dict[str, Any],
        provider: Optional[LLMProvider] = None,
    ) -> Dict[str, Any]:
        bi  = (inputs or {}).get("behavioral_indicators") or {}
        det_ids: List[str] = list(bi.get("techniques") or [])

        # Deterministic resolution first.
        techniques = _resolve(det_ids)

        # Optional LLM augmentation pass.
        if provider is not None:
            try:
                resp = await provider.complete(
                    messages=[
                        {"role": "system", "content": _AUGMENT_PROMPT},
                        {"role": "user",   "content":
                            "## Existing\n" + json.dumps(det_ids) +
                            "\n## Indicators\n" + json.dumps(bi, indent=2)[:3000] +
                            "\n## IOCs\n" + json.dumps((inputs or {}).get("iocs") or {}, indent=2)[:1500]},
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.0,
                    max_tokens=500,
                )
                if not resp.error and resp.message:
                    extra = (json.loads(resp.message).get("additions") or [])[:8]
                    for item in extra:
                        tid = (item.get("technique_id") or "").upper()
                        if not tid or any(t["technique_id"] == tid for t in techniques):
                            continue
                        resolved = _resolve([tid])
                        if resolved:
                            resolved[0]["confidence"] = 0.6   # LLM-augmented = medium
                            resolved[0]["evidence"]   = item.get("evidence") or ""
                            techniques.append(resolved[0])
            except Exception:
                pass

        return {"mitre_techniques": techniques}
