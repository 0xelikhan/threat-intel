"""
Skill registry — the programmatic entry point for every AI-backed
procedure in the system.

There are two equal-citizen entry points into the platform:
  1. The LangGraph orchestrator (`agents.orchestrator.run_pipeline`) — the
     end-to-end SOC pipeline (triage → enrichment → investigation →
     response) used by /api/analyze and the chat SSE stream.
  2. The skill registry (this module) — granular access to any one
     procedure in isolation. Used by tests, the Teams bot prototype,
     and any future API endpoint that needs a single step.

Both routes call the same underlying agent functions and both flow through
`providers.get_provider()`, so swapping the LLM backend is a single
config change regardless of which entry point a caller used.

Add a new skill by importing it here and adding it to SKILL_REGISTRY.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Type

from .base                  import Skill
from .extract_iocs           import ExtractIOCsSkill
from .enrich_ioc             import EnrichIOCSkill
from .triage_alert           import TriageAlertSkill
from .investigate            import InvestigateSkill
from .generate_sigma         import GenerateSigmaSkill
from .generate_kql           import GenerateKQLSkill
from .map_mitre              import MapMITRESkill
from .correlate_signals      import CorrelateSignalsSkill
from .generate_hypothesis    import GenerateHypothesisSkill
from .generate_able_table    import GenerateAbleTableSkill
from .generate_hunt_plan     import GenerateHuntPlanSkill
from .domain_permutations    import DomainPermutationsSkill
from .analyze_capabilities   import AnalyzeCapabilitiesSkill
from .match_sigma_rules      import MatchSigmaRulesSkill
from .classify_capabilities  import ClassifyCapabilitiesSkill
from .match_detections       import MatchDetectionsSkill
from .semantic_search_detections import SemanticSearchDetectionsSkill


SKILL_REGISTRY: Dict[str, Type[Skill]] = {
    "extract_iocs":         ExtractIOCsSkill,
    "enrich_ioc":           EnrichIOCSkill,
    "triage_alert":         TriageAlertSkill,
    "investigate":          InvestigateSkill,
    "generate_sigma":       GenerateSigmaSkill,
    "generate_kql":         GenerateKQLSkill,
    "map_mitre":            MapMITRESkill,
    "correlate_signals":    CorrelateSignalsSkill,
    "generate_hypothesis":  GenerateHypothesisSkill,
    "generate_able_table":  GenerateAbleTableSkill,
    "generate_hunt_plan":   GenerateHuntPlanSkill,
    "domain_permutations":  DomainPermutationsSkill,
    "analyze_capabilities":   AnalyzeCapabilitiesSkill,
    "match_sigma_rules":      MatchSigmaRulesSkill,
    "classify_capabilities":  ClassifyCapabilitiesSkill,
    "match_detections":       MatchDetectionsSkill,
    "semantic_search_detections": SemanticSearchDetectionsSkill,
}


def get_skill(name: str) -> Skill:
    """Return a fresh instance of the named skill. Raises KeyError for
    unknown names."""
    cls = SKILL_REGISTRY[name]
    return cls()


def list_skills() -> list[str]:
    return list(SKILL_REGISTRY.keys())


async def run_skill(
    name:     str,
    inputs:   Dict[str, Any],
    provider: Optional[Any] = None,
) -> Dict[str, Any]:
    """One-shot dispatch: look up `name`, build an instance, execute it.

    Pass `provider` when you want to pin a specific LLM (tests, A/B
    comparisons). Leave it None to let the skill resolve the configured
    provider via `providers.get_provider()`.

    Raises KeyError if `name` isn't registered.
    """
    skill = get_skill(name)
    return await skill.execute(inputs, provider=provider)
