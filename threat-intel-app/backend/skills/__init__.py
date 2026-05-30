"""
Skill registry.

Add a new skill by importing it here and adding it to SKILL_REGISTRY.
get_skill(name) returns an instance; tests + the orchestrator both go
through this so the wiring lives in one place.

Today's registry is intentionally small — ExtractIOCsSkill is the
first concrete migration. Remaining skills (EnrichIOC, TriageAlert,
Investigate, GenerateSigma, GenerateKQL, MapMITRE, CorrelateSignals)
land in a follow-up commit once their host agents have been moved
behind the provider layer.
"""

from __future__ import annotations

from typing import Dict, Type

from .base         import Skill
from .extract_iocs import ExtractIOCsSkill


SKILL_REGISTRY: Dict[str, Type[Skill]] = {
    "extract_iocs": ExtractIOCsSkill,
}


def get_skill(name: str) -> Skill:
    """Return a fresh instance of the named skill. Raises KeyError for
    unknown names."""
    cls = SKILL_REGISTRY[name]
    return cls()


def list_skills() -> list[str]:
    return list(SKILL_REGISTRY.keys())
