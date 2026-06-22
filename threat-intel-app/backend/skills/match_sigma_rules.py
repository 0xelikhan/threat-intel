"""
MatchSigmaRulesSkill — cross-reference an analysis against the bundled
SigmaHQ rule corpus and surface rules whose MITRE coverage overlaps the
techniques the investigation produced.

This is purely a metadata lookup over the inverted index built by
intel/sigma_corpus.py — no LLM, no IO, ~100µs per query after the
corpus is loaded. The matcher is cheap enough to call on every
investigation run; we just need to be explicit about citation
(SigmaHQ rules are DRL 1.1, attribution required when surfaced).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from providers.base import LLMProvider

from .base import Skill


class MatchSigmaRulesSkill(Skill):
    @property
    def name(self) -> str:
        return "match_sigma_rules"

    @property
    def description(self) -> str:
        return ("Match the analysis's MITRE techniques against the bundled "
                "SigmaHQ rule corpus and return rule citations.")

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "mitre_techniques": "list[str]",
            "max_results":      "int (optional, default 15)",
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "matches":     "list[dict]",
            "total":       "int",
            "corpus_size": "int",
        }

    @property
    def test_input(self) -> Dict[str, Any]:
        return {"mitre_techniques": ["T1059.001", "T1027"], "max_results": 10}

    async def execute(
        self,
        inputs:   Dict[str, Any],
        provider: Optional[LLMProvider] = None,
    ) -> Dict[str, Any]:
        from intel.sigma_corpus import match_by_techniques, stats

        techniques  = list((inputs or {}).get("mitre_techniques") or [])
        max_results = int((inputs or {}).get("max_results") or 15)

        matches = match_by_techniques(techniques, max_results=max_results)

        # Strip path + author from the analyst-facing payload — they're
        # build artifacts. Keep the source attribution simple ("SigmaHQ").
        public: List[Dict[str, Any]] = []
        for m in matches:
            public.append({
                "title":       m.get("title"),
                "id":          m.get("id"),
                "description": m.get("description"),
                "level":       m.get("level"),
                "logsource":   {
                    "category": m.get("category"),
                    "product":  m.get("product"),
                },
                "techniques":  m.get("techniques") or [],
                "source":      "SigmaHQ",
            })

        s = stats()
        return {
            "matches":     public,
            "total":       len(public),
            "corpus_size": s.get("rule_count", 0),
        }
