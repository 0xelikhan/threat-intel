"""
SemanticSearchDetectionsSkill — natural-language search over the 11
bundled detection corpora.

Where match_detections is exact-match (MITRE technique ID overlap), this
skill is a fuzzy/semantic lookup. Use case: an analyst is investigating
a behavioural pattern they don't yet have an ATT&CK mapping for —
"PowerShell encoded command launched from an Office macro" — and wants
to see whether anyone has shipped a detection for it. Each rule's
title + description + technique list is embedded once; queries are
cosine-similarity ranked.

This skill does NOT call an LLM. The embedder runs locally
(sentence-transformers if installed, otherwise a sklearn TF-IDF char-
ngram fallback).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from providers.base import LLMProvider

from .base import Skill


class SemanticSearchDetectionsSkill(Skill):
    @property
    def name(self) -> str:
        return "semantic_search_detections"

    @property
    def description(self) -> str:
        return ("Natural-language search across SigmaHQ, panther-analysis, "
                "Splunk security_content, MITRE CAR, OTRF ThreatHunter-"
                "Playbook, Sublime, Chronicle YARA-L, olafhartong, "
                "falco-rules, Stratus Red Team, and ET Open + Snort. "
                "Returns top-ranked rule citations by embedding similarity.")

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "query":     "str (natural language query)",
            "top_k":     "int (optional, default 10)",
            "sources":   "list[str] (optional — filter to subset of corpora)",
            "min_score": "float (optional, drop matches below this score)",
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "query":   "str",
            "results": "list[dict]",
            "total":   "int",
            "backend": "str (sentence_transformers | tfidf)",
        }

    @property
    def test_input(self) -> Dict[str, Any]:
        return {
            "query": "PowerShell encoded command launched from Office macro",
            "top_k": 5,
        }

    async def execute(
        self,
        inputs:   Dict[str, Any],
        provider: Optional[LLMProvider] = None,
    ) -> Dict[str, Any]:
        query   = (inputs or {}).get("query") or ""
        top_k   = int((inputs or {}).get("top_k") or 10)
        sources = (inputs or {}).get("sources") or None
        min_s   = float((inputs or {}).get("min_score") or 0.0)

        try:
            from intel.semantic_search import search, stats
            results = search(query, top_k=top_k, sources=sources, min_score=min_s)
            backend = stats().get("backend") or "unknown"
        except Exception as e:
            return {
                "query":   query,
                "results": [],
                "total":   0,
                "backend": "error",
                "error":   str(e)[:200],
            }

        return {
            "query":   query,
            "results": results,
            "total":   len(results),
            "backend": backend,
        }
