"""Default card visualizer — covers every analyser without a custom
render override. Returns a flat {verdict, summary, details_url}
component hint the frontend can render as a generic enrichment card.
"""

from __future__ import annotations

from typing import Any, Dict

from plugins import AnalysisResult, Visualizer, register


class DefaultCardVisualizer(Visualizer):
    name = "default_card"
    description = ("Fallback render hint — any analyser's result can be "
                   "shown as a verdict-coloured card with summary + "
                   "details link.")
    # Empty list means "all sources" — the frontend checks this one last.
    supported_sources = []

    def to_component_hint(self, result: AnalysisResult) -> Dict[str, Any]:
        return {
            "component": "GenericEnrichmentCard",
            "source": result.source,
            "verdict": result.verdict,
            "summary": result.summary,
            "details_url": result.details_url,
            "has_error": bool(result.error),
            "ioc_type": result.ioc_type,
            "ioc_value": result.ioc_value,
            # Pull a few common fields up to the top level so the card
            # can render without opening the raw payload.
            "preview": {k: v for k, v in (result.raw or {}).items()
                         if k in {"family", "signature", "threat", "tags",
                                   "country", "asn", "ports", "last_seen"}},
        }


register(DefaultCardVisualizer)
