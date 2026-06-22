"""
Palantir Alerting and Detection Strategy (ADS) framework loader.

Source: https://github.com/palantir/alerting-detection-strategy-framework
(Apache-2.0). The framework defines a vendor-neutral schema for
documenting detections: Goal, Categorization, Strategy Abstract,
Technical Context, Blind Spots and Assumptions, False Positives,
Validation, Priority, Response.

We bundle the framework markdown so the response agent can structure
its analyst summary around the same sections — gives the report a
recognised industry shape instead of an ad-hoc layout.

The module is intentionally tiny: it just exposes the framework
sections + section descriptions so the agent prompt can reference them
deterministically.
"""

from __future__ import annotations

from typing import Dict, List


# Authoritative section list (verbatim from Palantir's ADS_Framework.md).
# Each entry is (heading, short description). Used as prompt-context for
# the analyst-summary generator + as ordering when the frontend renders
# the structured ADS layout.
ADS_SECTIONS: List[Dict[str, str]] = [
    {
        "heading":     "Goal",
        "description": "What this detection is supposed to find — short, "
                       "behavioural, and outcome-focused.",
    },
    {
        "heading":     "Categorization",
        "description": "Where the activity sits in the kill chain / "
                       "MITRE ATT&CK matrix.",
    },
    {
        "heading":     "Strategy Abstract",
        "description": "Plain-English description of how the detection "
                       "works; analyst should grasp the approach without "
                       "reading any queries.",
    },
    {
        "heading":     "Technical Context",
        "description": "Background on the systems, protocols, or APIs "
                       "involved; enough that an analyst unfamiliar with "
                       "the surface can investigate effectively.",
    },
    {
        "heading":     "Blind Spots and Assumptions",
        "description": "What this detection will NOT catch; assumptions "
                       "made about the environment / data sources.",
    },
    {
        "heading":     "False Positives",
        "description": "Known benign causes; how to recognise / dismiss them.",
    },
    {
        "heading":     "Validation",
        "description": "How a hunter can prove the detection works (test "
                       "data, atomic-red-team mappings, replay procedures).",
    },
    {
        "heading":     "Priority",
        "description": "Severity tier with the reasoning that justifies it.",
    },
    {
        "heading":     "Response",
        "description": "Concrete next steps when the detection fires.",
    },
]


def ads_section_outline() -> str:
    """Return a Markdown bulleted list of the ADS sections + descriptions,
    suitable for direct injection into an LLM system prompt."""
    parts = [
        "## Alerting & Detection Strategy (ADS) sections — structure the "
        "analyst summary around these, in order:",
        "",
    ]
    for s in ADS_SECTIONS:
        parts.append(f"- **{s['heading']}** — {s['description']}")
    return "\n".join(parts)


def ads_headings() -> List[str]:
    return [s["heading"] for s in ADS_SECTIONS]


def stats() -> Dict:
    return {
        "loaded":   True,
        "sections": len(ADS_SECTIONS),
    }
