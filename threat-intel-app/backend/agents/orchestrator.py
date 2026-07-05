"""
LangGraph orchestrator — defines the multi-agent pipeline graph.
Triage → Enrichment → Investigation → (loop if low confidence) → Response

Pipeline note: every node here is a thin wrapper around an agent function
(run_triage / run_enrichment / run_investigation / run_response), and
every one of those functions now routes its LLM calls through
`providers.get_provider()` rather than importing the OpenAI SDK directly.
Swapping LLM_PROVIDER swaps the backend for the whole graph at once.

If you need to invoke a single procedure (triage-only, sigma-only, etc.)
without running the full pipeline, use `skills.run_skill(name, inputs)`
— same provider abstraction, granular surface.
"""

from typing import TypedDict, Literal
from langgraph.graph import StateGraph, END

from agents.triage import run_triage
from agents.enrichment import run_enrichment
from agents.investigation import run_investigation
from agents.response import run_response


class SOCState(TypedDict, total=False):
    """LangGraph pipeline state. total=False because the agents lift
    different keys at different stages (triage adds behavioral_indicators,
    investigation adds investigation_result + threat_actor, etc.) and
    the orchestrator builds an initial state that doesn't carry every
    one. Listing the keys here keeps mypy / IDE inspection honest about
    what's available downstream."""
    raw_input:             str
    input_type:            str
    triage_score:          float
    iocs:                  dict
    suppressed_iocs:       dict
    should_proceed:        bool
    triage_reasoning:      str
    behavioral_indicators: dict
    enrichments:           dict
    investigation_result:  dict
    mitre_techniques:      list
    threat_level:          str
    confidence:            float
    needs_more_enrichment: bool
    sigma_rule:            str
    kql_query:             str
    response_summary:      dict
    stix_bundle:           dict
    agent_trace:           list
    iteration_count:       int
    cross_refs:            dict
    email_analysis:        dict
    # Analyst-provided context for the re-analyze flow; the investigation
    # prompt prepends this as authoritative input when set. Was added to
    # the initial state builder but never declared on the type.
    analyst_feedback:      str
    # Fields the agents lift onto state but the type didn't enumerate:
    log_translation:       dict
    defender_parse:        dict
    multi_log:             dict
    log_count:             int
    gti_scores:            dict
    confidence_scores:     dict
    malware_family:        str
    threat_actor:          dict
    campaign:              str
    attack_stage:          str
    geopolitical:          dict
    tool_call_log:         list
    log_correlation:       dict
    analyst_answers:       dict
    clarifying_questions:  list
    context_impact:        str


def _route_triage(state: SOCState) -> Literal["enrichment", "investigation", "dropped"]:
    """Routing:
      - If triage explicitly dropped (very low score AND no signals)         → dropped
      - If we have IPs/domains/hashes/URLs to enrich                         → enrichment
      - Otherwise (process/path/behavior-only logs)                          → investigation
    The pipeline now ALWAYS produces an AI analysis unless triage scored ~0.
    """
    if not state.get("should_proceed") and state.get("triage_score", 0) <= 0.10:
        return "dropped"
    iocs = state.get("iocs", {}) or {}
    # CVEs — NVD / EPSS / CISA KEV. Emails — OFAC SDN + HIBP breach-by-
    # domain. Crypto — Ransomwhe.re + OFAC SDN.
    has_enrichable = any((iocs.get(k) or []) for k in
                         ("ips", "domains", "hashes", "urls", "cves",
                          "emails", "crypto"))
    return "enrichment" if has_enrichable else "investigation"


def _route_investigation(state: SOCState) -> Literal["response", "enrichment"]:
    if (state.get("confidence", 1.0) < 0.55
            and state.get("needs_more_enrichment", False)
            and state.get("iteration_count", 0) < 2):
        return "enrichment"
    return "response"


async def _dropped(state: SOCState) -> SOCState:
    from datetime import datetime, timezone
    trace = state.get("agent_trace", [])
    trace.append({
        "agent": "triage",
        "status": "dropped",
        "summary": f"Alert scored {state.get('triage_score', 0):.2f} — below threshold. Likely noise.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return {**state, "agent_trace": trace}


def _build():
    g = StateGraph(SOCState)
    g.add_node("triage",        run_triage)
    g.add_node("enrichment",    run_enrichment)
    g.add_node("investigation", run_investigation)
    g.add_node("response",      run_response)
    g.add_node("dropped",       _dropped)
    g.set_entry_point("triage")
    g.add_conditional_edges("triage", _route_triage, {
        "enrichment":    "enrichment",
        "investigation": "investigation",
        "dropped":       "dropped",
    })
    g.add_edge("enrichment", "investigation")
    g.add_conditional_edges("investigation", _route_investigation, {"response": "response", "enrichment": "enrichment"})
    g.add_edge("response", END)
    g.add_edge("dropped", END)
    return g.compile()


graph = _build()


def make_initial_state(raw_input: str, input_type: str = "log",
                        analyst_feedback: str = "") -> SOCState:
    """Build a fresh SOCState with EVERY key in the type declaration
    populated with a sensible default.

    Single source of truth used by /api/analyze (SSE), /api/analyze/sync,
    /api/analyze/clarify, and the skill registry — previously each call
    site rolled its own dict and they drifted apart. The SSE builder in
    main.py omitted ~18 keys that the type declares, so downstream agents
    relied on `.get(key, default)` instead of indexing. That worked, but
    the TypedDict became a documentation lie.

    Inputs:
      * raw_input        — analyst-pasted log / IOC text
      * input_type       — "log" / "ioc" / "ioc_url" / "file_summary"
      * analyst_feedback — optional analyst verdict / context block; the
                           investigation prompt treats this as authoritative
                           when present.
    """
    return {
        # Inputs
        "raw_input":             raw_input,
        "input_type":            input_type,
        "analyst_feedback":      (analyst_feedback or "").strip(),

        # Triage outputs
        "triage_score":          0.0,
        "iocs":                  {},
        "suppressed_iocs":       {},
        "should_proceed":        False,
        "triage_reasoning":      "",
        "behavioral_indicators": {},
        "cross_refs":            {},
        "email_analysis":        {},
        "log_translation":       None,
        "defender_parse":        None,
        "multi_log":             {},
        "log_count":             1,

        # Enrichment outputs
        "enrichments":           {},
        "confidence_scores":     {},
        "iteration_count":       0,

        # Investigation outputs
        "investigation_result":  {},
        "mitre_techniques":      [],
        "threat_level":          "INFORMATIONAL",
        "confidence":            0.0,
        "needs_more_enrichment": False,
        "malware_family":        "",
        "threat_actor":          {},
        "campaign":              "",
        "attack_stage":          "",
        "geopolitical":          {},
        "tool_call_log":         [],
        "log_correlation":       None,
        "analyst_answers":       {},
        "clarifying_questions":  [],
        "context_impact":        "",

        # Response outputs
        "sigma_rule":            "",
        "kql_query":             "",
        "response_summary":      {},
        "stix_bundle":           {},
        "gti_scores":            {},

        # Cross-stage observability
        "agent_trace":           [],
    }


async def run_pipeline(raw_input: str, input_type: str = "log",
                        analyst_feedback: str = "") -> dict:
    """End-to-end pipeline driver. Used by /api/analyze/sync and the
    skill registry — the streaming /api/analyze path uses make_initial_state
    too but interleaves SSE writes between stages itself.

    analyst_feedback: optional analyst-supplied verdict / context. When
    non-empty the investigation prompt treats it as authoritative,
    overriding AI inference when they conflict.
    """
    return await graph.ainvoke(
        make_initial_state(raw_input, input_type, analyst_feedback)
    )