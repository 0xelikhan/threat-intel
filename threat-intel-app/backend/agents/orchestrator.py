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


class SOCState(TypedDict):
    raw_input:             str
    input_type:            str
    triage_score:          float
    iocs:                  dict
    should_proceed:        bool
    triage_reasoning:      str
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
    # CVEs are enrichable via NVD / EPSS / CISA KEV. Emails are still
    # extracted but no longer enriched (paid breach sources removed).
    has_enrichable = any((iocs.get(k) or []) for k in
                         ("ips", "domains", "hashes", "urls", "cves"))
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


async def run_pipeline(raw_input: str, input_type: str = "log") -> dict:
    initial: SOCState = {
        "raw_input":             raw_input,
        "input_type":            input_type,
        "triage_score":          0.0,
        "iocs":                  {},
        "should_proceed":        False,
        "triage_reasoning":      "",
        "enrichments":           {},
        "investigation_result":  {},
        "mitre_techniques":      [],
        "threat_level":          "INFORMATIONAL",
        "confidence":            0.0,
        "needs_more_enrichment": False,
        "sigma_rule":            "",
        "kql_query":             "",
        "response_summary":      {},
        "stix_bundle":           {},
        "agent_trace":           [],
        "iteration_count":       0,
        "cross_refs":            {},
        "email_analysis":        {},
    }
    return await graph.ainvoke(initial)