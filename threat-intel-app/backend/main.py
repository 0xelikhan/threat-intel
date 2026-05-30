"""
Threat Intelligence Platform — FastAPI Backend
Single process: serves React frontend as static files + all API endpoints.
"""

import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel

from config import config, API_KEY_DEFINITIONS, FREE_APIS
from agents.orchestrator import run_pipeline
from intel.taxii_poller import poll_all_feeds, parse_misp_csv, parse_misp_json
from intel.auth import auth_configured, verify_credentials, current_user
from gti_score import compute_gti_scores, get_highest_score

app = FastAPI(title="Threat Intelligence Platform", version="3.0.0",
              docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")

app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# Auth gate — everything under /api/* requires a session EXCEPT:
#   * /api/health        — needed by the Docker HEALTHCHECK and the deploy probe
#   * /api/auth/*        — login / logout / me; you can't log in if login is gated
#   * /api/docs, /api/openapi.json — FastAPI's own doc routes
# Static frontend assets (everything not under /api) are served unauthenticated
# so the LoginPage can render. The LoginPage POSTs to /api/auth/login and the
# rest of the app waits behind that wall.
#
# Implementation note: this MUST be a class-based middleware added *before*
# SessionMiddleware so it ends up INNER to it in the dispatch chain. ASGI
# middleware order is "last added = outermost = runs first," so adding the
# gate first means SessionMiddleware wraps around it and populates
# request.session before the gate inspects it. The earlier @app.middleware
# decorator put the gate outermost, and request.session blew up with an
# AssertionError because Session hadn't run yet.
_PUBLIC_PREFIXES = ("/api/auth/", "/api/health", "/api/docs", "/api/openapi.json")


class AuthGateMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if not path.startswith("/api/") or path.startswith(_PUBLIC_PREFIXES):
            return await call_next(request)
        if current_user(request.session):
            return await call_next(request)
        return JSONResponse({"detail": "auth required"}, status_code=401)


# Order matters — last add_middleware is OUTERMOST (runs first per request).
# Goal: SessionMiddleware sits OUTSIDE AuthGate so session is populated by
# the time the gate inspects it.
app.add_middleware(AuthGateMiddleware)

# Spec §9 platform hardening — security headers + body size cap + audit log
from intel.security import SecurityHeadersMiddleware, AuditMiddleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(AuditMiddleware)

# Signed HTTP-only session cookie. Secret comes from AUTH_SESSION_SECRET, which
# is a Container App secret bound to env at startup. A development fallback
# lets the app boot locally without the secret, but every login attempt will
# fail closed because auth_configured() also checks for username + hash.
_SESSION_SECRET = os.environ.get("AUTH_SESSION_SECRET") or "dev-only-not-for-production"
app.add_middleware(
    SessionMiddleware,
    secret_key=_SESSION_SECRET,
    session_cookie="recon_session",
    same_site="strict",
    https_only=True,
    max_age=60 * 60 * 12,  # 12 h
)


@app.on_event("startup")
async def _kick_prewarm():
    """Schedule pre-warm to run in the background so the server starts immediately.
    Each module is loaded in its own thread so a slow one (YARA, warning lists)
    doesn't block the others. First analysis still benefits from whatever's
    finished warming by then."""
    import asyncio

    async def _warm_one(name: str, mod_path: str, attr: str, arg=None):
        import importlib, time
        t0 = time.perf_counter()
        try:
            def _run():
                m = importlib.import_module(mod_path)
                fn = getattr(m, attr, None)
                if not fn:
                    return False
                fn(arg) if arg is not None else fn()
                return True
            ok = await asyncio.to_thread(_run)
            dt = time.perf_counter() - t0
            print(f"[recon] pre-warm {name}: {'OK' if ok else 'skip'} ({dt:.1f}s)")
        except Exception as e:
            print(f"[recon] pre-warm {name}: skip ({e})")

    async def _warm_all():
        # Light modules first so they're ready almost immediately,
        # heavy ones (YARA, warning lists) finish in the background.
        light = [
            ("KEV",            "intel.kev",                 "_index",          None),
            ("EPSS",           "intel.epss",                "_index",          None),
            ("LOLBAS",         "intel.lolbas",              "_catalog",        None),
            ("MISP galaxy",    "intel.actor_data",          "_misp_lookup",    None),
            ("MITRE",          "intel.mitre_data",          "_mitre",          None),
            ("Atomic Red Team","intel.atomic_red_team",     "get_tests",       "T1059.001"),
        ]
        heavy = [
            ("LOLDrivers",     "intel.loldrivers",          "_catalog",        None),
            ("IP blocklists",  "intel.feeds_loader",        "malicious_ips",   None),
            ("Phishing domains","intel.feeds_loader",       "phishing_domains",None),
            ("Warning lists",  "intel.warninglist_filter",  "load_warninglists", None),
            ("YARA rules",     "intel.yara_scanner",        "_ruleset",        None),
        ]
        # Fan out — all warm in parallel; startup completes immediately
        await asyncio.gather(*[_warm_one(*m) for m in light + heavy])
        print("[recon] all intel pre-warm tasks complete")

    asyncio.create_task(_warm_all())

    # Spec §8: kick off the unified TAXII + FreshRSS polling loop in the background
    try:
        from intel.feed_aggregator import run_polling_loop
        asyncio.create_task(run_polling_loop(lambda: config.get_all() if hasattr(config, "get_all") else {
            "FRESHRSS_URL":     config.get("FRESHRSS_URL", ""),
            "FRESHRSS_API_KEY": config.get("FRESHRSS_API_KEY", ""),
        }))
        print("[recon] feed aggregator polling loop scheduled")
    except Exception as e:
        print(f"[recon] feed aggregator NOT started: {e}")

    print("[recon] startup: pre-warm scheduled in background, accepting requests now")


@app.on_event("shutdown")
async def _close_http_pool():
    """Close the shared TCP connector used by the enrichment fan-out so
    we don't leak sockets on graceful shutdown (Ctrl-C, container stop)."""
    try:
        from agents.enrichment import close_connector
        await close_connector()
    except Exception:
        pass


_results: dict = {}
# IOC pivot index: { ioc_value: [(run_id, timestamp_iso, threat_level), ...] }
_ioc_index: dict[str, list[tuple]] = {}
# Sandbox job tracker: { job_id: { state, submitted_at, sha256, ... } }
_sandbox_jobs: dict[str, dict] = {}
# Chat conversations per run: { run_id: [{role, content, timestamp}, ...] }
_chats: dict[str, list] = {}
_taxii_cache: dict = {}
_history: list = []

FRONTEND_BUILD = Path(__file__).parent.parent / "frontend" / "build"


# ─── SCHEMAS ──────────────────────────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    logText: str
    inputType: str = "log"
    label: Optional[str] = None

class TaxiiPollRequest(BaseModel):
    sinceHours: int = 24

class SettingsRequest(BaseModel):
    keys: dict

class DetectionRequest(BaseModel):
    action: str
    iocs: Optional[dict] = None
    analysis: Optional[dict] = None
    query: Optional[str] = None
    mitreTechniques: Optional[list] = None

class GTIScoreRequest(BaseModel):
    enrichments: dict


# ─── SETTINGS ─────────────────────────────────────────────────────────────────────
@app.get("/api/settings")
async def get_settings():
    return {"configured": config.is_configured(),
            "keys": config.get_settings_response(),
            "freeApis": FREE_APIS,
            "keyDefinitions": API_KEY_DEFINITIONS}

@app.post("/api/settings")
async def update_settings(req: SettingsRequest):
    config.set_many(req.keys)
    return {"saved": True, "configured": config.is_configured()}

@app.post("/api/settings/test")
async def test_key():
    if not config.get("OPENAI_API_KEY") and not os.environ.get("ANTHROPIC_API_KEY"):
        return {"ok": False, "error": "No LLM API key configured"}
    from providers import get_provider
    provider = get_provider()
    resp = await provider.complete(
        messages=[{"role": "user", "content": "hi"}],
        max_tokens=5,
    )
    if resp.error:
        return {"ok": False, "error": resp.error}
    return {"ok": True, "message": f"Valid · provider {resp.provider} · model {resp.model}"}


# ─── HEALTH ───────────────────────────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    status = config.get_status()
    missing = [k for k, v in status.items() if v["required"] and not v["configured"]]
    return {
        "status":          "ready" if config.is_configured() else "setup_required",
        "version":         "3.0.0",
        "timestamp":       _ts(),
        "configured":      config.is_configured(),
        "ai_provider":     config.get_ai_provider(),
        "azure_openai":    config.is_azure_openai(),
        "apiKeys":         {k: v["configured"] for k, v in status.items()},
        "requiredMissing": missing,
        "cachedRuns":      len(_results),
        "historyCount":    len(_history),
        "webhooks":        _webhooks_available(),
        "intel_layer":     _intel_status(),
    }


# ─── Auth ────────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
async def auth_login(req: LoginRequest, request: Request):
    """Validate credentials and start a signed-cookie session. 503 when the
    operator hasn't wired up AUTH_USERNAME / AUTH_PASSWORD_HASH yet (so an
    empty deployment doesn't silently 401 forever)."""
    if not auth_configured():
        raise HTTPException(503, "authentication is not configured on this deployment")
    if not verify_credentials(req.username, req.password):
        raise HTTPException(401, "invalid credentials")
    request.session["auth_user"] = req.username.strip()
    return {"ok": True, "user": req.username.strip()}


@app.post("/api/auth/logout")
async def auth_logout(request: Request):
    """Clear the session cookie. Safe to call when not logged in."""
    request.session.clear()
    return {"ok": True}


@app.get("/api/auth/me")
async def auth_me(request: Request):
    """Frontend uses this on app mount to decide whether to render LoginPage
    or the main app. 200 + user when authed, 401 otherwise."""
    user = current_user(request.session)
    if not user:
        raise HTTPException(401, "not authenticated")
    return {"user": user}


def _check_ioc_pivot(iocs: dict, current_run_id: str) -> list[dict]:
    """Disabled for full per-investigation isolation: no cross-investigation IOC
    pivots are surfaced (a new investigation never reads data from prior runs)."""
    return []


def _index_iocs(run_id: str, iocs: dict, response_summary: dict):
    """Disabled for full per-investigation isolation: IOCs from one investigation
    are not indexed for/recalled by later ones."""
    return


def _webhooks_available() -> dict:
    try:
        from intel.webhooks import available
        return available(config)
    except Exception:
        return {}


def _intel_status() -> dict:
    """Snapshot of how much offline intelligence is loaded."""
    out = {}
    try:
        from intel.feeds_loader import stats as f; out.update(f())
    except Exception: pass
    try:
        from intel.actor_data import stats as a; out.update(a())
    except Exception: pass
    try:
        from intel.kev import stats as k; out.update(k())
    except Exception: pass
    try:
        from intel.epss import stats as e; out.update(e())
    except Exception: pass
    try:
        from intel.lolbas import stats as l; out.update(l())
    except Exception: pass
    try:
        from intel.loldrivers import stats as d; out.update(d())
    except Exception: pass
    try:
        from intel.atomic_red_team import stats as t; out.update(t())
    except Exception: pass
    try:
        from intel.yara_scanner import stats as y; out.update(y())
    except Exception: pass
    try:
        from intel.phishing_kit  import stats as pk; out.update(pk())
    except Exception: pass
    try:
        from intel.ja_fingerprints import stats as ja; out.update(ja())
    except Exception: pass
    return out


# ─── ANALYZE (streaming pipeline — pushes partial results between stages) ────────
def _strip(state: dict, run_id: str, label: str = "") -> dict:
    """Build the analyst-facing snapshot from current state — safe to send mid-pipeline."""
    out = {k: v for k, v in state.items() if k != "stix_bundle"}
    out["runId"] = run_id
    if label:
        out["label"] = label
    return out


def _sse_event(kind: str, payload: dict, run_id: str, label: str = "") -> str:
    """Format one streamed agent event as an SSE frame. `kind` is either
    'trace' (→ agent_update, a single pipeline trace entry) or 'partial'
    (→ partial_result, a result fragment the UI merges in)."""
    if kind == "trace":
        return f"data: {json.dumps({'event': 'agent_update', 'runId': run_id, 'trace': payload})}\n\n"
    result = {**payload, "runId": run_id}
    if label:
        result["label"] = label
    return f"data: {json.dumps({'event': 'partial_result', 'runId': run_id, 'result': result})}\n\n"


async def _drain_events(task: "asyncio.Task", q: "asyncio.Queue", run_id: str, label: str = ""):
    """Yield SSE frames for events a running agent `task` pushes onto `q` as
    (kind, payload) tuples, until the task finishes — then flush whatever's left
    queued. The agent runs concurrently with this drain, so its tool calls /
    partial enrichments reach the browser the moment they happen instead of all
    at once when the stage returns. The caller awaits the task afterwards to get
    its return value (and surface any exception it raised)."""
    while True:
        getter = asyncio.ensure_future(q.get())
        done, _pending = await asyncio.wait({getter, task}, return_when=asyncio.FIRST_COMPLETED)
        if getter in done:
            kind, payload = getter.result()
            yield _sse_event(kind, payload, run_id, label)
            continue
        # Agent finished — stop waiting for more events and flush the backlog.
        getter.cancel()
        while not q.empty():
            kind, payload = q.get_nowait()
            yield _sse_event(kind, payload, run_id, label)
        return


async def _stream(raw_input: str, input_type: str, label: str = ""):
    """Walk the pipeline one agent at a time, emitting partial_result events after
    each stage so the UI populates progressively — extracted IOCs land immediately,
    enrichment data lands when ready, AI assessment lands when investigation finishes,
    detection rules land when response finishes."""
    if not config.is_configured():
        yield f"data: {json.dumps({'event': 'error', 'error': 'Add your API keys in Settings first.'})}\n\n"
        yield "data: [DONE]\n\n"
        return

    from agents.triage        import run_triage
    from agents.enrichment    import run_enrichment
    from agents.investigation import run_investigation
    from agents.response      import run_response

    run_id = str(uuid.uuid4())
    yield f"data: {json.dumps({'event': 'start', 'runId': run_id, 'timestamp': _ts()})}\n\n"

    try:
        # Initial state matches SOCState shape
        state = {
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

        # ── Stage 1: TRIAGE ──────────────────────────────────────────────────
        state = await run_triage(state)
        trace = state.get("agent_trace", [])
        if trace:
            yield f"data: {json.dumps({'event': 'agent_update', 'runId': run_id, 'trace': trace[-1]})}\n\n"
        # Push extracted IOCs + cross_refs + email_analysis immediately —
        # the sidebar IOC list and the EmailAnalysis card render instantly.
        yield f"data: {json.dumps({'event': 'partial_result', 'runId': run_id, 'result': _strip(state, run_id, label)})}\n\n"

        # Drop alert if triage refused (very low score AND no signals)
        if not state.get("should_proceed") and state.get("triage_score", 0) <= 0.10:
            yield f"data: {json.dumps({'event': 'complete', 'runId': run_id, 'result': _strip(state, run_id, label), 'timestamp': _ts()})}\n\n"
            yield "data: [DONE]\n\n"
            return

        # ── Stage 2: ENRICHMENT (skip when no enrichable IOCs) ──────────────
        iocs = state.get("iocs", {}) or {}
        has_enrichable = any((iocs.get(k) or []) for k in ("ips", "domains", "hashes", "urls"))
        if has_enrichable:
            # Stream each IOC type's enrichment as it lands so cards fill
            # progressively rather than all at once when the slowest type returns.
            enr_q: asyncio.Queue = asyncio.Queue()
            async def _on_enrich_partial(snap, _q=enr_q):
                await _q.put(("partial", snap))
            enr_task = asyncio.create_task(run_enrichment(state, on_partial=_on_enrich_partial))
            async for frame in _drain_events(enr_task, enr_q, run_id, label):
                yield frame
            state = await enr_task
            # GTI scores depend on enrichment data
            state["gti_scores"] = compute_gti_scores(state.get("enrichments", {}))
            trace = state.get("agent_trace", [])
            if trace:
                yield f"data: {json.dumps({'event': 'agent_update', 'runId': run_id, 'trace': trace[-1]})}\n\n"
            yield f"data: {json.dumps({'event': 'partial_result', 'runId': run_id, 'result': _strip(state, run_id, label)})}\n\n"

            # Provisional verdict (P3): a deterministic, enrichment-based read the
            # analyst sees NOW — ~2 min before the AI investigation finishes. Clearly
            # flagged `provisional` so the UI labels it preliminary; the AI verdict
            # (early_rs below) overwrites it the moment investigation completes.
            _counts = (state.get("enrichment_summary", {}).get("verdict_counts") or {})
            _cscores = state.get("confidence_scores") or {}
            _max_score = max((v.get("score", 0) for v in _cscores.values()
                              if isinstance(v, dict)), default=0)
            if _counts.get("MALICIOUS"):
                _prov_level = "HIGH"
            elif _counts.get("SUSPICIOUS"):
                _prov_level = "MEDIUM"
            elif _max_score >= 25:
                _prov_level = "LOW"
            else:
                _prov_level = "INFORMATIONAL"
            _bits = [f"{_counts[k]} {k.lower()}" for k in ("MALICIOUS", "SUSPICIOUS", "CLEAN")
                     if _counts.get(k)]
            state["response_summary"] = {
                "provisional":      True,
                "threat_level":     _prov_level,
                "confidence":       round(_max_score / 100.0, 2),
                "summary":          ("Preliminary read from automated enrichment: "
                                     + (", ".join(_bits) or "no high-risk indicators")
                                     + " indicator(s). Full AI correlation in progress…"),
                "ioc_assessments":  [],
                "mitre_techniques": [],
                "cross_refs":       state.get("cross_refs", {}),
                "timestamp":        _ts(),
            }
            yield f"data: {json.dumps({'event': 'partial_result', 'runId': run_id, 'result': _strip(state, run_id, label)})}\n\n"

        # ── Stage 3: INVESTIGATION (AI correlation + tool-calling loop) ─────
        # Stream each tool call the AI makes the moment it happens (via on_event)
        # so the analyst watches the investigation reason live, instead of seeing
        # the whole multi-roundtrip stage land at once when it finally returns.
        inv_q: asyncio.Queue = asyncio.Queue()
        async def _on_inv_event(entry, _q=inv_q):
            await _q.put(("trace", entry))
        inv_task = asyncio.create_task(run_investigation(state, on_event=_on_inv_event))
        async for frame in _drain_events(inv_task, inv_q, run_id, label):
            yield frame
        state = await inv_task
        trace = state.get("agent_trace", [])
        # The live stream above already sent the intermediate tool-call entries;
        # emit just the final 'complete' investigation summary entry now.
        if trace:
            yield f"data: {json.dumps({'event': 'agent_update', 'runId': run_id, 'trace': trace[-1]})}\n\n"
        # Surface an in-flight response_summary now so the AI Assessment card lands
        # before the response stage runs — give the analyst the verdict ASAP.
        inv = state.get("investigation_result") or {}
        early_rs = {
            "threat_level":         inv.get("threat_level"),
            "confidence":           inv.get("confidence"),
            "summary":              inv.get("summary"),
            "key_findings":         inv.get("key_findings", []),
            "ioc_assessments":      inv.get("ioc_assessments", []),
            "mitre_techniques":     inv.get("mitre_techniques", []),
            "attack_patterns":      inv.get("attack_patterns", []),
            "chain_of_thought":     inv.get("chain_of_thought", []),
            "recommended_actions":  inv.get("recommended_actions", []),
            "cross_refs":           state.get("cross_refs", {}),
            "timestamp":            _ts(),
        }
        state["response_summary"] = early_rs
        yield f"data: {json.dumps({'event': 'partial_result', 'runId': run_id, 'result': _strip(state, run_id, label)})}\n\n"

        # ── Stage 4: RESPONSE (Sigma/KQL/multi-SIEM/analyst hand-off) ───────
        state = await run_response(state)
        trace = state.get("agent_trace", [])
        if trace:
            yield f"data: {json.dumps({'event': 'agent_update', 'runId': run_id, 'trace': trace[-1]})}\n\n"

        # Final post-processing: IOC pivot + persist + index
        final = _strip(state, run_id, label)
        final["ioc_pivot"] = _check_ioc_pivot(state.get("iocs", {}), run_id)
        _index_iocs(run_id, state.get("iocs", {}), final.get("response_summary", {}))
        _results[run_id] = state
        _add_history(run_id, final, label)

        yield f"data: {json.dumps({'event': 'complete', 'runId': run_id, 'result': final, 'timestamp': _ts()})}\n\n"

    except Exception as e:
        import traceback
        traceback.print_exc()
        yield f"data: {json.dumps({'event': 'error', 'runId': run_id, 'error': str(e)})}\n\n"
    yield "data: [DONE]\n\n"

@app.post("/api/analyze")
async def analyze_stream(req: AnalyzeRequest):
    if not req.logText.strip():
        raise HTTPException(400, "logText required")
    return StreamingResponse(_stream(req.logText, req.inputType, req.label or ""),
                             media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.post("/api/analyze/sync")
async def analyze_sync(req: AnalyzeRequest):
    if not req.logText.strip():
        raise HTTPException(400, "logText required")
    if not config.is_configured():
        raise HTTPException(503, "Add API keys in Settings first.")
    run_id = str(uuid.uuid4())
    state = await run_pipeline(req.logText, req.inputType)
    gti_scores = compute_gti_scores(state.get("enrichments", {}))
    state["gti_scores"] = gti_scores
    _results[run_id] = state
    result = {k: v for k, v in state.items() if k != "stix_bundle"}
    result.update({"runId": run_id})
    _add_history(run_id, result, req.label or "")
    return result


class ClarifyRequest(BaseModel):
    answers: dict   # {question_text: answer_text}


@app.post("/api/analyze/clarify/{run_id}")
async def analyze_clarify(run_id: str, req: ClarifyRequest):
    """Spec §5 Phase 2: re-run investigation with analyst answers to clarifying
    questions. Re-uses the original triage/enrichment state — only the AI
    investigation step runs again, with analyst_answers appended to the prompt."""
    if run_id not in _results:
        raise HTTPException(404, f"unknown run_id {run_id}")
    if not req.answers:
        raise HTTPException(400, "answers required")

    state = dict(_results[run_id])
    state["analyst_answers"] = req.answers

    from agents.investigation import run_investigation
    state = await run_investigation(state)

    # Refresh GTI scores and persist updated state
    state["gti_scores"] = compute_gti_scores(state.get("enrichments", {}))
    _results[run_id] = state
    result = {k: v for k, v in state.items() if k != "stix_bundle"}
    result.update({"runId": run_id, "rephased": True})
    return result


# ─── GTI SCORE ───────────────────────────────────────────────────────────────────
@app.post("/api/gti-score")
async def gti_score_standalone(req: GTIScoreRequest):
    """Compute GTI-style threat scores from enrichment data without running the full pipeline."""
    scores = compute_gti_scores(req.enrichments)
    highest = get_highest_score(scores)
    return {
        "gti_scores":    scores,
        "highest":       highest,
        "total":         len(scores),
        "critical_count": sum(1 for s in scores.values() if s.get("score", 0) >= 85),
        "high_count":     sum(1 for s in scores.values() if 65 <= s.get("score", 0) < 85),
        "elevated_count": sum(1 for s in scores.values() if 45 <= s.get("score", 0) < 65),
    }


# ─── DETECTION ────────────────────────────────────────────────────────────────────
MITRE = [
    {"id": "T1566",     "name": "Phishing",                       "tactic": "Initial Access",      "description": "Adversaries send malicious emails to gain initial access.",               "detection": "Monitor email logs for suspicious senders and attachments. Alert on Office spawning child processes."},
    {"id": "T1566.001", "name": "Spearphishing Attachment",       "tactic": "Initial Access",      "description": "Targeted phishing with malicious attachments.",                           "detection": "Alert on macro-enabled docs from external senders. Monitor unusual parent-child process chains."},
    {"id": "T1566.002", "name": "Spearphishing Link",             "tactic": "Initial Access",      "description": "Targeted phishing with malicious links.",                                 "detection": "Monitor proxy logs for clicks on newly registered domains after email delivery."},
    {"id": "T1190",     "name": "Exploit Public-Facing App",      "tactic": "Initial Access",      "description": "Exploitation of internet-facing application vulnerabilities.",             "detection": "Monitor web app logs for exploitation patterns and unusual error codes."},
    {"id": "T1133",     "name": "External Remote Services",       "tactic": "Initial Access",      "description": "Abuse of VPN, RDP, or Citrix for initial access.",                        "detection": "Monitor auth to external remote services. Alert on logins from new geolocations."},
    {"id": "T1078",     "name": "Valid Accounts",                 "tactic": "Initial Access",      "description": "Use of legitimate credentials for unauthorized access.",                   "detection": "Monitor for impossible travel, unusual login times, authentication from new devices."},
    {"id": "T1059",     "name": "Command and Scripting Interpreter","tactic": "Execution",         "description": "Abuse of command-line interfaces and scripting engines.",                  "detection": "Monitor process creation for cmd.exe, powershell.exe, wscript.exe with suspicious args."},
    {"id": "T1059.001", "name": "PowerShell",                     "tactic": "Execution",           "description": "Use of PowerShell, often with encoded commands.",                          "detection": "Enable ScriptBlock logging. Alert on -EncodedCommand, -NonInteractive, bypass flags."},
    {"id": "T1059.003", "name": "Windows Command Shell",          "tactic": "Execution",           "description": "Use of cmd.exe for command execution.",                                   "detection": "Monitor cmd.exe spawned by unusual parents. Alert on cmd /c executing scripts."},
    {"id": "T1047",     "name": "Windows Management Instrumentation","tactic": "Execution",        "description": "WMI used for local or remote execution.",                                  "detection": "Monitor WMI activity. Alert on WMI subscriptions or remote WMI calls to workstations."},
    {"id": "T1053",     "name": "Scheduled Task/Job",             "tactic": "Persistence",         "description": "Tasks or jobs scheduled for persistent execution.",                        "detection": "Monitor schtasks.exe and Task Scheduler logs. Alert on tasks with encoded actions."},
    {"id": "T1547",     "name": "Boot or Logon Autostart",        "tactic": "Persistence",         "description": "Programs configured to execute automatically at startup.",                 "detection": "Monitor registry run keys and startup folders for new or modified entries."},
    {"id": "T1136",     "name": "Create Account",                 "tactic": "Persistence",         "description": "Creating accounts for persistent access.",                                 "detection": "Alert on new account creation, especially outside change management windows."},
    {"id": "T1055",     "name": "Process Injection",              "tactic": "Defense Evasion",     "description": "Injecting code into another process to evade detection.",                  "detection": "Monitor VirtualAllocEx, WriteProcessMemory, CreateRemoteThread across process boundaries."},
    {"id": "T1027",     "name": "Obfuscated Files or Information","tactic": "Defense Evasion",     "description": "Encoding or packing malicious files to evade detection.",                  "detection": "Monitor for high-entropy files and scripts with Base64 encoded strings."},
    {"id": "T1562",     "name": "Impair Defenses",                "tactic": "Defense Evasion",     "description": "Disabling or modifying security tools and logging.",                       "detection": "Monitor AV/EDR process termination. Alert on Defender service being stopped."},
    {"id": "T1218",     "name": "System Binary Proxy Execution",  "tactic": "Defense Evasion",     "description": "Using trusted LOLBins to execute malicious code.",                        "detection": "Monitor mshta, regsvr32, rundll32, certutil, bitsadmin for unusual usage."},
    {"id": "T1036",     "name": "Masquerading",                   "tactic": "Defense Evasion",     "description": "Disguising malicious files or processes as legitimate ones.",               "detection": "Monitor for processes with system-like names running from unusual directories."},
    {"id": "T1003",     "name": "OS Credential Dumping",          "tactic": "Credential Access",   "description": "Extracting credentials from the OS, such as LSASS memory.",               "detection": "Monitor LSASS access (Event 4663). Alert on Mimikatz signatures or sekurlsa commands."},
    {"id": "T1003.001", "name": "LSASS Memory",                   "tactic": "Credential Access",   "description": "Dumping credentials from LSASS process memory.",                          "detection": "Alert on unusual processes accessing LSASS. Monitor for procdump or comsvcs.dll MiniDump."},
    {"id": "T1110",     "name": "Brute Force",                    "tactic": "Credential Access",   "description": "Attempting many passwords to guess credentials.",                          "detection": "Monitor multiple failed auth attempts from a single source. Alert on password spray patterns."},
    {"id": "T1552",     "name": "Unsecured Credentials",          "tactic": "Credential Access",   "description": "Finding credentials stored insecurely in files or the registry.",         "detection": "Monitor access to files with passwords in names. Alert on searching for credentials in scripts."},
    {"id": "T1082",     "name": "System Information Discovery",   "tactic": "Discovery",           "description": "Gathering information about the compromised system.",                      "detection": "Monitor for systeminfo, hostname, and env commands executed in rapid succession."},
    {"id": "T1046",     "name": "Network Service Discovery",      "tactic": "Discovery",           "description": "Scanning for open network services and ports.",                            "detection": "Alert on port scanning from internal hosts. Monitor for nmap signatures."},
    {"id": "T1018",     "name": "Remote System Discovery",        "tactic": "Discovery",           "description": "Enumerating other systems on the network.",                               "detection": "Monitor for ping sweeps, arp -a, netscan from workstations."},
    {"id": "T1021",     "name": "Remote Services",                "tactic": "Lateral Movement",    "description": "Using RDP, SSH, or WinRM for lateral movement.",                          "detection": "Monitor RDP and SMB auth events. Alert on lateral movement patterns."},
    {"id": "T1021.001", "name": "Remote Desktop Protocol",        "tactic": "Lateral Movement",    "description": "Using RDP to move laterally between systems.",                            "detection": "Monitor Event ID 4624 LogonType 10. Alert on RDP between workstations."},
    {"id": "T1021.002", "name": "SMB/Windows Admin Shares",       "tactic": "Lateral Movement",    "description": "Using SMB admin shares for lateral movement.",                            "detection": "Monitor access to ADMIN$, C$, IPC$ from non-server systems. Alert on pass-the-hash patterns."},
    {"id": "T1071",     "name": "Application Layer Protocol",     "tactic": "Command and Control", "description": "Using HTTP, DNS, or SMTP for C2 communications.",                         "detection": "Monitor for beaconing patterns. Alert on connections to newly registered domains."},
    {"id": "T1071.001", "name": "Web Protocols",                  "tactic": "Command and Control", "description": "Using HTTP/HTTPS for C2.",                                               "detection": "Monitor for HTTP beaconing. Alert on regular interval connections with consistent byte sizes."},
    {"id": "T1071.004", "name": "DNS",                            "tactic": "Command and Control", "description": "Using DNS for C2 communications (DNS tunneling).",                        "detection": "Monitor high-frequency DNS queries and queries with unusually long subdomains."},
    {"id": "T1105",     "name": "Ingress Tool Transfer",          "tactic": "Command and Control", "description": "Downloading additional tools onto compromised systems.",                   "detection": "Monitor certutil, bitsadmin, PowerShell DownloadFile for unusual usage."},
    {"id": "T1041",     "name": "Exfiltration Over C2 Channel",   "tactic": "Exfiltration",        "description": "Exfiltrating data through the existing C2 channel.",                     "detection": "Monitor for unusually large outbound POST requests over C2 connections."},
    {"id": "T1567",     "name": "Exfiltration Over Web Service",  "tactic": "Exfiltration",        "description": "Using cloud services for data exfiltration.",                             "detection": "Monitor unusual uploads to cloud storage. Alert on large transfers to personal accounts."},
    {"id": "T1486",     "name": "Data Encrypted for Impact",      "tactic": "Impact",              "description": "Ransomware encrypting data to extort victims.",                           "detection": "Monitor rapid file modification with extension changes. Alert on shadow copy deletion."},
    {"id": "T1490",     "name": "Inhibit System Recovery",        "tactic": "Impact",              "description": "Deleting shadow copies and backups to prevent recovery.",                  "detection": "Alert on vssadmin delete shadows, wbadmin delete, or bcdedit /set commands."},
    {"id": "T1489",     "name": "Service Stop",                   "tactic": "Impact",              "description": "Stopping security or critical business services.",                        "detection": "Monitor net stop or Stop-Service targeting AV, backup, or database services."},
]

from agents.response import _match_actors as _match_threat_actors_fn


async def _ai_gen(prompt: str) -> str:
    if not config.get("OPENAI_API_KEY"):
        return "# OpenAI API key not configured. Add it in Settings."
    # Detection-content generation (Sigma/KQL/YARA) is a light, latency-sensitive
    # task → use the fast model tier.
    from providers import get_provider
    provider = get_provider()
    resp = await provider.complete(
        model=config.get_model(fast=True),
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1500,
        temperature=0.1,
    )
    if resp.error:
        return f"# Generation failed: {resp.error}"
    return (resp.message or "").strip()


@app.post("/api/detection")
async def detection(req: DetectionRequest):
    if req.action == "mitre":
        try:
            from intel.mitre_data import search_techniques, get_all_techniques
            q = (req.query or "").strip()
            techniques = search_techniques(q) if len(q) >= 2 else get_all_techniques()[:20]
            if techniques:
                return {"result": techniques, "source": "enterprise-attack"}
        except Exception:
            pass
        q = (req.query or "").lower()
        if len(q) < 2:
            return {"result": MITRE[:20], "source": "builtin"}
        matches = [t for t in MITRE if q in t["id"].lower() or q in t["name"].lower()
                   or q in t["tactic"].lower() or q in t["description"].lower()]
        return {"result": matches[:30], "source": "builtin"}

    if req.action == "actors":
        try:
            from intel.mitre_data import get_groups_by_techniques
            tech_ids = [t.split(" ")[0] for t in (req.mitreTechniques or [])]
            groups = get_groups_by_techniques(tech_ids)
            if groups:
                return {"result": groups, "source": "enterprise-attack"}
        except Exception:
            pass
        return {"result": _match_threat_actors_fn(req.mitreTechniques or []), "source": "builtin"}

    if req.action == "sigma":
        # Spec §6: AI generates → sigma-cli validates → retry up to 3× on failure,
        # then auto-convert to SPL and KQL via pySigma backends.
        import uuid as _u
        a = req.analysis or {}
        ioc_json = json.dumps({k: v[:3] for k, v in (req.iocs or {}).items() if v})
        techniques = a.get("mitreTechniques", [])
        attack_tags = " ".join(f"attack.{t.split(' ')[0].lower()}" for t in techniques if t.startswith("T"))
        prompt = (
            f"Generate a complete, valid Sigma detection rule. Output ONLY the YAML "
            f"document — no markdown fences, no commentary.\n\n"
            f"Required fields and their values:\n"
            f"  title: a descriptive 4-8 word name\n"
            f"  id: {str(_u.uuid4())}\n"
            f"  status: experimental\n"
            f"  description: 2-3 sentences explaining what is detected and why it matters\n"
            f"  references: array of MITRE ATT&CK technique URLs like "
            f"    https://attack.mitre.org/techniques/Txxxx/\n"
            f"  author: RECON Platform\n"
            f"  date: {datetime.now().strftime('%Y/%m/%d')}\n"
            f"  tags: {attack_tags}\n"
            f"  logsource: appropriate category/product (e.g. category: process_creation, product: windows)\n"
            f"  detection: selection block with actual IOC values and process / command-line patterns\n"
            f"    condition: selection\n"
            f"  falsepositives: realistic list (legitimate admin tooling, scanners, etc.)\n"
            f"  level: matching severity ({(a.get('threatLevel') or 'medium').lower()})\n\n"
            f"Context for the rule:\n"
            f"  Threat Level: {a.get('threatLevel','MEDIUM')}\n"
            f"  Summary: {a.get('summary','')}\n"
            f"  MITRE: {', '.join(techniques)}\n"
            f"  IOCs: {ioc_json}\n"
        )
        from intel.detection_engineering import (
            generate_validated_sigma, convert_sigma_to_spl, convert_sigma_to_kql,
            search_existing_sigma, search_existing_elastic,
        )
        sigma = await generate_validated_sigma(_ai_gen, prompt)
        spl, spl_err = convert_sigma_to_spl(sigma["rule"]) if sigma["valid"] else (None, "skipped: rule invalid")
        kql, kql_err = convert_sigma_to_kql(sigma["rule"]) if sigma["valid"] else (None, "skipped: rule invalid")
        return {
            "result":         sigma["rule"],
            "valid":          sigma["valid"],
            "errors":         sigma["errors"],
            "attempts":       sigma["attempts"],
            "splunk_spl":     spl,
            "splunk_error":   spl_err,
            "kql":            kql,
            "kql_error":      kql_err,
            "existing_sigma":   search_existing_sigma(techniques)[:8],
            "existing_elastic": search_existing_elastic(techniques)[:8],
        }

    if req.action == "kql":
        a = req.analysis or {}
        ioc_json = json.dumps({k: v[:3] for k, v in (req.iocs or {}).items() if v})
        prompt = (f"Generate a complete Microsoft Sentinel KQL analytics rule.\n"
                  f"CHARACTER: Senior Detection Engineer specializing in Microsoft Sentinel.\n"
                  f"CONSTRAINTS: Output ONLY valid KQL with inline comments.\n"
                  f"Threat Level: {a.get('threatLevel','MEDIUM')}\n"
                  f"Summary: {a.get('summary','')}\n"
                  f"MITRE: {', '.join(a.get('mitreTechniques',[]))}\n"
                  f"IOCs: {ioc_json}\n"
                  f"Requirements: let statements, relevant Sentinel tables, entity mapping fields, "
                  f"// comments explaining each section, rule metadata as // comments at top.")
        return {"result": await _ai_gen(prompt)}

    if req.action == "yara":
        # Spec §6: AI generates → yara-python compiles → retry up to 3× on syntax error.
        a = req.analysis or {}
        family = a.get("malwareFamily") or a.get("malware_family") or "unknown"
        hashes = (req.iocs or {}).get("hashes", [])[:3]
        prompt = (
            f"Generate a YARA rule for detecting samples of the malware family '{family}'. "
            f"Output ONLY the YARA rule — no markdown fences, no commentary.\n\n"
            f"Requirements:\n"
            f"  rule meta: description, author = 'RECON Platform', date = '{datetime.now().strftime('%Y-%m-%d')}', "
            f"    hash = first hash from the IOC list ({hashes[0] if hashes else 'unknown'}), "
            f"    mitre = first technique ID\n"
            f"  strings: pattern strings drawn from behavioral indicators — mutex names, registry keys, "
            f"    file paths, network strings, encoded command patterns from any sandbox report context. "
            f"    Mix ASCII and wide. Use $s1, $s2, $s3, … naming.\n"
            f"  condition: filesize appropriate to the malware type (typically < 5MB) AND at least 2 of the strings.\n\n"
            f"Context:\n"
            f"  Malware family: {family}\n"
            f"  Hashes: {hashes}\n"
            f"  Summary: {a.get('summary','')}\n"
            f"  MITRE: {', '.join(a.get('mitreTechniques',[]))}\n"
        )
        from intel.detection_engineering import generate_validated_yara, search_existing_yara
        yara_out = await generate_validated_yara(_ai_gen, prompt)
        return {
            "result":          yara_out["rule"],
            "valid":           yara_out["valid"],
            "errors":          yara_out["errors"],
            "attempts":        yara_out["attempts"],
            "existing_yara":   search_existing_yara(family, hashes[0] if hashes else None)[:8],
        }

    if req.action == "existing":
        # Spec §6: GET /api/detection/existing
        from intel.detection_engineering import search_existing_sigma, search_existing_elastic
        techniques = req.mitreTechniques or []
        return {
            "sigma":   search_existing_sigma(techniques),
            "elastic": search_existing_elastic(techniques),
        }

    raise HTTPException(400, f"Unknown action: {req.action}")


# Convenience GET endpoint per spec §6: /api/detection/existing?techniques=T1059.001,T1566
@app.get("/api/detection/existing")
async def detection_existing(techniques: str = ""):
    """Find existing detection content in the cloned vendor rule libraries that
    matches any of the supplied MITRE technique IDs (comma-separated)."""
    from intel.detection_engineering import search_existing_sigma, search_existing_elastic
    tids = [t.strip() for t in techniques.split(",") if t.strip()]
    return {
        "sigma":   search_existing_sigma(tids),
        "elastic": search_existing_elastic(tids),
        "queried": tids,
    }


# ─── UNIFIED FEED INTEL (spec §8 — TAXII + FreshRSS) ────────────────────────────
@app.get("/api/feeds")
async def feeds_list(source: Optional[str] = None, type: Optional[str] = None,
                     since_hours: Optional[int] = None, limit: int = 500):
    """Unified IOC cache populated by TAXII + FreshRSS. Filterable by source/type/age."""
    from intel.feed_aggregator import list_iocs, list_articles
    return {
        "iocs":     list_iocs(source=source, type_=type, since_hours=since_hours, limit=limit),
        "articles": list_articles(limit=20),
    }


@app.get("/api/feeds/stats")
async def feeds_stats():
    """Cache stats — IOC counts per feed + last poll times."""
    from intel.feed_aggregator import stats
    return stats()


@app.post("/api/feeds/refresh")
async def feeds_refresh(source: str = "all"):
    """Manual refresh — useful for the frontend 'Refresh' button."""
    from intel.feed_aggregator import poll_taxii, poll_freshrss
    out = {}
    if source in ("all", "taxii"):
        out["taxii"] = await poll_taxii()
    if source in ("all", "freshrss"):
        url = config.get("FRESHRSS_URL", "")
        key = config.get("FRESHRSS_API_KEY", "")
        out["freshrss"] = await poll_freshrss(url, key)
    return out


# ─── THREAT ACTOR INTELLIGENCE (spec §7) ─────────────────────────────────────────
@app.get("/api/actors")
async def actors_all():
    """All MITRE-documented threat actor groups (130+)."""
    from intel.threat_actors import get_all_groups
    return {"groups": get_all_groups()}


@app.get("/api/actors/match")
async def actors_match(techniques: str = ""):
    """Score every group by overlap with the supplied technique IDs."""
    from intel.threat_actors import match_groups_by_techniques
    tids = [t.strip() for t in techniques.split(",") if t.strip()]
    return {"matches": match_groups_by_techniques(tids), "queried": tids}


@app.get("/api/actors/{group_id}")
async def actors_detail(group_id: str):
    """Full profile: techniques + software + campaigns + APTnotes references."""
    from intel.threat_actors import (
        get_all_groups, get_group_techniques, get_group_software, get_group_campaigns,
    )
    # Look up base profile from the cached list
    base = next((g for g in get_all_groups() if g["id"].lower() == group_id.lower()
                 or g["name"].lower() == group_id.lower()), None)
    if not base:
        raise HTTPException(404, f"unknown group {group_id}")
    return {
        **base,
        "techniques": get_group_techniques(group_id),
        "software":   get_group_software(group_id),
        "campaigns":  get_group_campaigns(group_id),
    }


# ─── STIX EXPORT ──────────────────────────────────────────────────────────────────
@app.get("/api/export/stix/{run_id}")
async def export_stix(run_id: str):
    if run_id not in _results:
        raise HTTPException(404, "Run not found")
    bundle = _results[run_id].get("stix_bundle")
    if not bundle:
        raise HTTPException(404, "No STIX bundle for this run")
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return JSONResponse(content=bundle,
                        headers={"Content-Disposition": f'attachment; filename="threat-intel-{ts}.stix.json"'})


# ─── CHAT (conversational follow-up on an investigation) ─────────────────────────
@app.get("/api/chat/{run_id}")
async def chat_history(run_id: str):
    """Return the conversation history for a run."""
    if run_id not in _results:
        raise HTTPException(404, "Run not found")
    return {"runId": run_id, "messages": _chats.get(run_id, [])}


def _build_chat_system_msg(state: dict) -> str:
    rs = state.get("response_summary") or {}
    raw = (state.get("raw_input") or "")[:1800]
    return f"""You are RECON, an MDR analyst's assistant currently helping with a SPECIFIC
investigation. You already produced an initial analysis below; the analyst is now
asking follow-up questions or giving you context you didn't have.

Your job:
  • Answer concisely and conversationally (short paragraphs, not walls of JSON)
  • If the analyst gives you new context that resolves an ambiguity, update your
    verdict explicitly: "Based on what you told me, this is most likely a false
    positive because…" or "That changes my read — this is malicious because…"
  • If you need more info to give a confident answer, ASK A SPECIFIC FOLLOW-UP
    QUESTION rather than guess
  • You have tools available (lookup_ip, lookup_domain, check_cve, etc.) — use them
    when the analyst asks about something you don't already know
  • Bias toward the false-positive interpretation when it's plausible — most alerts
    in MDR work are FPs (vulnerability scanners, approved RMM, patching tools,
    auto-updates, scheduled maintenance, etc.)

═══════════════════════════════════════════════════════════════════════════════════
ORIGINAL ALERT (first 1800 chars):
{raw}

═══════════════════════════════════════════════════════════════════════════════════
YOUR INITIAL ANALYSIS:
  Verdict: {rs.get('threat_level', '?')} (confidence {rs.get('confidence', 0)})
  Classification: {rs.get('verdict_classification', '?')}
  Summary: {rs.get('summary', '')}
  Key findings: {json.dumps(rs.get('key_findings', [])[:5])}
  IOCs: {json.dumps(state.get('iocs', {}))[:500]}
  MITRE: {', '.join(rs.get('mitre_techniques', [])[:6])}
"""


async def _chat_stream(run_id: str, user_msg: str):
    """SSE-stream the AI reply token-by-token so the analyst sees it type out."""
    from providers import get_provider
    from agents.investigation_tools import TOOL_SCHEMAS, execute_tool, _summarize_for_trace

    provider = get_provider()

    state = _results[run_id]
    sys_msg = _build_chat_system_msg(state)
    history = _chats.get(run_id, [])

    # Persist user turn immediately so a refresh keeps it
    now = _ts()
    history.append({"role": "user", "content": user_msg, "timestamp": now})
    _chats[run_id] = history

    messages = [{"role": "system", "content": sys_msg}]
    for m in history:
        if m["role"] in ("user", "assistant"):
            messages.append({"role": m["role"], "content": m["content"]})

    tool_calls_made = []
    final_content = ""

    try:
        # Tool-calling loop — non-streamed for tool decisions, streamed for the final answer
        for iteration in range(4):
            # First, a non-streaming call to decide if tools are needed.
            # Chat is interactive → fast model tier for snappy replies.
            resp = await provider.complete(
                model=config.get_model(fast=True),
                messages=messages,
                tools=TOOL_SCHEMAS,
                tool_choice="auto",
                temperature=0.2,
                max_tokens=700,
            )
            if resp.error:
                yield f"data: {json.dumps({'event': 'error', 'error': resp.error})}\n\n"
                yield "data: [DONE]\n\n"
                return
            if resp.tool_calls:
                # Tell the client we're calling tools so it shows "RECON checked X"
                messages.append({
                    "role":      "assistant", "content": resp.message or "",
                    "tool_calls": [{"id": tc["id"], "type": "function",
                                     "function": {"name": tc["name"],
                                                  "arguments": json.dumps(tc["arguments"])}}
                                    for tc in resp.tool_calls],
                })
                for tc in resp.tool_calls:
                    args = tc.get("arguments") or {}
                    tool_result = await execute_tool(tc["name"], args, config)
                    tc_summary = _summarize_for_trace(tc["name"], tool_result)
                    tool_calls_made.append({
                        "tool": tc["name"], "args": args, "summary": tc_summary,
                    })
                    # Stream the tool call to the UI live
                    yield f"data: {json.dumps({'event': 'tool_call', 'tool': tc['name'], 'args': args, 'summary': tc_summary})}\n\n"
                    messages.append({
                        "role": "tool", "tool_call_id": tc["id"],
                        "content": json.dumps(tool_result, default=str)[:2000],
                    })
                continue

            # No more tool calls — re-issue this turn with streaming for the visible answer
            final_content = resp.message or ""
            if final_content:
                # We already have the text from the non-stream call — fake-stream it word by word
                # so the UI fills progressively. (Avoids a 2nd AI roundtrip.)
                tokens = final_content.split(" ")
                buf = ""
                for i, w in enumerate(tokens):
                    chunk = (" " if i > 0 else "") + w
                    buf += chunk
                    yield f"data: {json.dumps({'event': 'token', 'text': chunk})}\n\n"
                    await asyncio.sleep(0.012)  # ~83 tokens/sec — feels like real streaming
            break

        # Persist the assistant turn
        history.append({"role": "assistant", "content": final_content,
                         "tool_calls": tool_calls_made, "timestamp": _ts()})
        _chats[run_id] = history

        yield f"data: {json.dumps({'event': 'done', 'tool_calls': tool_calls_made, 'reply': final_content})}\n\n"
    except Exception as e:
        yield f"data: {json.dumps({'event': 'error', 'error': str(e)})}\n\n"
    yield "data: [DONE]\n\n"


@app.post("/api/chat/{run_id}")
async def chat_send(run_id: str, req: dict):
    """Stream a follow-up reply token-by-token via SSE.

    The AI gets: the original alert, the full analysis, the conversation history,
    and the same tool-calling toolbox the investigation agent had. Replies are
    conversational — focused on helping the analyst decide FP vs malicious.
    Tokens stream as they generate so the analyst reads while the AI writes.
    """
    if run_id not in _results:
        raise HTTPException(404, "Run not found")
    user_msg = (req or {}).get("message", "").strip()
    if not user_msg:
        raise HTTPException(400, "message required")
    if not config.get("OPENAI_API_KEY"):
        raise HTTPException(503, "OpenAI key not configured")
    return StreamingResponse(_chat_stream(run_id, user_msg),
                              media_type="text/event-stream",
                              headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ─── WEBHOOKS ─────────────────────────────────────────────────────────────────────
@app.post("/api/webhook/{target}/{run_id}")
async def send_webhook(target: str, run_id: str, request: Request):
    """Dispatch an analysis result to a configured webhook target.
    target ∈ {slack, teams, thehive, generic}."""
    if run_id not in _results:
        raise HTTPException(404, "Run not found")
    from intel import webhooks as wh
    result = {k: v for k, v in _results[run_id].items() if k != "stix_bundle"}
    base = str(request.base_url).rstrip("/")
    run_url = f"{base}/#run/{run_id}"

    if target == "slack":
        url = config.get("SLACK_WEBHOOK_URL")
        if not url: raise HTTPException(400, "SLACK_WEBHOOK_URL not configured")
        return await wh.send_slack(url, result, run_url)
    if target == "teams":
        url = config.get("TEAMS_WEBHOOK_URL")
        if not url: raise HTTPException(400, "TEAMS_WEBHOOK_URL not configured")
        return await wh.send_teams(url, result, run_url)
    if target == "thehive":
        return await wh.send_thehive(config.get("THEHIVE_URL", ""),
                                     config.get("THEHIVE_TOKEN", ""), result, run_url)
    if target == "opencti":
        from intel.opencti import push_result
        return await push_result(result, config.get("OPENCTI_URL", ""),
                                  config.get("OPENCTI_TOKEN", ""))
    if target == "generic":
        url = config.get("WEBHOOK_GENERIC_URL")
        if not url: raise HTTPException(400, "WEBHOOK_GENERIC_URL not configured")
        return await wh.send_generic(url, result)
    raise HTTPException(400, f"Unknown webhook target: {target}")


# ─── REST API DOCS ────────────────────────────────────────────────────────────────
@app.get("/api/docs", response_class=JSONResponse)
async def api_docs(request: Request):
    """Machine-readable doc of the public REST API with curl examples."""
    base = str(request.base_url).rstrip("/")
    return {
        "platform": "RECON Threat Intelligence Platform",
        "version":  "3.0.0",
        "base_url": base,
        "authentication": {
            "type": "optional API token via X-API-Key header" if config.get("API_TOKEN") else "none (open)",
            "configured": bool(config.get("API_TOKEN")),
        },
        "endpoints": [
            {
                "method": "GET",  "path": "/api/health",
                "description": "Service status, configured AI provider, intel layer counts.",
                "example": f"curl {base}/api/health",
            },
            {
                "method": "POST", "path": "/api/analyze",
                "description": "Run the full agentic pipeline. Streams Server-Sent Events.",
                "body": {"logText": "<alert text or IOCs>", "inputType": "log", "label": "optional"},
                "example": (
                    f'curl -N -X POST {base}/api/analyze \\\n'
                    f'  -H "Content-Type: application/json" \\\n'
                    f'  -d \'{{"logText":"185.220.101.45 CVE-2024-3400","inputType":"log"}}\''
                ),
            },
            {
                "method": "POST", "path": "/api/analyze/sync",
                "description": "Same pipeline, single JSON response (no streaming).",
                "example": f'curl -X POST {base}/api/analyze/sync -H "Content-Type: application/json" -d \'{{"logText":"..."}}\'',
            },
            {
                "method": "POST", "path": "/api/scan-file",
                "description": "YARA-scan a binary, hash it, check LOLDrivers BYOVD catalog.",
                "example": f'curl -X POST {base}/api/scan-file -F "file=@/path/to/sample.exe"',
            },
            {
                "method": "POST", "path": "/api/gti-score",
                "description": "Score IOCs without full pipeline. Returns GTI score per IOC.",
                "body": {"iocs": {"ips": ["..."], "domains": ["..."], "hashes": ["..."]}},
            },
            {
                "method": "GET",  "path": "/api/history/{run_id}",
                "description": "Fetch a cached analysis result.",
                "example": f"curl {base}/api/history/<run_id>",
            },
            {
                "method": "GET",  "path": "/api/export/stix/{run_id}",
                "description": "Download STIX 2.1 bundle for a run.",
                "example": f"curl {base}/api/export/stix/<run_id> -o bundle.stix.json",
            },
            {
                "method": "POST", "path": "/api/webhook/{target}/{run_id}",
                "description": "Push a result to Slack / Teams / TheHive / generic webhook. Targets must be configured in config.json.",
                "example": f"curl -X POST {base}/api/webhook/slack/<run_id>",
            },
            {
                "method": "POST", "path": "/api/detection",
                "description": "Search the MITRE ATT&CK technique library; match groups by techniques.",
            },
        ],
        "python_example": (
            "import requests\n"
            f"r = requests.post('{base}/api/analyze/sync', json={{'logText': '...'}})\n"
            "print(r.json()['response_summary']['threat_level'])"
        ),
    }


# ─── YARA FILE SCAN ───────────────────────────────────────────────────────────────
@app.post("/api/scan-file")
async def scan_file(file: UploadFile = File(...)):
    """Hash + YARA-scan a binary. Returns hashes, file metadata, and matched rules.

    Spec §9: validates magic bytes (not just extension), enforces 50MB cap,
    audit-logs every upload."""
    import hashlib
    data = await file.read()
    if not data:
        raise HTTPException(400, "Empty file")
    if len(data) > 50 * 1024 * 1024:
        raise HTTPException(413, "File exceeds 50 MB limit")

    from intel.security import validate_file_upload, audit_log
    ok, detected_type = validate_file_upload(data, max_mb=50)
    if not ok:
        raise HTTPException(400, detected_type)
    audit_log("file_upload", filename=file.filename, size=len(data),
              detected_type=detected_type)
    hashes = {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    yara_hits = []
    try:
        from intel.yara_scanner import scan_bytes
        yara_hits = scan_bytes(data)
    except Exception as e:
        yara_hits = [{"error": str(e)}]
    # Also check the SHA-256 against LOLDrivers BYOVD catalog
    driver_hit = None
    try:
        from intel.loldrivers import lookup_hash
        driver_hit = lookup_hash(hashes["sha256"])
    except Exception:
        pass

    # Cloud sandbox lookup — Hybrid Analysis + ANY.RUN by SHA-256
    sandbox = {}
    try:
        from intel.sandbox import lookup_all
        sandbox = await lookup_all(hashes["sha256"], config)
    except Exception:
        pass

    return {
        "filename":       file.filename,
        "size":           len(data),
        "hashes":         hashes,
        "yara_matches":   yara_hits,
        "loldrivers_hit": driver_hit,
        "sandbox":        sandbox,
    }


# ─── ALL-IN-ONE FILE SCANNER (spec §8) ───────────────────────────────────────
@app.post("/api/scan/file")
async def scan_file_v2(file: UploadFile = File(...)):
    """Comprehensive static + threat-intel + YARA + detection-content analysis.
    Returns the complete analysis dict from intel.file_analyzer plus a
    threat_intel section from intel.file_correlation, an ai_yara section
    from intel.yara_ai_gen, and persists to the scan history."""
    data = await file.read()
    if not data:
        raise HTTPException(400, "Empty file")
    if len(data) > 50 * 1024 * 1024:
        raise HTTPException(413, "File exceeds 50 MB limit")

    # Magic-byte gate + audit log (re-uses spec §9 helpers)
    try:
        from intel.security import validate_file_upload, audit_log
        ok, detected_type = validate_file_upload(data, max_mb=50)
        if not ok:
            raise HTTPException(400, detected_type)
        audit_log("file_scan", filename=file.filename, size=len(data),
                  detected_type=detected_type)
    except HTTPException:
        raise
    except Exception:
        pass

    from intel.file_analyzer import analyze_file
    # Static analysis is CPU-bound (hashing, entropy, regex string extraction,
    # YARA). Run it in a worker thread so a large upload doesn't block the event
    # loop — keeps concurrent requests and SSE streams responsive during a scan.
    analysis = await asyncio.to_thread(analyze_file, data, file.filename or "uploaded")

    # Stash the bytes on the result temporarily so yara_ai_gen can verify the
    # generated rule against the actual sample. Stripped before persistence.
    analysis["_file_bytes"] = data

    # Combined YARA (vendor + custom)
    try:
        from intel.yara_custom import scan_combined
        analysis["yara_matches"] = scan_combined(data)
    except Exception:
        pass

    # TI correlation (async)
    try:
        from intel.file_correlation import correlate
        analysis["threat_intel"] = await correlate(analysis, config)
    except Exception as e:
        analysis["threat_intel"] = {"error": str(e)}

    # Mark AI as pending so the frontend knows to poll. The three AI
    # workflows then run in a background task; the persisted scan is
    # updated as each completes. Polling endpoint: GET /api/scan/{sha256}
    analysis["ai_pending"] = True
    analysis.pop("_file_bytes", None)

    # Persist what we have right now so polling works immediately
    try:
        from intel.file_correlation import append_scan_history
        append_scan_history(analysis)
    except Exception:
        pass

    # Kick off AI workflows in the background — caller doesn't wait for them
    sha256 = (analysis.get("hashes") or {}).get("sha256")
    if sha256:
        asyncio.create_task(_finish_ai_in_background(sha256, data))

    return analysis


async def _finish_ai_in_background(sha256: str, file_bytes: bytes):
    """Runs the four AI workstreams concurrently and persists each the moment it
    finishes — so the frontend poller (GET /api/scan/by-hash) surfaces cards
    progressively: the fast triage verdict appears first, then the summary/YARA,
    then the deep analyst report (itself ~2x faster now that it's split into two
    parallel field-groups). Each stream fails open independently."""
    from intel.file_correlation import load_scan, append_scan_history
    from intel.yara_ai_gen import generate_yara_for_file
    from intel.file_ai_summary import summarize_file
    from intel.file_ai_analyst import triage_classify, analyze_deep, gather_comparative_context
    from intel.scanner_feedback import institutional_knowledge_prompt

    scan = load_scan(sha256)
    if not scan:
        return
    # yara_ai_gen needs the bytes for match verification — re-attach briefly.
    # Kept on the in-memory dict only; stripped from every persisted snapshot.
    scan["_file_bytes"] = file_bytes
    scan.setdefault("ai_analyst", {})
    extra = institutional_knowledge_prompt(scan)
    comparative = gather_comparative_context(scan)

    def _persist():
        append_scan_history({k: v for k, v in scan.items() if k != "_file_bytes"})

    def _val(r):
        return {"error": str(r)[:200]} if isinstance(r, Exception) else r

    tasks = {
        asyncio.ensure_future(generate_yara_for_file(scan, _ai_gen)):  "ai_yara",
        asyncio.ensure_future(summarize_file(scan, config)):           "ai_summary",
        asyncio.ensure_future(triage_classify(scan, config)):          "triage",
        asyncio.ensure_future(analyze_deep(scan, config,
            comparative_context=comparative, extra_context=extra)):    "deep",
    }
    pending = set(tasks)
    while pending:
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        for t in done:
            kind = tasks[t]
            val = _val(t.exception() or t.result())
            if kind == "ai_yara":
                scan["ai_yara"] = val
            elif kind == "ai_summary":
                if val and not isinstance(val, dict):  # summary is a plain string
                    scan["ai_summary"] = val
            elif kind == "triage":
                scan["ai_analyst"]["triage"] = val
            elif kind == "deep":
                scan["ai_analyst"]["deep"] = val
                if extra and isinstance(val, dict) and "error" not in val:
                    scan["ai_analyst"]["institutional_knowledge_applied"] = True
            _persist()   # progressive — each poll picks up whatever has landed

    scan["ai_pending"] = False
    scan.pop("_file_bytes", None)
    _persist()


@app.get("/api/scan/by-hash/{sha256}")
async def scan_get(sha256: str):
    """Polling endpoint — returns the current state of a scan, including
    any AI fields that have completed since the initial POST returned.
    Path is /by-hash/ to avoid shadowing /api/scan/history|stats|rules|etc."""
    from intel.file_correlation import load_scan
    scan = load_scan(sha256)
    if not scan:
        raise HTTPException(404, "no scan for that sha256")
    return scan


@app.post("/api/scan/hash")
async def scan_hash(req: dict):
    """Hash lookup — always a fresh TI query.

    Full per-investigation isolation: we do NOT return a prior scan from history,
    so a lookup never serves data saved from an earlier investigation."""
    h = (req or {}).get("hash", "").strip().lower()
    if not h:
        raise HTTPException(400, "hash required")
    if len(h) not in (32, 40, 64):
        raise HTTPException(400, "hash must be MD5 (32), SHA1 (40), or SHA256 (64) hex")
    out = {"hash": h, "sources": {}}

    # 2. No prior scan — query TI sources by hash and shape the result like a
    #    scan (hashes + threat_intel + verdict) so the frontend renders it via the
    #    existing FileIdentity / ThreatIntelSection / VerdictBanner components
    #    instead of a blank report.
    htype = "sha256" if len(h) == 64 else "sha1" if len(h) == 40 else "md5"
    vt = mb = ha = {}
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            from intel.file_correlation import _vt_file, _malwarebazaar, _hybrid_analysis
            r_vt, r_mb, r_ha = await asyncio.gather(
                _vt_file(session, h, config.get("VIRUSTOTAL_KEY", "")),
                _malwarebazaar(session, h),
                _hybrid_analysis(session, h, config.get("HYBRID_ANALYSIS_KEY", "")),
                return_exceptions=True,
            )
            vt = r_vt if isinstance(r_vt, dict) else {}
            mb = r_mb if isinstance(r_mb, dict) else {}
            ha = r_ha if isinstance(r_ha, dict) else {}
    except Exception as e:
        out["error"] = str(e)

    threat_intel = {"virustotal": vt, "malwarebazaar": mb, "hybrid_analysis": ha}
    vt_mal = vt.get("malicious") if isinstance(vt.get("malicious"), int) else 0
    ha_verdict = (ha.get("verdict") or "").lower()
    if mb.get("found") or vt_mal > 5 or ha_verdict == "malicious":
        verdict = "MALICIOUS"
    elif vt_mal >= 1 or ha_verdict in {"suspicious", "ambiguous"}:
        verdict = "SUSPICIOUS"
    else:
        verdict = "UNKNOWN"
    return {
        "hash":         h,
        "hashes":       {htype: h},
        "filename":     f"hash lookup · {h[:16]}…",
        "verdict":      verdict,
        "threat_intel": threat_intel,
        "sources":      threat_intel,   # also under 'sources' for API consumers
        "hash_lookup":  True,
        "from_cache":   False,
    }


@app.post("/api/scan/url")
async def scan_url_endpoint(req: dict):
    """Download a URL safely (30s timeout, 50MB cap) and run the file scanner on it."""
    url = (req or {}).get("url", "").strip()
    if not url:
        raise HTTPException(400, "url required")
    if not url.startswith(("http://", "https://")):
        raise HTTPException(400, "url must be http(s)")
    import aiohttp
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
            async with session.get(url, allow_redirects=True) as r:
                if r.status != 200:
                    raise HTTPException(400, f"download HTTP {r.status}")
                chunks = []
                total = 0
                async for chunk in r.content.iter_chunked(64 * 1024):
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > 50 * 1024 * 1024:
                        raise HTTPException(413, "remote file exceeds 50 MB cap")
                data = b"".join(chunks)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"download failed: {e}")

    filename = url.rstrip("/").rsplit("/", 1)[-1].split("?", 1)[0] or "downloaded"
    from intel.file_analyzer import analyze_file
    # Mirror the file-scanner fast path: CPU-bound static analysis runs off the
    # event loop, the full AI suite (triage badge, summary, YARA-gen, split deep
    # analyst) runs in the background on the two-tier models, and we return
    # immediately so the frontend can poll /api/scan/by-hash for progressive fill.
    analysis = await asyncio.to_thread(analyze_file, data, filename)
    analysis["source_url"] = url
    analysis["_file_bytes"] = data
    try:
        from intel.yara_custom import scan_combined
        analysis["yara_matches"] = scan_combined(data)
    except Exception:
        pass
    # Two parallel correlation passes:
    #  (1) file_correlation runs hash-based lookups (VT/MalwareBazaar/Hybrid
    #      Analysis on the downloaded content) and lands under threat_intel.
    #  (2) url_enrichment runs URL + domain reputation (VT URL endpoint,
    #      Maltiverse hostname, GreyNoise/AbuseIPDB/Shodan when the
    #      hostname resolves to an IP, etc.) and lands under enrichments.
    #      Without this, the AI summary cited "VirusTotal/Maltiverse" with no
    #      actual data behind it because file_correlation only sees the
    #      downloaded bytes, never the URL or hostname.
    try:
        from intel.file_correlation import correlate
        analysis["threat_intel"] = await correlate(analysis, config)
    except Exception as e:
        analysis["threat_intel"] = {"error": str(e)}
    try:
        import aiohttp
        from urllib.parse import urlparse
        from agents.enrichment import enrich_url as _enrich_url, enrich_domain as _enrich_domain
        host = (urlparse(url).hostname or "").strip().lower()
        keys = {k: config.get(k, "") for k in (
            "VIRUSTOTAL_KEY", "ABUSEIPDB_KEY", "OTX_KEY", "URLSCAN_KEY",
            "GREYNOISE_KEY", "SHODAN_KEY", "PULSEDIVE_KEY", "MALTIVERSE_KEY",
            "IPINFO_TOKEN",
        )}
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as sess:
            url_enr, dom_enr = await asyncio.gather(
                _enrich_url(sess, url, keys),
                _enrich_domain(sess, host, keys) if host else asyncio.sleep(0, result={}),
                return_exceptions=True,
            )
        analysis["enrichments"] = {
            "urls":    {url: url_enr if isinstance(url_enr, dict) else {}},
            "domains": {host: dom_enr if (host and isinstance(dom_enr, dict)) else {}},
        }
    except Exception as e:
        analysis["enrichments"] = {"error": str(e)}
    analysis["ai_pending"] = True
    analysis.pop("_file_bytes", None)
    try:
        from intel.file_correlation import append_scan_history
        append_scan_history(analysis)
    except Exception:
        pass
    sha256 = (analysis.get("hashes") or {}).get("sha256")
    if sha256:
        asyncio.create_task(_finish_ai_in_background(sha256, data))
    return analysis


@app.get("/api/scan/history")
async def scan_history():
    from intel.file_correlation import get_scan_history
    return {"history": get_scan_history()}


@app.get("/api/scan/stats")
async def scan_stats():
    from intel.file_correlation import get_scan_history
    hist = get_scan_history()
    verdicts = {"MALICIOUS": 0, "SUSPICIOUS": 0, "LOW": 0, "CLEAN": 0, "UNKNOWN": 0}
    for e in hist:
        v = e.get("verdict") or "UNKNOWN"
        verdicts[v] = verdicts.get(v, 0) + 1
    try:
        from intel.yara_custom import stats as ystats
        yc = ystats()
    except Exception:
        yc = {}
    try:
        from intel.yara_scanner import stats as ys
        yv = ys()
    except Exception:
        yv = {}
    return {
        "total_scanned":  len(hist),
        "verdicts":       verdicts,
        "yara_vendor":    yv,
        "yara_custom":    yc,
    }


@app.get("/api/scan/rules")
async def scan_rules_list():
    from intel.yara_custom import list_rules, stats
    return {"rules": list_rules(), "stats": stats()}


class CustomRuleSave(BaseModel):
    name: str
    rule: str


@app.post("/api/scan/rules")
async def scan_rules_save(req: CustomRuleSave):
    from intel.yara_custom import save_rule
    out = save_rule(req.name, req.rule)
    if not out.get("saved"):
        raise HTTPException(400, {"errors": out.get("errors")})
    return out


@app.delete("/api/scan/rules/{rule_name}")
async def scan_rules_delete(rule_name: str):
    from intel.yara_custom import delete_rule
    ok = delete_rule(rule_name)
    if not ok:
        raise HTTPException(404, "rule not found")
    return {"deleted": True, "name": rule_name}


@app.post("/api/scan/compare")
async def scan_compare(req: dict):
    """Side-by-side compare two prior scans by SHA-256."""
    a = (req or {}).get("a", "").lower()
    b = (req or {}).get("b", "").lower()
    if not (a and b):
        raise HTTPException(400, "supply 'a' and 'b' SHA-256 hashes")
    from intel.file_correlation import load_scan
    sa, sb = load_scan(a), load_scan(b)
    if not sa:
        raise HTTPException(404, f"no scan for {a}")
    if not sb:
        raise HTTPException(404, f"no scan for {b}")
    def _diff(left, right):
        return {
            "a_only": sorted(set(left) - set(right)),
            "b_only": sorted(set(right) - set(left)),
            "shared": sorted(set(left) & set(right)),
        }
    return {
        "a":       {"sha256": a, "verdict": sa.get("verdict"), "filename": sa.get("filename")},
        "b":       {"sha256": b, "verdict": sb.get("verdict"), "filename": sb.get("filename")},
        "capabilities_diff": _diff(
            (sa.get("capabilities") or {}).get("tags") or [],
            (sb.get("capabilities") or {}).get("tags") or [],
        ),
        "yara_diff": _diff(
            [m.get("rule") for m in (sa.get("yara_matches") or []) if isinstance(m, dict)],
            [m.get("rule") for m in (sb.get("yara_matches") or []) if isinstance(m, dict)],
        ),
        "ioc_diff": {
            "ips":     _diff((sa.get("iocs") or {}).get("ips") or [], (sb.get("iocs") or {}).get("ips") or []),
            "domains": _diff((sa.get("iocs") or {}).get("domains") or [], (sb.get("iocs") or {}).get("domains") or []),
        },
        "imphash": {
            "a": ((sa.get("format_specific") or {}).get("pe") or {}).get("imphash"),
            "b": ((sb.get("format_specific") or {}).get("pe") or {}).get("imphash"),
            "match": ((sa.get("format_specific") or {}).get("pe") or {}).get("imphash") ==
                     ((sb.get("format_specific") or {}).get("pe") or {}).get("imphash"),
        },
    }


class YaraHuntRequest(BaseModel):
    rule: str


@app.post("/api/scan/hunt")
async def scan_hunt(req: YaraHuntRequest):
    """Compile a YARA rule and run it against every previously scanned file."""
    try:
        import yara
    except ImportError:
        raise HTTPException(500, "yara-python not installed")
    try:
        compiled = yara.compile(source=req.rule)
    except Exception as e:
        raise HTTPException(400, f"rule compile error: {e}")
    from intel.file_correlation import get_scan_history
    matches = []
    for entry in get_scan_history():
        sha = entry.get("sha256")
        if not sha:
            continue
        # We don't keep original file bytes — hunt only against stored strings.
        # This is a deliberate trade-off (binary bytes can be massive).
        from intel.file_correlation import load_scan
        scan = load_scan(sha)
        if not scan:
            continue
        # Combine all stored strings into a synthetic buffer for the hunt
        ascii_s   = (scan.get("strings") or {}).get("ascii_sample") or []
        unicode_s = (scan.get("strings") or {}).get("unicode_sample") or []
        haystack  = ("\n".join(ascii_s) + "\n" + "\n".join(unicode_s)).encode("utf-8", "ignore")
        if not haystack:
            continue
        try:
            ms = compiled.match(data=haystack, timeout=5)
        except Exception:
            continue
        if ms:
            matches.append({
                "sha256":   sha,
                "filename": entry.get("filename"),
                "verdict":  entry.get("verdict"),
                "matched":  [m.rule for m in ms],
            })
    return {"hunted": len(get_scan_history()), "hits": matches, "hit_count": len(matches)}


# ─── ITERATIVE REFINEMENT (spec §2) ──────────────────────────────────────────
class ScanClarifyRequest(BaseModel):
    scan_id: str          # SHA-256 of the scanned file
    answers: dict         # {question_text: answer_text}


@app.post("/api/scan/clarify")
async def scan_clarify(req: ScanClarifyRequest):
    """Re-run only the deep AI analysis with analyst answers appended to the
    prompt. Returns the updated assessment with a context_impact field
    explaining how the answers changed the conclusion."""
    from intel.file_correlation import load_scan, append_scan_history
    from intel.file_ai_analyst import analyze_deep, gather_comparative_context
    from intel.scanner_feedback import institutional_knowledge_prompt

    scan = load_scan(req.scan_id)
    if not scan:
        raise HTTPException(404, "no prior scan for that sha256 — run /api/scan/file first")
    if not req.answers:
        raise HTTPException(400, "answers required")

    qa_lines = "\n".join(f"  Q: {q}\n  A: {a}" for q, a in req.answers.items() if a)
    extra = (
        "## Analyst-supplied clarifications\n"
        "The analyst answered your earlier clarifying questions. Incorporate "
        "this context into the assessment and add a top-level field "
        '"context_impact" explaining how these answers changed your conclusions '
        "compared to your prior assessment.\n\n"
        f"{qa_lines}"
    )
    inst = institutional_knowledge_prompt(scan)
    if inst:
        extra = inst + "\n\n" + extra

    deep = await analyze_deep(scan, config,
                              comparative_context=gather_comparative_context(scan),
                              extra_context=extra)
    if not deep or deep.get("error"):
        raise HTTPException(500, f"AI re-analysis failed: {(deep or {}).get('error') or 'no key'}")

    scan.setdefault("ai_analyst", {})
    scan["ai_analyst"]["deep"] = deep
    scan["ai_analyst"]["analyst_answers"] = req.answers
    # Surface context_impact on the analyst object too so the UI can show it
    if isinstance(deep, dict) and deep.get("context_impact"):
        scan["ai_analyst"]["context_impact"] = deep["context_impact"]
    append_scan_history(scan)
    return scan


class ScanFeedbackRequest(BaseModel):
    scan_id: str
    thumbs: str          # 'up' | 'down'
    correction: Optional[dict] = None
    notes: Optional[str] = ""
    analyst: Optional[str] = ""


@app.post("/api/scan/feedback")
async def scan_feedback(req: ScanFeedbackRequest):
    """Record analyst feedback on an AI scan result. Used as institutional
    knowledge on subsequent analyses of similar files."""
    if req.thumbs not in ("up", "down"):
        raise HTTPException(400, "thumbs must be 'up' or 'down'")
    from intel.scanner_feedback import record
    entry = record(req.scan_id, req.thumbs, req.correction, req.notes, req.analyst)
    return {"saved": True, "entry": entry}


@app.get("/api/scan/feedback")
async def scan_feedback_list(scan_id: Optional[str] = None):
    from intel.scanner_feedback import list_all, for_scan
    return {"feedback": for_scan(scan_id) if scan_id else list_all()}


@app.get("/api/sandbox/{sha256}")
async def sandbox_lookup(sha256: str):
    """Hash-only lookup against configured cloud sandboxes."""
    if len(sha256) != 64:
        raise HTTPException(400, "Provide a SHA-256 hash (64 hex chars).")
    try:
        from intel.sandbox import lookup_all
        return {"sha256": sha256, "sandbox": await lookup_all(sha256, config)}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/api/urlscan/submit")
async def urlscan_submit(req: dict):
    """Submit a URL for live scanning via URLScan.io."""
    api_key = config.get("URLSCAN_KEY")
    if not api_key:
        raise HTTPException(400, "URLSCAN_KEY not configured")
    url = (req or {}).get("url", "").strip()
    if not url:
        raise HTTPException(400, "url required")
    from intel.urlscan import submit_url
    out = await submit_url(url, api_key, visibility=req.get("visibility", "unlisted"))
    if not out.get("ok"):
        raise HTTPException(502, out.get("error", "submission failed"))
    return out


@app.get("/api/urlscan/result/{uuid}")
async def urlscan_result(uuid: str):
    """Poll a URLScan result. Returns ready=false while processing."""
    from intel.urlscan import get_result
    return await get_result(uuid, config.get("URLSCAN_KEY", ""))


@app.post("/api/sandbox/submit")
async def sandbox_submit(file: UploadFile = File(...)):
    """Submit a fresh sample to Hybrid Analysis for detonation. Returns job_id."""
    api_key = config.get("HYBRID_ANALYSIS_KEY")
    if not api_key:
        raise HTTPException(400, "HYBRID_ANALYSIS_KEY not configured")
    data = await file.read()
    if not data:
        raise HTTPException(400, "Empty file")
    if len(data) > 100 * 1024 * 1024:
        raise HTTPException(413, "File exceeds 100 MB submission limit")
    from intel.sandbox import submit_hybrid_analysis
    result = await submit_hybrid_analysis(data, file.filename or "sample.bin", api_key)
    if not result.get("ok"):
        raise HTTPException(502, result.get("error", "submission failed"))
    job_id = result["job_id"]
    _sandbox_jobs[job_id] = {
        "state":         "IN_QUEUE",
        "filename":      file.filename,
        "sha256":        result.get("sha256"),
        "environment":   result.get("environment_id"),
        "submitted_at":  _ts(),
    }
    return {"job_id": job_id, "sha256": result.get("sha256"),
            "submitted_at": _sandbox_jobs[job_id]["submitted_at"]}


@app.get("/api/sandbox/job/{job_id}")
async def sandbox_job_status(job_id: str):
    """Poll status for a Hybrid Analysis submission. When SUCCESS, returns summary."""
    api_key = config.get("HYBRID_ANALYSIS_KEY")
    if not api_key:
        raise HTTPException(400, "HYBRID_ANALYSIS_KEY not configured")
    from intel.sandbox import hybrid_analysis_state, hybrid_analysis_summary
    state = await hybrid_analysis_state(job_id, api_key)
    record = _sandbox_jobs.get(job_id, {})
    record["state"] = state.get("state", "UNKNOWN")
    record["error"] = state.get("error")
    if record["state"] == "SUCCESS":
        record["summary"] = await hybrid_analysis_summary(job_id, api_key)
    _sandbox_jobs[job_id] = record
    return {"job_id": job_id, **record}


# ─── HEALTH + STATUS (spec §11) ──────────────────────────────────────────────────
@app.get("/api/status")
async def status_check():
    """Spec §11: lightweight test calls to every configured source so analysts
    can see at a glance which integrations are working, rate-limited, or failing."""
    import aiohttp
    out = {"sources": {}, "checked_at": datetime.now(timezone.utc).isoformat()}
    timeout = aiohttp.ClientTimeout(total=8)

    async def probe(name, url, headers=None, params=None, ok_codes=(200,)):
        try:
            async with aiohttp.ClientSession(timeout=timeout) as s:
                async with s.get(url, headers=headers or {}, params=params or {}) as r:
                    if r.status in ok_codes:
                        return {"state": "ok", "http": r.status}
                    if r.status == 429:
                        return {"state": "rate_limited", "http": 429}
                    if r.status in (401, 403):
                        return {"state": "auth_failed", "http": r.status}
                    return {"state": "failing", "http": r.status}
        except asyncio.TimeoutError:
            return {"state": "timeout"}
        except Exception as e:
            return {"state": "error", "detail": str(e)[:120]}

    checks = []
    if config.get("VIRUSTOTAL_KEY"):
        checks.append(("virustotal", "https://www.virustotal.com/api/v3/users/current",
                       {"x-apikey": config.get("VIRUSTOTAL_KEY")}, None))
    if config.get("ABUSEIPDB_KEY"):
        checks.append(("abuseipdb", "https://api.abuseipdb.com/api/v2/check",
                       {"Key": config.get("ABUSEIPDB_KEY"), "Accept": "application/json"},
                       {"ipAddress": "8.8.8.8"}))
    if config.get("SHODAN_KEY"):
        checks.append(("shodan", "https://api.shodan.io/api-info",
                       None, {"key": config.get("SHODAN_KEY")}))
    if config.get("GREYNOISE_KEY"):
        checks.append(("greynoise", "https://api.greynoise.io/ping",
                       {"key": config.get("GREYNOISE_KEY")}, None))
    if config.get("OTX_KEY"):
        checks.append(("otx", "https://otx.alienvault.com/api/v1/user/me",
                       {"X-OTX-API-KEY": config.get("OTX_KEY")}, None))
    if config.get("URLSCAN_KEY"):
        checks.append(("urlscan", "https://urlscan.io/api/v1/user/quotas/",
                       {"API-Key": config.get("URLSCAN_KEY")}, None))

    results = await asyncio.gather(*[probe(*args) for args in [(n, u, h, p) for n, u, h, p in checks]])
    for (name, *_), result in zip(checks, results):
        out["sources"][name] = result

    # Free no-key sources (probe with cheap GETs)
    free_probes = [
        ("circl_pdns",   "https://www.circl.lu/pdns/query/1.1.1.1"),
        ("robtex",       "https://freeapi.robtex.com/ipquery/1.1.1.1"),
        ("hackertarget", "https://api.hackertarget.com/aslookup/?q=1.1.1.1"),
        ("hashlookup",   "https://hashlookup.circl.lu/lookup/sha256/0000000000000000000000000000000000000000000000000000000000000000"),
    ]
    free_results = await asyncio.gather(*[probe(name, url, ok_codes=(200, 404)) for name, url in free_probes])
    for (name, _), r in zip(free_probes, free_results):
        out["sources"][name] = r
    return out


# ─── SECURITY SELF-CHECK (spec §9) ────────────────────────────────────────────
@app.get("/api/security/check")
async def security_check():
    from intel.security import security_self_check
    return security_self_check(config)


@app.get("/api/startup-check")
async def startup_check():
    """Spec §11: confirm packages installed + report which keys are configured."""
    from intel.warninglist_filter import _stats as wl_stats
    pkg_status = {}
    for name in ("openai", "sigma", "yara", "stix2", "taxii2client", "feedparser",
                 "mitreattack", "aiohttp", "fastapi"):
        try:
            __import__(name)
            pkg_status[name] = "ok"
        except ImportError:
            pkg_status[name] = "missing"

    required = ("OPENAI_API_KEY",)
    optional = ("VIRUSTOTAL_KEY", "ABUSEIPDB_KEY", "SHODAN_KEY", "GREYNOISE_KEY",
                "OTX_KEY", "URLSCAN_KEY", "PULSEDIVE_KEY", "CENSYS_ID",
                "CENSYS_SECRET", "HYBRID_ANALYSIS_KEY", "CROWDSEC_KEY",
                "MALTIVERSE_KEY", "OPENCTI_TOKEN", "FRESHRSS_API_KEY")

    keys = {}
    for k in required:
        keys[k] = "green" if config.get(k) else "red"
    for k in optional:
        keys[k] = "green" if config.get(k) else "yellow"

    return {
        "packages": pkg_status,
        "keys":     keys,
        "warninglists": wl_stats(),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


# ─── REPORT GENERATION (spec §10) ────────────────────────────────────────────────
def _build_report(run_id: str, state: dict) -> dict:
    rs = state.get("response_summary") or {}
    iocs = state.get("iocs") or {}
    techniques = state.get("mitre_techniques") or rs.get("mitre_techniques") or []

    # Group recommended_actions by IMMEDIATE / SHORTTERM / LONGTERM per spec §5
    actions = rs.get("recommended_actions") or []
    grouped = {"IMMEDIATE": [], "SHORTTERM": [], "LONGTERM": []}
    for a in actions:
        if isinstance(a, dict):
            prio = (a.get("priority") or "SHORTTERM").upper()
            grouped.setdefault(prio, []).append(a)
        else:
            grouped["SHORTTERM"].append({"action": str(a), "priority": "SHORTTERM"})

    mitre_table = []
    for t in techniques:
        tid = str(t).split(" ")[0]
        mitre_table.append({
            "id":   tid,
            "name": (str(t).split(" - ", 1)[1] if " - " in str(t) else ""),
            "url":  f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
        })

    return {
        "metadata": {
            "run_id":           run_id,
            "label":            state.get("label", ""),
            "analyst":          state.get("analyst", ""),
            "generated_at":     datetime.now(timezone.utc).isoformat(),
            "investigation_at": state.get("timestamp"),
            "platform_version": "RECON 1.0",
        },
        "executive_summary":   rs.get("summary") or "",
        "threat_level":        rs.get("threat_level") or state.get("threat_level"),
        "confidence":          rs.get("confidence") or state.get("confidence"),
        "malware_family":      state.get("malware_family") or rs.get("malware_family"),
        "threat_actor":        state.get("threat_actor") or rs.get("threat_actor"),
        "campaign":            state.get("campaign") or rs.get("campaign"),
        "attack_stage":        state.get("attack_stage") or rs.get("attack_stage"),
        "technical_findings": {
            "key_findings":     rs.get("key_findings") or [],
            "chain_of_thought": rs.get("chain_of_thought") or [],
            "ioc_assessments":  rs.get("ioc_assessments") or [],
            "iocs":             iocs,
            "suppressed_iocs":  state.get("suppressed_iocs") or {},
        },
        "detection_content": {
            "sigma":  state.get("sigma_rule"),
            "kql":    state.get("kql_query"),
            "spl":    state.get("splunk_spl"),
            "yara":   state.get("yara_rule"),
        },
        "mitre_coverage":      mitre_table,
        "recommended_actions": grouped,
        "analyst_notes":       rs.get("analyst_notes") or "",
        "appendix": {
            "enrichments": state.get("enrichments") or {},
            "cross_refs":  state.get("cross_refs") or {},
            "gti_scores":  state.get("gti_scores") or {},
        },
    }


@app.get("/api/report/{run_id}")
async def report_full(run_id: str):
    """Spec §10: full structured report for the front-end + export buttons."""
    if run_id not in _results:
        raise HTTPException(404, "Run not found")
    return _build_report(run_id, _results[run_id])


@app.get("/api/report/{run_id}/markdown")
async def report_markdown(run_id: str):
    """Spec §10: Markdown report for pasting into Jira / Confluence / Slack."""
    if run_id not in _results:
        raise HTTPException(404, "Run not found")
    r = _build_report(run_id, _results[run_id])
    lines = []
    m = r["metadata"]
    lines.append(f"# Threat intelligence report — {m['label'] or 'Untitled'}")
    lines.append(f"**Run ID:** `{m['run_id']}`  ")
    lines.append(f"**Generated:** {m['generated_at']}  ")
    lines.append(f"**Analyst:** {m['analyst'] or '_unassigned_'}  ")
    lines.append(f"**Platform:** {m['platform_version']}\n")
    lines.append(f"## Verdict")
    lines.append(f"- **Threat level:** {r['threat_level']}")
    lines.append(f"- **Confidence:** {r['confidence']}")
    if r["malware_family"]:    lines.append(f"- **Malware family:** {r['malware_family']}")
    if r["threat_actor"]:      lines.append(f"- **Threat actor:** {r['threat_actor']}")
    if r["campaign"]:          lines.append(f"- **Campaign:** {r['campaign']}")
    if r["attack_stage"]:      lines.append(f"- **Attack stage:** {r['attack_stage']}")
    lines.append("")
    lines.append("## Executive summary")
    lines.append(r["executive_summary"] or "_no summary available_")
    lines.append("")
    lines.append("## Key findings")
    for f in r["technical_findings"]["key_findings"]:
        lines.append(f"- {f}")
    lines.append("")
    lines.append("## MITRE ATT&CK coverage")
    for t in r["mitre_coverage"]:
        lines.append(f"- [{t['id']}]({t['url']}) — {t['name']}")
    lines.append("")
    for prio, items in r["recommended_actions"].items():
        if not items:
            continue
        lines.append(f"## Recommended actions ({prio.lower()})")
        for a in items:
            txt = a.get("action") if isinstance(a, dict) else str(a)
            tf = a.get("timeframe", "") if isinstance(a, dict) else ""
            lines.append(f"- {txt}" + (f" _(by {tf})_" if tf else ""))
        lines.append("")
    lines.append("## Detection content")
    dc = r["detection_content"]
    for label, content in (("Sigma", dc["sigma"]), ("KQL", dc["kql"]),
                           ("Splunk SPL", dc["spl"]), ("YARA", dc["yara"])):
        if content:
            lines.append(f"### {label}")
            lines.append("```")
            lines.append(content)
            lines.append("```")
    return JSONResponse(content={"markdown": "\n".join(lines)})


# ─── HISTORY ──────────────────────────────────────────────────────────────────────
@app.get("/api/history")
async def get_history():
    return {"history": _history[-50:], "total": len(_history)}

@app.get("/api/history/{run_id}")
async def get_history_item(run_id: str):
    if run_id not in _results:
        raise HTTPException(404, "Run not found")
    return {k: v for k, v in _results[run_id].items() if k != "stix_bundle"}


# ─── EMAIL COMPOSER (RECON port of TL.MDR.email — ThreatLocker branding stripped) ─
class EmailParseRequest(BaseModel):
    log_text: str


class EmailComposeRequest(BaseModel):
    alert_type: str
    parsed: dict
    options: Optional[dict] = None
    ip1: Optional[dict] = None
    ip2: Optional[dict] = None


class EmailSendRequest(BaseModel):
    subject: str
    body_text: str
    body_html: str
    to: str
    cc: Optional[str] = ""


class EmailTemplateSave(BaseModel):
    alert_type: str
    body: str


@app.get("/api/email/templates")
async def email_templates_list():
    """List every available email template plus the response-action vocabulary."""
    from intel.email_composer import list_templates, list_alert_types, list_response_actions
    return {
        "templates": list_templates(),
        "alert_types": list_alert_types(),
        "response_actions": list_response_actions(),
    }


@app.get("/api/email/templates/{alert_type}")
async def email_template_get(alert_type: str):
    from intel.email_composer import load_template
    body = load_template(alert_type)
    if not body:
        raise HTTPException(404, f"no template for {alert_type}")
    return {"alert_type": alert_type, "body": body}


@app.post("/api/email/templates")
async def email_template_save(req: EmailTemplateSave):
    from intel.email_composer import save_template
    if not save_template(req.alert_type, req.body):
        raise HTTPException(400, "unknown alert_type")
    return {"saved": True, "alert_type": req.alert_type}


@app.post("/api/email/parse")
async def email_parse(req: EmailParseRequest):
    """Parse raw log text and return every field the composer will reference."""
    from intel.email_composer import parse_log
    if not req.log_text or not req.log_text.strip():
        raise HTTPException(400, "log_text required")
    return parse_log(req.log_text)


@app.post("/api/email/compose")
async def email_compose(req: EmailComposeRequest):
    """Render the email — returns subject + plain text + HTML."""
    from intel.email_composer import compose
    cfg = {
        "EMAIL_FROM_NAME":    config.get("EMAIL_FROM_NAME"),
        "EMAIL_FROM_ADDRESS": config.get("EMAIL_FROM_ADDRESS"),
        "EMAIL_SIGNATURE":    config.get("EMAIL_SIGNATURE"),
    }
    options = dict(req.options or {})
    if not options.get("team_name"):
        options["team_name"] = config.get("EMAIL_TEAM_NAME") or "the MDR analyst team"
    if not options.get("from_address"):
        options["from_address"] = config.get("EMAIL_FROM_ADDRESS") or ""
    return compose(req.alert_type, req.parsed, options, cfg,
                   ip1=req.ip1, ip2=req.ip2)


class EmailComposeAIRequest(BaseModel):
    log_text: str
    parsed: Optional[dict] = None
    options: Optional[dict] = None


@app.post("/api/email/compose-ai")
async def email_compose_ai(req: EmailComposeAIRequest):
    """Generate a customer email via AI using the static templates as style
    models. Returns the same {subject, text, html, template_used} shape as
    /api/email/compose so the frontend can render it identically."""
    from intel.email_composer import compose_ai
    cfg = {
        "OPENAI_API_KEY":     config.get("OPENAI_API_KEY"),
        "OPENAI_BASE_URL":    config.get("OPENAI_BASE_URL"),
        "AI_MODEL":           config.get("AI_MODEL"),
        "FAST_AI_MODEL":      config.get("FAST_AI_MODEL"),
        "EMAIL_FROM_NAME":    config.get("EMAIL_FROM_NAME"),
        "EMAIL_FROM_ADDRESS": config.get("EMAIL_FROM_ADDRESS"),
        "EMAIL_SIGNATURE":    config.get("EMAIL_SIGNATURE"),
    }
    options = dict(req.options or {})
    if not options.get("team_name"):
        options["team_name"] = config.get("EMAIL_TEAM_NAME") or "the MDR analyst team"
    if not options.get("from_address"):
        options["from_address"] = config.get("EMAIL_FROM_ADDRESS") or ""
    out = await compose_ai(req.log_text, req.parsed, options, cfg)
    if "error" in out:
        raise HTTPException(503, out["error"])
    return out


@app.post("/api/email/send")
async def email_send(req: EmailSendRequest):
    """Send via configured SMTP if available. Returns clipboard-ready payload
    if SMTP isn't configured (caller can fall back to copy / mailto)."""
    from intel.email_composer import send_smtp
    smtp_cfg = {
        "EMAIL_SMTP_HOST":     config.get("EMAIL_SMTP_HOST"),
        "EMAIL_SMTP_PORT":     config.get("EMAIL_SMTP_PORT"),
        "EMAIL_SMTP_USER":     config.get("EMAIL_SMTP_USER"),
        "EMAIL_SMTP_PASSWORD": config.get("EMAIL_SMTP_PASSWORD"),
        "EMAIL_FROM_ADDRESS":  config.get("EMAIL_FROM_ADDRESS"),
        "EMAIL_FROM_NAME":     config.get("EMAIL_FROM_NAME"),
    }
    if not smtp_cfg["EMAIL_SMTP_HOST"]:
        return {"sent": False, "error": "SMTP not configured",
                "fallback": {"subject": req.subject, "text": req.body_text, "html": req.body_html}}
    cc = req.cc or config.get("EMAIL_COPY_TO") or ""
    out = send_smtp(req.subject, req.body_html, req.body_text, req.to, cc, smtp_cfg)
    # Log every send attempt to history regardless of outcome
    try:
        from intel.email_composer import append_history
        append_history({
            "to": req.to, "cc": cc, "subject": req.subject,
            "sent": bool(out.get("sent")),
            "error": out.get("error") if not out.get("sent") else None,
        })
    except Exception:
        pass
    return out


@app.get("/api/email/drafts")
async def email_drafts_list():
    """List every saved draft (most recent first)."""
    from intel.email_composer import list_drafts
    return {"drafts": list_drafts()}


@app.get("/api/email/drafts/{draft_id}")
async def email_draft_get(draft_id: str):
    from intel.email_composer import load_draft
    d = load_draft(draft_id)
    if not d:
        raise HTTPException(404, "draft not found")
    return d


@app.post("/api/email/drafts")
async def email_draft_save(req: dict):
    """Persist a composed email to backend/data/email_drafts/."""
    from intel.email_composer import save_draft
    return save_draft(req or {})


@app.delete("/api/email/drafts/{draft_id}")
async def email_draft_delete(draft_id: str):
    from intel.email_composer import delete_draft
    if not delete_draft(draft_id):
        raise HTTPException(404, "draft not found")
    return {"deleted": True}


@app.get("/api/email/history")
async def email_history_list():
    """Return the rolling send log (most recent first, capped at 200)."""
    from intel.email_composer import read_history
    return {"history": read_history()}


@app.post("/api/email/send-test")
async def email_send_test(req: dict):
    """Send a smoke-test email to the supplied recipient using the current
    SMTP configuration. Used by the Settings drawer's Send Test Email button."""
    from intel.email_composer import send_smtp
    to = (req or {}).get("to") or ""
    if not to:
        raise HTTPException(400, "to address required")
    smtp_cfg = {
        "EMAIL_SMTP_HOST":     config.get("EMAIL_SMTP_HOST"),
        "EMAIL_SMTP_PORT":     config.get("EMAIL_SMTP_PORT"),
        "EMAIL_SMTP_USER":     config.get("EMAIL_SMTP_USER"),
        "EMAIL_SMTP_PASSWORD": config.get("EMAIL_SMTP_PASSWORD"),
        "EMAIL_FROM_ADDRESS":  config.get("EMAIL_FROM_ADDRESS"),
        "EMAIL_FROM_NAME":     config.get("EMAIL_FROM_NAME"),
    }
    return send_smtp(
        "RECON Email Composer — SMTP test",
        "<p>If you're reading this, your RECON email tool SMTP is configured correctly.</p>",
        "If you're reading this, your RECON email tool SMTP is configured correctly.",
        to, "", smtp_cfg,
    )


# ─── MISP INGESTION ───────────────────────────────────────────────────────────────
@app.post("/api/ingest/misp")
async def ingest_misp(file: UploadFile = File(...)):
    import tempfile, os as _os
    content = await file.read()
    suffix = ".csv" if file.filename.endswith(".csv") else ".json"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False, mode="wb") as tmp:
        tmp.write(content)
        tmp_path = tmp.name
    try:
        iocs = parse_misp_csv(tmp_path) if suffix == ".csv" else parse_misp_json(tmp_path)
    finally:
        _os.unlink(tmp_path)
    by_type = {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []}
    for ioc in iocs:
        k = {"ip": "ips", "domain": "domains", "url": "urls", "hash": "hashes", "email": "emails"}.get(ioc["type"])
        if k:
            by_type[k].append(ioc["value"])
    by_type = {k: list(set(v)) for k, v in by_type.items()}
    return {"status": "parsed", "total_iocs": sum(len(v) for v in by_type.values()),
            "by_type": {k: len(v) for k, v in by_type.items()}, "iocs": by_type, "filename": file.filename}


# ─── TAXII ────────────────────────────────────────────────────────────────────────
@app.post("/api/taxii/poll")
async def taxii_poll(req: TaxiiPollRequest, background_tasks: BackgroundTasks):
    poll_id = str(uuid.uuid4())
    async def _poll():
        _taxii_cache[poll_id] = await poll_all_feeds(since_hours=req.sinceHours)
    background_tasks.add_task(_poll)
    return {"pollId": poll_id, "status": "polling"}

@app.get("/api/taxii/results/{poll_id}")
async def taxii_results(poll_id: str):
    return {"status": "complete", **_taxii_cache[poll_id]} if poll_id in _taxii_cache else {"status": "pending"}

@app.get("/api/taxii/feeds")
async def taxii_feeds():
    from intel.taxii_poller import FEEDS
    return {"feeds": [{"name": f["name"], "description": f["description"]} for f in FEEDS]}


# ─── FRONTEND ─────────────────────────────────────────────────────────────────────
if FRONTEND_BUILD.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_BUILD / "static")), name="static")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        if full_path.startswith("api/"):
            raise HTTPException(404)
        # Serve actual files from build/ when they exist (logo.png, favicon, manifest, etc.)
        if full_path:
            asset = FRONTEND_BUILD / full_path
            if asset.is_file() and asset.resolve().is_relative_to(FRONTEND_BUILD.resolve()):
                return FileResponse(str(asset))
        # Otherwise fall back to SPA index
        idx = FRONTEND_BUILD / "index.html"
        if idx.exists():
            return FileResponse(str(idx))
        raise HTTPException(404, "Frontend not built. Run: cd frontend && npm run build")


# ─── HELPERS ──────────────────────────────────────────────────────────────────────
def _add_history(run_id: str, result: dict, label: str):
    """Disabled for full per-investigation isolation: investigations are not
    accumulated into a cross-session history. (Per-run state is still held in
    _results for the lifetime of the current run so chat / export / clarify on
    THAT run keep working; nothing from one investigation feeds another.)"""
    return

def _ts():
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=os.getenv("HOST", "0.0.0.0"),
                port=int(os.getenv("PORT", 8000)), reload=False)
