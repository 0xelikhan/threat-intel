"""
Threat Intelligence Platform — FastAPI Backend
Single process: serves React frontend as static files + all API endpoints.
"""

import asyncio
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.responses import JSONResponse as _JSONResponse
from fastapi.responses import StreamingResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel, Field

from config import config, API_KEY_DEFINITIONS, FREE_APIS
from agents.orchestrator import run_pipeline
from intel.taxii_poller import poll_all_feeds, parse_misp_csv, parse_misp_json
from intel.auth import auth_configured, verify_credentials, current_user
from gti_score import compute_gti_scores, get_highest_score

from contextlib import asynccontextmanager


@asynccontextmanager
async def _lifespan(app):
    """Replaces the deprecated @app.on_event("startup") + ("shutdown")
    handlers. Code BEFORE the `yield` runs once at startup; code AFTER
    runs at graceful shutdown (Ctrl-C, container stop). The two
    halves are kept in this single function so startup-side state
    (background tasks created here, sockets opened) can be referenced
    by the shutdown side without module-level globals.
    """
    # ─── STARTUP ──────────────────────────────────────────────────────
    import asyncio

    # No-persistence policy: any analyst-derived state from a previous
    # container's lifetime must not survive a restart. Wipe known
    # legacy paths under backend/data/ on startup. config.json (operator
    # API keys) is preserved — that's platform config, not analyst data.
    try:
        from pathlib import Path
        import shutil
        _data_dir = Path(__file__).resolve().parent / "data"
        _doomed_files = (
            "audit.log",
            "calibration_overrides.jsonl",
            "email_history.json",
            "feed_cache.json",
            "scanner_feedback.json",
            "scanned_files.json",
        )
        _doomed_dirs = (
            "scanned_files",
            "email_drafts",
            "cases",
            "sandbox_results",
        )
        for name in _doomed_files:
            try:
                (_data_dir / name).unlink(missing_ok=True)
            except Exception as _e:
                _log.debug("cleanup skip %s: %s", name, _e)
        for name in _doomed_dirs:
            p = _data_dir / name
            if p.exists():
                try:
                    shutil.rmtree(p, ignore_errors=True)
                except Exception as _e:
                    _log.debug("cleanup skip %s/: %s", name, _e)
    except Exception as _e:
        _log.debug("startup cleanup failed: %s", _e)

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
            _log.info("pre-warm %s: %s (%.1fs)", name, "OK" if ok else "skip", dt)
        except Exception as e:
            _log.warning("pre-warm %s: skip (%s)", name, e)

    async def _warm_all():
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
            ("Feodo Tracker",  "intel.feeds_loader",        "refresh_feodo_now", None),
            ("Warning lists",  "intel.warninglist_filter",  "load_warninglists", None),
            ("YARA rules",     "intel.yara_scanner",        "_ruleset",        None),
        ]
        await asyncio.gather(*[_warm_one(*m) for m in light + heavy])
        # Register static-dataset namespaces in the TTL cache so they
        # appear in /api/status. A long-TTL marker entry keeps the
        # namespace non-empty for hit-rate accounting.
        try:
            from intel.cache import cache_for
            for ns in ("mitre", "warninglists", "feodo", "sslbl", "kev"):
                cache_for(ns).set("__warmed__", True)
        except Exception as e:
            _log.debug("cache namespace registration failed: %s", e)
        _log.info("all intel pre-warm tasks complete")

    track_task(asyncio.create_task(_warm_all()))

    # Spec §8: kick off the unified TAXII + FreshRSS polling loop.
    try:
        from intel.feed_aggregator import run_polling_loop
        track_task(asyncio.create_task(run_polling_loop(lambda: config.get_all() if hasattr(config, "get_all") else {
            "FRESHRSS_URL":     config.get("FRESHRSS_URL", ""),
            "FRESHRSS_API_KEY": config.get("FRESHRSS_API_KEY", ""),
        })))
        _log.info("feed aggregator polling loop scheduled")
    except Exception as e:
        _log.warning("feed aggregator NOT started: %s", e)

    # Feodo Tracker refresh every 6h — keeps the in-memory C2 list hot
    # without ever blocking an enrichment fan-out on the upstream fetch.
    async def _feodo_periodic():
        from intel.feeds_loader import refresh_feodo_now
        while True:
            await asyncio.sleep(6 * 3600)
            try:
                await asyncio.to_thread(refresh_feodo_now)
            except Exception as e:
                _log.debug("feodo periodic refresh failed: %s", e)
    track_task(asyncio.create_task(_feodo_periodic()))

    # Phishing.Database (mitchellkrogza) — hourly active phishing-domain
    # feed. Warmed on startup, then refreshed every hour. Domain triage
    # consults the in-memory set synchronously, so the feed needs to be
    # populated *before* the first analyze fires; if it isn't (network
    # outage), the lookup returns False and the rest of triage proceeds.
    async def _phishing_db_periodic():
        import aiohttp
        from intel.phishing_db import ensure_loaded
        while True:
            try:
                async with aiohttp.ClientSession() as s:
                    await ensure_loaded(s)
            except Exception as e:
                _log.debug("phishing_db refresh failed: %s", e)
            await asyncio.sleep(3600)
    track_task(asyncio.create_task(_phishing_db_periodic()))

    # Tranco top-1M ranked domains — once-a-day refresh. Domain triage
    # uses is_top_n() to avoid flagging Microsoft/Google/etc. when they
    # appear in an alert.
    async def _tranco_periodic():
        import aiohttp
        from intel.tranco import ensure_loaded as _tr_ensure
        while True:
            try:
                async with aiohttp.ClientSession() as s:
                    await _tr_ensure(s)
            except Exception as e:
                _log.debug("tranco refresh failed: %s", e)
            await asyncio.sleep(24 * 3600)
    track_task(asyncio.create_task(_tranco_periodic()))

    _log.info("startup: pre-warm scheduled in background, accepting requests now")

    # Self-diagnosis: once at startup, then every 15 min for /api/health.
    try:
        from intel.diagnose import run_startup_checks, background_health_loop
        track_task(asyncio.create_task(run_startup_checks()))
        track_task(asyncio.create_task(background_health_loop(interval_s=900)))
        _log.info("self-diagnosis scheduled")
    except Exception as e:
        _log.warning("self-diagnosis NOT started: %s", e)

    yield   # ─── App runs here ───────────────────────────────────────

    # ─── SHUTDOWN ─────────────────────────────────────────────────────
    # Cancel every long-lived background task we spawned at startup
    # (warm-up, feed polling, Feodo refresh, health probe, diagnostics).
    # Without explicit cancellation uvicorn waits for them on shutdown
    # — the periodic loops have `while True: await asyncio.sleep(6h)`
    # so the await never returns and uvicorn's grace period eventually
    # SIGKILLs the worker. Doing it ourselves gives a clean exit.
    try:
        from bg_utils import _BG_TASKS
        for _bg in list(_BG_TASKS):
            if not _bg.done():
                _bg.cancel()
    except Exception as _e:
        _log.debug("bg task cancel failed: %s", _e)

    # Close the shared TCP connector used by the enrichment fan-out so
    # we don't leak sockets on graceful shutdown.
    try:
        from agents.enrichment import close_connector
        await close_connector()
    except Exception as e:
        _log.debug("connector close failed: %s", e)


app = FastAPI(title="Threat Intelligence Platform", version="3.0.0",
              docs_url="/api/docs", redoc_url=None,
              openapi_url="/api/openapi.json",
              lifespan=_lifespan)

# Hold strong references to long-lived background tasks. asyncio only
# keeps a weakref to scheduled tasks, so a fire-and-forget
# `asyncio.create_task(...)` can be garbage-collected before the
# coroutine completes. Any background work that outlives the request
# that spawned it (sandbox polling, post-scan AI fan-out, periodic
# refresh loops) should go through track_task() instead. Implementation
# in bg_utils.py so the test suite can exercise it without paying the
# full main.py import cost.
from bg_utils import _BG_TASKS, track_task  # noqa: F401

# Structured logging + per-request UUID. Configured before anything else
# touches logging so the first log line carries the right format.
from intel.observability import (
    configure_logging,
    RequestIDMiddleware,
    error_envelope,
)
configure_logging()
import logging as _logging
_log = _logging.getLogger("recon.main")


def _clean_exc(e: BaseException, *, prefix: str = "") -> str:
    """Map any exception to a short analyst-readable string. Drops SDK
    reprs like aiohttp's '0, message='', url=URL(...)' or OpenAI's
    'APIError' wrappers. Use this any time an exception is going into a
    user-visible field (HTTPException detail, SSE error event, persisted
    'error' key in a scan result). `prefix` is prepended verbatim so
    callers can give context: _clean_exc(e, prefix='MalwareBazaar') →
    'MalwareBazaar: request timed out after 30s'."""
    try:
        import aiohttp
    except Exception:
        aiohttp = None

    def _label(label: str) -> str:
        return f"{prefix}: {label}" if prefix else label

    if isinstance(e, asyncio.TimeoutError):
        return _label("request timed out")
    if aiohttp is not None:
        if isinstance(e, getattr(aiohttp, "TooManyRedirects", ())):
            return _label("too many redirects")
        if isinstance(e, getattr(aiohttp, "InvalidURL", ())):
            return _label("URL is malformed")
        if isinstance(e, getattr(aiohttp, "ClientConnectorError", ())):
            return _label("could not connect (DNS or refused)")
        if isinstance(e, getattr(aiohttp, "ServerDisconnectedError", ())):
            return _label("server closed the connection before responding")
        if isinstance(e, getattr(aiohttp, "ClientPayloadError", ())):
            return _label("malformed or truncated response body")
        if isinstance(e, getattr(aiohttp, "ClientResponseError", ())):
            status = getattr(e, "status", 0) or 0
            if status > 0:
                msg = getattr(e, "message", "") or ""
                return _label(f"HTTP {status}" + (f" ({msg})" if msg else ""))
            return _label("server returned an empty or malformed response")
    msg = str(e).strip()
    if (not msg
            or msg.startswith("0, message=")
            or "message='', url=URL(" in msg):
        # SDK noise — surface the class name in a human shape.
        cls = type(e).__name__
        human = (cls.replace("Error", " error")
                    .replace("Exception", " exception")
                    .replace("Client", "client ").strip().lower())
        return _label(human or "unknown error")
    return _label(msg[:200])

# CORS. The frontend is served same-origin from this app in production, so
# CORS is only needed for the local dev server (CRA on :3000 → :8000). A
# wildcard `*` combined with `allow_credentials=True` is rejected by every
# modern browser (and is unsafe even when it's not), so the default origin
# list is restricted. Operators can override via RECON_CORS=https://a,https://b.
_cors_env = (os.environ.get("RECON_CORS") or "").strip()
_cors_origins = (
    [o.strip() for o in _cors_env.split(",") if o.strip()]
    if _cors_env and _cors_env != "*"
    else ["http://localhost:3000", "http://127.0.0.1:3000"]
)
app.add_middleware(CORSMiddleware, allow_origins=_cors_origins,
                   allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# Compress JSON responses >= 1 KB. Browsers / proxies all negotiate gzip
# automatically via Accept-Encoding; analyze responses can hit 200-400 KB
# pre-compression so this is a meaningful network win on every page load.
# minimum_size=1024 skips tiny payloads where the gzip framing overhead
# would actually grow the response.
app.add_middleware(GZipMiddleware, minimum_size=1024)

# Per-request UUID — outermost so every log line in every handler
# carries the same rid. Echoed back as X-Request-ID for client tooling.
app.add_middleware(RequestIDMiddleware)


# HTTP HEAD support. FastAPI routes default to GET-only, so every
# uptime monitor / browser favicon discovery / RFC-compliant client
# that sends HEAD on a GET endpoint used to get a 405. Map HEAD → GET
# upstream of the router, then strip the response body so the headers
# still match what GET would have produced.
@app.middleware("http")
async def _head_to_get(request: Request, call_next):
    if request.method == "HEAD":
        request.scope["method"] = "GET"
        response = await call_next(request)
        response.body_iterator = _empty_body()
        # Content-Length stays accurate (per HTTP/1.1 RFC 7230 §4.3.2:
        # HEAD must return the same Content-Length as GET would).
        return response
    return await call_next(request)


async def _empty_body():
    if False:
        yield b""
    return


# Global error envelope — additive. The existing `detail` key (which the
# React frontend reads via `err.detail || err.error`) is preserved; new
# fields (`error_code`, `details`, `request_id`, `ts`) are stacked on.
@app.exception_handler(StarletteHTTPException)
async def _http_exc_handler(_request, exc: StarletteHTTPException):
    body = error_envelope(
        detail=str(exc.detail) if exc.detail is not None else "HTTP error",
        code=f"http_{exc.status_code}",
        status=exc.status_code,
    )
    headers = dict(exc.headers or {})
    return _JSONResponse(body, status_code=exc.status_code, headers=headers)


@app.exception_handler(RequestValidationError)
async def _validation_exc_handler(_request, exc: RequestValidationError):
    body = error_envelope(
        detail="Request validation failed",
        code="validation_error",
        extras={"errors": exc.errors()[:10]},
        status=422,
    )
    return _JSONResponse(body, status_code=422)


# Catch-all for anything that escapes the typed handlers above. Without
# this, an uncaught exception (e.g. POSTing to a JSON endpoint with no
# Content-Type header, which trips FastAPI's body parser BEFORE it
# becomes a RequestValidationError) falls through to Starlette's
# default `Internal Server Error` plain-text 500 — which breaks the
# `err.detail || err.error` shape every other API error response uses.
@app.exception_handler(Exception)
async def _catchall_exc_handler(request, exc: Exception):
    _log.exception("unhandled exception in handler chain: %s", exc)
    # ExceptionMiddleware fires OUTSIDE RequestIDMiddleware in
    # Starlette's chain, so by the time we get here the
    # current_request_id() contextvar has already been reset. Pull
    # from the inbound header or mint a fresh UUID so the 500
    # envelope can still carry a correlation id, then prime the
    # contextvar so error_envelope() picks it up.
    import uuid as _uuid
    from intel.observability import request_id_var, _RID_RE
    inbound = request.headers.get("X-Request-ID")
    rid = inbound if inbound and _RID_RE.match(inbound) else str(_uuid.uuid4())
    request_id_var.set(rid)
    body = error_envelope(
        detail="Internal server error",
        code="internal_error",
        status=500,
    )
    return _JSONResponse(body, status_code=500,
                        headers={"X-Request-ID": rid})

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
        # CORS preflight OPTIONS requests carry no credentials by design
        # — browsers send them to discover whether the cross-origin POST
        # is permitted. Gating them on auth means CORSMiddleware never
        # gets to ship the Access-Control-Allow-* headers and the
        # browser refuses the actual request without ever trying. Let
        # OPTIONS pass through; CORSMiddleware (added INSIDE this one)
        # will short-circuit it correctly.
        if request.method == "OPTIONS":
            return await call_next(request)
        if current_user(request.session):
            return await call_next(request)
        # Middleware can't raise HTTPException through the global handler —
        # the exception fires before the handler chain. Build the envelope
        # inline so 401s carry the same shape (error_code/request_id/ts)
        # as every other API error response.
        # AuthGate runs OUTSIDE RequestIDMiddleware so the contextvar isn't
        # populated yet when we reject; pull it from the inbound
        # X-Request-ID header (reverse-proxy trace ID propagation) or
        # generate a fresh UUID and prime the contextvar so error_envelope
        # picks it up. Also stamp the header on the response so the
        # client can grep logs.
        import uuid as _uuid
        from intel.observability import request_id_var, _RID_RE
        inbound = request.headers.get("X-Request-ID")
        rid = inbound if inbound and _RID_RE.match(inbound) else str(_uuid.uuid4())
        request_id_var.set(rid)
        body = error_envelope(
            detail="auth required",
            code="auth_required",
            status=401,
        )
        return JSONResponse(body, status_code=401,
                            headers={"X-Request-ID": rid})


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
if (_SESSION_SECRET == "dev-only-not-for-production"
        and (os.environ.get("RECON_ENV") or "").lower() == "production"):
    # Fail-closed: a production deploy that boots with the public dev
    # key signs every session cookie with a string anyone can read in
    # this file. The earlier _log.error() was easy to miss in noisy
    # container startup logs and the platform would happily serve
    # forgeable sessions. Refuse to construct the middleware instead
    # so the deploy probe fails until the operator wires the env var.
    raise RuntimeError(
        "AUTH_SESSION_SECRET is required when RECON_ENV=production. "
        "Set it to a 32+ byte random string before serving traffic."
    )
# Cookie Secure flag gated on RECON_HTTPS so local plain-HTTP dev can
# actually receive the session cookie. https_only=True ships the Secure
# attribute, which strict HTTP clients (PowerShell Invoke-RestMethod /
# .NET HttpClient) reject over plain HTTP — so any non-browser smoke
# test or CLI helper hitting localhost:8000 couldn't establish a session.
# Production behind Azure Container Apps (TLS-terminated) sets RECON_HTTPS=1.
_HTTPS_ONLY = (os.environ.get("RECON_HTTPS") or "").lower() in {"1", "true", "yes"}
app.add_middleware(
    SessionMiddleware,
    secret_key=_SESSION_SECRET,
    session_cookie="recon_session",
    same_site="strict",
    https_only=_HTTPS_ONLY,
    max_age=60 * 60 * 12,  # 12 h
)


# Startup + shutdown logic moved to the _lifespan handler above
# (FastAPI deprecated @app.on_event in favour of a single lifespan
# context manager).

# BoundedDict lives in bg_utils.py so tests can hit it without paying
# the full FastAPI import cost — see test_bounded_dict.py.
from bg_utils import BoundedDict as _BoundedDict

_results: dict = _BoundedDict(cap=500)
# Sandbox job tracker: { job_id: { state, submitted_at, sha256, ... } }
_sandbox_jobs: dict[str, dict] = _BoundedDict(cap=500)
# Chat conversations per run: { run_id: [{role, content, timestamp}, ...] }
_chats: dict[str, list] = _BoundedDict(cap=500)
_taxii_cache: dict = _BoundedDict(cap=100)

FRONTEND_BUILD = Path(__file__).parent.parent / "frontend" / "build"


# ─── SCHEMAS ──────────────────────────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    # 1 MB pasteable log per request — keeps the LLM prompt bounded
    # while still accepting full event-grid / Defender exports. The
    # 50 MB outer cap is for the file-scan endpoints; pasted text is
    # tighter.
    logText: str = Field(..., min_length=1, max_length=1_000_000)
    inputType: str = "log"
    label: Optional[str] = Field(default=None, max_length=200)
    # Optional analyst-provided verdict and context. When present the
    # investigation prompt renders an "ANALYST VERDICT AND CONTEXT" block
    # at the top of the user message and instructs the AI to treat the
    # analyst's findings as authoritative when they conflict with its own
    # inference. Used by the post-analysis feedback re-run flow.
    # Capped at 4 KB — the investigation prompt truncates to 2000 chars
    # internally; the schema cap stops an analyst from re-paste-attacking
    # the body cap with megabyte-long "feedback" that the prompt would
    # have thrown away anyway.
    analystFeedback: Optional[str] = Field(default=None, max_length=4_000)

class TaxiiPollRequest(BaseModel):
    # 1 hour to 30 days is the reasonable window the UI dropdown maps to.
    # An unbounded int let a caller pass negative values (future date,
    # returns nothing) or absurdly large ones (no upstream impact but a
    # confusing UI surface).
    sinceHours: int = Field(default=24, ge=1, le=720)

class SettingsRequest(BaseModel):
    keys: dict

class DetectionRequest(BaseModel):
    action: str = Field(..., max_length=64)
    iocs: Optional[dict] = None
    analysis: Optional[dict] = None
    query: Optional[str] = Field(default=None, max_length=500)
    mitreTechniques: Optional[list] = Field(default=None, max_length=100)

class GTIScoreRequest(BaseModel):
    enrichments: dict

class DomainPermutationsRequest(BaseModel):
    """Body for /api/hunt/permutations. Triggers dnstwist-based lookalike
    enumeration for a single domain, optionally with DNS resolution per variant
    so the analyst sees which permutations are real registered domains."""
    domain:           str  = Field(..., max_length=253)
    max_results:      Optional[int]  = Field(default=25)
    resolve:          Optional[bool] = Field(default=True)
    high_signal_only: Optional[bool] = Field(default=False)


class HuntPlanRequest(BaseModel):
    """Body for /api/hunt/plan. Re-uses the verdict + IOCs + MITRE coverage
    produced by /api/analyze to derive 3-5 hypotheses, an ABLE table, and a
    structured hunt plan. `hypothesis` is optional — when blank the first
    auto-generated hypothesis is used to drive ABLE + plan."""
    iocs:       Optional[dict] = None
    analysis:   Optional[dict] = None
    hypothesis: Optional[str]  = Field(default=None, max_length=2000)


# ─── Self-contained route groups extracted to backend/routers/ ───────────
# Mounted here so the URL paths + middleware behaviour are unchanged.
# Proof-of-concept split — the rest of main.py is too cross-coupled to
# move without a deeper refactor, but new routes go in routers/.
from routers import calibration as _calibration_router
from routers import sandbox     as _sandbox_router
app.include_router(_calibration_router.router)
app.include_router(_sandbox_router.router)


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
    if not _llm_key_configured():
        return {"ok": False, "error": "No LLM provider configured for the active LLM_PROVIDER"}
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
async def health(request: Request):
    """Public liveness + (when authenticated) full status snapshot.

    Unauthenticated callers — the Docker HEALTHCHECK, the Azure
    Container Apps deploy probe — get a minimal {status, version,
    timestamp} envelope. That's all a probe needs.

    Authenticated callers (the frontend dashboard reading via cookie)
    get the full breakdown: which API keys are wired up, which
    webhooks are available, the cache + circuit-breaker + diagnosis
    rollups. The full payload used to leak to unauth callers — an
    information disclosure surface (which TI sources are wired, which
    webhook destinations are configured) for free reconnaissance.
    """
    is_authed = bool(current_user(request.session))
    base = {
        "status":    "ready" if config.is_configured() else "setup_required",
        "version":   "3.0.0",
        "timestamp": _ts(),
    }
    if not is_authed:
        return base

    status = config.get_status()
    missing = [k for k, v in status.items() if v["required"] and not v["configured"]]
    # Additive: existing fields untouched, plus a `cache` rollup so the
    # status page can show hit rate without breaking older clients that
    # only read the legacy keys.
    try:
        from intel.cache import global_stats as _cache_stats
        cache_block = _cache_stats()
    except Exception as e:
        cache_block = {"error": _clean_exc(e, prefix="cache stats")}
    try:
        from intel.circuit_breaker import get_breaker as _get_breaker
        breaker_block = _get_breaker().stats()
    except Exception as e:
        breaker_block = {"error": _clean_exc(e, prefix="breaker stats")}
    # Live diagnosis snapshot — updated by the 15-min background loop
    # so /api/health reflects current source / AI provider state, not
    # the boot-time snapshot. Additive — old fields preserved.
    try:
        from intel.diagnose import get_current_health
        diagnosis_block = get_current_health()
    except Exception as e:
        diagnosis_block = {"error": _clean_exc(e, prefix="health probe")}
    return {
        **base,
        "configured":      config.is_configured(),
        "ai_provider":     config.get_ai_provider(),
        "azure_openai":    config.is_azure_openai(),
        "apiKeys":         {k: v["configured"] for k, v in status.items()},
        "requiredMissing": missing,
        "cachedRuns":      len(_results),
        "webhooks":        _webhooks_available(),
        "intel_layer":     _intel_status(),
        "cache":           cache_block,
        "circuit_breaker": breaker_block,
        "diagnosis":       diagnosis_block,
    }


# ─── /api/diagnose — on-demand self-diagnosis report ────────────────────────
@app.get("/api/diagnose")
async def diagnose():
    """Run every health check on demand and return the full report. Each
    entry carries {name, status, message, fix_hint, detail} so the UI
    can render an actionable list."""
    from intel.diagnose import run_all_checks
    return await run_all_checks()


# ─── Auth ────────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    # Cap both fields so an attacker can't ship megabyte-long credentials
    # to slow down bcrypt verification (bcrypt only hashes the first 72
    # bytes of password but reads the whole input first). Username sees
    # a constant-time comparison; password feeds bcrypt.checkpw. 256/1024
    # is well above any realistic credential length.
    username: str = Field(..., min_length=1, max_length=256)
    password: str = Field(..., min_length=1, max_length=1024)


# Per-IP login throttle. Sliding 60-second window of failure timestamps;
# after 5 failures the IP gets a 429 with Retry-After until the oldest
# failure expires. Without this, the bcrypt-rounds=12 cost (~250ms per
# verify) is the only thing slowing a brute-force attempt — and an
# attacker who concurrent-POSTs can still saturate worker capacity.
_LOGIN_FAILURES: dict = _BoundedDict(cap=2000)
_LOGIN_WINDOW_S    = 60
_LOGIN_MAX_FAILURES = 5

# Per-username throttle complements the per-IP one. Per-IP alone gets
# defeated by an attacker rotating across IPs (cloud / Tor / botnet) —
# each fresh IP starts with a clean 5-attempt budget against the same
# username. The per-username window is wider (15 min) and higher (20
# attempts) than the per-IP one: legitimate users almost never hit it,
# but the cumulative-across-the-internet attempt count does. Eviction
# at 200 distinct usernames means an attacker who rotates BOTH IPs AND
# usernames can still degrade tracking, but at that point they're just
# guessing usernames blind — which doesn't help them against the one
# username that's actually configured.
_LOGIN_USER_FAILURES: dict = _BoundedDict(cap=200)
_LOGIN_USER_WINDOW_S     = 15 * 60
_LOGIN_USER_MAX_FAILURES = 20


def _login_client_ip(request: Request) -> str:
    # Honour X-Forwarded-For only when the operator opts in via
    # RECON_TRUST_PROXY=1, matching the audit middleware's
    # _audit_client_ip behaviour. Without the gate, the throttle would
    # trust an arbitrary inbound XFF — meaning on a dev box / any
    # deployment NOT behind a TLS proxy that strips XFF, an attacker
    # could rotate the "IP" the throttle keys off by spoofing the
    # header. The per-username throttle (15 min / 20 attempts) covers
    # this even when the per-IP layer is bypassed, but consistency
    # with the audit attribution helper means both layers see the same
    # universe of identifiers.
    if (os.environ.get("RECON_TRUST_PROXY") or "").lower() in {"1", "true", "yes"}:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",", 1)[0].strip()[:64]
    return (str(request.client.host) if request.client else "unknown")[:64]


@app.post("/api/auth/login")
async def auth_login(req: LoginRequest, request: Request):
    """Validate credentials and start a signed-cookie session. 503 when the
    operator hasn't wired up AUTH_USERNAME / AUTH_PASSWORD_HASH yet (so an
    empty deployment doesn't silently 401 forever)."""
    if not auth_configured():
        raise HTTPException(503, "authentication is not configured on this deployment")
    # Per-IP throttle check. Walk the IP's window, drop expired entries,
    # then check the live count.
    _ip = _login_client_ip(request)
    _now = time.time()
    _window = _LOGIN_FAILURES.get(_ip) or []
    _window = [t for t in _window if (_now - t) < _LOGIN_WINDOW_S]
    # Per-username throttle. Same shape but wider window so it captures
    # IP-rotating brute-force across hours, not just within 60 s. Keyed
    # by the username the caller is TARGETING — not the configured
    # one — so an attacker probing different usernames doesn't share a
    # bucket with the real user.
    _user_key = (req.username or "").strip().lower()[:64]
    _user_window = _LOGIN_USER_FAILURES.get(_user_key) or []
    _user_window = [t for t in _user_window if (_now - t) < _LOGIN_USER_WINDOW_S]
    if len(_window) >= _LOGIN_MAX_FAILURES:
        _retry_after = int(max(1, _LOGIN_WINDOW_S - (_now - _window[0])))
        # Emit an audit event so the brute-force attempt shows up in
        # the same stream as the underlying auth_failure records.
        try:
            from intel.security import audit_log
            audit_log("auth_throttled", client=_ip,
                      window_failures=len(_window),
                      retry_after_s=_retry_after, reason="per_ip")
        except Exception:
            pass
        raise HTTPException(
            429, "too many failed login attempts — wait and retry",
            headers={"Retry-After": str(_retry_after)},
        )
    if len(_user_window) >= _LOGIN_USER_MAX_FAILURES:
        _retry_after = int(max(1, _LOGIN_USER_WINDOW_S - (_now - _user_window[0])))
        try:
            from intel.security import audit_log
            audit_log("auth_throttled", client=_ip, username=_user_key,
                      window_failures=len(_user_window),
                      retry_after_s=_retry_after, reason="per_username")
        except Exception:
            pass
        raise HTTPException(
            429, "too many failed login attempts for this user — wait and retry",
            headers={"Retry-After": str(_retry_after)},
        )
    if not verify_credentials(req.username, req.password):
        # Record this failure inside both sliding windows.
        _window.append(_now)
        _LOGIN_FAILURES[_ip] = _window
        _user_window.append(_now)
        _LOGIN_USER_FAILURES[_user_key] = _user_window
        try:
            from intel.security import audit_log
            audit_log("auth_failure", username=(req.username or "").strip()[:64],
                      client=_ip)
        except Exception:
            pass
        raise HTTPException(401, "invalid credentials")
    # Successful login clears both failure windows so a legitimate
    # user who mistyped once isn't stuck for 60s / 15 min.
    _LOGIN_FAILURES[_ip] = []
    _LOGIN_USER_FAILURES[_user_key] = []
    request.session["auth_user"] = req.username.strip()
    # Log successful logins too — a security audit trail with only
    # failures is incomplete. An attacker who steals a credential and
    # successfully logs in is the most interesting event to have on
    # tape, not the failed brute-force attempts.
    try:
        from intel.security import audit_log
        audit_log("auth_success", username=req.username.strip()[:64],
                  client=_login_client_ip(request))
    except Exception:
        pass
    return {"ok": True, "user": req.username.strip()}


@app.post("/api/auth/logout")
async def auth_logout(request: Request):
    """Clear the session cookie. Safe to call when not logged in."""
    # Capture the user BEFORE we clear the session so the audit log
    # actually has someone to attribute the logout to.
    _user = current_user(request.session) or ""
    request.session.clear()
    if _user:
        try:
            from intel.security import audit_log
            audit_log("auth_logout", username=_user[:64],
                      client=_login_client_ip(request))
        except Exception:
            pass
    return {"ok": True}


@app.get("/api/auth/me")
async def auth_me(request: Request):
    """Frontend uses this on app mount to decide whether to render LoginPage
    or the main app. 200 + user when authed, 401 otherwise."""
    user = current_user(request.session)
    if not user:
        raise HTTPException(401, "not authenticated")
    return {"user": user}


def _webhooks_available() -> dict:
    try:
        from intel.webhooks import available
        return available(config)
    except Exception:
        return {}


def _intel_status() -> dict:
    """Snapshot of how much offline intelligence is loaded. Each module's
    stats() is called independently — a single broken stats() must not
    blank the whole status report. Failures log at debug level so a
    permanently-broken module surfaces in the build/dev logs."""
    out = {}
    _sources = [
        ("feeds_loader",     "intel.feeds_loader"),
        ("actor_data",       "intel.actor_data"),
        ("kev",              "intel.kev"),
        ("epss",             "intel.epss"),
        ("lolbas",           "intel.lolbas"),
        ("loldrivers",       "intel.loldrivers"),
        ("atomic_red_team",  "intel.atomic_red_team"),
        ("yara_scanner",     "intel.yara_scanner"),
        ("phishing_kit",     "intel.phishing_kit"),
        ("ja_fingerprints",  "intel.ja_fingerprints"),
    ]
    for name, mod_path in _sources:
        try:
            import importlib
            mod = importlib.import_module(mod_path)
            fn = getattr(mod, "stats", None)
            if fn:
                out.update(fn())
        except Exception as e:
            _log.debug("intel_status: %s.stats() failed: %s", name, e)
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


async def _stream(raw_input: str, input_type: str, label: str = "",
                   analyst_feedback: str = ""):
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

    # Background tasks (enrichment, investigation) we asyncio.create_task and
    # await later in the generator. If the client disconnects mid-stream
    # (browser tab closed, network blip), Python cancels the generator but
    # asyncio's event loop still holds strong refs to these tasks — they'd
    # run to completion in the background, burning LLM cost on a dead
    # client. Track them here and cancel in the finally block.
    _bg_tasks: list[asyncio.Task] = []

    try:
        # Centralised initial-state builder lives in orchestrator.py so the
        # streaming and sync paths can't drift apart. Includes every key
        # the SOCState TypedDict declares — including the ones populated
        # by later stages — so downstream `state[key]` reads see a typed
        # default instead of falling back to `.get(key, default)`.
        from agents.orchestrator import make_initial_state
        state = make_initial_state(raw_input, input_type, analyst_feedback)

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
        has_enrichable = any((iocs.get(k) or []) for k in
                             ("ips", "domains", "hashes", "urls", "emails", "cves"))
        if has_enrichable:
            # Stream each IOC type's enrichment as it lands so cards fill
            # progressively rather than all at once when the slowest type returns.
            enr_q: asyncio.Queue = asyncio.Queue()
            async def _on_enrich_partial(snap, _q=enr_q):
                await _q.put(("partial", snap))
            enr_task = asyncio.create_task(run_enrichment(state, on_partial=_on_enrich_partial))
            _bg_tasks.append(enr_task)
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
        _bg_tasks.append(inv_task)
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
            "threat_level":            inv.get("threat_level"),
            "threat_level_reasoning":  inv.get("threat_level_reasoning", ""),
            "confidence":              inv.get("confidence"),
            "summary":                 inv.get("summary"),
            "key_findings":            inv.get("key_findings", []),
            "ioc_assessments":         inv.get("ioc_assessments", []),
            "mitre_techniques":        inv.get("mitre_techniques", []),
            "attack_patterns":         inv.get("attack_patterns", []),
            "chain_of_thought":        inv.get("chain_of_thought", []),
            "recommended_actions":     inv.get("recommended_actions", []),
            "log_correlation":         inv.get("log_correlation"),
            "cross_refs":              state.get("cross_refs", {}),
            "timestamp":               _ts(),
        }
        state["response_summary"] = early_rs
        yield f"data: {json.dumps({'event': 'partial_result', 'runId': run_id, 'result': _strip(state, run_id, label)})}\n\n"

        # ── Stage 4: RESPONSE (Sigma/KQL/multi-SIEM/analyst hand-off) ───────
        state = await run_response(state)
        trace = state.get("agent_trace", [])
        if trace:
            yield f"data: {json.dumps({'event': 'agent_update', 'runId': run_id, 'trace': trace[-1]})}\n\n"

        # Final post-processing: per-investigation isolation means we
        # never read state from a prior run, so ioc_pivot is always
        # empty and there's nothing to index. Kept as an empty list in
        # the result so the frontend's `result?.ioc_pivot || []` reader
        # has the field it expects.
        final = _strip(state, run_id, label)
        final["ioc_pivot"] = []
        _results[run_id] = state

        yield f"data: {json.dumps({'event': 'complete', 'runId': run_id, 'result': final, 'timestamp': _ts()})}\n\n"

    except Exception as e:
        _log.exception("analyze stream failed run_id=%s", run_id)
        yield f"data: {json.dumps({'event': 'error', 'runId': run_id, 'error': _clean_exc(e)})}\n\n"
    finally:
        # Cancel any background tasks the client never got to see finish.
        # On normal completion they're already done so cancel() is a no-op;
        # on client disconnect (GeneratorExit / CancelledError) this stops
        # the orphan from continuing to run.
        for _t in _bg_tasks:
            if not _t.done():
                _t.cancel()
    yield "data: [DONE]\n\n"

@app.post("/api/analyze")
async def analyze_stream(req: AnalyzeRequest):
    if not req.logText.strip():
        raise HTTPException(400, "logText required")
    return StreamingResponse(
        _stream(req.logText, req.inputType, req.label or "",
                analyst_feedback=req.analystFeedback or ""),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

@app.post("/api/analyze/sync")
async def analyze_sync(req: AnalyzeRequest):
    if not req.logText.strip():
        raise HTTPException(400, "logText required")
    if not config.is_configured():
        raise HTTPException(503, "Add API keys in Settings first.")
    run_id = str(uuid.uuid4())
    # run_pipeline now drives the full triage → enrichment → investigation
    # → response graph, and run_response computes gti_scores onto state.
    # No post-hoc mutation here — the agent contract owns its output keys.
    state = await run_pipeline(req.logText, req.inputType,
                                analyst_feedback=req.analystFeedback or "")
    _results[run_id] = state
    result = {k: v for k, v in state.items() if k != "stix_bundle"}
    result.update({"runId": run_id})
    return result


class ClarifyRequest(BaseModel):
    answers: dict   # {question_text: answer_text}


@app.post("/api/analyze/clarify/{run_id}")
async def analyze_clarify(run_id: str, req: ClarifyRequest):
    """Spec §5 Phase 2: re-run investigation with analyst answers to clarifying
    questions. Re-uses the original triage/enrichment state — only the AI
    investigation step runs again, with analyst_answers appended to the prompt.

    Consumed by: documented in /api/docs as part of the public REST surface.
    The frontend wires the analyst-feedback re-run through /api/analyze itself
    (with `analystFeedback` in the body) instead of through this endpoint —
    they're equivalent paths to the same outcome, kept distinct so external
    tooling can re-run just the investigation step without re-paying the
    enrichment fan-out.
    """
    if run_id not in _results:
        raise HTTPException(404, f"unknown run_id {run_id}")
    if not req.answers:
        raise HTTPException(400, "answers required")
    # Same 16KB cap as /api/scan/clarify — prevents an analyst from
    # pasting the whole log into a clarifying answer and blowing out the
    # prompt budget on the re-run.
    _answers_size = sum(len(str(q)) + len(str(a)) for q, a in req.answers.items())
    if _answers_size > 16_000:
        raise HTTPException(413,
            f"answers too large ({_answers_size:,} chars; cap is 16,000)")

    # Deep-copy so the re-investigation's mutations to nested lists/dicts
    # (agent_trace.append, investigation_result writes, …) don't pollute the
    # cached prior run. The shallow `dict(...)` used to share `agent_trace`
    # by reference, so a clarify call would append its trace entries onto
    # the original run's history.
    import copy as _copy
    state = _copy.deepcopy(_results[run_id])
    state["analyst_answers"] = req.answers

    from agents.investigation import run_investigation
    try:
        state = await run_investigation(state)
    except Exception as e:
        raise HTTPException(503, _clean_exc(e, prefix="re-investigation"))

    # Refresh GTI scores and persist updated state
    state["gti_scores"] = compute_gti_scores(state.get("enrichments", {}))
    _results[run_id] = state
    result = {k: v for k, v in state.items() if k != "stix_bundle"}
    result.update({"runId": run_id, "rephased": True})
    return result


# ─── Attribution: MalwareBazaar hash pivot ──────────────────────────────────
#
# The AttributionChip's "Hunt for" tab needs concrete sample hashes for
# malware-typed entries (Mivast, Sakula, Derusbi, etc.). MITRE STIX
# doesn't carry hashes; abuse.ch's MalwareBazaar does. This endpoint is
# called on demand from the frontend so we don't slow down /api/analyze
# with extra outbound HTTPS calls per matched actor.
_MB_HASH_CACHE: dict = _BoundedDict(cap=500)   # family_name.lower() -> {ts, payload}

@app.get("/api/attribution/hashes")
async def attribution_hashes(family: str, limit: int = 10):
    """Return up to N recent SHA256 / SHA1 / MD5 samples for a malware
    family from abuse.ch MalwareBazaar. Returns:
      { "family": "...", "hashes": [{sha256, sha1, md5, file_name,
                                     file_type, first_seen, signature}],
        "source": "MalwareBazaar (abuse.ch)" }
    or { "error": "..." } when the API is unavailable / rate-limited /
    returns no matches. The frontend renders the error verbatim so the
    analyst knows the lookup failed rather than seeing an empty list.
    """
    fam = (family or "").strip()
    if not fam or len(fam) > 80:
        raise HTTPException(400, "family required (<=80 chars)")
    cache_key = fam.lower()
    now = time.time()
    cached = _MB_HASH_CACHE.get(cache_key)
    if cached and (now - cached["ts"] < 21600):   # 6h cache
        return cached["payload"]

    # abuse.ch added required authentication on the MalwareBazaar API in
    # late 2023 — every endpoint now needs an Auth-Key header. The key is
    # free at https://auth.abuse.ch but it must be provisioned by the
    # operator. Look it up under multiple config aliases so existing
    # deployments don't have to rename their stored key.
    auth_key = (config.get("MALWAREBAZAAR_API_KEY")
                or config.get("ABUSE_CH_AUTH_KEY")
                or config.get("ABUSECH_AUTH_KEY")
                or os.environ.get("MALWAREBAZAAR_API_KEY")
                or os.environ.get("ABUSE_CH_AUTH_KEY")
                or "").strip()
    if not auth_key:
        return {"family": fam, "hashes": [],
                "error": ("MalwareBazaar requires an Auth-Key as of Nov 2023. "
                          "Get a free key at https://auth.abuse.ch and save "
                          "it under Settings → MALWAREBAZAAR_API_KEY."),
                "source": "MalwareBazaar (abuse.ch)",
                "needs_auth_key": True}

    import aiohttp
    from agents.enrichment import _get_connector
    limit = max(1, min(int(limit or 10), 50))
    headers = {
        "User-Agent": "RECON/1.0 (+attribution-pivot)",
        "Auth-Key":   auth_key,
    }
    try:
        async with aiohttp.ClientSession(
            connector=_get_connector(),
            connector_owner=False,
            timeout=aiohttp.ClientTimeout(total=12),
        ) as session:
            async with session.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_siginfo", "signature": fam,
                      "limit": str(limit)},
                headers=headers,
            ) as r:
                if r.status == 401:
                    return {"family": fam, "hashes": [],
                            "error": ("MalwareBazaar rejected the Auth-Key "
                                      "(HTTP 401). Verify the key under "
                                      "Settings → MALWAREBAZAAR_API_KEY is "
                                      "still active at auth.abuse.ch."),
                            "source": "MalwareBazaar (abuse.ch)",
                            "needs_auth_key": True}
                if r.status != 200:
                    return {"family": fam, "hashes": [],
                            "error": f"MalwareBazaar HTTP {r.status}",
                            "source": "MalwareBazaar (abuse.ch)"}
                body = await r.json(content_type=None)
    except asyncio.TimeoutError:
        return {"family": fam, "hashes": [],
                "error": "MalwareBazaar timed out (12s)",
                "source": "MalwareBazaar (abuse.ch)"}
    except Exception as e:
        return {"family": fam, "hashes": [],
                "error": _clean_exc(e, prefix="MalwareBazaar"),
                "source": "MalwareBazaar (abuse.ch)"}

    status = (body or {}).get("query_status") or ""
    if status != "ok":
        # "no_results" / "no_signature" / "limit_exceeded" / "illegal_..."
        payload = {"family": fam, "hashes": [],
                   "error": f"MalwareBazaar: {status or 'unknown response'}",
                   "source": "MalwareBazaar (abuse.ch)"}
        _MB_HASH_CACHE[cache_key] = {"ts": now, "payload": payload}
        return payload

    data = body.get("data") or []
    hashes = []
    for entry in data[:limit]:
        if not isinstance(entry, dict):
            continue
        hashes.append({
            "sha256":     entry.get("sha256_hash") or "",
            "sha1":       entry.get("sha1_hash") or "",
            "md5":        entry.get("md5_hash") or "",
            "file_name":  entry.get("file_name") or "",
            "file_type":  entry.get("file_type") or "",
            "first_seen": entry.get("first_seen") or "",
            "signature":  entry.get("signature") or fam,
            "reporter":   entry.get("reporter") or "",
        })
    payload = {"family": fam, "hashes": hashes,
               "count": len(hashes),
               "source": "MalwareBazaar (abuse.ch)"}
    _MB_HASH_CACHE[cache_key] = {"ts": now, "payload": payload}
    return payload


# ─── GTI SCORE ───────────────────────────────────────────────────────────────────
@app.post("/api/gti-score")
async def gti_score_standalone(req: GTIScoreRequest):
    """Compute GTI-style threat scores from enrichment data without running
    the full pipeline.

    Consumed by: external tooling — SIEM playbooks / scripts that have
    already gathered enrichment data and want a deterministic scoring
    layer on top. The frontend reads `gti_scores` directly off the
    /api/analyze result instead (run_response now writes them onto
    state), so it doesn't need this standalone endpoint.
    """
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


# ─── DOMAIN PERMUTATIONS (dnstwist) ──────────────────────────────────────────────
@app.post("/api/hunt/permutations")
async def hunt_permutations(req: DomainPermutationsRequest):
    """Generate typo-squat / homoglyph / TLD-swap permutations for a domain via
    dnstwist and resolve each to surface live registered lookalikes. On-demand
    (not part of auto-enrichment) because DNS-resolving 200+ permutations per
    analyze is too expensive."""
    from skills import run_skill
    try:
        out = await run_skill("domain_permutations", {
            "domain":           req.domain,
            "max_results":      req.max_results,
            "resolve":          req.resolve,
            "high_signal_only": req.high_signal_only,
        })
        return out
    except Exception as e:
        _log.warning("domain_permutations skill failed: %s", e)
        body = error_envelope(
            detail=f"Permutation generation failed: {e}",
            code="permutation_failed",
            status=500,
        )
        return _JSONResponse(body, status_code=500)


# ─── HUNT PLANNING (PEAK-style) ──────────────────────────────────────────────────
@app.post("/api/hunt/plan")
async def hunt_plan(req: HuntPlanRequest):
    """Generate a PEAK-style hunt artifact set (hypotheses + ABLE + plan) from
    an existing RECON analysis. Reactive triage → proactive hunt; the analysis
    must be supplied by the caller (the frontend passes the current /api/analyze
    result). Skills run sequentially because each consumes the previous output.

    Returns a single payload with all three artifacts so the UI can render
    them progressively without three separate round trips.
    """
    if not _llm_key_configured():
        body = error_envelope(
            detail="LLM provider not configured. Add an API key in Settings.",
            code="llm_not_configured",
            status=503,
        )
        return _JSONResponse(body, status_code=503)

    analysis = req.analysis or {}
    iocs     = req.iocs or {}

    from skills import run_skill

    hypotheses: list[str] = []
    if req.hypothesis and req.hypothesis.strip():
        hypotheses = [req.hypothesis.strip()]
    else:
        try:
            h_out = await run_skill("generate_hypothesis",
                                    {"analysis": analysis, "iocs": iocs})
            hypotheses = list(h_out.get("hypotheses") or [])
        except Exception as e:
            _log.warning("generate_hypothesis failed: %s", e)
            hypotheses = []

    primary = hypotheses[0] if hypotheses else ""
    able_md = ""
    plan_md = ""
    plan_iterations = 0
    plan_approved   = False

    if primary:
        try:
            a_out = await run_skill("generate_able_table", {
                "hypothesis": primary, "analysis": analysis, "iocs": iocs,
            })
            able_md = a_out.get("able_markdown") or ""
        except Exception as e:
            _log.warning("generate_able_table failed: %s", e)

        try:
            p_out = await run_skill("generate_hunt_plan", {
                "hypothesis":    primary,
                "able_markdown": able_md,
                "analysis":      analysis,
                "iocs":          iocs,
            })
            plan_md         = p_out.get("hunt_plan_markdown") or ""
            plan_iterations = int(p_out.get("iterations") or 0)
            plan_approved   = bool(p_out.get("critic_approved"))
        except Exception as e:
            _log.warning("generate_hunt_plan failed: %s", e)

    return {
        "hypotheses":      hypotheses,
        "primary":         primary,
        "able_markdown":   able_md,
        "hunt_plan":       plan_md,
        "plan_iterations": plan_iterations,
        "plan_approved":   plan_approved,
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


def _llm_key_configured() -> bool:
    """Thin wrapper around providers.provider_configured() for callers
    in this module that pass the ConfigManager singleton implicitly.
    The shared helper now lives in providers/factory.py so triage,
    investigation, email composer, file analyst etc. all gate on the
    same logic instead of each rolling their own OPENAI_API_KEY check."""
    from providers import provider_configured
    return provider_configured(config)


async def _ai_gen(prompt: str) -> str:
    if not _llm_key_configured():
        return "# LLM provider not configured. Add an API key in Settings."
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
            f"  date: {datetime.now(timezone.utc).strftime('%Y/%m/%d')}\n"
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
                  f"Requirements: let statements, relevant Sentinel tables, entity mapping fields, "
                  f"// comments explaining each section, rule metadata as // comments at top.\n"
                  f"IOCs: {ioc_json}\n")
        return {"result": await _ai_gen(prompt)}

    if req.action == "query":
        # Query DSL — pure pattern language: no tables, no schema joins,
        # just (Attribute Operator Value) statements composed with AND /
        # OR / parens. The model needs the full grammar in the prompt
        # because it isn't standard SQL / KQL / Lucene.
        a = req.analysis or {}
        ioc_json = json.dumps({k: v[:5] for k, v in (req.iocs or {}).items() if v})
        prompt = (
            "Generate ONE Query that would match the activity described\n"
            "below, using the grammar specified here. Output ONLY the query\n"
            "- no markdown fences, no commentary, no explanation.\n\n"

            "## Query grammar (hard rules)\n"
            "- Attribute names are CamelCase and case-sensitive: SourceIPAddress,\n"
            "  DestinationDomain, ProcessName, FullPath, SHA256, etc.\n"
            "- Operators are case-insensitive but write them in UPPERCASE for\n"
            "  readability: AND, OR, NOT, IN, LIKE, CONTAINS.\n"
            "- String values use double quotes; escape inner quotes as \\\".\n"
            "- Integer / float values are bare (no quotes).\n"
            "- Lists use parens with no commas required:\n"
            "    Attribute IN (\"a\" \"b\" \"c\")\n"
            "- Group sub-expressions with parens to control precedence.\n"
            "- NOT only combines with IN / LIKE / CONTAINS:\n"
            "    Attribute NOT IN (...) / NOT LIKE \"...\" / NOT CONTAINS \"...\".\n"
            "- LIKE takes a regex string (anchored ^...$ for full match).\n"
            "- Comparison operators (>, >=, <, <=) work on numeric attributes.\n\n"

            "## Operators (use exactly these tokens)\n"
            "  =   !=   AND   OR   CONTAINS   IN   LIKE   NOT\n"
            "  >   >=   <   <=   (   )\n\n"

            "## Attribute catalog (pick the ones that fit; do NOT invent new names)\n"
            "  IPs / network:    SourceIPAddress, DestinationIPAddress,\n"
            "                    SourcePort, DestinationPort, DestinationDomain,\n"
            "                    TransportLayer, NetworkDirection, Hostname,\n"
            "                    MacAddress\n"
            "  Process / file:   ProcessName, ProcessPath, ProcessId, FullPath,\n"
            "                    FullPathWithCmdLine, CmdLineParameters,\n"
            "                    ParentProcessName, ParentProcessId,\n"
            "                    CreatedByProcess, FileSize, ProcessFileSize,\n"
            "                    DeviceType\n"
            "  Hashes:           SHA256, SHA1, MD5Hash, ParentProcessSHA256\n"
            "  Identity:         username, computerId, OrganizationId\n"
            "  Policy / action:  PolicyName, PolicyIds, ApplicationName,\n"
            "                    ApplicationId, ActionType, ActionId,\n"
            "                    EffectiveAction, MonitorOnly,\n"
            "                    ElevationStatus\n"
            "  Event log:        EventLogDescription, EventLogSourceId,\n"
            "                    EventLogLevel, EventLogOpCode, EventLogTaskName,\n"
            "                    EventLogTaskMessage, EventTime, LogName\n"
            "  Threat / risk:    ThreatType, ThreatLevel := CurrentThreatLevel,\n"
            "                    RiskScore, RiskState, Severity, Priority,\n"
            "                    ResultStatus, Source, Service\n"
            "  Misc:             Notes, Data, RemotePresence, IsProtectedProcess,\n"
            "                    MemoryBytes, Location\n\n"

            "## Examples\n"
            "  ProcessName = \"powershell.exe\" AND CmdLineParameters CONTAINS \"-enc\"\n"
            "  DestinationIPAddress IN (\"45.61.169.99\" \"185.220.101.45\")\n"
            "  FullPath LIKE \"^.*\\\\\\\\appdata\\\\\\\\local\\\\\\\\temp\\\\\\\\.*\\\\.exe$\"\n"
            "  (PolicyName = \"Block Office Macros\" OR PolicyName = \"Block LOLBINs\")\n"
            "      AND EffectiveAction = \"deny\"\n"
            "  SHA256 = \"d9661e2378b88fbf51ce409333ba97ee2c798485cfd7ad8e50c360bce05836ba\"\n\n"

            "## What this specific alert is\n"
            f"  Threat level: {a.get('threatLevel','MEDIUM')}\n"
            f"  Summary:      {a.get('summary','')}\n"
            f"  MITRE:        {', '.join(a.get('mitreTechniques',[]))}\n"
            f"  IOCs:         {ioc_json}\n\n"

            "Write the tightest single Query statement that flags this activity.\n"
            "Prefer specific hash / IP / domain matches over loose path patterns\n"
            "when concrete IOCs are present. Use NOT IN sparingly to exclude\n"
            "known-good values. Output the query only."
        )
        # Validation loop: same shape as Sigma + YARA. Generate → compile
        # through intel.query_parser → on SyntaxError, retry with the
        # error fed back into the prompt. Caps at 3 attempts so a
        # pathologically broken model still ships (valid: false) instead
        # of looping forever.
        from intel.query_parser import validate as _validate_query
        attempt = 0
        prompt_now = prompt
        last_text  = ""
        last_error = None
        last_pos   = -1
        for attempt in range(1, 4):
            text = (await _ai_gen(prompt_now)).strip()
            # Strip any stray markdown fences the model produces despite
            # the rule (same defensive pattern as the KQL handler).
            if text.startswith("```"):
                text = text.split("\n", 1)[1] if "\n" in text else text[3:]
                if text.rstrip().endswith("```"):
                    text = text.rstrip()[:-3]
            text = text.strip()
            check = _validate_query(text)
            if check["ok"]:
                return {"result": text, "valid": True, "errors": [],
                        "attempts": attempt}
            last_text  = text
            last_error = check["error"]
            last_pos   = check["position"]
            prompt_now = (
                f"Your previous Query failed to parse:\n"
                f"  {last_error}\n\n"
                f"Here is the query you produced:\n{text}\n\n"
                "Fix the syntax and output ONLY the corrected Query. No "
                "markdown fences. No commentary. Common mistakes: NOT only "
                "combines with IN/LIKE/CONTAINS (never bare NOT =); string "
                "values must be quoted; numeric values are bare; list items "
                "go inside parens; double-escape regex backslashes inside "
                "LIKE strings."
            )
        return {"result": last_text, "valid": False,
                "errors": [last_error] if last_error else ["unknown parse error"],
                "error_position": last_pos,
                "attempts": attempt}

    if req.action == "yara":
        # Spec §6: AI generates → yara-python compiles → retry up to 3× on syntax error.
        a = req.analysis or {}
        family = a.get("malwareFamily") or a.get("malware_family") or "unknown"
        hashes = (req.iocs or {}).get("hashes", [])[:3]
        prompt = (
            f"Generate a YARA rule for detecting samples of the malware family '{family}'. "
            f"Output ONLY the YARA rule — no markdown fences, no commentary.\n\n"
            f"Requirements:\n"
            f"  rule meta: description, author = 'RECON Platform', date = '{datetime.now(timezone.utc).strftime('%Y-%m-%d')}', "
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

    # Additional detection-rule formats — analysts wanted the Detection
    # card to cover EVERY platform, not just Sigma + KQL + YARA. Each
    # action below produces one platform's rule as plain text.
    if req.action in ("splunk_spl", "elastic_eql", "suricata",
                       "chronicle_yara_l", "crowdstrike_fql"):
        a = req.analysis or {}
        ioc_json = json.dumps({k: v[:3] for k, v in (req.iocs or {}).items() if v})
        mitre_str = ", ".join(a.get("mitreTechniques", []))
        common_ctx = (
            f"Threat Level: {a.get('threatLevel','MEDIUM')}\n"
            f"Summary: {a.get('summary','')}\n"
            f"MITRE: {mitre_str}\n"
            f"IOCs: {ioc_json}\n"
        )
        _PROMPTS = {
            "splunk_spl": (
                "Generate a Splunk SPL detection search.\n"
                "CHARACTER: Senior Detection Engineer specialising in Splunk.\n"
                "CONSTRAINTS: Output ONLY valid SPL. Inline `\"...\"` comments.\n"
                f"{common_ctx}"
                "Requirements: use realistic sourcetype filters (e.g. WinEventLog:Sysmon, "
                "wineventlog:security, suricata, zeek, aws_cloudtrail, o365_management_activity), "
                "include relevant field extractions, stats / tstats aggregations where useful, "
                "and a final | table or | sort line. Begin with a one-line `# Title` comment."
            ),
            "elastic_eql": (
                "Generate an Elastic EQL detection query.\n"
                "CHARACTER: Senior Detection Engineer specialising in Elastic Security.\n"
                "CONSTRAINTS: Output ONLY valid EQL syntax. Inline `// ...` comments.\n"
                f"{common_ctx}"
                "Requirements: use sequence by host.id with maxspan when the alert is "
                "multi-step, otherwise a single process/network/file event match. Use ECS "
                "field names (process.name, process.parent.name, destination.ip, "
                "file.path, host.name). Wildcard glob patterns where appropriate."
            ),
            "suricata": (
                "Generate Snort / Suricata IDS rules.\n"
                "CHARACTER: Senior Detection Engineer specialising in network IDS.\n"
                "CONSTRAINTS: Output ONLY rule lines. One rule per line. No prose.\n"
                f"{common_ctx}"
                "Requirements: each rule should have `alert <proto> <src> <port> -> <dst> <port>` "
                "header, content / pcre / flowbits matchers, msg, classtype, sid (use 9000000+ "
                "as the analyst-allocated range), rev:1. Reference the IOCs or MITRE-implied "
                "tradecraft (e.g. C2 beacon timing, suspicious User-Agent, ja3 hash)."
            ),
            "chronicle_yara_l": (
                "Generate a Google Chronicle YARA-L 2.0 rule.\n"
                "CHARACTER: Senior Detection Engineer specialising in Chronicle.\n"
                "CONSTRAINTS: Output ONLY valid YARA-L 2.0 syntax. No markdown fences.\n"
                f"{common_ctx}"
                "Requirements: rule block with meta / events / match / condition sections. "
                "Use UDM field paths (principal.process.command_line, target.ip, "
                "metadata.event_type). Add a `match` window for multi-event sequences. "
                "Include meta fields: author = 'RECON Platform', severity, mitre_attack."
            ),
            "crowdstrike_fql": (
                "Generate a CrowdStrike Falcon FQL (Falcon Query Language) custom IOA rule.\n"
                "CHARACTER: Senior Detection Engineer specialising in CrowdStrike Falcon.\n"
                "CONSTRAINTS: Output ONLY the FQL pattern + IOA metadata. No markdown fences.\n"
                f"{common_ctx}"
                "Requirements: emit a Custom IOA expression using FileName, CommandLine, "
                "ParentBaseFileName, ImageFileName fields. Add `Severity`, `Description`, "
                "`Disposition` (Block or Detect) metadata as // comments above the rule. "
                "Reference the matched MITRE techniques in the description."
            ),
        }
        return {"result": await _ai_gen(_PROMPTS[req.action])}

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
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
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
    return f"""OUTPUT STYLE (hard rule): Write in plain ASCII. NEVER use em-dashes (—), en-dashes (–), or curly quotes. Use hyphens (-), commas, or restructure the sentence. Analysts immediately spot AI text by the em-dash and discount it.

You are RECON, an MDR analyst's assistant currently helping with a SPECIFIC
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

    # _results is a BoundedDict capped at 500. The chat_send handler
    # checks `run_id in _results` before constructing this generator,
    # but the generator runs at first iteration of the StreamingResponse
    # — by which time enough new analyses could have landed to evict
    # this run. Use .get() and bail with an SSE error event instead of
    # KeyErroring out of the generator (which would surface as a 500
    # without the consistent SSE shape the frontend expects).
    state = _results.get(run_id)
    if state is None:
        yield f"data: {json.dumps({'event': 'error', 'error': 'analysis result expired — re-run the analyze'})}\n\n"
        yield "data: [DONE]\n\n"
        return
    sys_msg = _build_chat_system_msg(state)
    history = _chats.get(run_id, [])

    # Persist user turn immediately so a refresh keeps it
    now = _ts()
    history.append({"role": "user", "content": user_msg, "timestamp": now})
    _chats[run_id] = history

    # Send the full conversation by default — analysts run long
    # investigations and the chat should never "forget" earlier turns.
    # The only thing we cap is the TOTAL CONTENT SIZE sent to the
    # model: once the cumulative body crosses a soft budget, we drop
    # the oldest user/assistant turns until we're back under it (but
    # always keep the most recent 10 turns verbatim so the immediate
    # thread is preserved). The user-visible chat history is never
    # trimmed; this only affects what the model sees.
    _CONTENT_BUDGET_BYTES = 96_000   # ~96 KB → roughly 24K tokens on
                                      # average prose; fits comfortably
                                      # in any modern fast-tier model's
                                      # context window with room for
                                      # the system message + tool
                                      # outputs + a 1200-token reply.
    _PROTECTED_RECENT_TURNS = 10
    _PER_MESSAGE_BYTE_CAP = 6_000     # a pasted log inside chat can be
                                      # 50KB on its own — clamp so one
                                      # message doesn't eat the budget.

    candidates = [m for m in history if m.get("role") in ("user", "assistant")]

    def _clamp(body: str) -> str:
        if len(body) > _PER_MESSAGE_BYTE_CAP:
            return body[:_PER_MESSAGE_BYTE_CAP] + "\n…[truncated by chat]"
        return body

    # Pre-clamp every message body, then sum from the END backwards so
    # the most recent turns are guaranteed to fit even if older ones
    # have to be dropped.
    prepared = [(m["role"], _clamp(m.get("content") or "")) for m in candidates]
    total = 0
    keep_reversed = []
    for i, (role, body) in enumerate(reversed(prepared)):
        # Always keep the most recent N turns regardless of budget.
        protected = i < _PROTECTED_RECENT_TURNS
        cost = len(body) + 32   # rough overhead per message envelope
        if protected or total + cost <= _CONTENT_BUDGET_BYTES:
            keep_reversed.append((role, body))
            total += cost
        else:
            # Stop walking back — older turns are dropped.
            break
    kept = list(reversed(keep_reversed))

    messages = [{"role": "system", "content": sys_msg}]
    # If we trimmed anything, give the model a heads-up so it doesn't
    # answer "earlier you said X" with confidence when it can no longer
    # see X. Analyst still sees the full history in the UI.
    if len(kept) < len(prepared):
        dropped = len(prepared) - len(kept)
        messages.append({
            "role": "system",
            "content": (
                f"[note: {dropped} earlier turn{'s' if dropped != 1 else ''} of "
                f"this conversation were trimmed from your view to keep the "
                f"context budget healthy. The analyst can still see them. If "
                f"you need something from earlier that you can't see, ask the "
                f"analyst to re-state it rather than guessing.]"
            ),
        })
    for role, body in kept:
        messages.append({"role": role, "content": body})

    tool_calls_made = []
    final_content = ""
    _MAX_ITERATIONS = 4
    # Tracks whether any assistant turn has been written to history. Used
    # by the finally below to close the orphan-on-client-disconnect gap:
    # if CancelledError fires during `provider.complete()` or
    # `execute_tool()` (which `except Exception` doesn't catch, since
    # CancelledError is a BaseException), neither the success nor the
    # except path persists, and the user message at line 1845 sits
    # orphaned in history. The finally appends a dropped-connection marker
    # so a refresh doesn't show a hanging question with no AI reply.
    _assistant_persisted = False

    try:
        # Tool-calling loop — non-streamed for tool decisions, streamed for the final answer
        iteration = 0
        for iteration in range(_MAX_ITERATIONS):
            # Drop tools after the iteration cap so the next call MUST
            # produce a text answer rather than another tool call. Stops
            # the rare loop where the model keeps asking for tools and
            # never composes a reply.
            allow_tools = iteration < _MAX_ITERATIONS - 1
            resp = await provider.complete(
                model=config.get_model(fast=True),
                messages=messages,
                tools=TOOL_SCHEMAS if allow_tools else None,
                tool_choice="auto" if allow_tools else None,
                temperature=0.2,
                max_tokens=1200,
            )
            if resp.error:
                # Mirror the except-handler persist path below: the user
                # turn was written at line 1845, the assistant never
                # produced a reply, and without a marker turn here a
                # refresh shows the user message hanging without context.
                # Without this the next chat turn the analyst sends
                # would have two consecutive user turns in the model's
                # view and confuse the downstream reasoning.
                try:
                    history.append({
                        "role": "assistant",
                        "content": "[chat error — the AI failed to respond. Try again.]",
                        "tool_calls": tool_calls_made,
                        "error": resp.error,
                        "timestamp": _ts(),
                    })
                    _chats[run_id] = history
                    _assistant_persisted = True
                except Exception:
                    pass
                yield f"data: {json.dumps({'event': 'error', 'error': resp.error})}\n\n"
                yield "data: [DONE]\n\n"
                return
            if resp.tool_calls and allow_tools:
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
                    yield f"data: {json.dumps({'event': 'tool_call', 'tool': tc['name'], 'args': args, 'summary': tc_summary})}\n\n"
                    messages.append({
                        "role": "tool", "tool_call_id": tc["id"],
                        "content": json.dumps(tool_result, default=str)[:2000],
                    })
                continue

            # Final answer turn — capture what the model produced.
            final_content = (resp.message or "").strip()
            break

        # Fallback when the model returned no usable text. Common causes:
        # context-window saturation, all four iterations spent on tool
        # calls, or the provider 'happily' returning an empty message.
        # Surface SOMETHING so the chat bubble isn't stuck empty.
        if not final_content:
            if tool_calls_made:
                tool_names = ", ".join(sorted({t['tool'] for t in tool_calls_made}))
                final_content = (
                    f"I ran {tool_names} but didn't produce a written reply. "
                    f"The tool output is above — try asking me to summarise it, "
                    f"or rephrase the question."
                )
            else:
                final_content = (
                    "I didn't manage to compose a reply this turn — likely a "
                    "model timeout or context-budget hiccup. Try sending the "
                    "message again."
                )

        # Persist the assistant turn BEFORE streaming. The 12ms-per-word
        # SSE drip below can be interrupted by client disconnect
        # (GeneratorExit propagates through the next yield), and we don't
        # want an orphaned user turn — same failure mode the except
        # handler below fixes for the tool-loop error path, applied here
        # to the cancellation path.
        history.append({"role": "assistant", "content": final_content,
                         "tool_calls": tool_calls_made, "timestamp": _ts()})
        _chats[run_id] = history
        _assistant_persisted = True

        # Stream the final answer word-by-word so the UI fills progressively.
        tokens = final_content.split(" ")
        for i, w in enumerate(tokens):
            chunk = (" " if i > 0 else "") + w
            yield f"data: {json.dumps({'event': 'token', 'text': chunk})}\n\n"
            await asyncio.sleep(0.012)

        yield f"data: {json.dumps({'event': 'done', 'tool_calls': tool_calls_made, 'reply': final_content})}\n\n"
    except Exception as e:
        # Persist a marker assistant turn so the user turn we already
        # wrote at the top doesn't sit orphaned in history. Without
        # this, a refresh-mid-error leaves the conversation with an
        # outstanding user message and no AI reply, which confuses the
        # next chat turn ("user said X then Y back-to-back, why?") and
        # makes forensics harder ("did the AI reply or not?").
        _err = _clean_exc(e)
        try:
            history.append({
                "role": "assistant",
                "content": "[chat error — the AI failed to respond. Try again.]",
                "tool_calls": tool_calls_made,
                "error": _err,
                "timestamp": _ts(),
            })
            _chats[run_id] = history
            _assistant_persisted = True
        except Exception:
            pass
        yield f"data: {json.dumps({'event': 'error', 'error': _err})}\n\n"
    finally:
        # Last-resort orphan check. CancelledError / KeyboardInterrupt /
        # GeneratorExit bypass `except Exception`, so the success and
        # error branches above can both be skipped when the client
        # disconnects mid-stream (during provider.complete, execute_tool,
        # or the token drip). In that case the user turn at line 1845 sits
        # orphaned and a later refresh shows their question hanging with
        # no AI reply. Append a dropped-connection marker so the
        # conversation history stays internally consistent — the model
        # never sees two consecutive user turns and the analyst sees the
        # "connection dropped" framing rather than a void.
        if not _assistant_persisted:
            try:
                history.append({
                    "role":      "assistant",
                    "content":   "[chat cancelled — the connection dropped before a reply could be generated.]",
                    "tool_calls": tool_calls_made,
                    "cancelled": True,
                    "timestamp": _ts(),
                })
                _chats[run_id] = history
            except Exception:
                pass
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
    # 32 KB is well above any real chat message, well below the 50 MB
    # AuditMiddleware envelope. Without this an attacker who can post
    # to /api/chat could send a giant body that gets prepended to the
    # next investigation prompt + persisted in _chats verbatim.
    if len(user_msg) > 32_000:
        raise HTTPException(400, "message too long (max 32 KB)")
    if not _llm_key_configured():
        raise HTTPException(503, "LLM provider not configured")
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
    audit-logs every upload.

    Consumed by: external tooling. The hyphenated path is the legacy
    spelling kept stable for curl scripts / SIEM playbooks documented
    against /api/docs. The frontend's File Scanner uses /api/scan/file
    (slash) instead, which carries the richer source-code-mode / capability
    / AI-analyst output. Keep both — removing the hyphen form would break
    every external script that hit this surface before the slash form
    existed.
    """
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
        yara_hits = [{"error": _clean_exc(e, prefix="YARA")}]
    # Also check the SHA-256 against LOLDrivers BYOVD catalog
    driver_hit = None
    try:
        from intel.loldrivers import lookup_hash
        driver_hit = lookup_hash(hashes["sha256"])
    except Exception as _e:
        _log.warning("LOLDrivers BYOVD lookup failed for %s: %s",
                     hashes["sha256"][:12], _e)

    # Cloud sandbox lookup — Hybrid Analysis by SHA-256
    sandbox = {}
    try:
        from intel.sandbox import lookup_all
        sandbox = await lookup_all(hashes["sha256"], config)
    except Exception as _e:
        _log.warning("cloud sandbox lookup failed for %s: %s",
                     hashes["sha256"][:12], _e)

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

    # TI correlation (async) — file_correlation handles VT/MB/HA/AnyRUN
    # via the hash; enrich_hash adds OTX file, ThreatFox, URLhaus payload,
    # CIRCL hashlookup, Hybrid Analysis search, Team Cymru MHR, Maltiverse,
    # OpenCTI, VT graph relationships, MalwareBazaar similar samples,
    # and the deep sandbox aggregator. Run both concurrently so every
    # hash-capable source the platform supports hits the file.
    sha256 = (analysis.get("hashes") or {}).get("sha256")
    md5    = (analysis.get("hashes") or {}).get("md5")
    sha1   = (analysis.get("hashes") or {}).get("sha1")
    primary_hash = sha256 or sha1 or md5
    try:
        from intel.file_correlation import correlate as _correlate
        from agents.enrichment import enrich_hash as _enrich_hash
        import aiohttp as _aiohttp
        # Snapshot the keys enrich_hash looks at into a plain dict (same
        # shape the URL-scan endpoint already builds).
        _keys = {k: (config.get(k) or "") for k in (
            "VIRUSTOTAL_KEY", "OTX_KEY", "HYBRID_ANALYSIS_KEY",
            "MALWAREBAZAAR_API_KEY", "ABUSECH_AUTH_KEY",
            "MALTIVERSE_KEY", "POLYSWARM_KEY",
        )}
        # Share the process-wide TCPConnector so the file scanner doesn't
        # spin up a fresh DNS cache + TLS handshakes for every upload.
        from agents.enrichment import _get_connector
        async with _aiohttp.ClientSession(
            connector=_get_connector(),
            connector_owner=False,
            timeout=_aiohttp.ClientTimeout(total=30),
        ) as _sess:
            _ti_res, _eh_res = await asyncio.gather(
                _correlate(analysis, config),
                _enrich_hash(_sess, primary_hash, _keys) if primary_hash else asyncio.sleep(0, result={}),
                return_exceptions=True,
            )
        # file_correlation result lands as threat_intel for backwards
        # compatibility with the file-scanner UI; enrich_hash result
        # lands as enrichments.hashes[sha256] mirroring how analyze
        # stores per-IOC enrichment.
        if isinstance(_ti_res, Exception):
            analysis["threat_intel"] = {"error": _clean_exc(_ti_res, prefix="threat-intel")}
        else:
            analysis["threat_intel"] = _ti_res
        if primary_hash and isinstance(_eh_res, dict):
            analysis.setdefault("enrichments", {}).setdefault("hashes", {})[primary_hash] = _eh_res
    except Exception as e:
        analysis["threat_intel"] = {"error": _clean_exc(e, prefix="threat-intel")}

    # Mark AI as pending so the frontend knows to poll. The three AI
    # workflows then run in a background task; the persisted scan is
    # updated as each completes. Polling endpoint: GET /api/scan/{sha256}
    analysis["ai_pending"] = True
    analysis.pop("_file_bytes", None)

    # Persist what we have right now so polling works immediately
    try:
        from intel.file_correlation import append_scan_history
        append_scan_history(analysis)
    except Exception as _e:
        # The frontend's File Scanner polls /api/scan/by-hash/<sha> to
        # progressively fill its cards as the AI background tasks land.
        # Append_scan_history is what makes the result visible to that
        # poll. A persistent failure here would leave the analyst staring
        # at a spinner that never resolves — surface it instead of pass.
        _log.warning("file_correlation.append_scan_history failed for "
                     "%s: %s",
                     ((analysis.get("hashes") or {}).get("sha256") or "?")[:12],
                     _e)

    # Kick off AI workflows in the background — caller doesn't wait for them
    if sha256:
        track_task(asyncio.create_task(_finish_ai_in_background(sha256, data)))

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

    # Progressive deep-result persistence — each of the three deep sub-calls
    # (narrative / verdict / structured) lands at a different time. Without
    # this hook, the deep result only persists once when ALL three complete,
    # so technical_summary / execution_narrative / key_findings all wait on
    # the slowest of the three. The callback merges each partial into
    # scan["ai_analyst"]["deep"] and calls _persist() so the next poll
    # picks them up immediately.
    async def _deep_partial(snap):
        try:
            existing = scan.get("ai_analyst", {}).get("deep") or {}
            if not isinstance(existing, dict):
                existing = {}
            existing.update(snap or {})
            scan.setdefault("ai_analyst", {})["deep"] = existing
            _persist()
        except Exception as _persist_e:
            # The main fan-out's final _persist() at the end of the loop
            # will still try — so a one-off transient failure here doesn't
            # block the final snapshot from landing. A persistent failure
            # would mean the frontend polls forever waiting for partial
            # snapshots that never appear; surface it so operators see
            # the cause in logs instead of staring at a stuck UI.
            _log.warning("deep AI partial-persist failed for %s: %s",
                         sha256, _persist_e)

    # Wrap the four-stream fan-out in try/finally so ai_pending gets
    # cleared no matter what — an unhandled exception before this point
    # used to leave the scan stuck pending forever, and the frontend
    # polled GET /api/scan/by-hash indefinitely waiting for cards that
    # would never land.
    try:
        tasks = {
            asyncio.ensure_future(generate_yara_for_file(scan, _ai_gen)):  "ai_yara",
            asyncio.ensure_future(summarize_file(scan, config)):           "ai_summary",
            asyncio.ensure_future(triage_classify(scan, config)):          "triage",
            asyncio.ensure_future(analyze_deep(scan, config,
                comparative_context=comparative, extra_context=extra,
                on_partial=_deep_partial)):                                "deep",
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
    except Exception as _ai_bg_e:
        _log.exception("AI background fan-out raised for %s", sha256)
        scan.setdefault("ai_analyst", {})["error"] = _clean_exc(
            _ai_bg_e, prefix="ai background")
    finally:
        scan["ai_pending"] = False
        scan.pop("_file_bytes", None)
        try:
            _persist()
        except Exception:
            pass


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


class ScanHashRequest(BaseModel):
    hash: str = Field(..., max_length=128)


@app.post("/api/scan/hash")
async def scan_hash(req: ScanHashRequest):
    """Hash lookup — always a fresh TI query.

    Full per-investigation isolation: we do NOT return a prior scan from history,
    so a lookup never serves data saved from an earlier investigation."""
    h = (req.hash or "").strip().lower()
    if not h:
        raise HTTPException(400, "hash required")
    if len(h) not in (32, 40, 64):
        raise HTTPException(400, "hash must be MD5 (32), SHA1 (40), or SHA256 (64) hex")
    if not all(c in "0123456789abcdef" for c in h):
        raise HTTPException(400, "hash must be hex characters only")
    out = {"hash": h, "sources": {}}

    # 2. No prior scan — query TI sources by hash and shape the result like a
    #    scan (hashes + threat_intel + verdict) so the frontend renders it via the
    #    existing FileIdentity / ThreatIntelSection / VerdictBanner components
    #    instead of a blank report.
    htype = "sha256" if len(h) == 64 else "sha1" if len(h) == 40 else "md5"
    vt = mb = ha = {}
    try:
        import aiohttp
        from agents.enrichment import _get_connector
        # 30s total cap so a hung TI source can't lock the request forever.
        async with aiohttp.ClientSession(
            connector=_get_connector(),
            connector_owner=False,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as session:
            from intel.file_correlation import _vt_file, _malwarebazaar, _hybrid_analysis
            # Pass the abuse.ch unified auth key so MalwareBazaar doesn't
            # hit anonymously and get rate-limited. Same fix the broader
            # file_correlation.correlate() path got — this direct
            # /api/scan/hash call site was a separate, parallel use.
            _abusech = (config.get("ABUSECH_AUTH_KEY")
                        or config.get("MALWAREBAZAAR_API_KEY") or "")
            r_vt, r_mb, r_ha = await asyncio.gather(
                _vt_file(session, h, config.get("VIRUSTOTAL_KEY", "")),
                _malwarebazaar(session, h, _abusech),
                _hybrid_analysis(session, h, config.get("HYBRID_ANALYSIS_KEY", "")),
                return_exceptions=True,
            )
            vt = r_vt if isinstance(r_vt, dict) else {}
            mb = r_mb if isinstance(r_mb, dict) else {}
            ha = r_ha if isinstance(r_ha, dict) else {}
    except Exception as e:
        out["error"] = _clean_exc(e, prefix="hash lookup")

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


class ScanUrlRequest(BaseModel):
    url: str = Field(..., max_length=4096)


@app.post("/api/scan/url")
async def scan_url_endpoint(req: ScanUrlRequest):
    """Scan a URL: try to download (30s timeout, 50MB cap) for static
    file analysis, but soft-fail to URL-reputation-only when the remote
    site blocks the fetch. Many security URLs (abuseipdb / virustotal /
    urlscan) return 403 to non-browser clients — we still want to run
    URL enrichment + URLScan submission on those, not error out."""
    url = (req.url or "").strip()
    if not url:
        raise HTTPException(400, "url required")
    if not url.startswith(("http://", "https://")):
        raise HTTPException(400, "url must be http(s)")
    # SSRF guard — analyst-supplied URL must not target internal
    # infrastructure. Resolves the hostname and rejects anything that
    # lands on RFC1918 / loopback / link-local / metadata service ranges.
    # Redirects are then resolved manually below so a 302 to localhost
    # can't bypass this check.
    import ipaddress, socket
    from urllib.parse import urlparse
    import aiohttp

    # Additional address ranges that Python's `ipaddress` module does NOT
    # classify as private/reserved/link-local but that an SSRF guard must
    # still refuse:
    #
    #   100.64.0.0/10    — RFC 6598 carrier-grade NAT. Catches Alibaba
    #                       Cloud's metadata endpoint at 100.100.100.200
    #                       (verified during the SSRF audit: ip_address
    #                       reports is_private=False for this range on
    #                       Python 3.11).
    #   198.18.0.0/15    — RFC 2544 benchmark-test space; should never
    #                       resolve a real public host.
    #   192.0.0.0/24     — RFC 5736 IANA IPv4 special purpose.
    #   192.0.2.0/24     — TEST-NET-1 documentation.
    #   198.51.100.0/24  — TEST-NET-2 documentation.
    #   203.0.113.0/24   — TEST-NET-3 documentation.
    #   fd00:ec2::/64    — AWS IPv6 metadata (the documented EC2-IMDS-v6
    #                       prefix; not flagged by is_private on its own).
    #   2001:db8::/32    — IPv6 documentation prefix.
    #   100::/64         — IPv6 discard prefix.
    _EXTRA_INTERNAL_NETS = tuple(ipaddress.ip_network(c) for c in (
        "100.64.0.0/10",
        "198.18.0.0/15",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "fd00:ec2::/64",
        "2001:db8::/32",
        "100::/64",
    ))

    def _ip_is_internal(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return True
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return True
        for net in _EXTRA_INTERNAL_NETS:
            try:
                if ip.version == net.version and ip in net:
                    return True
            except (TypeError, ValueError):
                continue
        return False

    def _resolve_public(host: str) -> list[str]:
        """Resolve `host` and return ONLY public IPs. Empty list means the
        host is unresolvable or every A/AAAA pointed somewhere internal.
        The caller treats empty as "block the request" — there is no
        "best-effort partial" path."""
        if not host:
            return []
        try:
            infos = socket.getaddrinfo(host, None)
        except (socket.gaierror, ValueError, UnicodeError):
            return []
        ips: list[str] = []
        seen: set[str] = set()
        for _fam, _t, _p, _c, sa in infos:
            ip = sa[0]
            if ip in seen:
                continue
            seen.add(ip)
            if _ip_is_internal(ip):
                # Reject the whole host: if ANY resolution is internal we
                # can't safely pin to the public subset (a DNS-rebinding
                # attacker can have us hit either one).
                return []
            ips.append(ip)
        return ips

    # aiohttp 3.14 removed the top-level `aiohttp.AbstractResolver` re-export
    # the previous code subclassed; the canonical location is
    # `aiohttp.abc.AbstractResolver`. Under the older path every
    # /api/scan/url POST blew up with AttributeError BEFORE the SSRF guard
    # even ran (the class definition raised at endpoint-eval time), so the
    # endpoint had been returning blanket 500s — masking both the guard and
    # any downstream behaviour. Import explicitly so a future re-export
    # change can't break us silently.
    from aiohttp.abc import AbstractResolver as _AiohttpAbstractResolver

    class _PinnedResolver(_AiohttpAbstractResolver):
        """aiohttp resolver that returns ONLY the pre-resolved set of IPs.
        Closes the DNS-rebinding window between the SSRF pre-check and
        aiohttp's connect-time lookup: we resolved once, decided the
        target was safe, and now aiohttp uses ONLY that decision.

        keyed by (host) -> list of {host, family} entries in
        aiohttp.resolver result shape. Anything aiohttp asks to resolve
        that isn't in the map raises OSError, which aiohttp surfaces as a
        connection failure (the redirect path needs to add new hosts to
        the map before the next hop).
        """
        def __init__(self, pinned: "dict[str, list[str]]"):
            self._pinned = pinned

        async def resolve(self, host, port=0, family=socket.AF_UNSPEC):
            ips = self._pinned.get(host.lower())
            if not ips:
                raise OSError(f"host not in pinned set: {host}")
            return [{
                "hostname": host, "host": ip, "port": port,
                "family": (socket.AF_INET6 if ":" in ip else socket.AF_INET),
                "proto":  0, "flags": 0,
            } for ip in ips]

        async def close(self):
            return

    # Pin the initial host. Internal target → 400 before we even open the
    # session, matching the previous behaviour but now with the same map
    # that aiohttp will use at connect time so DNS can't flip on us.
    _pinned_ips: "dict[str, list[str]]" = {}
    _initial_host = (urlparse(url).hostname or "").lower()
    _initial_ips = _resolve_public(_initial_host)
    if not _initial_ips:
        raise HTTPException(400, "url targets a non-public address")
    _pinned_ips[_initial_host] = _initial_ips
    # Most sites bot-detect on either UA or missing browser headers.
    # We send a full Chrome header set first; on 403/406/429 we retry
    # once with Firefox in case the first signature was fingerprinted.
    # Real anti-bot stacks (Cloudflare turnstile, PerimeterX, DataDome)
    # we cannot beat without a headless browser — we soft-fail and
    # surface URLScan's screenshot as the visual evidence instead.
    _CHROME_HEADERS = {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/127.0.0.0 Safari/537.36"),
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                   "image/avif,image/webp,image/apng,*/*;q=0.8,"
                   "application/signed-exchange;v=b3;q=0.7"),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Sec-Ch-Ua": '"Chromium";v="127", "Not;A=Brand";v="24", "Google Chrome";v="127"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    }
    _FIREFOX_HEADERS = {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) "
                       "Gecko/20100101 Firefox/131.0"),
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                   "image/avif,image/webp,*/*;q=0.8"),
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    }
    _SOFT_BLOCK_STATUSES = {401, 403, 406, 429, 503}

    async def _try_fetch(headers):
        """Returns (data_bytes, status_code, exc_str). data is empty on
        any non-200. Caller decides whether the result is a soft fail.
        Redirects are followed manually so the SSRF guard runs on each hop
        (a remote 302 to http://127.0.0.1 would otherwise bypass the
        check we ran on the original URL). Each hop's host is pre-resolved
        and the resulting IP set is pinned in the connector's resolver so
        aiohttp's connect-time DNS lookup can't return a different (now-
        internal) address."""
        try:
            current = url
            connector = aiohttp.TCPConnector(resolver=_PinnedResolver(_pinned_ips))
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=30),
                headers=headers,
            ) as session:
                for _hop in range(5):
                    async with session.get(current, allow_redirects=False) as r:
                        if r.status in (301, 302, 303, 307, 308):
                            nxt = r.headers.get("Location") or ""
                            if not nxt:
                                return b"", r.status, ""
                            from urllib.parse import urljoin
                            current = urljoin(current, nxt)
                            _hop_host = (urlparse(current).hostname or "").lower()
                            if _hop_host not in _pinned_ips:
                                _hop_ips = _resolve_public(_hop_host)
                                if not _hop_ips:
                                    return b"", 403, "redirect targets a non-public address"
                                _pinned_ips[_hop_host] = _hop_ips
                            continue
                        if r.status != 200:
                            return b"", r.status, ""
                        chunks = []
                        total = 0
                        async for chunk in r.content.iter_chunked(64 * 1024):
                            chunks.append(chunk)
                            total += len(chunk)
                            if total > 50 * 1024 * 1024:
                                return b"", 413, "remote file exceeds 50 MB cap"
                        return b"".join(chunks), 200, ""
                return b"", 0, "too many redirects"
        except Exception as e:
            return b"", 0, _clean_exc(e)

    data, last_status, last_err = await _try_fetch(_CHROME_HEADERS)
    if not data and last_status in _SOFT_BLOCK_STATUSES:
        data, last_status, last_err = await _try_fetch(_FIREFOX_HEADERS)
    if last_status == 413:
        raise HTTPException(413, "remote file exceeds 50 MB cap")
    download_warning = ""
    if not data:
        if last_status in _SOFT_BLOCK_STATUSES:
            download_warning = (
                f"Remote site is gated behind bot protection (HTTP {last_status}). "
                f"This is normal for sites using Cloudflare, Akamai, or similar — "
                f"see URLScan's screenshot below for the rendered page."
            )
        elif last_status and last_status != 200:
            download_warning = (
                f"Remote returned HTTP {last_status}. The page may have been "
                f"removed or the URL requires authentication."
            )
        elif last_err:
            download_warning = (
                f"Couldn't reach the URL: {last_err}. Check that the host is "
                f"resolvable and the link is still live."
            )

    filename = url.rstrip("/").rsplit("/", 1)[-1].split("?", 1)[0] or "downloaded"
    from intel.file_analyzer import analyze_file
    # Mirror the file-scanner fast path: CPU-bound static analysis runs off the
    # event loop, the full AI suite (triage badge, summary, YARA-gen, split deep
    # analyst) runs in the background on the two-tier models, and we return
    # immediately so the frontend can poll /api/scan/by-hash for progressive fill.
    # If the download soft-failed (data == b""), the analyser produces a stub
    # with empty hashes; the URL enrichment block below still runs.
    if data:
        analysis = await asyncio.to_thread(analyze_file, data, filename)
    else:
        analysis = {
            "filename": filename,
            "size": 0,
            "hashes": {},
            "type": {"detected_mime": "n/a (no body)", "detected_desc": ""},
            "entropy": {"overall": 0, "band": "n/a"},
            "iocs": {}, "suspicious_strings": [], "yara_matches": [],
            "format_specific": {},
            "verdict": "UNKNOWN",
            "_download_skipped": True,
        }
    analysis["source_url"] = url
    if download_warning:
        analysis["download_warning"] = download_warning
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
        import aiohttp
        from urllib.parse import urlparse
        from intel.file_correlation import correlate
        from agents.enrichment import (
            enrich_url as _enrich_url,
            enrich_domain as _enrich_domain,
            enrich_hash as _enrich_hash,
        )
        host = (urlparse(url).hostname or "").strip().lower()
        sha256 = (analysis.get("hashes") or {}).get("sha256")
        keys = {k: config.get(k, "") for k in (
            "VIRUSTOTAL_KEY", "ABUSEIPDB_KEY", "OTX_KEY", "URLSCAN_KEY",
            "GREYNOISE_KEY", "PULSEDIVE_KEY", "MALTIVERSE_KEY",
            "IPINFO_TOKEN", "WHOISXML_KEY", "GOOGLE_API_KEY",
            "HYBRID_ANALYSIS_KEY", "MALWAREBAZAAR_API_KEY",
            "ABUSECH_AUTH_KEY",
            "POLYSWARM_KEY", "PHISHTANK_KEY",
            "PROXYCHECK_KEY", "FULLHUNT_KEY", "CENSYS_API_KEY",
            "CENSYS_ID", "CENSYS_SECRET", "CRIMINAL_IP_KEY",
            "CROWDSEC_KEY",
        )}
        # Run hash correlation (file_correlation) + per-IOC enrichment in
        # parallel — every source the platform supports gets a fair shot.
        from agents.enrichment import _get_connector
        async with aiohttp.ClientSession(
            connector=_get_connector(),
            connector_owner=False,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as sess:
            ti_res, url_enr, dom_enr, hash_enr = await asyncio.gather(
                correlate(analysis, config),
                _enrich_url(sess, url, keys),
                _enrich_domain(sess, host, keys) if host else asyncio.sleep(0, result={}),
                _enrich_hash(sess, sha256, keys) if sha256 else asyncio.sleep(0, result={}),
                return_exceptions=True,
            )
        if isinstance(ti_res, Exception):
            analysis["threat_intel"] = {"error": _clean_exc(ti_res, prefix="threat-intel")}
        else:
            analysis["threat_intel"] = ti_res
        analysis["enrichments"] = {
            "urls":    {url: url_enr if isinstance(url_enr, dict) else {}},
            "domains": {host: dom_enr if (host and isinstance(dom_enr, dict)) else {}},
            "hashes":  ({sha256: hash_enr} if (sha256 and isinstance(hash_enr, dict)) else {}),
        }
    except Exception as e:
        analysis["enrichments"] = {"error": _clean_exc(e, prefix="enrichment")}
        if "threat_intel" not in analysis:
            analysis["threat_intel"] = {"error": _clean_exc(e, prefix="threat-intel")}
    # Only schedule the AI pipeline when we actually have bytes to analyse.
    # Soft-fail downloads produce a stub analysis; the URL-reputation +
    # WHOIS + Wayback + URLScan submission paths still work without AI.
    analysis["ai_pending"] = bool(data)
    analysis.pop("_file_bytes", None)
    try:
        from intel.file_correlation import append_scan_history
        append_scan_history(analysis)
    except Exception as _e:
        # The frontend's File Scanner polls /api/scan/by-hash/<sha> to
        # progressively fill its cards as the AI background tasks land.
        # Append_scan_history is what makes the result visible to that
        # poll. A persistent failure here would leave the analyst staring
        # at a spinner that never resolves — surface it instead of pass.
        _log.warning("file_correlation.append_scan_history failed for "
                     "%s: %s",
                     ((analysis.get("hashes") or {}).get("sha256") or "?")[:12],
                     _e)
    sha256 = (analysis.get("hashes") or {}).get("sha256")
    if sha256 and data:
        track_task(asyncio.create_task(_finish_ai_in_background(sha256, data)))
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
    # save_rule() runs _safe_name() over the slug so the path is bounded,
    # but cap inputs at the schema layer to keep DoS surface tight.
    # 200 KB is enough for the most complex YARA rule a real hunter
    # writes by hand — anything bigger is generated noise.
    name: str = Field(..., max_length=128)
    rule: str = Field(..., max_length=200_000)


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
    rule: str = Field(..., max_length=200_000)


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
    scan_id: str = Field(..., max_length=128)   # SHA-256 of the scanned file
    answers: dict                               # {question_text: answer_text}


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
    # Cap the answers payload — 16KB is way more than any real clarifying
    # exchange and stops a paste-the-whole-log mistake from blowing up
    # the prompt budget.
    _answers_size = sum(len(str(q)) + len(str(a)) for q, a in req.answers.items())
    if _answers_size > 16_000:
        raise HTTPException(413,
            f"answers too large ({_answers_size:,} chars; cap is 16,000)")

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

    try:
        deep = await analyze_deep(scan, config,
                                  comparative_context=gather_comparative_context(scan),
                                  extra_context=extra)
    except Exception as e:
        raise HTTPException(503, _clean_exc(e, prefix="AI re-analysis"))
    if not deep or deep.get("error"):
        raise HTTPException(503,
            f"AI re-analysis unavailable: {(deep or {}).get('error') or 'no key configured'}")

    scan.setdefault("ai_analyst", {})
    scan["ai_analyst"]["deep"] = deep
    scan["ai_analyst"]["analyst_answers"] = req.answers
    # Surface context_impact on the analyst object too so the UI can show it
    if isinstance(deep, dict) and deep.get("context_impact"):
        scan["ai_analyst"]["context_impact"] = deep["context_impact"]
    append_scan_history(scan)
    return scan


class ScanFeedbackRequest(BaseModel):
    scan_id:    str           = Field(..., max_length=128)
    thumbs:     str           = Field(..., max_length=8)    # 'up' | 'down'
    correction: Optional[dict] = None
    notes:      Optional[str] = Field(default="", max_length=4_000)
    analyst:    Optional[str] = Field(default="", max_length=128)


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
    """Hash-only lookup against configured cloud sandboxes.

    Consumed by: external tooling. The frontend's File Scanner polls
    /api/sandbox/result/{sha256} (in routers/sandbox.py) instead — that's
    the auto-submission status poll, this is the on-demand "do you already
    have a report for this hash?" probe used by SIEM playbooks before
    bothering to upload the sample.
    """
    if len(sha256) != 64:
        raise HTTPException(400, "Provide a SHA-256 hash (64 hex chars).")
    try:
        from intel.sandbox import lookup_all
        return {"sha256": sha256, "sandbox": await lookup_all(sha256, config)}
    except Exception as e:
        raise HTTPException(503, _clean_exc(e, prefix="sandbox lookup"))


_URLSCAN_VISIBILITIES = {"public", "unlisted", "private"}
# URLScan UUIDs are RFC 4122 — accept either the canonical 8-4-4-4-12
# hex form or a 32-char dashless form. Anything else is bogus and we
# refuse to ask URLScan about it (avoids spamming upstream with garbage).
import re as _re_validate
_UUID_RE = _re_validate.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    r"|^[0-9a-f]{32}$",
    _re_validate.IGNORECASE,
)
_SHA256_RE = _re_validate.compile(r"^[0-9a-fA-F]{64}$")


@app.post("/api/urlscan/submit")
async def urlscan_submit(req: dict):
    """Submit a URL for live scanning via URLScan.io."""
    api_key = config.get("URLSCAN_KEY")
    if not api_key:
        raise HTTPException(400, "URLSCAN_KEY not configured")
    url = (req or {}).get("url", "").strip()
    if not url:
        raise HTTPException(400, "url required")
    if not url.startswith(("http://", "https://")):
        raise HTTPException(400, "url must be http(s)://")
    if len(url) > 4096:
        raise HTTPException(400, "url too long (>4096 chars)")
    visibility = (req.get("visibility") or "unlisted").lower()
    if visibility not in _URLSCAN_VISIBILITIES:
        raise HTTPException(400,
            f"visibility must be one of {sorted(_URLSCAN_VISIBILITIES)}")
    from intel.urlscan import submit_url
    try:
        out = await submit_url(url, api_key, visibility=visibility)
    except Exception as e:
        raise HTTPException(502, _clean_exc(e, prefix="URLScan submit"))
    if not out.get("ok"):
        raise HTTPException(502, out.get("error") or "URLScan submission failed")
    return out


@app.get("/api/urlscan/result/{uuid}")
async def urlscan_result(uuid: str):
    """Poll a URLScan result. Returns ready=false while processing."""
    if not _UUID_RE.match(uuid or ""):
        raise HTTPException(400, "uuid must be an RFC 4122 UUID")
    from intel.urlscan import get_result
    try:
        return await get_result(uuid, config.get("URLSCAN_KEY", ""))
    except Exception as e:
        raise HTTPException(502, _clean_exc(e, prefix="URLScan poll"))


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
    # Hybrid Analysis job IDs are 24-char hex (their internal mongo
    # ObjectId-style). Reject anything else so we don't poll upstream
    # with random analyst-typed strings AND don't pollute _sandbox_jobs
    # with junk keys.
    if not job_id or not _re_validate.match(r"^[0-9a-f]{8,64}$", job_id):
        raise HTTPException(400, "job_id must be a hex token (8-64 chars)")
    from intel.sandbox import hybrid_analysis_state, hybrid_analysis_summary
    try:
        state = await hybrid_analysis_state(job_id, api_key)
    except Exception as e:
        raise HTTPException(502, _clean_exc(e, prefix="sandbox poll"))
    record = _sandbox_jobs.get(job_id, {})
    record["state"] = state.get("state", "UNKNOWN")
    record["error"] = state.get("error")
    if record["state"] == "SUCCESS":
        try:
            record["summary"] = await hybrid_analysis_summary(job_id, api_key)
        except Exception as e:
            record["error"] = _clean_exc(e, prefix="sandbox summary")
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
            return {"state": "error", "detail": _clean_exc(e)}

    checks = []
    if config.get("VIRUSTOTAL_KEY"):
        checks.append(("virustotal", "https://www.virustotal.com/api/v3/users/current",
                       {"x-apikey": config.get("VIRUSTOTAL_KEY")}, None))
    if config.get("ABUSEIPDB_KEY"):
        checks.append(("abuseipdb", "https://api.abuseipdb.com/api/v2/check",
                       {"Key": config.get("ABUSEIPDB_KEY"), "Accept": "application/json"},
                       {"ipAddress": "8.8.8.8"}))
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

    # Pick the required key based on the active LLM_PROVIDER instead of
    # hardcoding OPENAI_API_KEY. Anthropic deployments need
    # ANTHROPIC_API_KEY; Ollama needs nothing (local install).
    _llm_provider = (os.environ.get("LLM_PROVIDER") or "openai").strip().lower()
    if _llm_provider == "anthropic":
        required = ("ANTHROPIC_API_KEY",)
    elif _llm_provider == "ollama":
        required = ()
    else:
        required = ("OPENAI_API_KEY",)
    optional = ("VIRUSTOTAL_KEY", "ABUSEIPDB_KEY", "GREYNOISE_KEY",
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
    """Spec §10: full structured report for export tooling.

    Consumed by: external tooling and the planned ReportView export. The
    in-app analyst report renders directly from the /api/analyze result —
    this endpoint exists so scripts / case-management integrations can
    re-fetch a normalised report shape by run_id.
    """
    if run_id not in _results:
        raise HTTPException(404, "Run not found")
    return _build_report(run_id, _results[run_id])


@app.get("/api/report/{run_id}/markdown")
async def report_markdown(run_id: str):
    """Spec §10: Markdown report for pasting into Jira / Confluence / Slack.

    Consumed by: external tooling. Same purpose as /api/report/{run_id} but
    rendered as markdown so the body is paste-ready.
    """
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
# /api/history listing was removed — investigations are not accumulated
# into a cross-session history (no-persistence policy), so the listing
# always returned []. Per-run fetch by id still works against the
# in-memory _results store.
@app.get("/api/history/{run_id}")
async def get_history_item(run_id: str):
    """Re-fetch the structured result for a previously analysed run.

    Consumed by: external tooling / case-management integrations that
    cached a runId and want to refresh the verdict + IOCs without
    re-running the pipeline. The frontend never lost its in-memory copy
    of the result so it doesn't need to re-fetch.
    """
    if run_id not in _results:
        raise HTTPException(404, "Run not found")
    return {k: v for k, v in _results[run_id].items() if k != "stix_bundle"}


# ─── EMAIL COMPOSER ─────────────────────────────────────────────────────────────
class EmailParseRequest(BaseModel):
    # The endpoint enforces _EMAIL_LOG_MAX (200 KB) at the handler too,
    # but anchoring the cap at the schema means the validation error is
    # consistent (ValidationError) instead of an HTTPException for the
    # same overflow.
    log_text: str = Field(..., max_length=200_000)


class EmailComposeRequest(BaseModel):
    # alert_type maps to a fixed set of ALERT_TYPES — short slug.
    alert_type: str = Field(..., max_length=64)
    parsed: dict
    options: Optional[dict] = None
    ip1: Optional[dict] = None
    ip2: Optional[dict] = None


class EmailSendRequest(BaseModel):
    # CRLF in any header value would propagate into the MIME headers
    # email_composer.send_smtp() builds. While SMTP RCPT TO won't honour
    # a Bcc: smuggled through the To field, the rendered headers reach
    # the recipient's MUA — which DOES display whatever extra header
    # rows the analyst's input invented. Pattern blocks \r and \n in
    # every address-shape field plus subject; body fields can carry
    # newlines because they're MIME bodies, not headers. Caps match
    # what a reasonable customer-comms email looks like.
    subject:   str = Field(..., max_length=300, pattern=r"^[^\r\n]*$")
    body_text: str = Field(..., max_length=200_000)
    body_html: str = Field(..., max_length=400_000)
    to:        str = Field(..., max_length=2_000, pattern=r"^[^\r\n]*$")
    cc: Optional[str] = Field(default="", max_length=2_000, pattern=r"^[^\r\n]*$")


class EmailTemplateSave(BaseModel):
    # alert_type slug is matched against a fixed ALERT_TYPES set in
    # save_template; body becomes a template file the composer renders
    # with f-string substitutions. 200 KB is well above any sane
    # template (the bundled ones are ~5 KB max).
    alert_type: str = Field(..., max_length=64)
    body:       str = Field(..., max_length=200_000)


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


_EMAIL_LOG_MAX = 200_000   # 200 KB log_text cap — well above any real
                            # alert payload, below the AuditMiddleware
                            # body cap, prevents OOM on accidental paste.


@app.post("/api/email/parse")
async def email_parse(req: EmailParseRequest):
    """Parse raw log text and return every field the composer will reference."""
    from intel.email_composer import parse_log
    if not req.log_text or not req.log_text.strip():
        raise HTTPException(400, "log_text required")
    if len(req.log_text) > _EMAIL_LOG_MAX:
        raise HTTPException(413,
            f"log_text too large ({len(req.log_text):,} chars; cap is {_EMAIL_LOG_MAX:,})")
    try:
        return parse_log(req.log_text)
    except Exception as e:
        raise HTTPException(500, _clean_exc(e, prefix="email parse"))


@app.post("/api/email/compose")
async def email_compose(req: EmailComposeRequest):
    """Render the email — returns subject + plain text + HTML."""
    from intel.email_composer import compose
    if not req.alert_type:
        raise HTTPException(400, "alert_type required")
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
    try:
        return compose(req.alert_type, req.parsed, options, cfg,
                       ip1=req.ip1, ip2=req.ip2)
    except Exception as e:
        raise HTTPException(500, _clean_exc(e, prefix="email compose"))


class EmailComposeAIRequest(BaseModel):
    # Same cap as /api/email/parse so the same paste size that the
    # parse endpoint accepts can land here, and nothing larger.
    log_text: str = Field(..., max_length=200_000)
    parsed: Optional[dict] = None
    options: Optional[dict] = None


@app.post("/api/email/compose-ai")
async def email_compose_ai(req: EmailComposeAIRequest):
    """Generate a customer email via AI using the static templates as style
    models. Returns the same {subject, text, html, template_used} shape as
    /api/email/compose so the frontend can render it identically."""
    from intel.email_composer import compose_ai
    if not req.log_text or not req.log_text.strip():
        raise HTTPException(400, "log_text required")
    if len(req.log_text) > _EMAIL_LOG_MAX:
        raise HTTPException(413,
            f"log_text too large ({len(req.log_text):,} chars; cap is {_EMAIL_LOG_MAX:,})")
    # cfg is a flat dict that compose_ai treats as the API-key bag. It
    # needs AI provider config AND every enrichment-API key compose_ai's
    # _gather_email_enrichment fans out to (VirusTotal, AbuseIPDB,
    # MalwareBazaar, Hybrid Analysis, etc.). Previously the dict only
    # carried the 7 AI / sender-identity keys and the enrichment helper
    # silently got None for everything else — that's why VT / Spamhaus
    # / WHOIS / Hybrid Analysis lines never appeared in the prose even
    # though the keys were configured in data/config.json.
    cfg = {
        # AI provider + email-sender identity
        "OPENAI_API_KEY":     config.get("OPENAI_API_KEY"),
        "OPENAI_BASE_URL":    config.get("OPENAI_BASE_URL"),
        "AI_MODEL":           config.get("AI_MODEL"),
        "FAST_AI_MODEL":      config.get("FAST_AI_MODEL"),
        "EMAIL_FROM_NAME":    config.get("EMAIL_FROM_NAME"),
        "EMAIL_FROM_ADDRESS": config.get("EMAIL_FROM_ADDRESS"),
        "EMAIL_SIGNATURE":    config.get("EMAIL_SIGNATURE"),
        # Enrichment APIs — full set. The earlier "every enrichment-API
        # key" comment was wrong: ABUSECH_AUTH_KEY / Censys / CrowdSec /
        # Criminal IP / ProxyCheck / FullHunt / OpenCTI / PhishTank were
        # silently missing, so compose_ai's enrichment fan-out had the
        # same throttling-on-abuse.ch + skipped-source problems as the
        # other key-stripped call sites we just fixed.
        "VIRUSTOTAL_KEY":     config.get("VIRUSTOTAL_KEY"),
        "ABUSEIPDB_KEY":      config.get("ABUSEIPDB_KEY"),
        "OTX_KEY":            config.get("OTX_KEY"),
        "URLSCAN_KEY":        config.get("URLSCAN_KEY"),
        "GREYNOISE_KEY":      config.get("GREYNOISE_KEY"),
        "PULSEDIVE_KEY":      config.get("PULSEDIVE_KEY"),
        "MALTIVERSE_KEY":     config.get("MALTIVERSE_KEY"),
        "IPINFO_TOKEN":       config.get("IPINFO_TOKEN"),
        "WHOISXML_KEY":       config.get("WHOISXML_KEY"),
        "GOOGLE_API_KEY":     config.get("GOOGLE_API_KEY"),
        "HYBRID_ANALYSIS_KEY": config.get("HYBRID_ANALYSIS_KEY"),
        "MALWAREBAZAAR_API_KEY": config.get("MALWAREBAZAAR_API_KEY"),
        "ABUSECH_AUTH_KEY":   config.get("ABUSECH_AUTH_KEY"),
        # Canonical Censys names — PAT first, legacy v2 pair as fallback.
        "CENSYS_API_KEY":     config.get("CENSYS_API_KEY"),
        "CENSYS_ID":          config.get("CENSYS_ID"),
        "CENSYS_SECRET":      config.get("CENSYS_SECRET"),
        "CROWDSEC_KEY":       config.get("CROWDSEC_KEY"),
        "CRIMINAL_IP_KEY":    config.get("CRIMINAL_IP_KEY"),
        "PROXYCHECK_KEY":     config.get("PROXYCHECK_KEY"),
        "FULLHUNT_KEY":       config.get("FULLHUNT_KEY"),
        "OPENCTI_URL":        config.get("OPENCTI_URL"),
        "OPENCTI_TOKEN":      config.get("OPENCTI_TOKEN"),
        "PHISHTANK_KEY":      config.get("PHISHTANK_KEY"),
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


# ─── AI remediation (Section 7) ─────────────────────────────────────────────
class EmailRemediateRequest(BaseModel):
    """Body for /api/email/remediate. Accepts whatever subset of parsed
    alert fields the email composer has populated — every field is
    optional because alert types vary widely. Field caps mirror the
    other /api/email/* request models so a 50 MB body can't be sent
    in as a "log" and round-trip into the LLM prompt unbounded."""
    parsed:            dict = Field(default_factory=dict)
    log_text:          str = Field(default="",                max_length=200_000)
    alert_type:        str = Field(default="",                max_length=64)
    threat_level:      str = Field(default="",                max_length=32)
    mitre_techniques:  list = Field(default_factory=list,     max_length=100)
    severity:          str = Field(default="",                max_length=32)


_REMEDIATION_SYSTEM_PROMPT = """OUTPUT STYLE (hard rule): Write in plain ASCII. NEVER use em-dashes (—), en-dashes (–), or curly quotes. Use hyphens (-), commas, or restructure the sentence. This applies to every word the customer or analyst will read.

You are a senior incident responder and threat-intelligence
analyst at a Managed Detection and Response provider with 10 years of experience.

An analyst is about to send a security alert notification email to a customer or
internal stakeholder. You have been given the parsed details of the alert. Your
job is to generate clear, SPECIFIC, ACTIONABLE remediation and investigation
guidance that will be included directly in the email.

Write as if you are advising the recipient on exactly what to do right now. Be
specific to the actual threat details provided — do NOT give generic advice. If
you can identify the malware family or threat actor from the details, reference
their known behaviors and typical next steps.

Output STRICT JSON with EXACTLY these keys (no markdown fences, no commentary):
{
  "immediate_actions": [
    "<3-5 things to do in the next 15 minutes. Each item is ONE actionable
     sentence starting with a verb: Isolate / Block / Revoke / Reset / Preserve / Disable / Notify>"
  ],
  "investigation_steps": [
    {
      "title":       "<short, specific title>",
      "description": "<2 sentences explaining what to do and what to look for>"
    }
    // 4-6 entries
  ],
  "containment_guidance": "<1 paragraph explaining how to contain THIS specific threat>",
  "recovery_guidance":    "<1 paragraph explaining how to safely recover affected systems>",
  "detection_guidance":   "<1 paragraph explaining what additional logging or monitoring to enable>",
  "executive_summary":    "<2-3 sentences in plain English suitable for non-technical management>"
}

Calibration rules:
* If the parsed details indicate likely benign / known-good vendor behaviour, say
  so in the executive_summary and skew the immediate_actions toward verification
  ("Confirm the alert matches expected vendor maintenance activity") rather than
  containment.
* If the threat is genuinely high-severity (named malware family, confirmed
  unauthorized access, lateral movement), make the immediate_actions decisive
  and time-bound."""


@app.post("/api/email/remediate")
async def email_remediate(req: EmailRemediateRequest):
    """Generate structured AI remediation guidance for the parsed alert.
    Returns the same 6-section dict the email composer's remediation
    panel renders, so the analyst can pick which sections to include
    in the outgoing email body."""
    from providers import get_provider
    import json as _json

    if not _llm_key_configured():
        # Use the OPENAI_API_KEY_MISSING error message when the active
        # provider IS openai/azure so the existing analyst-facing copy
        # still surfaces; for anthropic/ollama just say the provider
        # isn't configured.
        import os as _os
        _prov = (_os.environ.get("LLM_PROVIDER") or "openai").strip().lower()
        if _prov in ("openai", "azure", "azure-openai", "azureopenai"):
            from intel.error_messages import lookup as _lookup
            err = _lookup("OPENAI_API_KEY_MISSING")
            raise HTTPException(503, err["detail"])
        raise HTTPException(503, "LLM provider not configured")

    # Compact, AI-friendly representation of the alert details.
    parsed = req.parsed or {}
    detail_lines = []
    for k in ("suggested_alert_type", "_alert_label", "user_principal_name",
              "user_display_name", "asset_name", "ip_address",
              "location_city", "location_country",
              "ep_process_path", "ep_cmd_line", "ep_sha256",
              "ep_application_name", "ep_message", "ep_defender_type",
              "risk_event_type", "risk_state", "risk_level", "risk_detail",
              "additional_info_risk_reasons", "additional_info_user_agent"):
        v = parsed.get(k)
        if v:
            detail_lines.append(f"  {k}: {v}")

    user_msg = (
        f"ALERT TYPE        : {req.alert_type or parsed.get('suggested_alert_type') or 'unknown'}\n"
        f"THREAT LEVEL      : {req.threat_level or 'unknown'}\n"
        f"SEVERITY          : {req.severity or 'unknown'}\n"
        f"MITRE TECHNIQUES  : {', '.join((req.mitre_techniques or [])[:8]) or '(none mapped)'}\n\n"
        f"PARSED ALERT DETAILS:\n"
        + ("\n".join(detail_lines) if detail_lines else "  (no structured fields available)")
        + "\n\nRAW LOG (first 2000 chars):\n"
        + (req.log_text or "")[:2000]
    )

    try:
        provider = get_provider()
        resp = await provider.complete(
            model=config.get_model(),   # smart model for the customer-facing guidance
            messages=[
                {"role": "system", "content": _REMEDIATION_SYSTEM_PROMPT},
                {"role": "user",   "content": user_msg},
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
            max_tokens=1800,
        )
    except Exception as e:
        raise HTTPException(503, _clean_exc(e, prefix="AI remediation"))

    if resp.error:
        raise HTTPException(503, resp.error)

    try:
        out = _json.loads(resp.message or "{}")
    except Exception:
        # Retry once with an explicit format-fix instruction — matches the
        # graceful-degradation rule in S4.
        try:
            resp2 = await provider.complete(
                model=config.get_model(),
                messages=[
                    {"role": "system", "content": _REMEDIATION_SYSTEM_PROMPT},
                    {"role": "user",   "content": user_msg},
                    {"role": "assistant", "content": resp.message or ""},
                    {"role": "user", "content":
                        "Your previous response was not valid JSON. Re-emit it as "
                        "strict JSON only — no markdown, no commentary, no fences."},
                ],
                response_format={"type": "json_object"},
                temperature=0.0,
                max_tokens=1800,
            )
            out = _json.loads(resp2.message or "{}")
        except Exception:
            out = {}

    # Schema fill-in so the frontend can render every section unconditionally.
    return {
        "immediate_actions":   out.get("immediate_actions") or [],
        "investigation_steps": out.get("investigation_steps") or [],
        "containment_guidance": out.get("containment_guidance") or "",
        "recovery_guidance":    out.get("recovery_guidance") or "",
        "detection_guidance":   out.get("detection_guidance") or "",
        "executive_summary":    out.get("executive_summary") or "",
        "model":                resp.model or "",
        "provider":             resp.provider or "",
    }


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
    except Exception as _hist_e:
        # The send already happened — losing the history entry isn't
        # catastrophic but it does mean an analyst hitting /api/email/history
        # wouldn't see this send. Worth surfacing so a persistently
        # broken append_history (corrupted in-memory store, bug in the
        # ring-buffer) shows up in operator logs instead of looking like
        # silent message loss.
        _log.warning("email history append failed after send "
                     "to=%s subject=%r: %s",
                     (req.to or "")[:64], (req.subject or "")[:120], _hist_e)
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
    """Stash a composed email in the in-memory drafts store. Lost on
    restart by design — per the platform's no-persistence policy. The
    old docstring claimed it persisted to backend/data/email_drafts/
    but save_draft has only ever touched _drafts_mem."""
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
    # Same CRLF defense as EmailSendRequest — the `to` value flows into a
    # MIME To: header via email_composer.send_smtp, and Python's email
    # module doesn't filter \r\n in header values. Reject early so an
    # attacker can't smuggle Bcc: / Reply-To: rows into the test path.
    if not isinstance(to, str) or len(to) > 2_000 or "\r" in to or "\n" in to:
        raise HTTPException(400, "to address malformed")
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
    if not content:
        raise HTTPException(400, "empty file")
    # UploadFile.filename is Optional[str] — without the guard,
    # file.filename.endswith(...) raises AttributeError for a body
    # uploaded without a Content-Disposition filename.
    fname = (file.filename or "").lower()
    suffix = ".csv" if fname.endswith(".csv") else ".json"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False, mode="wb") as tmp:
        tmp.write(content)
        tmp_path = tmp.name
    try:
        iocs = parse_misp_csv(tmp_path) if suffix == ".csv" else parse_misp_json(tmp_path)
    finally:
        try:
            _os.unlink(tmp_path)
        except OSError:
            pass
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
        # Catch every exception — BackgroundTasks runs this AFTER the
        # response is already sent, so an uncaught raise has no caller
        # to surface to. Without the store-error path the GET poller
        # saw {"status": "pending"} forever on a backend that had
        # actually failed; the client retried indefinitely with no
        # signal anything was wrong.
        try:
            _taxii_cache[poll_id] = await poll_all_feeds(since_hours=req.sinceHours)
        except Exception as _e:
            _log.exception("taxii poll %s failed", poll_id)
            _taxii_cache[poll_id] = {"error": _clean_exc(_e, prefix="taxii poll")}
    background_tasks.add_task(_poll)
    return {"pollId": poll_id, "status": "polling"}

@app.get("/api/taxii/results/{poll_id}")
async def taxii_results(poll_id: str):
    cached = _taxii_cache.get(poll_id)
    if cached is None:
        return {"status": "pending"}
    if "error" in cached:
        return {"status": "error", "error": cached["error"]}
    return {"status": "complete", **cached}

@app.get("/api/taxii/feeds")
async def taxii_feeds():
    from intel.taxii_poller import FEEDS
    return {"feeds": [{"name": f["name"], "description": f["description"]} for f in FEEDS]}


# ─── FRONTEND ─────────────────────────────────────────────────────────────────────
# index.html MUST be served with no-cache headers — it references
# fingerprinted chunk filenames (e.g. /static/js/633.{hash}.chunk.js) and a
# stale cached index pointing at chunk hashes the new deployment no longer
# has produces a "Loading chunk N failed" crash for every analyst with an
# open tab during the redeploy. Static chunk files keep their long-term
# cache because their filename changes on every build.
_INDEX_NOCACHE_HEADERS = {
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma":        "no-cache",
    "Expires":       "0",
}

if FRONTEND_BUILD.exists():
    # CRA emits content-hashed filenames under /static/ (main.<hash>.js,
    # <chunk>.<hash>.chunk.js, main.<hash>.css). Hashed assets are
    # immutable by construction — a new build mints a new hash — so we
    # can safely tell browsers to cache them for a year. Default
    # StaticFiles ships no Cache-Control, which means every page load
    # does a conditional revalidation (etag round-trip) on a 670 KB JS
    # bundle. Subclass + inject one Cache-Control header on every
    # response.
    class _ImmutableStatic(StaticFiles):
        async def get_response(self, path, scope):
            resp = await super().get_response(path, scope)
            if resp.status_code == 200:
                resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            return resp

    app.mount("/static", _ImmutableStatic(directory=str(FRONTEND_BUILD / "static")), name="static")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        if full_path.startswith("api/"):
            raise HTTPException(404)
        # /favicon.ico convention path — browsers always request this even
        # when index.html declares a different <link rel="icon">. Without
        # a real file the SPA fallback served HTML, which made every
        # browser console log a "Resource interpreted as Image" warning
        # and a faviconLoad failure. Serve logo.png with image/x-icon so
        # the tab gets a real icon.
        if full_path == "favicon.ico":
            logo = FRONTEND_BUILD / "logo.png"
            if logo.exists():
                return FileResponse(
                    str(logo), media_type="image/x-icon",
                    headers={"Cache-Control": "public, max-age=86400"},
                )
        # Serve actual files from build/ when they exist (logo.png, favicon, manifest, etc.)
        if full_path:
            asset = FRONTEND_BUILD / full_path
            if asset.is_file() and asset.resolve().is_relative_to(FRONTEND_BUILD.resolve()):
                # Top-level index.html (when requested by name) also gets the
                # no-cache headers; other named assets keep default caching.
                if asset.name == "index.html":
                    return FileResponse(str(asset), headers=_INDEX_NOCACHE_HEADERS)
                return FileResponse(str(asset))
        # Otherwise fall back to SPA index — never cached.
        idx = FRONTEND_BUILD / "index.html"
        if idx.exists():
            return FileResponse(str(idx), headers=_INDEX_NOCACHE_HEADERS)
        raise HTTPException(404, "Frontend not built. Run: cd frontend && npm run build")


# ─── HELPERS ──────────────────────────────────────────────────────────────────────
def _ts():
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=os.getenv("HOST", "0.0.0.0"),
                port=int(os.getenv("PORT", 8000)), reload=False)
