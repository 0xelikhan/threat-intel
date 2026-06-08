# RECON — Threat Intelligence Platform

A portfolio SOC platform: paste a security alert / log / IOC and the
backend runs a multi-agent LangGraph pipeline (triage → enrichment →
investigation → response) plus a constellation of TI sources. The
frontend is React + MUI with an OpenCTI dark theme. Auth is a single
signed cookie; deploy target is Azure Container Apps at
`https://0xrecon.com`.

This file is what Claude Code reads at the start of every session, so
it's the canonical map of where things live and how they fit together.
Skip the open-ended exploration and start here.

---

## Layout

```
threat-intel-app/
├── backend/                 # FastAPI + LangGraph + TI integrations
│   ├── main.py              # All 40+ REST endpoints, middlewares, auth
│   ├── config.py            # API-key store (data/config.json)
│   ├── mcp_server.py        # MCP exposure for Claude / Cursor
│   ├── gti_score.py         # Deterministic GTI verdict scorer
│   ├── constants.py         # Threat levels, verdicts, MITRE tactics, ...
│   ├── models.py            # Lazy re-export of every Pydantic model
│   ├── agents/              # LangGraph nodes
│   │   ├── orchestrator.py  # The StateGraph + run_pipeline()
│   │   ├── triage.py        # AI + heuristic alert triage, IOC extraction
│   │   ├── enrichment.py    # Parallel TI fan-out, no LLM
│   │   ├── investigation.py # Tool-calling deep analysis
│   │   ├── response.py      # Sigma/KQL/STIX/email synthesis
│   │   └── investigation_tools.py
│   ├── providers/           # LLM provider abstraction (Section: LLMs)
│   │   ├── base.py          # ABC + LLMResponse / LLMChunk shapes
│   │   ├── factory.py       # get_provider(name=None) singleton
│   │   ├── openai_provider.py
│   │   ├── anthropic_provider.py
│   │   └── ollama_provider.py
│   ├── skills/              # Granular, individually-runnable units
│   │   ├── base.py          # Skill ABC
│   │   ├── __init__.py      # SKILL_REGISTRY + get_skill + run_skill
│   │   └── (8 skills)
│   ├── intel/               # TI data layer + everything not an agent
│   │   ├── auth.py          # bcrypt verify_credentials
│   │   ├── cache.py         # TTLCache + namespace registry (Section 3)
│   │   ├── circuit_breaker.py
│   │   ├── observability.py # request IDs + structured logging + envelope
│   │   ├── redactor.py      # Fail-closed secret redaction
│   │   ├── identity_hash.py # Tenant-scoped HMAC
│   │   ├── warninglist_filter.py
│   │   ├── mitre_data.py    # MITRE ATT&CK loader
│   │   ├── misp_feeds.py    # CIRCL/DigitalSide/Botvrij flat hash dumps
│   │   ├── misp_galaxies.py # Threat-actor / malpedia / ransomware lookup
│   │   ├── known_good_baseline.py  # short-circuit for public DNS, MS auth, etc.
│   │   ├── deobfuscator.py  # 12-format detector + CyberChef-Magic recursive decoder
│   │   ├── prose_validator.py  # server-side de-dup of AI-emitted prose fields
│   │   ├── query_parser.py  # lexer + AST + evaluator for the Query DSL
│   │   ├── calibration_log.py  # analyst override JSONL recorder
│   │   └── (40+ other modules — file analysis, sandbox, feeds, ...)
│   ├── routers/             # FastAPI router modules (gradual main.py split)
│   │   ├── calibration.py   # /api/calibration/override
│   │   └── sandbox.py       # /api/sandbox/result/{sha256}
│   └── tests/               # pytest, namespace-based grouping
└── frontend/
    └── src/
        ├── App.js           # 3.9k-line root — auth, routing, drawer
        ├── theme.js         # MUI overrides on the OpenCTI palette
        ├── ui.js            # Shared MUI primitives (Tag, Card, ...)
        └── components/
            ├── AgentPipeline.jsx    # The analyze SSE stream UI
            ├── FileScannerView.jsx  # Big file-analyst report (lazy)
            ├── EmailComposerView.jsx
            ├── MapTab.jsx           # Leaflet IP geo (lazy)
            ├── LoginPage.jsx        # (lazy)
            ├── DetectionTab.jsx     # Sigma/KQL generator
            ├── HistoryPanel.jsx
            ├── GTIScorePanel.jsx
            ├── ReportView.jsx       # Print-friendly markdown
            └── ExportBar.jsx        # IOC CSV / plaintext download
```

---

## Data flow — what happens when you click Analyze

1. **POST /api/analyze** is an SSE stream. Body: `{logText, inputType, label}`.
2. `main.py` builds an initial `SOCState`, calls `agents/orchestrator.py::run_pipeline(...)`.
3. **LangGraph** walks the state machine:
   * `triage.run_triage` — heuristic IOC regex + AI alert classifier.
     MISP warninglist filter runs HERE so known-good IOCs never reach
     the enrichment fan-out. Updates `state["iocs"]`, `triage_score`,
     `behavioral_indicators`, `agent_trace`.
   * Routing decision (`_route_triage`):
     - score ≤ 0.10 + no signals  → `dropped`
     - has IPs/domains/hashes/URLs → `enrichment`
     - otherwise (process/path-only behavioral logs) → straight to `investigation`
   * `enrichment.run_enrichment` — opens an `aiohttp.ClientSession` with a
     **shared process-wide TCPConnector** (Section 2), fans out per IOC
     type concurrently via `asyncio.gather`. Each `_get`/`_post` is wrapped
     in a global `asyncio.Semaphore(10)` + an `asyncio.wait_for(12s)` safety
     timeout + the per-host circuit breaker (Section 5). Partial snapshots
     stream back to the UI via `on_partial` whenever a category finishes.
   * `investigation.run_investigation` — tool-calling loop against the
     LLM provider, three concurrent synthesis calls (verdict / key_findings /
     probing_questions), single-shot fallback. May loop back to enrichment
     when `confidence < 0.55 and needs_more_enrichment and iteration < 2`.
   * `response.run_response` — produces Sigma + KQL + analyst summary +
     STIX bundle + email draft. All concurrent.
4. State is serialised back to the SSE stream as `event: complete`.

---

## LLM provider system

Every AI call goes through `providers/get_provider()`. The factory
reads `LLM_PROVIDER` from env (default `openai`) and returns an
`LLMProvider` instance with a uniform `complete()` + `stream()` API.

Implementations:
* `openai_provider.py` — Azure OpenAI auto-detected when `OPENAI_BASE_URL`
  contains `openai.azure.com`. Manual retry layer: 429 → wait 2s retry once;
  5xx → retry once; auth errors → clear analyst message, no retry.
* `anthropic_provider.py` — Claude Sonnet, default `claude-sonnet-4-20250514`.
* `ollama_provider.py` — local models, no tool calling.

To swap the backend LLM for the whole platform set
`LLM_PROVIDER=anthropic` (or `=ollama`) and restart. No code edits.

---

## Skill system

Skills are granular, individually-testable wrappers over the agent
logic. The orchestrator is the pipeline entry point; skills are the
programmatic entry point used by tests and any future per-step caller
(Teams bot, future API endpoints).

```
SKILL_REGISTRY = {
  "extract_iocs", "enrich_ioc", "triage_alert", "investigate",
  "generate_sigma", "generate_kql", "map_mitre", "correlate_signals",
}
```

Invoke one in isolation:
```python
from skills import run_skill
out = await run_skill("extract_iocs", {"raw_text": "..."})
```

Each skill has `input_schema`, `output_schema`, `test_input`, and an
async `execute(inputs, provider=None)`. Provider defaults to
`get_provider()`; pass a `MockProvider` in tests.

---

## Caching

`intel/cache.py` exposes a namespaced TTLCache. Static datasets (MITRE,
warninglists, KEV, Feodo, SSL BL) live for 86 400 s; live TI sources
(VT, AbuseIPDB, …) live for 3 600 s. `EnrichIOCSkill` consults the
`enrich` namespace before every API call.

Stats are surfaced at `/api/status` under the `cache` and
`circuit_breaker` keys, additive to every existing field.

---

## Security model

* **Fail-closed redactor** (`intel/redactor.py`) — typed placeholders
  for PEM keys, AWS/Azure/OpenAI/Anthropic keys, JWTs, credentials,
  emails, IPs, MAC, UNC paths, hostnames, hex blobs. Confidence-scored.
* **Tenant-scoped HMAC** (`intel/identity_hash.py`) — per-tenant key
  precedence, normalised inputs, `HMAC(key, tenant || kind || normalized)`.
* **Auth** — bcrypt password hash + signed HTTP-only cookie
  (SameSite=Strict, 12 h max age). `AuthGateMiddleware` walls off every
  `/api/*` route except `/api/auth/*`, `/api/health`, `/api/docs`.
* **AuditMiddleware** — body cap 50 MB, redacts string values on
  sensitive fields before writing.
* **CSP / X-Frame-Options / X-Content-Type-Options** via
  `SecurityHeadersMiddleware`.

Auth credentials are env vars: `AUTH_USERNAME`, `AUTH_PASSWORD_HASH`,
`AUTH_SESSION_SECRET`. When unset the platform returns 503 on every
login attempt — fail closed.

---

## API contracts (what the frontend reads)

The frontend reads error responses as `err.detail || err.error ||
"HTTP <status>"`. The error envelope (`intel/observability.py::error_envelope`)
preserves both `detail` and `error` and **stacks new fields on top**:

```json
{
  "detail":      "...",
  "error":       "...",
  "error_code":  "machine_readable_slug",
  "details":     { ... optional extras ... },
  "request_id":  "uuid-or-null",
  "ts":          1700000000000,
  "status":      400
}
```

Old clients keep working; new clients can read the structured fields.

Every endpoint response also carries an `X-Request-ID` header for
log correlation.

---

## Running it

```powershell
# backend
cd threat-intel-app/backend
.\venv\Scripts\Activate.ps1
uvicorn main:app --reload --port 8000

# frontend
cd ../frontend
npm install
npm start          # dev server on :3000, proxies /api to :8000
npm run build      # production bundle (warnings are pre-existing)
```

### Tests

```powershell
cd backend
.\venv\Scripts\python.exe -m pytest tests/ -v
```

Suite covers: providers (mock + live), skills (every registered skill +
specific behavioural checks), TTL cache, circuit breaker, error envelope,
observability. Anthropic / Ollama provider tests skip without creds.

### Useful env vars

| Var                          | Default       | Purpose |
|------------------------------|---------------|---------|
| `LLM_PROVIDER`               | `openai`      | Swap LLM backend (openai/azure/anthropic/ollama) |
| `OPENAI_BASE_URL`            | OpenAI public | Set to `…openai.azure.com` for Azure detection |
| `LOG_LEVEL`                  | `INFO`        | Root logger level |
| `ENRICH_CONCURRENCY`         | `10`          | asyncio.Semaphore cap on TI fan-out |
| `ENRICH_SOURCE_TIMEOUT_S`    | `12`          | asyncio.wait_for cap per source |
| `ENRICH_POOL_LIMIT`          | `100`         | TCPConnector total connection cap |
| `ENRICH_POOL_PER_HOST`       | `10`          | TCPConnector per-host cap |
| `CIRCUIT_BREAKER_THRESHOLD`  | `3`           | Failures before breaker opens |
| `CIRCUIT_BREAKER_COOLDOWN_S` | `300`         | Seconds open before half-open probe |
| `AUTH_USERNAME`              | unset         | Login user (no auth = 503 on login) |
| `AUTH_PASSWORD_HASH`         | unset         | bcrypt hash, generate via `bcrypt.hashpw` |
| `AUTH_SESSION_SECRET`        | dev fallback  | Cookie signing key |

---

## Things to know about this codebase

* **`main.py` is 2.3k lines** — splitting into routers was considered
  and deliberately deferred; it's a working seam, not a dumping ground.
* **`email_composer.py` is 2.5k lines** — ported from an older C# WPF app;
  the templates are inline f-strings on purpose so a single grep finds them.
* **The orchestrator and the skill registry are equal-citizen entry points**.
  LangGraph for the full pipeline (every `/api/analyze`); `run_skill()` for
  granular access (tests, MCP server, future Teams bot).
* **Two HTTP rate limits in play**: the global `asyncio.Semaphore` (you
  set it) and per-TI-source rate limits (each provider enforces its own).
  The semaphore protects against pathological fan-out; per-source limits
  are visible via 429 → circuit-breaker failures → eventual skip.
* **MISP warninglist suppression happens in triage, not enrichment**.
  Don't double-filter at the source level — by the time you're enriching
  the IOC, it's already passed the warninglist gate.
* **Per-investigation isolation** — `enrichment._cache` is cleared at the
  top of every `run_enrichment()` so two analyses never share intel state.
  The TTL cache (`intel/cache.py::enrich` namespace) is a separate layer
  that DOES persist across runs for the same IOC — pick the right one
  for the use case.

---

## Conventions

* **Comments** — sparse, focused on the WHY. Don't add a comment that
  just restates the code. Module docstrings up top, brief block comments
  for non-obvious decisions. The user's preference, repeatedly stated.
* **Em-dashes (` — `) are fine in module docstrings and code comments.
  Avoid them in user-facing strings** (UI labels, email templates) where
  they signal "AI wrote this". Use a hyphen or restructure the sentence.
* **No backwards-compat shims for self-imposed renames**. If you remove
  a function, remove its callers in the same commit. Don't leave a
  re-export wrapper that nothing calls.
* **The provider abstraction is the only way to talk to an LLM**. No
  direct `AsyncOpenAI` / `AsyncAzureOpenAI` / `anthropic.Anthropic`
  imports outside `providers/`.
* **`error_envelope()` for every error response**. Use the global
  exception handlers in `main.py` — don't `return JSONResponse({...},
  status_code=400)` from a handler if you can `raise HTTPException(...)`.

---

## Things the user has explicitly asked NOT to change

* Don't break the existing error shape (`detail` field, `err.detail || err.error`).
* Don't move every Pydantic model out of `main.py` — use `models.py`'s
  lazy re-export.
* Don't add docstrings to tiny utility functions just to satisfy a
  linter — only where the why is non-obvious.
* Don't introduce a virtualization library for the IOC / MITRE lists —
  they top out at ~30 items in practice.

---

## Recent perf + reliability work (commit log highlights)

* `7532117` — backend dead code + import cleanup (152 deletions)
* `fe7d7b7` — async concurrency: TCPConnector pool + semaphore + wait_for
* `282c1cc` — TTL caching layer with per-namespace TTL + /api/status integration
* `3c077fe` — frontend perf: GZip middleware + React.memo on top-level views
* `<this commit>` — code organization: constants.py, models.py, CLAUDE.md
