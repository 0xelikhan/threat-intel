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
│   ├── main.py              # All 60+ REST endpoints, middlewares, auth
│   ├── config.py            # API-key store (data/config.json)
│   ├── mcp_server.py        # Separate stdio MCP entry point for Claude
│   │                        #   Desktop / Cursor / Continue / Zed —
│   │                        #   NOT mounted by main.py; launched by
│   │                        #   the MCP host (`python mcp_server.py`).
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
│   │   └── ollama_provider.py
│   ├── skills/              # Granular, individually-runnable units
│   │   ├── base.py          # Skill ABC
│   │   ├── __init__.py      # SKILL_REGISTRY + get_skill + run_skill
│   │   └── (17 skills — round-14 added semantic_search_detections)
│   ├── intel/               # TI data layer + everything not an agent
│   │   ├── auth.py          # bcrypt verify_credentials
│   │   ├── cache.py         # TTLCache + namespace registry (Section 3)
│   │   ├── circuit_breaker.py
│   │   ├── observability.py # request IDs + structured logging + envelope
│   │   ├── redactor.py      # Fail-closed secret redaction
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
        ├── App.js           # ~6.3k-line root — auth, routing, drawer,
        │                    #   AND ~30 inline analysis sub-components
        │                    #   (Sidebar, AnalystSummary, ChatWithRecon,
        │                    #    Detection, ThreatScore, BulkTable, …).
        │                    #   Sigma/KQL generation, threat score, IOC
        │                    #   export and the analyst report all live
        │                    #   here as inline functions, NOT as
        │                    #   separate files.
        ├── theme.js         # MUI overrides on the OpenCTI palette
        ├── sourceUrls.js    # IOC → public-UI deep-link builders
        ├── index.js / index.css
        ├── utils/
        │   ├── api.js       # apiFetch + retry + onApiError bus
        │   └── format.js    # smartTruncate, sourceErrorMessage
        └── components/
            ├── ui.js                # Shared MUI primitives (Tag, Card, …)
            ├── AgentPipeline.jsx    # The analyze SSE stream UI
            ├── FileScannerView.jsx  # Big file-analyst report (lazy)
            ├── MapTab.jsx           # Leaflet IP geo (lazy)
            ├── LoginPage.jsx        # (lazy)
            ├── URLScanLive.jsx      # URLScan submit + poll block
            ├── ErrorBoundary.jsx    # Generic boundary + ChunkLoadError reload
            ├── Toast.jsx            # Toast surface bound to onApiError
            └── Skeleton.jsx         # Pulse-animated placeholders
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
     in a global `asyncio.Semaphore(16)` + an `asyncio.wait_for(12s)` safety
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
* `ollama_provider.py` — local models, no tool calling.

To swap the backend LLM to a local Ollama instance set
`LLM_PROVIDER=ollama` and restart. No code edits.

---

## Skill system

Skills are granular, individually-testable wrappers over the agent
logic. The orchestrator is the pipeline entry point; skills are the
programmatic entry point used by tests and any future per-step caller
(Teams bot, future API endpoints).

```
SKILL_REGISTRY = {
  # Core analyst-pipeline skills (rounds 1-2)
  "extract_iocs", "enrich_ioc", "triage_alert", "investigate",
  "generate_sigma", "generate_kql", "map_mitre", "correlate_signals",
  # PEAK threat-hunt skills (round 2)
  "generate_hypothesis", "generate_able_table", "generate_hunt_plan",
  # Round 3+
  "domain_permutations", "analyze_capabilities",
  "match_sigma_rules", "classify_capabilities", "match_detections",
  # Round 14 — natural-language search across the 11 detection corpora
  "semantic_search_detections",
  # Round 15 — see "Round 15" section below for the cti-expert
  # integrations that landed as intel modules (not skills).
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

* **No-persistence policy** — analyst-submitted data must NEVER hit disk.
  Pasted logs, IOCs, scan results, calibration overrides, email drafts,
  feed cache, and audit records all live in module-level in-memory
  stores (capped via `_BoundedDict` or `deque(maxlen=...)`). The ONLY
  acceptable file under `backend/data/` is `config.json` (operator API
  keys). On startup the lifespan handler wipes any legacy
  `audit.log` / `calibration_overrides.jsonl` / `email_history.json` /
  `feed_cache.json` / `scanner_feedback.json` files plus
  `scanned_files/` / `email_drafts/` / `cases/` / `sandbox_results/`
  directories. Treat any new disk write under `backend/data/` (other
  than the config file) as a code smell.
* **Fail-closed redactor** (`intel/redactor.py`) — typed placeholders
  for PEM keys, AWS/Azure/OpenAI/Anthropic keys, JWTs, credentials,
  emails, IPs, MAC, UNC paths, hostnames, hex blobs. Confidence-scored.
* **Auth** — bcrypt password hash + signed HTTP-only cookie
  (SameSite=Strict, 12 h max age). `AuthGateMiddleware` walls off every
  `/api/*` route except `/api/auth/*`, `/api/health`, `/api/docs`.
  The 401 response goes through `error_envelope()` inline (middleware
  can't raise HTTPException), so it carries the same shape as every
  other error.
* **AuditMiddleware** — body cap 50 MB. `audit_log()` emits via the
  structured logger to stdout (transient), NOT to a file — operator
  log shipping is what makes it durable, not the platform.
* **CORS** — `RECON_CORS` env var overrides the origin list; default is
  `http://localhost:3000` + `http://127.0.0.1:3000` for dev. Wildcard +
  credentials is rejected by the config (and by every browser anyway).
* **SSRF guard** on `/api/scan/url` — resolves the hostname, rejects
  RFC1918 / loopback / link-local / metadata-service addresses, follows
  redirects manually with the same guard on every hop.
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
| `ENRICH_CONCURRENCY`         | `16`          | asyncio.Semaphore cap on TI fan-out (per-host independently capped at ENRICH_POOL_PER_HOST) |
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
* **Bounded module-level state** (`_BoundedDict` in `main.py`) — `_results`,
  `_chats`, `_sandbox_jobs` are capped at 500 entries with LRU eviction.
  `intel/file_correlation.py::_scan_store` is a 500-entry `OrderedDict`.
  `intel/calibration_log.py::_RECORDS` is a `deque(maxlen=5000)`.
  Anything new that accumulates per-run state should use one of these
  patterns — never an unbounded `dict = {}`.
* **Background tasks** — fire-and-forget `asyncio.create_task(...)` calls
  must go through `main.track_task(...)`. asyncio only keeps a weakref,
  so a discarded reference can be GC'd mid-flight. The lifespan handler
  uses this for the warm/poll/health loops; external modules can
  `from main import track_task` (see `intel/file_correlation.py`).
* **TI source pivots** — `frontend/src/sourceUrls.js` maps
  `(source label, IOC type)` to a public-web-UI deep link. When the
  per-IOC expanded view renders a source row, the source label becomes
  an anchor if `sourceUrl()` returns a URL. Adding a new TI source?
  Drop its `(source label) → URL builder` row in `BUILDERS`.

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
* `447deb6` — lifespan handler + race lock + datetime tz + silent except logging + Pydantic + Dockerfile sanity
* `ac6d432` — frontend leaks + perf + CORS + SSRF + auth logging + logText bound
* `5a36e36` — no-persistence policy: every analyst-data store moved in-memory
* `1e95ca4` — MITRE/feed/actor inverted indexes + module-level regex compilation
* `e06ed50` — runtime correctness: datetime, auth envelope, Pydantic mutable defaults
* `c8c143f` — clickable TI source labels deep-link to each source's web UI
* `478322c` — agent/provider silent-failure logging + tool result truncation cap
* `781eecb` — dropped 4 dead React components + MCP inventory error surfacing
* `8ad5f34` — EmailComposer "+N more" expandable + triage/investigate hardening

## June 2026 expansion (rounds 1-11)

A multi-session expansion took RECON from ~40 OSS sources to ~90. The
architecture is unchanged — same LangGraph pipeline, same skill
registry, same providers/ abstraction. What changed is what flows
through it.

### New intel modules (~70 added)

**TI / IOC sources:** Shodan InternetDB, FireHOL blocklists (~400),
cloud provider IP ranges (AWS / Azure / GCP / Cloudflare / Fastly /
GitHub), DataPlane.org honeypot feeds, SANS DShield, Spamhaus DROP/
EDROP, MalwareBazaar (abuse.ch), HIBP Pwned Passwords (k-anonymity),
ESET malware-ioc, MVT mobile spyware (Pegasus / Predator / RCS Lab),
OFAC SDN list (sanctioned crypto + emails + domains), Phishing.Database
+ OpenPhish merged feed, Tranco top-1M, Chromium HSTS preload list,
Mozilla Observatory web-grader, Ransomwhe.re, EPSS, OSV.dev, GHSA,
Red Hat Security Data, MSRC, OASIS CSAF, ProjectDiscovery nuclei-
templates, trickest/cve PoC index, Apple/Adobe/Oracle vendor RSS,
endoflife.date.

**Detection corpora (11 sources unified in `match_detections` skill):**
SigmaHQ (~2,700), panther-analysis (~1,500 cloud), Splunk security_
content, MITRE CAR, OTRF ThreatHunter-Playbook, Sublime email rules,
Chronicle YARA-L, olafhartong KQL/Sentinel, falco-rules (containers),
Stratus Red Team (cloud TTPs), ET Open + Snort Community IDS rules.

**YARA corpora (23 sources):** Florian Roth signature-base, Yara-Rules
community, Mandiant RTC, ReversingLabs, Volexity, ESET, Trellix ATR,
bartblaze, mthcht-strict, Chainguard malcontent (capability-bucketed),
ditekshen, delivr-to, filescan.io, Google Chronicle GCTI,
ConventionEngine, InQuest, jeFF0Falltrades, Intezer, Rapid7 Labs,
securitymagic, f0wl, CyStack, Operation Epic Fury.

**Analyst frameworks:** PEAK threat-hunting (Cisco Talos) — `skills/
generate_hypothesis` + `generate_able_table` + `generate_hunt_plan`
with `providers/critic_loop.py` (gen→critic re-prompt without
AutoGen). CTID Attack Flow STIX 2.1 extension in
`agents/response.py::_build_stix`. Palantir ADS Framework injected
into the analyst-summary prompt. MITRE D3FEND, CAPEC, NIST 800-53,
CISA CPG, SSVC decision tree, ETW provider catalog, ForensicArtifacts
evidence registry — all surface in `state["d3fend_countermeasures"]`,
`capec_patterns`, `nist_controls`, `cisa_cpg`, `etw_providers`,
`forensic_targets`, `emulation_plan` from the investigation node.
ATT&CK Mobile / ICS matrices loaded alongside Enterprise via
`intel/mitre_data.py`; `looks_like_{ics,mobile,cloud,container}_alert`
keyword routers gate the matrix-specific lookups.

**File scanner additions:** FLARE capa (opt-in, slow), Chainguard
malcontent capability bucket grouping, MalAPI.io Windows API → MITRE
mapping. `_capa_eligible` gates the subprocess to PE / .NET / ELF
inputs over 1 KB.

### New skills

`generate_hypothesis`, `generate_able_table`, `generate_hunt_plan`,
`domain_permutations`, `analyze_capabilities`, `match_sigma_rules`,
`classify_capabilities`, `match_detections`, and (round 14)
`semantic_search_detections` — 17 skills total.

### Output formats + outbound integrations

- **STIX 2.1** bundle export — `/api/export/stix/{run_id}` (always existed)
- **Attack Flow** overlay (CTID STIX extension) — appended inside the bundle
- **SARIF 2.1.0** — `/api/export/sarif/{run_id}` for GitHub Code Scanning
- **OASIS CACAO 2.0** — `/api/export/cacao/{run_id}` for SOAR playbooks
- **MISP push** — `/api/integrations/misp/push` (operator sets `MISP_URL` + `MISP_KEY`)
- **TheHive push** — `/api/integrations/thehive/push` (operator sets `THEHIVE_URL` + `THEHIVE_KEY`)
- **STIX-Shifter translate** — `/api/integrations/stix-shifter/translate` (Splunk / KQL / QRadar / Elastic / CrowdStrike). Built-in fallback translator; upstream stix-shifter library auto-picks up if installed.

Every outbound push hits `audit_log()` so an analyst can grep the
audit stream for what left the system.

### Speed / opt-in env flags (consult Settings via `config.get()`)

- `RECON_ENABLE_MSRC` (default 0) — Microsoft Security Update Guide CVE lookup; slow
- `RECON_ENABLE_MOZILLA_OBSERVATORY` (default 0) — per-domain web grade; slow
- `RECON_ENABLE_CAPA` (default 0) — FLARE capa subprocess per PE
- `RECON_ENABLE_OSV` (default 1)
- `RECON_ENABLE_RHSA` (default 1)
- `RECON_ENABLE_SHODAN_INTERNETDB` (default 1)
- `RECON_TAXII_FEEDS` — comma-separated slugs from `intel/taxii_feeds_catalog.py`

### Frontend cards — current detail-view stack (round-14 consolidation)

The analyst-results detail view is intentionally **6 cards**, in order:

1. **Summary** (`AnalystSummary`) — verdict + threat score + inline
   feedback form.
2. **Ask RECON** (`ChatWithRecon`) — conversational follow-up.
3. **Triage** — rolls up 9 sub-sections via the `bare` prop pattern:
   URL detonation (URLScanLive), lookalike domains
   (DomainPermutationsView), log normalisation (LogTranslation),
   threat-intel cross-references (CrossRefs — KEV/LOLBAS/LOLDrivers/
   RMM/phishing kits), sandbox process tree (SandboxBehavioral),
   OSINT (InfrastructureIntel), MISP suppressed IOCs, recommended
   actions, analyst notes.
4. **Email analysis** (`EmailAnalysis`) — only when an EML is parsed.
5. **Geolocation** — Leaflet map + `GeopoliticalContext bare` (country
   + ASN breakdown + attribution hints). Only when IPs are present.
6. **Detection Rules** (`Detection`) — generated SIEM rules (Sigma /
   KQL / SPL / EQL / Suricata / YARA-L / FQL / YARA tabs) + JA3/JA4
   TLS fingerprints (when present) + **public detection citations +
   semantic-search bar** (`DetectionCitationsView bare`, round-14).

Cards that no longer appear in the analyst-results layout:

* `DefenseContextView` — removed; the backend still emits
  `d3fend_countermeasures` / `capec_patterns` / `nist_controls` /
  `cisa_cpg` / `etw_providers` / `forensic_targets` / `emulation_plan`
  on state, so operators can hit them via the API.
* `HuntPlanView` — removed (round 11, UI bloat). PEAK skills +
  `/api/hunt/plan` endpoint still work.
* `ExportButtons` — removed; STIX / SARIF / CACAO endpoints still
  live at `/api/export/{stix,sarif,cacao}/{run_id}`.

Conventions:

* The `bare` prop pattern (used by URLScanLive, DomainPermutationsView,
  SuppressedIOCs, CrossRefs, etc.) strips the outer Card wrapper so a
  component can render as a Section inside a parent Card. Use this
  rather than duplicating the body across "card" and "section" forms.

### Defensive coercion

`agents/response.py` final pass coerces 17 LLM-emitted list fields
(recommended_actions, probing_questions, analysis_assessment, etc.)
to arrays so the React UI's `.filter()` calls never see a string /
dict. Frontend has a matching `asArray()` helper as defence-in-depth.

### Operator fetcher scripts

9 shell scripts under `scripts/fetch_*.sh` clone the heavyweight rule
corpora into `vendor/`. The platform is fully functional out-of-the-
box via built-in fallbacks; fetchers add depth.

## Rounds 12-14 (post-expansion polish)

### Round 12-13 — perf profiling + email polish

* `agents/enrichment.py::_record_timing` / `network_timings_snapshot`
  — per-host timing histogram surfaced at `/api/status` under
  `network_timings` (mean / max / ok / errors). `POST
  /api/status/timings/reset` clears for scoped measurement.
* Defender 1116/1117 email grammar fixes in
  `intel/email_composer.py::_FILLER_SUBS`.
* Summary card production crash fixed via 17-array-field force-coerce
  in `agents/response.py` (see "Defensive coercion" above) + frontend
  `asArray()` defence in depth.

### Round 14 — Trained ML augmentations

Three sklearn-backed enhancements over the existing heuristic /
keyword-match paths, all trained at first call on bundled in-tree
data (no disk persistence; pre-warmed in the lifespan handler so the
first request doesn't pay the train cost):

* `intel/dga_classifier.py` — LogisticRegression over char-bigram
  TF-IDF + 7 structural features (entropy, vowel/digit ratio, longest
  consonant run). Wired into `agents/enrichment.enrich_domain`
  alongside `_typosquat_check`. Augments training with the loaded
  Tranco corpus when present. Output: `{is_dga, probability,
  confidence, verdict, label, summary, source}`. Surfaces in the
  per-IOC source list as "DGA classifier" with a probability
  percentage.
* `intel/phishing_url_classifier.py` — GradientBoosting over 22
  URL-structural features (length, special-char ratios, IP-in-URL,
  abused-TLD list, brand-Levenshtein distance vs ~60 impersonation
  targets, brand-in-subdomain, brand-in-path). Wired into
  `agents/enrichment.enrich_url`. Output adds a `features` dict so
  the analyst report can show WHICH drivers fired. Surfaces as
  "Phishing URL classifier" with the top 3 drivers in the row label.
* `intel/semantic_search.py` + `skills/semantic_search_detections.py`
  + `GET /api/detection/search` — natural-language search across the
  11 detection corpora. Uses `sentence-transformers` (all-MiniLM-L6-v2,
  ~80 MB) when installed, otherwise a sklearn TF-IDF char-ngram
  fallback. Index built lazily, in-memory only. Frontend search bar
  lives at the top of the Detection Rules card's "Public detection
  citations" section — it's the only user-visible surface for the
  endpoint.

All three modules return a structured shape with verdict tier +
confidence + summary, and degrade gracefully to a heuristic when
sklearn is unavailable. `requirements.txt` lists `scikit-learn>=1.4.0`
as baseline; `sentence-transformers` is operator-opt-in
(commented out).

### Perf wins in this band

* `ENRICH_CONCURRENCY` default bumped `10 → 16`. Per-host
  TCPConnector cap (`ENRICH_POOL_PER_HOST=10`) independently rate-
  limits any one TI source, so this only adds cross-host parallelism.
* Lifespan `_warm_all()` pre-trains both sklearn classifiers + loads
  all 11 detection corpora + builds the semantic-search index — first
  request no longer pays the lazy-load cost (~12 s of YAML walks +
  ~150 ms of training when these were paid on the request path).
* Audit pass (post-round-14): pre-warm gap filled for the 7 defensive-
  context corpora (D3FEND, CAPEC, NIST 800-53, CISA CPG, ETW providers,
  ForensicArtifacts, emulation plans) — saves ~2-3 s off the first
  investigation after a restart.
* `intel/multi_log.py` deleted (audit found it orphaned; feature was
  intentionally retired in triage.py but the module wasn't removed).

## Round 15 — cti-expert integrations

Adapted from 7onez/cti-expert (MIT, Hieu Ngo / chongluadao.vn). Audited
the whole repo; four ship items + three narrow steals were worth
absorbing. The other pieces (AEAD framework, TI-source curl handbooks,
Scrapling/AgentFlow, DOCX report generator, drift monitor, guided-flow
UX) were verified dud comparisons against RECON's equivalents.

### Ship items

* `scripts/stealer_log_parse.py` — operator-runnable CLI for infostealer
  log triage. Family fingerprinting (StealC/Vidar/RedLine/Lumma/Raccoon/
  RisePro/META), victim-vs-operator classification, cross-log actor
  clustering by dropper/HWID/email. Stdlib-only. Intentionally NOT
  wired into `/api/analyze` — stealer logs contain third-party PII that
  the no-persistence policy treats as too sensitive for the bounded
  in-memory stores. Run from a workstation with appropriate handling.

* `intel/m365_tenant_recon.py` — unauthenticated Microsoft 365 / Entra
  fingerprinting. Four parallel probes: `openid-configuration`
  (tenant GUID via `issuer`), `getuserrealm.srf` (federation type +
  IdP), `{tenant}.sharepoint.com`, `{tenant}.azurewebsites.net`.
  Wired into `agents/enrichment.enrich_domain`, gated by
  `is_m365_candidate()` which scans the rest of the domain's payload
  for `protection.outlook.com` / `onmicrosoft.com` etc. so non-M365
  domains skip the network cost. Output lands on `m365_tenant` in the
  per-source enrichment dict; frontend `_ocSources` renders it as
  "M365 tenant" with `tenant ID · cloud · federation · IdP · sharepoint`.

* `intel/admin_endpoint_classifier.py` — admin / panel / customer-
  service endpoint detector. Subdomain-prefix + path-segment +
  localised-keyword matching (`管理` / `后台` / `客服` +
  Indonesian / Spanish equivalents). Scam-TLD amplifier
  (`.tk .top .icu .xyz …`) bumps verdict to MALICIOUS when combined
  with a strong indicator. Wired into `agents/enrichment.enrich_url`,
  surfaces as `admin_endpoint` in per-source dict.

* `intel/maltego_export.py` + `GET /api/export/maltego/{run_id}` —
  serialises the investigation IOCs + relationships to GraphML.
  Standard `maltego.*` entity types so no custom-entity registration
  needed in Maltego CE / XL. Derived edges: URL → on_domain → Domain;
  Domain → resolves_to → IP (read from WHOIS); Actor → seen_with → IOCs.
  Caps per IOC type at 50 nodes to keep the canvas readable.

### Narrow steals

* `intel/case_score.py` — case-level rollup score with letter grade
  (`A1..F9`) + recency multipliers (≤30d ×1.25, >730d ×0.80) +
  active-compromise amplifier (×1.35 when high-signal drivers like
  KEV/named-malware combine with credential-access/lateral-movement/
  C2). Lives ON TOP of the per-IOC `gti_score.py` — doesn't replace
  it. Surfaces as `response_summary.case_score` with `{score, grade,
  tier, drivers, multipliers, summary}`. Frontend renders a colored
  chip in the Summary card. Adapted from cti-expert weight-engine.md
  + exposure-model.md.

* `analyst_summary.intelligence_gaps` + `analyst_summary.analyst_caveats`
  — two new sections on the analyst-summary LLM prompt that force the
  model to declare what evidence it would need for higher confidence
  + what methodology caveats apply. Defensive-coerced to arrays so the
  React renderer's `.map()` never sees a string / dict. Renders under
  the prose paragraph in the Summary card. Adapted from cti-expert
  INTSUM template.

### Skipped (and why)

* AEAD framework (Acquire/Enrich/Assess/Deliver) — rename of RECON's
  triage→enrichment→investigation→response. No new mental model.
* TI-source curl handbooks — cti-expert has zero real client code, no
  fan-out engine, no pooling, no breaker. RECON's `agents/enrichment.py`
  is a real implementation; nothing to copy from a handbook.
* Scrapling / AgentFlow — pinned to 0.1.0 pre-stable, less capable
  than RECON's LangGraph fan-out (their concurrency cap is 4-8 vs
  ours at 16).
* DOCX report generator — overkill for a web product; the structural
  ideas (Gaps + Caveats) were absorbed via the steal above.
* Drift monitor — targets persona/social-account watch (username
  changes, follower deltas). Wrong domain for SOC alert triage.
* Skill tiers / guided flows / case templates — UX paradigm doesn't
  fit RECON's card-driven analyst report. The Novice/Specialist
  verbosity toggle could work, but it's a UX experiment that needs
  design feedback, not just code — deferred.
