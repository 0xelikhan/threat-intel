# RECON

A multi-agent threat-intel platform. Paste a security alert, a log line,
or a file, and the backend runs a LangGraph pipeline (triage → enrichment
→ investigation → response) plus 40+ TI sources to produce a calibrated
verdict, IOC enrichment, MITRE ATT&CK mapping, and detection content.

**Live demo:** [https://0xrecon.com](https://0xrecon.com)
*(login required — credentials on request)*

---

## What makes it different

There's a lot of "I built a ChatGPT wrapper for SOC alerts" out there.
This one is built around the things that wrapper-style projects skip:

- **Multi-agent pipeline**, not a single LLM call. Triage classifies the
  alert and extracts IOCs deterministically; enrichment fans out across
  40+ TI sources in parallel; investigation runs a tool-calling loop
  against the enriched data; response synthesises detection content.
  Each stage is independently testable and swappable.

- **Validators on every piece of AI-generated output.** Sigma rules
  compile through `sigma-cli` or are rejected. YARA rules compile
  through `yara-python` and must match the analyzed sample. The Query
  DSL has a real lexer + recursive-descent parser + AST evaluator that
  rejects malformed queries before the analyst sees them. All three
  re-prompt on failure (up to 3 attempts) with the validator's error
  message fed back to the model.

- **Server-side prose validators.** The investigation result passes
  through `intel/prose_validator.py` before leaving the backend: drops
  cross-field paraphrase duplicates, caps `summary` at 2 sentences,
  strips em-dashes and forbidden keys. Mechanical enforcement instead
  of brittle prompt prose.

- **Defensive parser semantics.** Every TI source (`agents/enrichment.py`)
  follows the same `_get()` → categorical `error_type` → graceful-fail
  pattern: `auth_failed`, `circuit_open`, `rate_limited`, `timed_out`,
  `unreachable`, `not_configured`. The UI translates each into readable
  analyst phrasing; a single source going down never bricks an analysis.

- **GreyNoise RIOT semantics that don't lie.** A `CLEAN_INFRA` verdict
  (the IP belongs to Microsoft Azure / AWS / Cloudflare) is treated
  distinctly from `CLEAN` (no observed scanning). Inbound RDP from an
  Azure IP no longer gets auto-cleared "because GreyNoise says benign".

- **Calibration tracking + eval harness.** Every analyst override of an
  AI verdict appends to a JSONL log keyed by prompt-version. `scripts/
  eval_prompts.py` replays the corpus through the current prompts to
  measure agreement-rate delta; `scripts/prompt_hygiene.py` flags
  prompt rules whose mechanical enforcer never fires (candidates for
  token-saving removal).

- **Real query DSL with a parser, not a regex.** The `Query` tab in the
  detection panel emits a custom-syntax detection query. `intel/
  query_parser.py` is a 400-line hand-rolled lexer + recursive-descent
  parser + AST evaluator that the same module can run client-side
  against arbitrary dict-shaped data.

---

## Architecture

```
threat-intel-app/
├── backend/                   # FastAPI + LangGraph + TI integrations
│   ├── main.py                # 40+ REST endpoints, middlewares, auth
│   ├── agents/                # LangGraph nodes (triage / enrichment /
│   │                            investigation / response / orchestrator)
│   ├── providers/             # LLM provider abstraction (OpenAI /
│   │                            Azure / Anthropic / Ollama). Swap with
│   │                            one env var.
│   ├── skills/                # Granular skills (extract_iocs,
│   │                            triage_alert, generate_sigma, etc.) —
│   │                            equal-citizen entry point alongside
│   │                            the orchestrator
│   ├── routers/               # New self-contained route groups
│   ├── intel/                 # 50+ modules — every TI source, every
│   │                            offline analyzer, the deobfuscator,
│   │                            the Query parser, the calibration log
│   └── tests/                 # 290+ pytest cases
├── frontend/
│   └── src/                   # React + MUI + OpenCTI dark theme
│       ├── App.js             # Main routing + analyst surface
│       ├── components/        # Per-section views (file analyzer, map,
│       │                        detection tabs, history, etc.)
│       └── utils/             # Testable helpers (format / overlap /
│                                verdict-color)
└── scripts/                   # CLI utilities (record_override,
                                 eval_prompts, prompt_hygiene)
```

---

## Pipeline

For every analysis the orchestrator (`agents/orchestrator.py`) walks a
LangGraph state machine:

1. **`triage`** — heuristic IOC regex + AI alert classifier. Strips
   X.509 OIDs / software version strings / Defender version strings out
   of the input before extraction so `1.3.6.1.4.1.311...` doesn't get
   shipped to VT as an IP. MISP warninglists filter known-good IOCs
   here so the enrichment stage never sees them.
2. **`enrichment`** — parallel fan-out across 40+ TI sources via
   `asyncio.gather`, gated by a global `asyncio.Semaphore(10)` and a
   per-host circuit breaker. Built-in known-good baseline short-circuit
   for public DNS / Microsoft auth endpoints / Cloudflare ranges so we
   don't burn API quota on `8.8.8.8`. Multi-format deobfuscator
   (hex / unicode / fromCharCode / base64 / gzip / XOR brute / +
   CyberChef-Magic recursive auto-decode) runs against the raw input
   so encoded payloads feed the same IOC extraction.
3. **`investigation`** — tool-calling loop against the LLM. Three
   concurrent synthesis calls (verdict, key_findings, probing
   questions). MISP-galaxy lookup augments any AI-emitted threat-actor
   or malware-family with country, aliases, target sectors, refs.
   Server-side prose validator strips duplicated content before return.
4. **`response`** — Sigma + KQL + Query + STIX bundle + analyst-summary
   email. All concurrent. Each AI output passes through its respective
   validator.

---

## TI source coverage (40+)

**Free, no key:** CIRCL passive DNS, Robtex, HackerTarget, Tor exit
list, Spamhaus DBL, abuse.ch URLhaus/ThreatFox/MalwareBazaar (TAXII +
auth-key), Wayback Machine, NVD, EPSS, CISA KEV, CIRCL hashlookup,
DShield, StopForumSpam, Emerging Threats compromised IPs, Project
Honeypot, BGP Ranking, MISP feeds (CIRCL OSINT / DigitalSide / Botvrij
hash dumps), FullHunt, Spamhaus DROP / EDROP, firehol/ipsum offline
blocklists.

**Keyed:** VirusTotal, AbuseIPDB, IPInfo, GreyNoise, OTX, URLScan,
Pulsedive, Censys, Hybrid Analysis (with auto-submit-on-miss),
Maltiverse, CrowdSec, Google Safe Browsing, WHOIS XML, ProxyCheck,
Criminal IP, PhishTank, OpenCTI, Polyswarm.

**MITRE / context:** MITRE ATT&CK STIX (loaded at startup), MISP
galaxy clusters (threat-actor + malpedia + ransomware + RAT + tool —
~9 800 records across 5 files), Atomic Red Team, MITRE CAR, sigma/yara
detection content, MISP warninglists (suppresses ~50k known-good
IOCs).

---

## Detection content generation

Five tabs in the detection panel, each generates rule-format-specific
output validated before display:

| Tab | Output format | Validator |
|-----|---------------|-----------|
| MITRE ATT&CK | Technique lookup + group attribution | — |
| Threat Actors | MITRE + MISP galaxy fusion | — |
| Sigma Rule | YAML Sigma rule | `sigma-cli` compile, retry on failure |
| KQL Builder | Microsoft Sentinel KQL | — |
| Query | Custom DSL (Attribute Op Value, AND / OR / parens, regex via LIKE, NOT only with IN/LIKE/CONTAINS) | Custom lexer + AST + evaluator, retry on parse failure |

YARA generation runs separately when a malware family is identified
(`yara-python` compile + must match the analyzed sample).

---

## Calibration loop

The analyst can disagree with any AI verdict via a "Disagree with this
verdict?" link in the summary card. The override (raw input, AI
verdict, analyst's verdict, optional reason, prompt-version git SHA)
appends to `backend/data/calibration_overrides.jsonl`.

Two CLI tools consume the log:

- `scripts/eval_prompts.py` replays each record through the current
  pipeline, classifies each as `AGREED_THEN_AGREES` / `AGREED_NOW`
  (improvement) / `DISAGREED_BOTH` / `AGREED_BACK_OFF` (regression).
  Net delta + per-record regression list lets you A/B test prompt
  changes before merging.
- `scripts/prompt_hygiene.py` flags FORBIDDEN-rule prose in the
  prompts whose mechanical enforcer never fires across N records —
  candidates for removal to save tokens.

Plus `scripts/record_override.py` for backfilling overrides from
historical miscalls.

---

## Running locally

```powershell
# Backend
cd threat-intel-app/backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend (separate terminal)
cd threat-intel-app/frontend
npm install
npm start          # dev server on :3000, proxies /api to :8000
```

### Tests

```powershell
# Backend (290+ tests)
cd threat-intel-app/backend
.\venv\Scripts\python.exe -m pytest tests/ -v

# Frontend (47 tests)
cd threat-intel-app/frontend
CI=true npm test -- --watchAll=false
```

### Useful env vars

| Var | Default | Purpose |
|---|---|---|
| `LLM_PROVIDER` | `openai` | Swap LLM backend (openai / azure / anthropic / ollama) |
| `OPENAI_BASE_URL` | OpenAI public | Set to `…openai.azure.com` for Azure detection |
| `LOG_LEVEL` | `INFO` | Root logger level |
| `ENRICH_CONCURRENCY` | `10` | `asyncio.Semaphore` cap on TI fan-out |
| `ENRICH_SOURCE_TIMEOUT_S` | `12` | `asyncio.wait_for` cap per source |
| `CIRCUIT_BREAKER_THRESHOLD` | `3` | Failures before per-host breaker opens |
| `CIRCUIT_BREAKER_COOLDOWN_S` | `300` | Seconds open before half-open probe |
| `AUTH_USERNAME` | unset | Login user (no auth = 503 on login) |
| `AUTH_PASSWORD_HASH` | unset | bcrypt hash |
| `AUTH_SESSION_SECRET` | dev fallback | Cookie signing key |

API keys go in `backend/data/config.json` (gitignored) or via env vars.
The app starts in degraded mode if any key is missing — sources that
need it just don't run.

---

## Deployment

- **Containerized**, multi-stage Dockerfile builds React frontend +
  Python backend in one image (base images pulled from AWS Public ECR
  mirror to dodge Docker Hub anonymous rate-limits).
- **MITRE ATT&CK STIX, MISP galaxies, firehol/ipsum/phishing-db
  blocklists** all fetched at build time. Weekly cron rebuild keeps
  them ≤ 7 days fresh.
- **Azure Container Apps** is the target. Auto-deploy on every push
  to `main` via GitHub Actions. Health check on `/api/health`.
- **Auth** is a single bcrypt-hashed user + signed HTTP-only cookie
  (SameSite=Strict, 12h max age). `AuthGateMiddleware` walls off every
  `/api/*` route except auth + health + docs.

---

## What's intentionally NOT in scope

A few things omitted deliberately that you might expect:

- **Multi-tenancy / RBAC.** Single-user platform. Adding org-level
  isolation would be a real product, not a portfolio piece.
- **Scan-history correlation.** Each scan stands alone. Cross-scan
  pattern matching ("similar files by ssdeep") sounded valuable in
  theory but in practice produced misleading "this looks like a past
  case" prose that biased the analyst. Removed deliberately.
- **Email breach lookups (HIBP / Dehashed).** Paid sources I don't
  have keys for. The code paths were removed entirely rather than
  shipping perpetually-failing source cards.
- **Shodan host lookups.** Free plan returns 403 on `/shodan/host/`
  every time. Code path removed; the Shodan link in the UI is gone.

---

## Tech stack

Python 3.11, FastAPI, LangGraph, async aiohttp, bcrypt + signed
cookies, pytest. React 18, MUI, OpenCTI-inspired dark theme,
react-leaflet for the IP geo map, Lucide icons, jest + React Testing
Library. Docker, Azure Container Apps, GitHub Actions.

LLM: OpenAI / Azure OpenAI (default), Anthropic, Ollama — selected
via `LLM_PROVIDER` env var, same provider abstraction across the
board.

---

## License

Source available for review. Not licensed for redistribution.
