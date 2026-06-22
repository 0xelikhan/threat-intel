# RECON

A multi-agent threat-intel platform. Paste a security alert, a log line,
or a file, and the backend runs a LangGraph pipeline (triage → enrichment
→ investigation → response) over **90+ open-source threat-intel sources**
to produce a calibrated verdict, IOC enrichment, MITRE ATT&CK mapping,
detection content, and downstream-tool exports.

**Live demo:** [https://0xrecon.com](https://0xrecon.com)
*(login required — credentials on request)*

## Capabilities at a glance

**Ingest:** alert text, log lines, IOCs (IP / domain / URL / hash /
email / CVE), files (PE / .NET / ELF / Office / PDF / EML), full
LangGraph pipeline streamed via SSE.

**Enrichment:** 18 IP sources (VT + AbuseIPDB + GreyNoise + OTX + CIRCL
PDNS + Robtex + hackertarget + Censys + CrowdSec + Feodo + Shodan
InternetDB + FireHOL + cloud-provider-IP-ranges + DataPlane + DShield
+ Spamhaus DROP + Maltiverse + OpenCTI), 8 hash sources (VT + Hybrid
Analysis + CIRCL hashlookup + MISP + MalwareBazaar + HIBP Pwned
Passwords + MVT mobile + file capability), 21 domain sources (VT +
URLScan + OTX + crt.sh + WHOIS + Pulsedive + Wayback + typosquat +
Spamhaus DBL + Maltiverse + OpenCTI + Phishing.DB + OpenPhish + Tranco
top-1M + MVT + OFAC SDN + HSTS preload + Mozilla Observatory), 14 CVE
sources (NVD + EPSS + CISA KEV + OSV.dev + Red Hat RHSA + Microsoft
MSRC live + nuclei-templates + GitHub Security Advisories + OASIS CSAF
+ ET Open/Snort IDS rules + trickest/cve PoCs + Apple/Adobe/Oracle
RSS + SSVC synth + endoflife.date).

**Detection generation:** Sigma + KQL/Sentinel + Splunk SPL + Elastic
EQL + Snort/Suricata + Chronicle YARA-L + CrowdStrike FQL + YARA, each
validated through the upstream compiler when available.

**11 detection-rule corpora** indexed by MITRE technique for citation
matching: SigmaHQ + panther-analysis + Splunk security_content + MITRE
CAR + OTRF ThreatHunter-Playbook + Sublime email + Chronicle YARA-L +
olafhartong KQL + falco-rules + Stratus Red Team + ET Open/Snort.

**23 YARA corpora** in the file scanner: Florian Roth signature-base +
Mandiant RTC + ReversingLabs + Volexity + ESET + Trellix-ATR + bartblaze
+ mthcht + Chainguard malcontent + ditekshen + delivr-to + filescan.io
+ Google Chronicle GCTI + ConventionEngine + InQuest + jeFF0Falltrades
+ Intezer + Rapid7-Labs + securitymagic + f0wl + CyStack + Operation
Epic Fury + (legacy Yara-Rules community).

**File analysis:** FLARE capa capability detection mapped to MITRE,
Chainguard malcontent capability buckets, PE-import → MITRE technique
mapping (intel/file_capability_map.py + MalAPI.io), 20+ YARA corpora,
Hybrid Analysis sandbox, custom CyberChef-Magic-style deobfuscator.

**Analyst frameworks:** PEAK threat-hunting (Cisco Talos) — hypothesis
+ ABLE table + hunt plan generator. CTID Attack Flow STIX 2.1 overlay.
Palantir ADS Framework structures the analyst summary. MITRE D3FEND
maps offensive techniques to defensive countermeasures. MITRE CAPEC
provides attack-pattern lineage. NIST SP 800-53 + CISA CPG controls
mapped per technique. SSVC decision tree synthesises CVE signals to
Act/Attend/Track\*/Track. ETW provider GUID catalogue for Windows
telemetry capture suggestions. ForensicArtifacts evidence-collection
targets for DFIR.

**Output formats:** STIX 2.1 + CTID Attack Flow extension + SARIF
2.1.0 (GitHub Code Scanning / Azure DevOps Advanced Security) + OASIS
CACAO 2.0 (Splunk SOAR / Tines / Torq).

**Outbound integrations:** push extracted IOCs to MISP as a single
event, create a TheHive 5 case with observables, translate the STIX
bundle to native SIEM queries (Splunk SPL / Sentinel KQL / QRadar AQL
/ Elastic ECS / CrowdStrike FQL) via a built-in fallback translator
or the upstream stix-shifter library when installed.

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

### Operator fetcher scripts

The platform ships ~90 OSS sources. The heavyweight rule corpora are
NOT vendored in the git repo (size + license attribution); operators
populate them once per deployment via the scripts under
`threat-intel-app/scripts/`:

| Script | What it pulls |
|---|---|
| `fetch_yara_corpora.sh` | 7 round-2/3 YARA corpora (signature-base, ReversingLabs, Volexity, ESET, Trellix-ATR, bartblaze, mthcht strict + malcontent) |
| `fetch_detection_corpora.sh` | Sublime, Chronicle YARA-L, olafhartong KQL, sentinel-attack, splunk attack_data |
| `fetch_nuclei_templates.sh` | ProjectDiscovery nuclei-templates (CVE→template index) |
| `fetch_round5_corpora.sh` | Stratus Red Team, falco-rules, OWASP CRS, MalAPI.io, GHSA, CodeQL (sparse) |
| `fetch_round6_corpora.sh` | trickest/cve, MVT, ETDA cyberMonitor, PayloadsAllTheThings + ATT&CK ICS + CAPEC + PSL |
| `fetch_round7_corpora.sh` | ET Open + Snort + FireHOL + ATT&CK Mobile + ETDA |
| `fetch_round8_corpora.sh` | OFAC SDN, HSTS preload, WADComs, OWASP Cheat Sheets |

Without the fetcher run, every loader falls back gracefully — most ship
with a built-in subset (D3FEND, MalAPI, CodeQL, CAPEC, NIST 800-53,
CISA CPG, ETW providers, HSTS preload all carry compact fallback maps),
so the platform is functional out-of-the-box. The fetchers add depth.

### Speed / opt-in toggles

Some enrichers add real latency. Defaults are tuned for snappy demos;
the operator can flip on the heavy ones via Settings (or env) when
they want depth:

| Setting | Default | What it adds |
|---|---|---|
| `RECON_ENABLE_MSRC` | off | Microsoft Security Update Guide CVE lookup (3-5 s) |
| `RECON_ENABLE_MOZILLA_OBSERVATORY` | off | per-domain web-security grade (3+ s) |
| `RECON_ENABLE_CAPA` | off | FLARE capa subprocess on every PE (5-30 s) |
| `RECON_ENABLE_OSV` | on | OSV.dev ecosystem advisories |
| `RECON_ENABLE_RHSA` | on | Red Hat Security Data |
| `RECON_ENABLE_SHODAN_INTERNETDB` | on | Shodan InternetDB IP inventory |

### Outbound integrations

RECON can push its findings into downstream tools:

- **MISP**: set `MISP_URL` + `MISP_KEY`; POST `/api/integrations/misp/push` with `{run_id}` to ship every extracted IOC as an Event tagged with the detected MITRE techniques.
- **TheHive**: set `THEHIVE_URL` + `THEHIVE_KEY` (+ optional `THEHIVE_ORG` / `THEHIVE_TLP`); POST `/api/integrations/thehive/push` to create a Case + attach Observables.
- **STIX-Shifter**: POST `/api/integrations/stix-shifter/translate` with `{target, pattern?, run_id?}` to translate STIX patterns into native SIEM queries (Splunk SPL / Sentinel KQL / QRadar AQL / Elastic ECS / CrowdStrike FQL). Built-in fallback translator covers the common cases; the upstream stix-shifter library auto-picks up when installed.
- **Exports**: `GET /api/export/{stix,sarif,cacao}/{run_id}` returns the run as STIX 2.1, SARIF 2.1.0 (GitHub Code Scanning), or OASIS CACAO 2.0 (SOAR playbook).

Every outbound push is audit-logged through the existing audit
middleware — analysts can grep the audit stream for
`integration_misp_push` / `integration_thehive_push` /
`integration_stix_shifter_translate` to see exactly what left the
system.

---

## What's intentionally NOT in scope

A few things omitted deliberately that you might expect:

- **Multi-tenancy / RBAC.** Single-user platform. Adding org-level
  isolation would be a real product, not a portfolio piece.
- **Scan-history correlation.** Each scan stands alone. Cross-scan
  pattern matching ("similar files by ssdeep") sounded valuable in
  theory but in practice produced misleading "this looks like a past
  case" prose that biased the analyst. Removed deliberately.
- **Paid / gated TI feeds.** Mandiant, Recorded Future, IBM X-Force,
  RiskIQ, Censys / Shodan paid tier, Bambenek, VulnDB. RECON sticks
  to OSS / free tiers. Shodan's free `/shodan/host/` endpoint was a
  dead source; Shodan's free **InternetDB** endpoint (no key) is
  integrated.
- **HackTricks, GTFOBins, CIS Controls.** All hit non-commercial or
  share-alike license clauses that RECON's policy rejects.
- **Volatility / MemProcFS memory forensics.** Runtime tools, not
  static corpora; out of scope for a reactive-triage platform.

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
