# RECON

Threat intelligence platform. Paste an alert / log / IOC, get a triaged
verdict plus enrichment from ~90 OSS sources and ML-augmented
classifiers.

Backend: FastAPI + LangGraph (Python 3.11).
Frontend: React + MUI.
LLM: OpenAI / Azure OpenAI / Anthropic / Ollama via a provider
abstraction (swap with `LLM_PROVIDER`).

## Layout

```
threat-intel-app/
  backend/
    main.py            FastAPI app, 60+ endpoints, middleware, auth
    config.py          API key store (data/config.json)
    agents/            LangGraph nodes: triage, enrichment,
                       investigation, response, orchestrator
    providers/         LLMProvider ABC + openai/anthropic/ollama
    skills/            17 individually-runnable units
    intel/             TI loaders, classifiers, caches, redactor,
                       circuit breaker, semantic search
    mcp_server.py      Stdio MCP entry point (Claude Desktop / Cursor)
    tests/             pytest, 585 tests
  frontend/
    src/App.js         Root + ~30 inline analysis sub-components
    src/components/    Lazy-loaded heavy views (SettingsView,
                       FileScannerView, MapTab, etc.)
```

Full architecture notes are in `CLAUDE.md`.

## Run

```powershell
# backend
cd threat-intel-app/backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# frontend (new shell)
cd threat-intel-app/frontend
npm install
npm start          # dev server on :3000, proxies /api to :8000
npm run build      # production bundle
```

## Tests

```powershell
cd threat-intel-app/backend
.\venv\Scripts\python.exe -m pytest tests/ -v
```


## Auth

Single signed cookie. Set these env vars before starting the backend
or every login returns 503:

| Var                   | What                                  |
|-----------------------|---------------------------------------|
| `AUTH_USERNAME`       | login user                            |
| `AUTH_PASSWORD_HASH`  | bcrypt hash of the password           |
| `AUTH_SESSION_SECRET` | cookie signing key                    |

Generate the hash with:

```python
import bcrypt
bcrypt.hashpw(b"your-password", bcrypt.gensalt()).decode()
```

## Useful env vars

| Var                          | Default    | Purpose |
|------------------------------|------------|---------|
| `LLM_PROVIDER`               | `openai`   | `openai`, `azure`, `anthropic`, `ollama` |
| `OPENAI_BASE_URL`            | OpenAI     | Set to `...openai.azure.com` for Azure detection |
| `LOG_LEVEL`                  | `INFO`     | Root logger level |
| `ENRICH_CONCURRENCY`         | `16`       | Global semaphore on TI fan-out |
| `ENRICH_SOURCE_TIMEOUT_S`    | `12`       | Per-source wait_for cap |
| `ENRICH_POOL_LIMIT`          | `100`      | TCPConnector total |
| `ENRICH_POOL_PER_HOST`       | `10`       | TCPConnector per-host |
| `CIRCUIT_BREAKER_THRESHOLD`  | `3`        | Failures before breaker opens |
| `CIRCUIT_BREAKER_COOLDOWN_S` | `300`      | Seconds open before half-open probe |
| `RECON_CORS`                 | localhost  | Comma-separated allowed origins |
| `RECON_ENABLE_CAPA`          | `0`        | FLARE capa per PE (opt-in, slow) |
| `RECON_ENABLE_MSRC`          | `0`        | Microsoft Security Update Guide |
| `RECON_ENABLE_MOZILLA_OBSERVATORY` | `0`  | Per-domain web grade |

API keys for TI sources live in `data/config.json` 

## Optional dependencies

| Package                     | Used for                          |
|-----------------------------|-----------------------------------|
| `flare-capa`                | PE capability extraction          |
| `sentence-transformers`     | Embedding backend for `/api/detection/search` (falls back to sklearn TF-IDF) |


