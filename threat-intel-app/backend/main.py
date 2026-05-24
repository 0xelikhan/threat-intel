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
from pydantic import BaseModel

from config import config, API_KEY_DEFINITIONS, FREE_APIS
from agents.orchestrator import run_pipeline
from intel.taxii_poller import poll_all_feeds, parse_misp_csv, parse_misp_json
from gti_score import compute_gti_scores, get_highest_score

app = FastAPI(title="Threat Intelligence Platform", version="3.0.0",
              docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")

app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


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
    print("[recon] startup: pre-warm scheduled in background, accepting requests now")

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
    from openai import AsyncAzureOpenAI, AsyncOpenAI
    key = config.get("OPENAI_API_KEY")
    base_url = config.get("OPENAI_BASE_URL", "")
    model = config.get("AI_MODEL", "gpt-4o-mini")
    if not key:
        return {"ok": False, "error": "No OpenAI API key configured"}
    try:
        if "openai.azure.com" in base_url:
            client = AsyncAzureOpenAI(
                api_key=key,
                azure_endpoint=base_url.rstrip("/"),
                api_version="2024-02-01",
            )
        else:
            client = AsyncOpenAI(api_key=key, base_url=base_url or "https://api.openai.com/v1")
        resp = await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "hi"}],
            max_tokens=5,
        )
        return {"ok": True, "message": f"Valid · model {resp.model}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


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


def _check_ioc_pivot(iocs: dict, current_run_id: str) -> list[dict]:
    """For each IOC in the current run, see if it appeared in any previous run.
    Returns the list of pivots so the analyst can jump to those earlier investigations."""
    pivots = []
    seen = set()
    for typ, lst in (iocs or {}).items():
        for ioc in lst or []:
            prior = _ioc_index.get(ioc) or []
            prior = [p for p in prior if p[0] != current_run_id]
            if prior and ioc not in seen:
                seen.add(ioc)
                # newest prior first
                prior_sorted = sorted(prior, key=lambda x: x[1], reverse=True)[:3]
                pivots.append({
                    "ioc":  ioc,
                    "type": typ,
                    "sightings": [{"run_id": rid, "timestamp": ts, "threat_level": lvl}
                                   for rid, ts, lvl in prior_sorted],
                })
    return pivots


def _index_iocs(run_id: str, iocs: dict, response_summary: dict):
    """Add this run's IOCs to the pivot index."""
    lvl = (response_summary or {}).get("threat_level", "INFORMATIONAL")
    ts = _ts()
    for typ, lst in (iocs or {}).items():
        for ioc in lst or []:
            _ioc_index.setdefault(ioc, []).append((run_id, ts, lvl))


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
            state = await run_enrichment(state)
            # GTI scores depend on enrichment data
            state["gti_scores"] = compute_gti_scores(state.get("enrichments", {}))
            trace = state.get("agent_trace", [])
            if trace:
                yield f"data: {json.dumps({'event': 'agent_update', 'runId': run_id, 'trace': trace[-1]})}\n\n"
            yield f"data: {json.dumps({'event': 'partial_result', 'runId': run_id, 'result': _strip(state, run_id, label)})}\n\n"

        # ── Stage 3: INVESTIGATION (AI correlation + tool-calling loop) ─────
        # Snapshot trace length so we can emit each NEW entry the agent adds —
        # the tool-calling investigation appends one entry per tool call so the
        # UI shows the AI's reasoning live.
        trace_before = len(state.get("agent_trace", []))
        state = await run_investigation(state)
        trace = state.get("agent_trace", [])
        for tr in trace[trace_before:]:
            yield f"data: {json.dumps({'event': 'agent_update', 'runId': run_id, 'trace': tr})}\n\n"
            await asyncio.sleep(0.02)
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
    from openai import AsyncAzureOpenAI, AsyncOpenAI
    key = config.get("OPENAI_API_KEY")
    base_url = config.get("OPENAI_BASE_URL", "")
    model = config.get("AI_MODEL", "gpt-4o-mini")
    if not key:
        return "# OpenAI API key not configured. Add it in Settings."
    try:
        if "openai.azure.com" in base_url:
            client = AsyncAzureOpenAI(
                api_key=key,
                azure_endpoint=base_url.rstrip("/"),
                api_version="2024-02-01",
            )
        else:
            client = AsyncOpenAI(api_key=key, base_url=base_url or "https://api.openai.com/v1")
        resp = await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1500, temperature=0.1)
        return resp.choices[0].message.content.strip()
    except Exception as e:
        return f"# Generation failed: {e}"


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
        a = req.analysis or {}
        ioc_json = json.dumps({k: v[:3] for k, v in (req.iocs or {}).items() if v})
        prompt = (f"Generate a complete production-ready Sigma detection rule.\n"
                  f"CHARACTER: Senior Detection Engineer.\n"
                  f"CONSTRAINTS: Output ONLY valid Sigma YAML. No markdown fences.\n"
                  f"Threat Level: {a.get('threatLevel','MEDIUM')}\n"
                  f"Summary: {a.get('summary','')}\n"
                  f"MITRE: {', '.join(a.get('mitreTechniques',[]))}\n"
                  f"IOCs: {ioc_json}\n"
                  f"Include: title, id (UUID), status: experimental, description, tags (with attack.*), "
                  f"logsource, detection (selection + condition), falsepositives, level.")
        return {"result": await _ai_gen(prompt)}

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

    raise HTTPException(400, f"Unknown action: {req.action}")


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
    from openai import AsyncAzureOpenAI, AsyncOpenAI
    from agents.investigation_tools import TOOL_SCHEMAS, execute_tool, _summarize_for_trace

    key = config.get("OPENAI_API_KEY")
    base_url = config.get("OPENAI_BASE_URL", "")
    if "openai.azure.com" in base_url:
        client = AsyncAzureOpenAI(api_key=key, azure_endpoint=base_url.rstrip("/"),
                                   api_version="2024-02-01")
    else:
        client = AsyncOpenAI(api_key=key, base_url=base_url or "https://api.openai.com/v1")

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
            # First, a non-streaming call to decide if tools are needed
            resp = await client.chat.completions.create(
                model=config.get("AI_MODEL", "gpt-4o-mini"),
                messages=messages,
                tools=TOOL_SCHEMAS,
                tool_choice="auto",
                temperature=0.2,
                max_tokens=700,
            )
            msg = resp.choices[0].message
            if msg.tool_calls:
                # Tell the client we're calling tools so it shows "RECON checked X"
                messages.append({
                    "role":      "assistant", "content": msg.content or "",
                    "tool_calls": [{"id": tc.id, "type": "function",
                                     "function": {"name": tc.function.name,
                                                  "arguments": tc.function.arguments}}
                                    for tc in msg.tool_calls],
                })
                for tc in msg.tool_calls:
                    try:
                        args = json.loads(tc.function.arguments)
                    except Exception:
                        args = {}
                    tool_result = await execute_tool(tc.function.name, args, config)
                    tc_summary = _summarize_for_trace(tc.function.name, tool_result)
                    tool_calls_made.append({
                        "tool": tc.function.name, "args": args, "summary": tc_summary,
                    })
                    # Stream the tool call to the UI live
                    yield f"data: {json.dumps({'event': 'tool_call', 'tool': tc.function.name, 'args': args, 'summary': tc_summary})}\n\n"
                    messages.append({
                        "role": "tool", "tool_call_id": tc.id,
                        "content": json.dumps(tool_result, default=str)[:2000],
                    })
                continue

            # No more tool calls — re-issue this turn with streaming for the visible answer
            final_content = msg.content or ""
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
    """Hash + YARA-scan a binary. Returns hashes, file metadata, and matched rules."""
    import hashlib
    data = await file.read()
    if not data:
        raise HTTPException(400, "Empty file")
    if len(data) > 50 * 1024 * 1024:
        raise HTTPException(413, "File exceeds 50 MB limit")
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


# ─── HISTORY ──────────────────────────────────────────────────────────────────────
@app.get("/api/history")
async def get_history():
    return {"history": _history[-50:], "total": len(_history)}

@app.get("/api/history/{run_id}")
async def get_history_item(run_id: str):
    if run_id not in _results:
        raise HTTPException(404, "Run not found")
    return {k: v for k, v in _results[run_id].items() if k != "stix_bundle"}


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
    _history.append({
        "runId": run_id,
        "label": label or "Untitled investigation",
        "timestamp": _ts(),
        "threatLevel": result.get("threat_level", "UNKNOWN"),
        "iocCount": sum(len(v) for v in (result.get("iocs") or {}).values() if isinstance(v, list)),
        "mitreTechniqueCount": len(result.get("mitre_techniques") or []),
        "dropped": (result.get("triage_score") or 1) < 0.15,
    })
    if len(_history) > 100:
        _history.pop(0)

def _ts():
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=os.getenv("HOST", "0.0.0.0"),
                port=int(os.getenv("PORT", 8000)), reload=False)
