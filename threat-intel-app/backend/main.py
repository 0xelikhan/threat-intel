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

from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks
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

_results: dict = {}
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
    import aiohttp
    key = config.get("OPENAI_API_KEY")
    base_url = config.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
    if not key:
        return {"ok": False, "error": "No OpenAI API key configured"}
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{base_url}/models",
                             headers={"Authorization": f"Bearer {key}"},
                             timeout=aiohttp.ClientTimeout(total=8)) as r:
                return {"ok": r.status == 200, "message": "Valid" if r.status == 200 else f"Status {r.status}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ─── HEALTH ───────────────────────────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    status = config.get_status()
    missing = [k for k, v in status.items() if v["required"] and not v["configured"]]
    return {"status": "ready" if config.is_configured() else "setup_required",
            "version": "3.0.0", "timestamp": _ts(),
            "configured": config.is_configured(),
            "apiKeys": {k: v["configured"] for k, v in status.items()},
            "requiredMissing": missing,
            "cachedRuns": len(_results), "historyCount": len(_history)}


# ─── ANALYZE ──────────────────────────────────────────────────────────────────────
async def _stream(raw_input: str, input_type: str, label: str = ""):
    if not config.is_configured():
        yield f"data: {json.dumps({'event': 'error', 'error': 'Add your API keys in Settings first.'})}\n\n"
        yield "data: [DONE]\n\n"
        return
    run_id = str(uuid.uuid4())
    yield f"data: {json.dumps({'event': 'start', 'runId': run_id, 'timestamp': _ts()})}\n\n"
    try:
        state = await run_pipeline(raw_input, input_type)
        gti_scores = compute_gti_scores(state.get("enrichments", {}))
        state["gti_scores"] = gti_scores
        for t in state.get("agent_trace", []):
            yield f"data: {json.dumps({'event': 'agent_update', 'runId': run_id, 'trace': t})}\n\n"
            await asyncio.sleep(0.05)
        result = {k: v for k, v in state.items() if k != "stix_bundle"}
        result.update({"runId": run_id, "label": label})
        _results[run_id] = state
        _add_history(run_id, result, label)
        yield f"data: {json.dumps({'event': 'complete', 'runId': run_id, 'result': result, 'timestamp': _ts()})}\n\n"
    except Exception as e:
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
@app.post(/api/gti-score)
async def gti_score_standalone(req: GTIScoreRequest):
    """Compute GTI-style threat scores from enrichment data without running the full pipeline."""
    scores = compute_gti_scores(req.enrichments)
    highest = get_highest_score(scores)
    return {
        gti_scores: scores,
        highest: highest,
        total: len(scores),
        critical_count: sum(1 for s in scores.values() if s.get("score", 0) >= 85),
        high_count:     sum(1 for s in scores.values() if 65 <= s.get("score", 0) < 85),
        elevated_count: sum(1 for s in scores.values() if 45 <= s.get("score", 0) < 65),
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
    from openai import AsyncOpenAI
    key = config.get("OPENAI_API_KEY")
    if not key:
        return "# OpenAI API key not configured. Add it in Settings."
    try:
        client = AsyncOpenAI(api_key=key,
                             base_url=config.get("OPENAI_BASE_URL", "https://api.openai.com/v1"))
        resp = await client.chat.completions.create(
            model=config.get("AI_MODEL", "gpt-4o-mini"),
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1500, temperature=0.1)
        return resp.choices[0].message.content.strip()
    except Exception as e:
        return f"# Generation failed: {e}"


@app.post("/api/detection")
async def detection(req: DetectionRequest):
    if req.action == "mitre":
        q = (req.query or "").lower()
        if len(q) < 2:
            return {"result": MITRE[:20]}
        matches = [t for t in MITRE if q in t["id"].lower() or q in t["name"].lower()
                   or q in t["tactic"].lower() or q in t["description"].lower()]
        return {"result": matches[:30]}

    if req.action == "actors":
        return {"result": _match_threat_actors_fn(req.mitreTechniques or [])}

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
