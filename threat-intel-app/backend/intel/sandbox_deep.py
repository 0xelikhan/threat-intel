"""
Deep sandbox extraction — spec §6.

Augments the existing intel.sandbox basic lookups with detailed report parsing:
process tree, network behavior, file-system activity, registry modifications,
injected processes, dropped files, extracted strings, mutex names, MITRE
mappings. Then synthesizes detection opportunities (Sigma rule sketches for
mutexes / registry persistence / suspicious processes; YARA stub for any
dropped-file hash).

Hybrid Analysis is preferred (full reports via /api/v2/report/{job_id}/summary)
because their schema is the most consistent.  ANY.RUN is supported in flatter
form via the public analysis listing.
"""

from __future__ import annotations
import asyncio
import aiohttp
from typing import Optional, Dict, List

_TIMEOUT = aiohttp.ClientTimeout(total=20)

# ── suspicious parent-child relationships flagged in the process tree ─────────
_SUSPICIOUS_PARENT_CHILD = [
    ("winword.exe",   "powershell.exe"),
    ("winword.exe",   "cmd.exe"),
    ("excel.exe",     "powershell.exe"),
    ("excel.exe",     "cmd.exe"),
    ("outlook.exe",   "powershell.exe"),
    ("outlook.exe",   "cmd.exe"),
    ("explorer.exe",  "cmd.exe"),
    ("explorer.exe",  "powershell.exe"),
    ("mshta.exe",     "powershell.exe"),
    ("regsvr32.exe",  "powershell.exe"),
    ("rundll32.exe",  "powershell.exe"),
    ("wmiprvse.exe",  "cmd.exe"),
    ("wmiprvse.exe",  "powershell.exe"),
    ("services.exe",  "powershell.exe"),
    ("lsass.exe",     "cmd.exe"),
]

# ── high-risk write locations on disk ──────────────────────────────────────────
_HIGH_RISK_WRITE_PREFIXES = [
    r"c:\users\public\\",
    r"c:\programdata\\",
    r"c:\windows\temp\\",
    r"c:\users\\",  # …\AppData\Local\Temp will match
    r"%temp%",
    r"%appdata%",
]
_STARTUP_DIRS = [
    r"\start menu\programs\startup",
    r"\windows\system32\config",
]
_PERSISTENCE_REG_KEYS = [
    r"\software\microsoft\windows\currentversion\run",
    r"\software\microsoft\windows\currentversion\runonce",
    r"\system\currentcontrolset\services",
    r"\software\microsoft\windows nt\currentversion\winlogon",
]


# ─── public entry point ────────────────────────────────────────────────────────
async def fetch_deep_report(sha256: str, hybrid_key: str = "",
                            anyrun_key: str = "") -> Optional[Dict]:
    """Pull the richest available report and return a normalized dict."""
    if not sha256:
        return None
    ha = await _hybrid_deep(sha256, hybrid_key) if hybrid_key else None
    if ha:
        return ha
    ar = await _anyrun_deep(sha256, anyrun_key) if anyrun_key else None
    return ar


# ─── Hybrid Analysis full-report fetch ─────────────────────────────────────────
async def _hybrid_deep(sha256: str, key: str) -> Optional[Dict]:
    headers = {"api-key": key, "user-agent": "Falcon Sandbox", "accept": "application/json"}
    async with aiohttp.ClientSession(headers=headers, timeout=_TIMEOUT) as s:
        # 1. find latest job
        try:
            async with s.post("https://www.hybrid-analysis.com/api/v2/search/hash",
                              data={"hash": sha256}) as r:
                if r.status != 200:
                    return None
                jobs = await r.json()
        except Exception:
            return None
        if not jobs or not isinstance(jobs, list):
            return None
        job_id = jobs[0].get("job_id")
        if not job_id:
            return _summarize_basic("Hybrid Analysis", jobs[0])
        # 2. full summary
        try:
            async with s.get(f"https://www.hybrid-analysis.com/api/v2/report/{job_id}/summary") as r:
                if r.status != 200:
                    return _summarize_basic("Hybrid Analysis", jobs[0])
                d = await r.json()
        except Exception:
            return _summarize_basic("Hybrid Analysis", jobs[0])

    return _normalize_hybrid(sha256, d, job_id)


def _summarize_basic(source: str, top: Dict) -> Dict:
    return {
        "source":         source,
        "verdict":        top.get("verdict") or "unknown",
        "threat_score":   top.get("threat_score"),
        "malware_family": top.get("vx_family"),
        "url":            f"https://www.hybrid-analysis.com/sample/{top.get('sha256') or top.get('md5')}",
        "process_tree":   [],
        "network":        {"dns": [], "http": [], "tls": [], "raw": []},
        "files":          [],
        "registry":       [],
        "injections":     [],
        "dropped":        [],
        "strings":        {"ips": [], "domains": [], "urls": [], "c2": []},
        "mutexes":        [],
        "mitre":          [],
        "detections":     [],
    }


def _normalize_hybrid(sha256: str, d: Dict, job_id: str) -> Dict:
    # ── Process tree ──────────────────────────────────────────────────────────
    processes_raw = d.get("processes") or []
    by_pid: Dict[int, Dict] = {}
    for p in processes_raw:
        pid = p.get("pid") or p.get("process_id")
        if pid is None:
            continue
        by_pid[pid] = {
            "pid":       pid,
            "ppid":      p.get("parentuid") or p.get("parent_pid") or p.get("ppid"),
            "name":      (p.get("name") or "").lower(),
            "image":     p.get("normalizedpath") or p.get("image"),
            "cmdline":   p.get("commandline") or "",
            "children":  [],
        }
    roots: List[Dict] = []
    for node in by_pid.values():
        parent = by_pid.get(node["ppid"])
        if parent:
            parent["children"].append(node)
        else:
            roots.append(node)
    # Flag suspicious parent-child
    def _flag(node):
        for ch in node["children"]:
            pname = (node["name"] or "").lower()
            cname = (ch["name"] or "").lower()
            for pp, cp in _SUSPICIOUS_PARENT_CHILD:
                if pname.endswith(pp) and cname.endswith(cp):
                    node["suspicious_child"] = ch["name"]
                    ch["suspicious_parent"] = node["name"]
            _flag(ch)
    for r in roots:
        _flag(r)

    # ── Network ──────────────────────────────────────────────────────────────
    network = d.get("hosts") or []
    dns = [{"domain": h.get("name"), "ip": h.get("address"), "country": h.get("country")}
           for h in network if h.get("name")][:30]
    http = [{"method": req.get("method"), "url": req.get("url"),
             "user_agent": req.get("userAgent"), "status": req.get("responseStatus")}
            for req in (d.get("http_requests") or [])][:30]
    tls  = [{"sni": t.get("sni"), "subject": t.get("subject"), "issuer": t.get("issuer")}
            for t in (d.get("ssl_certificates") or [])][:20]
    raw  = [{"protocol": c.get("protocol"), "ip": c.get("address"), "port": c.get("port")}
            for c in network if not c.get("name")][:30]

    # ── File-system activity ─────────────────────────────────────────────────
    files = []
    for f in (d.get("extracted_files") or [])[:50]:
        path = (f.get("path") or "").lower()
        flags = []
        if any(path.startswith(p) for p in _HIGH_RISK_WRITE_PREFIXES):
            flags.append("temp_or_user_dir")
        if any(sd in path for sd in _STARTUP_DIRS):
            flags.append("startup_persistence")
        files.append({
            "path":  f.get("path"),
            "sha256": f.get("sha256"),
            "type":  f.get("file_type"),
            "size":  f.get("file_size"),
            "flags": flags,
        })

    # ── Registry ─────────────────────────────────────────────────────────────
    registry = []
    for entry in (d.get("registry") or [])[:50]:
        op = entry.get("op", "")
        path = (entry.get("path") or "").lower()
        persistence = any(k in path for k in _PERSISTENCE_REG_KEYS)
        registry.append({
            "op":          op,
            "path":        entry.get("path"),
            "value_name":  entry.get("name"),
            "value":       entry.get("value"),
            "persistence": persistence,
        })

    # ── Injections, mutexes, strings ─────────────────────────────────────────
    injections = [{"source": i.get("source"), "target": i.get("target"),
                   "type": i.get("type") or i.get("technique")}
                  for i in (d.get("process_injections") or [])][:20]
    mutexes = [m for m in (d.get("mutants") or [])[:30] if m]
    strings_raw = d.get("string_info") or {}
    strings = {
        "ips":      (strings_raw.get("ips") or [])[:20],
        "domains":  (strings_raw.get("domains") or [])[:20],
        "urls":     (strings_raw.get("urls") or [])[:20],
        "c2":       (strings_raw.get("c2") or [])[:10],
    }

    # ── MITRE & verdict ──────────────────────────────────────────────────────
    mitre = [t.get("technique") + " - " + t.get("name", "") for t in (d.get("mitre_attcks") or [])][:20]
    verdict = (d.get("verdict") or "").lower()
    verdict_norm = "MALICIOUS" if verdict in {"malicious", "suspicious"} else "UNKNOWN"

    # ── Detection opportunities synthesis ────────────────────────────────────
    detections = _synthesize_detections(mutexes=mutexes, registry=registry,
                                        processes=processes_raw, dropped=files)

    return {
        "source":         "Hybrid Analysis (deep)",
        "verdict":        verdict_norm,
        "verdict_raw":    d.get("verdict"),
        "threat_score":   d.get("threat_score"),
        "av_detect":      d.get("av_detect"),
        "malware_family": d.get("vx_family"),
        "environment":    d.get("environment_description"),
        "submit_name":    d.get("submit_name"),
        "report_url":     f"https://www.hybrid-analysis.com/sample/{sha256}",
        "process_tree":   roots[:8],
        "network":        {"dns": dns, "http": http, "tls": tls, "raw": raw},
        "files":          files,
        "registry":       registry,
        "injections":     injections,
        "dropped":        [f for f in files if "startup_persistence" in (f.get("flags") or [])
                            or "temp_or_user_dir" in (f.get("flags") or [])][:20],
        "strings":        strings,
        "mutexes":        mutexes,
        "mitre":          mitre,
        "detections":     detections,
    }


# ─── ANY.RUN flatter report ────────────────────────────────────────────────────
async def _anyrun_deep(sha256: str, key: str) -> Optional[Dict]:
    url = "https://api.any.run/v1/analysis"
    headers = {"Authorization": f"API-Key {key}"}
    try:
        async with aiohttp.ClientSession(headers=headers, timeout=_TIMEOUT) as s:
            async with s.get(url, params={"hash": sha256, "skip": 0, "limit": 1}) as r:
                if r.status != 200:
                    return None
                d = await r.json()
    except Exception:
        return None
    tasks = (d or {}).get("data", {}).get("tasks") or []
    if not tasks:
        return None
    t = tasks[0]
    verdict_raw = t.get("verdict") or t.get("scores", {}).get("verdict", {}).get("threatLevelText", "")
    return {
        "source":         "ANY.RUN",
        "verdict":        "MALICIOUS" if str(verdict_raw).lower() in {"malicious", "suspicious"} else "UNKNOWN",
        "verdict_raw":    verdict_raw,
        "threat_score":   t.get("scores", {}).get("verdict", {}).get("score"),
        "malware_family": t.get("malwareFamily"),
        "report_url":     f"https://app.any.run/tasks/{t.get('uuid')}",
        "process_tree":   [],   # ANY.RUN process tree requires a second call we'd rather avoid
        "network":        {"dns": [], "http": [], "tls": [], "raw": []},
        "files":          [],
        "registry":       [],
        "injections":     [],
        "dropped":        [],
        "strings":        {"ips": [], "domains": [], "urls": [], "c2": []},
        "mutexes":        [],
        "mitre":          [],
        "detections":     [],
    }


# ─── detection opportunity synthesis ───────────────────────────────────────────
def _synthesize_detections(mutexes, registry, processes, dropped) -> List[Dict]:
    """Generate Sigma rule stubs from sandbox observations. The detection_engineering
    module's validate_sigma loop can later finalize/validate any rule the analyst
    chooses to keep."""
    out = []
    for m in mutexes[:5]:
        out.append({
            "type":     "sigma",
            "trigger":  f"Mutex created: {m}",
            "stub": (
                f"title: Mutex creation '{m}'\n"
                f"id: 00000000-0000-0000-0000-000000000000\n"
                f"status: experimental\n"
                f"description: Detect creation of mutex {m} observed during sandbox analysis\n"
                f"logsource:\n  product: windows\n  category: process_creation\n"
                f"detection:\n  selection:\n    MutantName: '{m}'\n  condition: selection\n"
                f"level: high\n"
            ),
        })
    for reg in (registry or [])[:5]:
        if reg.get("persistence"):
            out.append({
                "type":    "sigma",
                "trigger": f"Persistence Run key: {reg.get('path')}",
                "stub": (
                    f"title: Suspicious Run-key persistence\n"
                    f"id: 00000000-0000-0000-0000-000000000000\n"
                    f"status: experimental\n"
                    f"logsource:\n  product: windows\n  category: registry_event\n"
                    f"detection:\n  selection:\n    TargetObject|contains: '{reg.get('path')}'\n"
                    f"  condition: selection\n"
                    f"level: high\n"
                ),
            })
    for d in (dropped or [])[:3]:
        if d.get("sha256"):
            out.append({
                "type":    "yara",
                "trigger": f"Dropped file: {d.get('path')}",
                "stub": (
                    f"rule dropped_sample_{(d.get('sha256') or '')[:8]} {{\n"
                    f"  meta:\n    description = \"Hash match for dropped sample\"\n"
                    f"    sha256 = \"{d.get('sha256')}\"\n"
                    f"  condition:\n    hash.sha256(0, filesize) == \"{d.get('sha256')}\"\n"
                    f"}}\n"
                ),
            })
    return out
