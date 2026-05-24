"""
Cloud sandbox integrations — look up existing detonation reports by SHA-256.

Why this design: building your own malware-detonation sandbox is heavy
(VMs, hypervisor, network isolation, sample storage, snapshot management) and is
not a TI-platform problem — it's an analysis-environment problem. The smart play
is to query cloud sandboxes that already detonated the sample. RECON does that.

Supported (hash lookup only, no new submission yet):
  - Hybrid Analysis (CrowdStrike Falcon Sandbox) — needs HYBRID_ANALYSIS_KEY
  - ANY.RUN community                            — needs ANYRUN_KEY (optional)
  - VirusTotal behaviour summary                 — already queried in enrichment
"""
import aiohttp


async def hybrid_analysis_lookup(sha256: str, api_key: str) -> dict | None:
    """Search Hybrid Analysis for an existing report on this hash."""
    if not (sha256 and api_key):
        return None
    url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    headers = {
        "api-key": api_key,
        "user-agent": "Falcon Sandbox",
        "accept": "application/json",
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, data={"hash": sha256},
                                    timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status != 200:
                    return None
                data = await r.json()
    except Exception:
        return None
    if not data or not isinstance(data, list):
        return None
    # Latest report wins
    latest = data[0]
    return {
        "source":        "Hybrid Analysis",
        "verdict":       latest.get("verdict", "unknown"),
        "threat_score":  latest.get("threat_score"),
        "av_detect":     latest.get("av_detect"),
        "vx_family":     latest.get("vx_family"),
        "malware_family":latest.get("vx_family") or latest.get("classification_tags", []),
        "submit_name":   latest.get("submit_name"),
        "environment":   latest.get("environment_description"),
        "type_short":    latest.get("type_short", []),
        "tags":          latest.get("tags", [])[:10],
        "mitre":         [t.get("technique") for t in (latest.get("mitre_attcks") or [])][:10],
        "url":           f"https://www.hybrid-analysis.com/sample/{sha256}",
        "submitted":     latest.get("analysis_start_time"),
    }


async def anyrun_lookup(sha256: str, api_key: str) -> dict | None:
    """Query ANY.RUN for an existing public task for this hash."""
    if not (sha256 and api_key):
        return None
    url = "https://api.any.run/v1/analysis"
    params = {"hash": sha256, "skip": 0, "limit": 1}
    headers = {"Authorization": f"API-Key {api_key}"}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status != 200:
                    return None
                data = await r.json()
    except Exception:
        return None
    tasks = (data or {}).get("data", {}).get("tasks") or []
    if not tasks:
        return None
    t = tasks[0]
    return {
        "source":       "ANY.RUN",
        "verdict":      t.get("verdict") or t.get("scores", {}).get("verdict", {}).get("threatLevelText"),
        "threat_score": t.get("scores", {}).get("verdict", {}).get("score"),
        "tags":         t.get("tags") or [],
        "main_object":  t.get("mainObject", {}).get("name"),
        "url":          t.get("permanentUrl"),
        "submitted":    t.get("date"),
    }


async def lookup_all(sha256: str, config) -> dict:
    """Run all configured sandbox lookups in parallel for one hash."""
    import asyncio
    ha_key = config.get("HYBRID_ANALYSIS_KEY")
    ar_key = config.get("ANYRUN_KEY")
    coros = []
    if ha_key:
        coros.append(("hybrid_analysis", hybrid_analysis_lookup(sha256, ha_key)))
    if ar_key:
        coros.append(("any_run", anyrun_lookup(sha256, ar_key)))
    out = {}
    if not coros:
        return out
    results = await asyncio.gather(*[c for _, c in coros], return_exceptions=True)
    for (name, _), r in zip(coros, results):
        if isinstance(r, dict):
            out[name] = r
    return out


# ─── HYBRID ANALYSIS SUBMISSION + POLLING ─────────────────────────────────────────
# Hybrid Analysis environment IDs — Windows 10 64-bit is the most common modern target.
ENV_WINDOWS_10_X64 = 200
ENV_WINDOWS_7_X64  = 120
ENV_LINUX_X64      = 300


async def submit_hybrid_analysis(file_bytes: bytes, filename: str, api_key: str,
                                  environment_id: int = ENV_WINDOWS_10_X64) -> dict:
    """Submit a new sample for detonation. Returns job_id for polling."""
    if not api_key:
        return {"ok": False, "error": "HYBRID_ANALYSIS_KEY not configured"}
    url = "https://www.hybrid-analysis.com/api/v2/submit/file"
    headers = {"api-key": api_key, "user-agent": "Falcon Sandbox", "accept": "application/json"}
    form = aiohttp.FormData()
    form.add_field("file", file_bytes, filename=filename or "sample.bin",
                   content_type="application/octet-stream")
    form.add_field("environment_id", str(environment_id))
    form.add_field("no_share_third_party", "true")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, data=form,
                                    timeout=aiohttp.ClientTimeout(total=60)) as r:
                data = await r.json()
                if r.status >= 400:
                    return {"ok": False, "error": data.get("message", f"HTTP {r.status}")}
                return {"ok": True,
                        "job_id":        data.get("job_id"),
                        "submission_id": data.get("submission_id"),
                        "sha256":        data.get("sha256"),
                        "environment_id":data.get("environment_id"),
                        "submitted_at":  None}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def hybrid_analysis_state(job_id: str, api_key: str) -> dict:
    """Poll the job state. Returns {state: IN_QUEUE|IN_PROGRESS|SUCCESS|ERROR}."""
    if not (job_id and api_key):
        return {"state": "ERROR", "error": "missing job_id or api_key"}
    url = f"https://www.hybrid-analysis.com/api/v2/report/{job_id}/state"
    headers = {"api-key": api_key, "user-agent": "Falcon Sandbox", "accept": "application/json"}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status >= 400:
                    return {"state": "ERROR", "error": f"HTTP {r.status}"}
                return await r.json()
    except Exception as e:
        return {"state": "ERROR", "error": str(e)}


async def hybrid_analysis_summary(job_id: str, api_key: str) -> dict | None:
    """Fetch the full summary once state == SUCCESS."""
    if not (job_id and api_key):
        return None
    url = f"https://www.hybrid-analysis.com/api/v2/report/{job_id}/summary"
    headers = {"api-key": api_key, "user-agent": "Falcon Sandbox", "accept": "application/json"}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=20)) as r:
                if r.status >= 400:
                    return None
                d = await r.json()
    except Exception:
        return None
    return {
        "source":         "Hybrid Analysis",
        "verdict":        d.get("verdict", "unknown"),
        "threat_score":   d.get("threat_score"),
        "av_detect":      d.get("av_detect"),
        "vx_family":      d.get("vx_family"),
        "malware_family": d.get("vx_family") or d.get("classification_tags", []),
        "submit_name":    d.get("submit_name"),
        "environment":    d.get("environment_description"),
        "type_short":     d.get("type_short", []),
        "tags":           d.get("tags", [])[:10],
        "mitre":          [t.get("technique") for t in (d.get("mitre_attcks") or [])][:10],
        "url":            f"https://www.hybrid-analysis.com/sample/{d.get('sha256', '')}",
        "submitted":      d.get("analysis_start_time"),
    }

