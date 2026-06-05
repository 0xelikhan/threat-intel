"""
Cloud sandbox integrations — look up existing detonation reports by SHA-256.

Why this design: building your own malware-detonation sandbox is heavy
(VMs, hypervisor, network isolation, sample storage, snapshot management) and is
not a TI-platform problem — it's an analysis-environment problem. The smart play
is to query cloud sandboxes that already detonated the sample. RECON does that.

Supported (hash lookup only, no new submission yet):
  - Hybrid Analysis (CrowdStrike Falcon Sandbox) — needs HYBRID_ANALYSIS_KEY
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


async def lookup_all(sha256: str, config) -> dict:
    """Run all configured sandbox lookups in parallel for one hash."""
    import asyncio
    ha_key = config.get("HYBRID_ANALYSIS_KEY")
    coros = []
    if ha_key:
        coros.append(("hybrid_analysis", hybrid_analysis_lookup(sha256, ha_key)))
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


async def auto_submit_and_poll(file_bytes: bytes, filename: str, sha256: str,
                                api_key: str, poll_interval_s: int = 30,
                                max_wait_s: int = 600) -> dict:
    """Submit a sample to Hybrid Analysis and poll until SUCCESS / ERROR /
    timeout. Persists the final summary to backend/data/sandbox_results/
    {sha256}.json so the UI can fetch it later. Returns the final summary
    dict or an error dict.

    Designed to be called as a background task (asyncio.create_task) from
    the file analyzer when sandbox_submission_eligible fires — the user
    doesn't wait, the result lands on disk when ready and the UI polls
    for it via GET /api/sandbox/result/{sha256}."""
    import asyncio
    import json
    import logging
    import time
    from pathlib import Path

    _log = logging.getLogger("recon.sandbox.auto")
    out_dir = Path(__file__).resolve().parents[1] / "data" / "sandbox_results"
    out_dir.mkdir(parents=True, exist_ok=True)
    status_path  = out_dir / f"{sha256}.json"

    def _persist(state: dict) -> None:
        try:
            status_path.write_text(json.dumps(state, default=str, indent=2))
        except Exception as e:
            _log.warning("Failed to persist sandbox status for %s: %s", sha256, e)

    submit_result = await submit_hybrid_analysis(file_bytes, filename, api_key)
    if not submit_result.get("ok"):
        state = {"sha256": sha256, "state": "SUBMIT_FAILED",
                 "error": submit_result.get("error"),
                 "submitted_at": time.time()}
        _persist(state)
        return state

    job_id = submit_result.get("job_id")
    _persist({"sha256": sha256, "state": "IN_QUEUE", "job_id": job_id,
              "submitted_at": time.time()})

    deadline = time.time() + max_wait_s
    while time.time() < deadline:
        await asyncio.sleep(poll_interval_s)
        s = await hybrid_analysis_state(job_id, api_key)
        st = (s.get("state") or "").upper()
        if st == "SUCCESS":
            summary = await hybrid_analysis_summary(job_id, api_key)
            final = {
                "sha256":       sha256,
                "state":        "SUCCESS",
                "job_id":       job_id,
                "summary":      summary or {},
                "completed_at": time.time(),
            }
            _persist(final)
            return final
        if st in ("ERROR", "FAILED"):
            final = {"sha256": sha256, "state": st, "job_id": job_id,
                     "error": s.get("error"), "completed_at": time.time()}
            _persist(final)
            return final
        # Still in IN_QUEUE / IN_PROGRESS — update timestamp and keep polling.
        _persist({"sha256": sha256, "state": st or "IN_PROGRESS",
                  "job_id": job_id, "last_check": time.time()})

    timeout_state = {"sha256": sha256, "state": "TIMEOUT", "job_id": job_id,
                     "max_wait_s": max_wait_s, "completed_at": time.time()}
    _persist(timeout_state)
    return timeout_state


def load_sandbox_result(sha256: str) -> dict | None:
    """Read the persisted sandbox status (or None if no submission ever
    happened for this hash). Used by the UI polling endpoint."""
    import json
    from pathlib import Path
    path = (Path(__file__).resolve().parents[1] / "data" /
            "sandbox_results" / f"{sha256}.json")
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


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

