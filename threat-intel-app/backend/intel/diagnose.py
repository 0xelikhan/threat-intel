"""
Backend self-diagnosis (Section 3).

Runs at startup and on demand via GET /api/diagnose. Each check returns
{name, status, message, fix_hint} so the analyst sees exactly what to
fix, not a vague "something's wrong".

Status values:
  * ok       — check passed
  * warn     — degraded but the platform still runs
  * fail     — required functionality is unavailable

Public surface:
  run_all_checks()              -> dict   (full report; called by /api/diagnose)
  run_startup_checks()          -> dict   (runs once at startup, logs each)
  background_health_loop()      -> coro   (re-runs key checks every 15min)
  get_current_health()          -> dict   (most recent in-memory health snapshot)

Network checks are time-bounded (3s connect, 5s total) so a slow
external endpoint can't stall the startup banner.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp

from intel.error_messages import lookup as _err

_log = logging.getLogger("recon.diagnose")

# Path constants — anchored to the backend/ directory.
_BACKEND_DIR    = Path(__file__).resolve().parents[1]
_MITRE_PATH     = _BACKEND_DIR / "intel" / "mitre" / "enterprise-attack.json"
_WARNINGS_DIR   = _BACKEND_DIR.parents[0] / "vendor" / "misp-warninglists" / "lists"
_DATA_DIR       = _BACKEND_DIR / "data"
_FRONTEND_BUILD = _BACKEND_DIR.parents[0] / "frontend" / "build" / "index.html"

# In-memory health snapshot — updated by the background loop and the
# initial startup run. `/api/health` reads this; staleness is encoded
# in the `as_of` timestamp.
_HEALTH: Dict[str, Any] = {"as_of": None, "checks": [], "summary": {"ok": 0, "warn": 0, "fail": 0}}


# ─── individual checks ────────────────────────────────────────────────────────
def _check(name: str, status: str, message: str, fix_hint: str = "",
           detail: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {"name": name, "status": status, "message": message,
            "fix_hint": fix_hint, "detail": detail or {}}


def check_required_packages() -> Dict[str, Any]:
    """Every package this backend reaches for at runtime."""
    required = ("openai", "aiohttp", "fastapi", "starlette", "pydantic",
                "bcrypt", "itsdangerous", "feedparser", "taxii2client",
                "stix2", "yaml", "yara", "mitreattack")
    missing = []
    for p in required:
        try:
            importlib.import_module(p)
        except ImportError:
            missing.append(p)
    if not missing:
        return _check("python_packages", "ok",
                      f"All {len(required)} required packages importable.")
    return _check("python_packages", "fail",
                  f"{len(missing)} required package(s) missing: {', '.join(missing)}",
                  fix_hint=f"Run `pip install {' '.join(missing)}` in the backend venv.",
                  detail={"missing": missing})


def check_mitre_dataset() -> Dict[str, Any]:
    if not _MITRE_PATH.exists():
        e = _err("MITRE_DATASET_MISSING")
        return _check("mitre_dataset", "fail", e["detail"], fix_hint=e["fix_hint"])
    try:
        with open(_MITRE_PATH, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or "objects" not in data:
            return _check("mitre_dataset", "fail",
                          "MITRE dataset exists but isn't valid STIX bundle JSON.",
                          fix_hint="Re-download from https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
        n_obj = len(data.get("objects") or [])
        return _check("mitre_dataset", "ok",
                      f"MITRE ATT&CK loaded ({n_obj} STIX objects).",
                      detail={"path": str(_MITRE_PATH), "objects": n_obj})
    except Exception as e:
        return _check("mitre_dataset", "fail",
                      f"MITRE dataset is corrupted: {e}",
                      fix_hint="Re-download enterprise-attack.json.")


def check_warninglists() -> Dict[str, Any]:
    if not _WARNINGS_DIR.exists():
        e = _err("WARNINGLISTS_MISSING")
        return _check("warninglists", "warn", e["detail"], fix_hint=e["fix_hint"])
    try:
        lists = [p for p in _WARNINGS_DIR.iterdir()
                 if p.is_dir() and (p / "list.json").exists()]
    except Exception as e:
        return _check("warninglists", "warn", f"Couldn't enumerate warninglists: {e}",
                      fix_hint="Re-run scripts/setup_vendor.sh.")
    if not lists:
        e = _err("WARNINGLISTS_MISSING")
        return _check("warninglists", "warn", e["detail"], fix_hint=e["fix_hint"])
    return _check("warninglists", "ok",
                  f"MISP warninglists loaded ({len(lists)} lists).",
                  detail={"count": len(lists)})


def check_data_dir() -> Dict[str, Any]:
    try:
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        probe = _DATA_DIR / ".diagnose_write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return _check("data_dir", "ok", f"Data directory is writable ({_DATA_DIR}).",
                      detail={"path": str(_DATA_DIR)})
    except Exception as e:
        return _check("data_dir", "fail",
                      f"Data directory is not writable: {e}",
                      fix_hint=f"Check filesystem permissions on {_DATA_DIR}, "
                               f"or set DATA_DIR env var to a writable path.")


def check_frontend_build() -> Dict[str, Any]:
    if _FRONTEND_BUILD.exists():
        return _check("frontend_build", "ok", "Frontend build artefact present.")
    return _check("frontend_build", "warn",
                  f"Frontend build missing at {_FRONTEND_BUILD}.",
                  fix_hint="Run `npm run build` in frontend/ to generate the production bundle.")


async def _probe_url(session: aiohttp.ClientSession, url: str, *,
                     headers: Optional[Dict[str, str]] = None,
                     timeout: float = 5.0) -> tuple:
    """Lightweight HEAD-ish probe. Returns (status_code, error_str).
    Treats non-2xx but ≥ 400 statuses as 'reachable but unauthorized'
    so the caller can distinguish 'down' from 'wrong key'."""
    try:
        async with session.get(url, headers=headers or {},
                               timeout=aiohttp.ClientTimeout(total=timeout)) as r:
            return r.status, ""
    except asyncio.TimeoutError:
        return 0, "timeout"
    except Exception as e:
        return 0, str(e)[:120]


async def check_api_key_reachability(config_module) -> List[Dict[str, Any]]:
    """For each configured API key, send a lightweight probe and report
    {reachable | auth_failed | timed_out | unconfigured}. Runs all probes
    concurrently so the total time is the slowest probe, not the sum."""
    # source name → (url, header builder, expected_ok_codes)
    sources = {
        "virustotal": (
            "https://www.virustotal.com/api/v3/users/me",
            lambda k: {"x-apikey": k}, {200, 401, 403},
        ),
        "abuseipdb": (
            "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8",
            lambda k: {"Key": k, "Accept": "application/json"}, {200, 401, 403, 422},
        ),
        "greynoise": (
            "https://api.greynoise.io/v3/community/8.8.8.8",
            lambda k: {"key": k}, {200, 401, 403, 404},
        ),
        "otx": (
            "https://otx.alienvault.com/api/v1/user/me",
            lambda k: {"X-OTX-API-KEY": k}, {200, 401, 403},
        ),
        "urlscan": (
            "https://urlscan.io/user/quotas/",
            lambda k: {"API-Key": k}, {200, 401, 403, 404},
        ),
        "shodan": (
            "https://api.shodan.io/api-info",   # ?key= appended below
            lambda k: {}, {200, 401, 403},
        ),
    }

    results: List[Dict[str, Any]] = []
    probes = []
    async with aiohttp.ClientSession() as session:
        for name, (url, hdr_builder, _ok_codes) in sources.items():
            cfg_key = name.upper() + ("_KEY" if name not in ("ipinfo",) else "_TOKEN")
            key = config_module.get(cfg_key, "") or ""
            if not key:
                results.append(_check(f"source.{name}", "warn",
                                      f"{name}: no API key configured.",
                                      fix_hint=f"Open Settings and add {cfg_key} to enable this source."))
                continue
            url_full = url + (f"?key={key}" if name == "shodan" else "")
            probes.append((name, _probe_url(session, url_full, headers=hdr_builder(key))))

        outcomes = await asyncio.gather(*[p[1] for p in probes], return_exceptions=True)
        for (name, _), outcome in zip(probes, outcomes):
            if isinstance(outcome, Exception):
                results.append(_check(f"source.{name}", "warn",
                                      f"{name}: probe raised {type(outcome).__name__}",
                                      fix_hint="This source may be temporarily unreachable. RECON will skip it."))
                continue
            status, err = outcome
            if status == 0:
                results.append(_check(f"source.{name}", "warn",
                                      f"{name}: unreachable ({err}).",
                                      fix_hint="The source is timing out or blocked. RECON will skip it on every analyze until it returns."))
            elif status in (401, 403):
                e = _err("SOURCE_AUTH_FAILED")
                results.append(_check(f"source.{name}", "fail",
                                      f"{name}: returned {status} — {e['detail']}",
                                      fix_hint=e["fix_hint"]))
            elif status == 429:
                e = _err("SOURCE_RATE_LIMITED")
                results.append(_check(f"source.{name}", "warn",
                                      f"{name}: rate-limited.", fix_hint=e["fix_hint"]))
            elif status < 500:
                results.append(_check(f"source.{name}", "ok",
                                      f"{name}: reachable (HTTP {status})."))
            else:
                results.append(_check(f"source.{name}", "warn",
                                      f"{name}: server error (HTTP {status}).",
                                      fix_hint="Source is returning a server error — likely temporary."))
    return results


async def check_ai_provider(config_module) -> Dict[str, Any]:
    """Send a tiny test message through the provider abstraction."""
    if not config_module.get("OPENAI_API_KEY"):
        e = _err("OPENAI_API_KEY_MISSING")
        return _check("ai_provider", "fail", e["detail"], fix_hint=e["fix_hint"])
    try:
        from providers import get_provider
        provider = get_provider()
        resp = await asyncio.wait_for(
            provider.complete(
                model=config_module.get_model(fast=True) if hasattr(config_module, "get_model") else None,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=4,
                temperature=0.0,
            ),
            timeout=15.0,
        )
        if resp.error:
            if "auth" in resp.error.lower():
                e = _err("OPENAI_AUTH_FAILED")
                return _check("ai_provider", "fail", e["detail"], fix_hint=e["fix_hint"])
            return _check("ai_provider", "fail", f"AI provider error: {resp.error[:160]}",
                          fix_hint="Check Settings and the Azure portal for your deployment status.")
        return _check("ai_provider", "ok",
                      f"AI provider reachable (model: {resp.model}, provider: {resp.provider}).")
    except asyncio.TimeoutError:
        e = _err("OPENAI_TIMEOUT")
        return _check("ai_provider", "warn", e["detail"], fix_hint=e["fix_hint"])
    except Exception as e:
        return _check("ai_provider", "fail", f"AI provider call raised: {type(e).__name__}: {str(e)[:160]}",
                      fix_hint="Check Settings; see logs for the full traceback.")


# ─── orchestrators ────────────────────────────────────────────────────────────
async def run_all_checks() -> Dict[str, Any]:
    """Run every check and return the full report. Used by /api/diagnose."""
    from config import config as _config
    start = time.perf_counter()

    sync_checks = [
        check_required_packages(),
        check_mitre_dataset(),
        check_warninglists(),
        check_data_dir(),
        check_frontend_build(),
    ]

    src_results, ai_result = await asyncio.gather(
        check_api_key_reachability(_config),
        check_ai_provider(_config),
        return_exceptions=True,
    )
    if isinstance(src_results, Exception):
        src_results = [_check("source_probes", "warn", f"Source probes failed: {src_results}", "")]
    if isinstance(ai_result, Exception):
        ai_result = _check("ai_provider", "fail", f"AI check raised: {ai_result}", "")

    checks = sync_checks + list(src_results) + [ai_result]
    summary = {"ok": 0, "warn": 0, "fail": 0}
    for c in checks:
        summary[c["status"]] = summary.get(c["status"], 0) + 1
    report = {
        "as_of":   int(time.time() * 1000),
        "elapsed_ms": int((time.perf_counter() - start) * 1000),
        "checks":  checks,
        "summary": summary,
    }
    # Update the in-memory cache so /api/health reflects the latest state.
    _HEALTH.update(report)
    return report


async def run_startup_checks() -> Dict[str, Any]:
    """Initial pass at boot. Logs each check; doesn't raise on failure
    so a degraded environment still serves requests."""
    _log.info("running startup self-diagnosis…")
    report = await run_all_checks()
    for c in report["checks"]:
        icon = {"ok": "✓", "warn": "!", "fail": "✗"}[c["status"]]
        _log.log(
            logging.INFO if c["status"] == "ok" else (logging.WARNING if c["status"] == "warn" else logging.ERROR),
            "[%s] %s — %s", icon, c["name"], c["message"],
        )
    s = report["summary"]
    _log.info("self-diagnosis summary: %d ok, %d warn, %d fail (%dms)",
              s["ok"], s["warn"], s["fail"], report["elapsed_ms"])
    return report


async def background_health_loop(interval_s: int = 900) -> None:
    """Re-run the API-key reachability + AI provider checks every 15
    minutes. Refreshes the in-memory health snapshot so /api/health
    reflects current state, not stale boot state."""
    from config import config as _config
    while True:
        try:
            await asyncio.sleep(interval_s)
            src_results = await check_api_key_reachability(_config)
            ai_result   = await check_ai_provider(_config)
            sync_checks = [
                check_required_packages(), check_mitre_dataset(),
                check_warninglists(), check_data_dir(), check_frontend_build(),
            ]
            checks = sync_checks + src_results + [ai_result]
            summary = {"ok": 0, "warn": 0, "fail": 0}
            for c in checks:
                summary[c["status"]] = summary.get(c["status"], 0) + 1
            _HEALTH.update({
                "as_of": int(time.time() * 1000),
                "checks": checks, "summary": summary,
            })
            _log.debug("background health check refreshed: %s", summary)
        except Exception as e:
            _log.warning("background health loop iteration failed: %s", e)


def get_current_health() -> Dict[str, Any]:
    """Return the most recent in-memory health snapshot. Used by
    /api/health to show LIVE source status rather than stale boot state."""
    return dict(_HEALTH)
