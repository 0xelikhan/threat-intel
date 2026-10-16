"""Shared Docker-service dispatcher for the file-analyzer sidecars.

Each Docker-based FileAnalyzer plugin exposes a tiny sidecar HTTP
service (Qiling, Speakeasy, Mobsf, etc.) that accepts a file upload
and returns a JSON report. This helper centralises:

  - the multipart POST to the service's /analyze endpoint
  - timeout + retry handling (one retry on transient 5xx / timeout)
  - response envelope normalisation
  - common AnalysisResult error shapes (unavailable, timeout, http_error)

Service contract (what the sidecars must implement):
  POST <RECON_<SERVICE>_URL>/analyze
  Content-Type: multipart/form-data
  Form field: file  (the sample bytes)
  Form field: filename (optional, defaults to 'sample')
  → 200 application/json  { ...service-specific fields..., verdict?, summary? }
  → 4xx/5xx application/json  { "error": "...", "error_type": "..." }

Service URL comes from the env var the stub's descriptor already
declares (RECON_QILING_URL, RECON_SPEAKEASY_URL, ...).
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from plugins import AnalysisResult

_log = logging.getLogger("recon.plugins.file_analyzers.docker")


async def dispatch(
    service_name: str,
    service_env_var: str,
    file_bytes: bytes,
    filename: str,
    *,
    endpoint_path: str = "/analyze",
    timeout_s: float = 60.0,
    extra_fields: Optional[Dict[str, str]] = None,
) -> AnalysisResult:
    """POST the file to the configured sidecar service URL. Returns an
    AnalysisResult; never raises."""
    base_url = os.environ.get(service_env_var, "").rstrip("/")
    if not base_url:
        return AnalysisResult(
            source=service_name,
            ioc_type="file", ioc_value=filename or "",
            found=False,
            error=(f"{service_name} not configured: set {service_env_var} and "
                   "run the matching Docker service (see "
                   "docker/docker-compose.yml)."),
            error_type="unavailable",
        )

    import aiohttp
    url = f"{base_url}{endpoint_path}"
    form = aiohttp.FormData()
    form.add_field("file", file_bytes, filename=filename or "sample",
                    content_type="application/octet-stream")
    form.add_field("filename", filename or "sample")
    for k, v in (extra_fields or {}).items():
        form.add_field(k, v)

    _TRANSIENT = {502, 503, 504}
    last_err_msg = ""
    last_err_type = "unreachable"

    for attempt in (1, 2):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, data=form,
                    timeout=aiohttp.ClientTimeout(total=timeout_s),
                ) as r:
                    status = r.status
                    try:
                        payload = await r.json(content_type=None)
                    except Exception:
                        text = await r.text()
                        payload = {"raw": text[:500]}
                    if 200 <= status < 300:
                        return _wrap(service_name, filename, payload)
                    if status in _TRANSIENT and attempt == 1:
                        continue   # one retry on transient
                    err = (payload.get("error")
                           if isinstance(payload, dict) else None) or f"HTTP {status}"
                    err_type = (payload.get("error_type")
                                 if isinstance(payload, dict) else None)
                    if not err_type:
                        if status in (401, 403):
                            err_type = "auth_failed"
                        elif status == 429:
                            err_type = "rate_limited"
                        elif status >= 500:
                            err_type = "http_error"
                        else:
                            err_type = "unreachable"
                    return AnalysisResult(
                        source=service_name,
                        ioc_type="file", ioc_value=filename or "",
                        found=False,
                        error=str(err)[:200], error_type=err_type,
                    )
        except Exception as e:
            last_err_msg = str(e)[:200]
            if "timeout" in last_err_msg.lower() or "timed out" in last_err_msg.lower():
                last_err_type = "timed_out"
            if attempt == 1:
                continue   # one retry on exception too
            break

    return AnalysisResult(
        source=service_name,
        ioc_type="file", ioc_value=filename or "",
        found=False,
        error=last_err_msg or "service unreachable",
        error_type=last_err_type,
    )


def _wrap(service_name: str, filename: str, payload: Any) -> AnalysisResult:
    """Normalise the service's JSON into AnalysisResult. The sidecar
    may already return the full shape (source/verdict/summary/raw) in
    which case we trust it; otherwise we build defaults."""
    if isinstance(payload, dict):
        verdict = payload.get("verdict") or "UNKNOWN"
        summary = payload.get("summary") or f"{service_name} returned data"
        details_url = payload.get("details_url")
        reserved = {"source", "found", "verdict", "summary", "details_url",
                     "error", "error_type"}
        raw = {k: v for k, v in payload.items() if k not in reserved}
    else:
        verdict = "UNKNOWN"
        summary = f"{service_name} returned data"
        details_url = None
        raw = {"raw": payload}

    return AnalysisResult(
        source=service_name,
        ioc_type="file", ioc_value=filename or "",
        found=True,
        verdict=verdict if verdict in ("CLEAN", "UNKNOWN", "SUSPICIOUS",
                                        "MALICIOUS") else "UNKNOWN",
        summary=summary,
        details_url=details_url,
        raw=raw,
    )
