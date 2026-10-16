"""Speakeasy Windows PE emulation sidecar."""

from __future__ import annotations

import tempfile
from typing import Any, Dict

from _base_wrapper import expose, run


def analyze_bytes(data: bytes, filename: str) -> Dict[str, Any]:
    try:
        import speakeasy
    except Exception as e:
        return {"error": f"speakeasy not installed: {e}",
                "error_type": "unavailable"}

    se = speakeasy.Speakeasy()
    try:
        module = se.load_from_bytes(filename or "sample.exe", data)
        se.run_module(module)
    except Exception as e:
        return {"error": f"speakeasy run failed: {e}",
                 "error_type": "runtime_error"}

    report = se.get_report() or {}
    entry_points = report.get("entry_points", [])
    api_calls: list = []
    strings: list = []
    for ep in entry_points:
        for api in (ep.get("apis") or [])[:200]:
            api_calls.append(api.get("api_name") or api)
    strings = (report.get("strings") or [])[:50]

    verdict = "SUSPICIOUS" if len(api_calls) > 30 else "UNKNOWN"
    return {
        "verdict":     verdict,
        "summary":     f"Speakeasy: {len(api_calls)} API call"
                        f"{'s' if len(api_calls) != 1 else ''} traced",
        "api_calls":   api_calls[:100],
        "strings":     strings,
        "errors":      (report.get("errors") or [])[:5],
    }


app = expose("speakeasy", analyze_bytes)

if __name__ == "__main__":
    run("speakeasy", analyze_bytes, default_port=5002)
