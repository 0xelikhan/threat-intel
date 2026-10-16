"""MobSF static-APK sidecar.

MobSF has its own REST API; this wrapper just proxies RECON's
POST /analyze into MobSF's upload + scan flow and returns a
summarised report.

Env vars:
  MOBSF_URL   base URL of the actual Mobile-Security-Framework-MobSF
              container (http://mobsf-internal:8000)
  MOBSF_KEY   MobSF API key (printed on first container boot)
"""

from __future__ import annotations

import os
from typing import Any, Dict

import requests

from _base_wrapper import run


def analyze_bytes(data: bytes, filename: str) -> Dict[str, Any]:
    base = os.environ.get("MOBSF_URL", "").rstrip("/")
    key = os.environ.get("MOBSF_KEY", "")
    if not base or not key:
        return {"error": "MOBSF_URL + MOBSF_KEY not configured",
                "error_type": "unavailable"}

    # 1. upload
    up = requests.post(f"{base}/api/v1/upload",
                        files={"file": (filename or "sample.apk", data,
                                         "application/octet-stream")},
                        headers={"Authorization": key},
                        timeout=60)
    if up.status_code != 200:
        return {"error": f"upload HTTP {up.status_code}",
                 "error_type": "api_error"}
    uploaded = up.json()
    scan_hash = uploaded.get("hash")
    scan_type = uploaded.get("scan_type")
    if not scan_hash:
        return {"error": "upload returned no hash", "error_type": "api_error"}

    # 2. scan
    sc = requests.post(f"{base}/api/v1/scan",
                        data={"hash": scan_hash, "scan_type": scan_type,
                              "file_name": uploaded.get("file_name")},
                        headers={"Authorization": key},
                        timeout=160)
    if sc.status_code != 200:
        return {"error": f"scan HTTP {sc.status_code}",
                 "error_type": "api_error"}
    report = sc.json() if sc.content else {}

    permissions = report.get("permissions") or {}
    high_sev_findings: list = []
    for finding_group in ("manifest_analysis", "network_security",
                            "binary_analysis", "code_analysis"):
        for f in (report.get(finding_group) or {}).values() if isinstance(
                report.get(finding_group), dict) else []:
            if (f.get("severity") or "").lower() in ("high", "critical"):
                high_sev_findings.append(f.get("title") or f.get("description"))

    verdict = "SUSPICIOUS" if (len(permissions) > 20 or high_sev_findings) else "UNKNOWN"
    if report.get("average_cvss", 0) and float(report.get("average_cvss", 0)) >= 7.0:
        verdict = "MALICIOUS"

    return {
        "verdict":          verdict,
        "summary":          (f"MobSF: {len(permissions)} permissions, "
                             f"{len(high_sev_findings)} high-sev finding"
                             f"{'s' if len(high_sev_findings) != 1 else ''}"),
        "package":          report.get("package_name"),
        "app_name":         report.get("app_name"),
        "sha256":           report.get("sha256"),
        "average_cvss":     report.get("average_cvss"),
        "permission_count": len(permissions),
        "high_sev":         high_sev_findings[:10],
        "trackers":         (report.get("trackers") or {}).get("trackers", [])[:10],
    }


if __name__ == "__main__":
    run("mobsf", analyze_bytes, default_port=5005)
