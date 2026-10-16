"""Thug honeyclient sidecar — emulates a browser visiting content."""

from __future__ import annotations

import os
import tempfile
from typing import Any, Dict

from _base_wrapper import expose, run


def analyze_bytes(data: bytes, filename: str) -> Dict[str, Any]:
    try:
        from thug import Thug
    except Exception as e:
        return {"error": f"thug not installed: {e}",
                "error_type": "unavailable"}

    tmp_dir = tempfile.mkdtemp(prefix="recon-thug-")
    html_path = os.path.join(tmp_dir, filename or "sample.html")
    with open(html_path, "wb") as f:
        f.write(data)

    try:
        # Thug's public entry is argv-driven; use its ThugAPI directly
        from thug.ThugAPI.ThugAPI import ThugAPI
        api = ThugAPI()
        api.set_file_logging()
        api.set_json_logging()
        api.run_local(html_path)
    except Exception as e:
        return {"error": f"thug run failed: {e}",
                 "error_type": "runtime_error"}

    # Thug writes a JSON report under its logs dir. In the containerised
    # setup we point it at /recon-thug-logs via env var; adapt as needed.
    log_dir = os.environ.get("THUG_LOGS", "/recon-thug-logs")
    exploits: list = []
    try:
        import json
        from pathlib import Path
        for p in Path(log_dir).rglob("analysis.json"):
            report = json.loads(p.read_text(errors="ignore"))
            for exp in (report.get("exploits") or []):
                exploits.append(exp)
            break
    except Exception:
        pass

    verdict = "MALICIOUS" if exploits else "UNKNOWN"
    return {
        "verdict":        verdict,
        "summary":        f"Thug: {len(exploits)} exploit"
                           f"{'s' if len(exploits) != 1 else ''} detected",
        "exploit_count":  len(exploits),
        "exploits":       exploits[:10],
    }


app = expose("thug", analyze_bytes)   # for `gunicorn service:app`

if __name__ == "__main__":
    run("thug", analyze_bytes, default_port=5003)
