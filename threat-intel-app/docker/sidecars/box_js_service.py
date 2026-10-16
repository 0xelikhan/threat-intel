"""Box-js JavaScript emulator sidecar.

Box-js is a Node.js tool, not a Python library. The sidecar just
shells out to `box-js` and parses its JSON report. The container
ships with Node + npm + box-js globally installed.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict

from _base_wrapper import expose, run


def analyze_bytes(data: bytes, filename: str) -> Dict[str, Any]:
    tmp_dir = tempfile.mkdtemp(prefix="recon-boxjs-")
    sample_path = os.path.join(tmp_dir, filename or "sample.js")
    with open(sample_path, "wb") as f:
        f.write(data)

    try:
        subprocess.run(
            ["box-js", sample_path, "--no-shell-error", "--output-dir", tmp_dir],
            capture_output=True, timeout=55, check=False,
        )
    except FileNotFoundError:
        return {"error": "box-js binary not on PATH",
                "error_type": "unavailable"}
    except subprocess.TimeoutExpired:
        return {"error": "box-js timed out", "error_type": "timed_out"}

    # Box-js writes `<sample>.results/` next to the input with a JSON report.
    results_dir = Path(sample_path + ".results")
    urls: list = []
    cmds: list = []
    iocs: Dict[str, Any] = {}
    try:
        for p in results_dir.glob("urls.json"):
            urls = json.loads(p.read_text(errors="ignore")) or []
        for p in results_dir.glob("snippets.json"):
            iocs["snippets"] = json.loads(p.read_text(errors="ignore"))
        for p in results_dir.glob("eval.log"):
            cmds = [line.strip() for line in p.read_text(errors="ignore").splitlines()
                     if line.strip()][:50]
    except Exception:
        pass

    verdict = "MALICIOUS" if urls or cmds else "UNKNOWN"
    return {
        "verdict":     verdict,
        "summary":     (f"Box-js: {len(urls)} URL IOC"
                        f"{'s' if len(urls) != 1 else ''}"
                        + (f", {len(cmds)} eval event" if cmds else "")),
        "url_iocs":    urls[:30],
        "eval_events": cmds[:20],
        "iocs":        iocs,
    }


app = expose("box_js", analyze_bytes)   # for `gunicorn service:app`

if __name__ == "__main__":
    run("box_js", analyze_bytes, default_port=5004)
