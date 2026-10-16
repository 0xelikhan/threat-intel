"""Hfinger — HTTP request fingerprinting from PCAP."""

from __future__ import annotations

import os
import subprocess
import tempfile
from typing import Any, Dict

from _base_wrapper import expose, run


def analyze_bytes(data: bytes, filename: str) -> Dict[str, Any]:
    tmp_dir = tempfile.mkdtemp(prefix="recon-hfinger-")
    pcap_path = os.path.join(tmp_dir, filename or "sample.pcap")
    with open(pcap_path, "wb") as f:
        f.write(data)

    try:
        # Hfinger ships as `hfinger-analyze -f <pcap>`
        result = subprocess.run(
            ["hfinger-analyze", "-f", pcap_path],
            capture_output=True, timeout=50, text=True, check=False,
        )
    except FileNotFoundError:
        return {"error": "hfinger-analyze binary not on PATH",
                "error_type": "unavailable"}
    except subprocess.TimeoutExpired:
        return {"error": "hfinger timed out", "error_type": "timed_out"}

    # Hfinger outputs one fingerprint per request to stdout.
    fingerprints = [ln.strip() for ln in (result.stdout or "").splitlines() if ln.strip()]

    return {
        "verdict":           "UNKNOWN",
        "summary":           f"Hfinger: {len(fingerprints)} HTTP request"
                              f"{'s' if len(fingerprints) != 1 else ''} fingerprinted",
        "fingerprint_count": len(fingerprints),
        "fingerprints":     fingerprints[:30],
        "stderr":           (result.stderr or "")[:300],
    }


app = expose("hfinger", analyze_bytes)   # for `gunicorn service:app`

if __name__ == "__main__":
    run("hfinger", analyze_bytes, default_port=5009)
