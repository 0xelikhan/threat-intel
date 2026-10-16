"""Stringsifter — ML-ranked strings extraction sidecar."""

from __future__ import annotations

import os
import subprocess
import tempfile
from typing import Any, Dict

from _base_wrapper import expose, run


def analyze_bytes(data: bytes, filename: str) -> Dict[str, Any]:
    tmp_dir = tempfile.mkdtemp(prefix="recon-ssifter-")
    sample_path = os.path.join(tmp_dir, filename or "sample.bin")
    with open(sample_path, "wb") as f:
        f.write(data)

    try:
        # `rank_strings` ships as a CLI entry point from stringsifter.
        result = subprocess.run(
            ["rank_strings", "--input-file", sample_path, "--limit", "50"],
            capture_output=True, timeout=50, text=True, check=False,
        )
    except FileNotFoundError:
        return {"error": "rank_strings binary not on PATH",
                "error_type": "unavailable"}
    except subprocess.TimeoutExpired:
        return {"error": "stringsifter timed out", "error_type": "timed_out"}

    ranked: list = []
    for ln in (result.stdout or "").splitlines():
        parts = ln.strip().split("\t", 1)
        if len(parts) == 2:
            try:
                score = float(parts[0])
            except ValueError:
                continue
            ranked.append({"score": score, "string": parts[1][:200]})

    return {
        "verdict":        "UNKNOWN",
        "summary":        f"Stringsifter: top {len(ranked)} ML-ranked string"
                           f"{'s' if len(ranked) != 1 else ''}",
        "ranked_strings": ranked[:30],
    }


app = expose("stringsifter", analyze_bytes)   # for `gunicorn service:app`

if __name__ == "__main__":
    run("stringsifter", analyze_bytes, default_port=5010)
