"""Qiling PE/ELF emulation sidecar.

Uses the Qiling framework to emulate the uploaded binary and return a
summary of executed APIs, memory operations, and syscalls. Qiling needs
a rootfs on disk (we ship Qiling's bundled Windows/Linux rootfs at
/qiling/examples/rootfs/).
"""

from __future__ import annotations

import os
import tempfile
from typing import Any, Dict

from _base_wrapper import expose, run


def _detect_rootfs(file_bytes: bytes) -> str:
    """Pick the Qiling rootfs matching the sample's platform. Falls back
    to the Windows x86_64 rootfs — Qiling will fail cleanly on mismatch."""
    base = os.environ.get("QILING_ROOTFS_BASE", "/qiling/examples/rootfs")
    if file_bytes[:4] == b"\x7fELF":
        return os.path.join(base, "x8664_linux")
    return os.path.join(base, "x8664_windows")


def analyze_bytes(data: bytes, filename: str) -> Dict[str, Any]:
    try:
        from qiling import Qiling
        from qiling.const import QL_VERBOSE
    except Exception as e:
        return {"error": f"qiling not installed: {e}",
                "error_type": "unavailable"}

    tmp_dir = tempfile.mkdtemp(prefix="recon-qiling-")
    sample_path = os.path.join(tmp_dir, filename or "sample.bin")
    with open(sample_path, "wb") as f:
        f.write(data)

    rootfs = _detect_rootfs(data)
    traced_calls: list = []
    try:
        ql = Qiling([sample_path], rootfs, verbose=QL_VERBOSE.OFF)
        orig_log = ql.log
        def _collect(fmt, *args, **_kw):
            try:
                msg = (fmt % args) if args else fmt
            except Exception:
                msg = str(fmt)
            if isinstance(msg, str) and len(traced_calls) < 500:
                traced_calls.append(msg[:200])
        ql.log = _collect   # type: ignore[assignment]
        try:
            ql.run(timeout=15_000_000)  # microseconds — 15s cap
        except Exception as e:
            traced_calls.append(f"[EMU-STOP] {type(e).__name__}: {e}")
        finally:
            ql.log = orig_log
    except Exception as e:
        return {"error": f"qiling bootstrap failed: {e}",
                "error_type": "runtime_error"}

    verdict = "SUSPICIOUS" if len(traced_calls) > 20 else "UNKNOWN"
    return {
        "verdict":        verdict,
        "summary":        f"Qiling: traced {len(traced_calls)} log event"
                           f"{'s' if len(traced_calls) != 1 else ''}",
        "trace_count":    len(traced_calls),
        "trace":          traced_calls[:50],
        "rootfs":         rootfs,
    }


app = expose("qiling", analyze_bytes)   # for `gunicorn service:app`

if __name__ == "__main__":
    run("qiling", analyze_bytes, default_port=5001)
