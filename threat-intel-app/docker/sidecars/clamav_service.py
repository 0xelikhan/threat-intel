"""ClamAV AV scan sidecar — talks to clamd via its network protocol."""

from __future__ import annotations

import os
import socket
import struct
from typing import Any, Dict

from _base_wrapper import expose, run


def _clamd_scan_stream(data: bytes, host: str, port: int) -> str:
    """Send file bytes to clamd over its INSTREAM protocol. Returns
    the raw clamd response ('OK' / 'FOUND <sig>' / 'ERROR ...')."""
    with socket.create_connection((host, port), timeout=20) as s:
        s.sendall(b"nINSTREAM\n")
        for chunk_start in range(0, len(data), 65536):
            chunk = data[chunk_start:chunk_start + 65536]
            s.sendall(struct.pack(">I", len(chunk)) + chunk)
        s.sendall(struct.pack(">I", 0))
        resp = b""
        while True:
            buf = s.recv(4096)
            if not buf:
                break
            resp += buf
    return resp.decode("utf-8", errors="replace").strip()


def analyze_bytes(data: bytes, filename: str) -> Dict[str, Any]:
    host = os.environ.get("CLAMD_HOST", "clamav")
    port = int(os.environ.get("CLAMD_PORT", "3310"))
    try:
        resp = _clamd_scan_stream(data, host, port)
    except Exception as e:
        return {"error": f"clamd unreachable at {host}:{port}: {e}",
                "error_type": "unavailable"}

    # clamd replies e.g. "stream: OK" or "stream: Eicar-Test-Signature FOUND"
    found_sig = None
    verdict = "CLEAN"
    if "FOUND" in resp:
        verdict = "MALICIOUS"
        # Signature name sits between ": " and " FOUND"
        try:
            found_sig = resp.split(":", 1)[1].rsplit("FOUND", 1)[0].strip()
        except Exception:
            found_sig = resp
    elif "ERROR" in resp:
        return {"error": resp[:200], "error_type": "api_error"}

    return {
        "verdict":     verdict,
        "summary":     (f"ClamAV: {found_sig}" if found_sig
                        else "ClamAV: no signature match"),
        "signature":   found_sig,
        "raw_resp":    resp[:200],
    }


app = expose("clamav", analyze_bytes)   # for `gunicorn service:app`

if __name__ == "__main__":
    run("clamav", analyze_bytes, default_port=5007)
