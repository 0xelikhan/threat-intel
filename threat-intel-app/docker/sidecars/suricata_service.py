"""Suricata PCAP sidecar — runs `suricata -r <pcap>` and parses eve.json."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict

from _base_wrapper import expose, run


def analyze_bytes(data: bytes, filename: str) -> Dict[str, Any]:
    tmp_dir = tempfile.mkdtemp(prefix="recon-suricata-")
    pcap_path = os.path.join(tmp_dir, filename or "sample.pcap")
    with open(pcap_path, "wb") as f:
        f.write(data)
    log_dir = os.path.join(tmp_dir, "log")
    os.makedirs(log_dir, exist_ok=True)

    cfg = os.environ.get("SURICATA_YAML", "/etc/suricata/suricata.yaml")
    try:
        subprocess.run(
            ["suricata", "-c", cfg, "-r", pcap_path, "-l", log_dir, "-k", "none"],
            capture_output=True, timeout=110, check=False,
        )
    except FileNotFoundError:
        return {"error": "suricata binary not on PATH",
                "error_type": "unavailable"}
    except subprocess.TimeoutExpired:
        return {"error": "suricata timed out", "error_type": "timed_out"}

    alerts: list = []
    flows: int = 0
    eve = Path(log_dir) / "eve.json"
    if eve.exists():
        for line in eve.read_text(errors="ignore").splitlines():
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if obj.get("event_type") == "alert":
                alerts.append({
                    "signature":    obj.get("alert", {}).get("signature"),
                    "category":     obj.get("alert", {}).get("category"),
                    "severity":     obj.get("alert", {}).get("severity"),
                    "src_ip":       obj.get("src_ip"),
                    "dest_ip":      obj.get("dest_ip"),
                })
            elif obj.get("event_type") == "flow":
                flows += 1

    verdict = "MALICIOUS" if alerts else "UNKNOWN"
    return {
        "verdict":      verdict,
        "summary":      f"Suricata: {len(alerts)} alert"
                         f"{'s' if len(alerts) != 1 else ''}, "
                         f"{flows} flow{'s' if flows != 1 else ''}",
        "alert_count":  len(alerts),
        "alerts":       alerts[:20],
        "flow_count":   flows,
    }


app = expose("suricata", analyze_bytes)   # for `gunicorn service:app`

if __name__ == "__main__":
    run("suricata", analyze_bytes, default_port=5008)
