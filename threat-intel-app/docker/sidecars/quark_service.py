"""Quark Engine Android APK scoring sidecar."""

from __future__ import annotations

import os
import tempfile
from typing import Any, Dict

from _base_wrapper import run


def analyze_bytes(data: bytes, filename: str) -> Dict[str, Any]:
    try:
        from quark.Objects.quark import Quark
        from quark.utils.pprint import Pprint  # noqa: F401
    except Exception as e:
        return {"error": f"quark-engine not installed: {e}",
                "error_type": "unavailable"}

    tmp_dir = tempfile.mkdtemp(prefix="recon-quark-")
    apk_path = os.path.join(tmp_dir, filename or "sample.apk")
    with open(apk_path, "wb") as f:
        f.write(data)

    try:
        q = Quark(apk_path)
        q.load_rules()
        q.run_all_rules()
    except Exception as e:
        return {"error": f"quark run failed: {e}",
                 "error_type": "runtime_error"}

    threat_level = getattr(q, "threat_level", None)
    score = getattr(q, "quark_analysis", None)
    behaviors: list = []
    try:
        for rule_name, result in (q.quark_analysis.crime_description or {}).items():
            behaviors.append({"rule": rule_name,
                               "confidence": result.get("confidence")})
    except Exception:
        pass

    tl = (threat_level or "").upper() if isinstance(threat_level, str) else ""
    verdict = ("MALICIOUS" if tl == "HIGH RISK" else
                 "SUSPICIOUS" if tl in ("MODERATE RISK", "LOW RISK") else "UNKNOWN")

    return {
        "verdict":       verdict,
        "summary":       f"Quark: {tl or 'risk unknown'}, "
                         f"{len(behaviors)} rule hit"
                         f"{'s' if len(behaviors) != 1 else ''}",
        "threat_level":  threat_level,
        "behavior_count": len(behaviors),
        "behaviors":     behaviors[:20],
    }


if __name__ == "__main__":
    run("quark_engine", analyze_bytes, default_port=5006)
