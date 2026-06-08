"""
AI calibration tracking — record every analyst override of the AI verdict.

Each override is a labeled training signal: the AI said X, the human
said Y. Storing them in a single append-only log lets us:

  * Spot prompt regressions before users complain (override rate
    suddenly spikes after a prompt tweak → roll back).
  * Build evals — a corpus of (input, AI verdict, analyst verdict)
    triples is exactly what offline eval harnesses chew on.
  * Surface trends in the UI (which threat-level brackets get overridden
    most, which alert types the AI is consistently miscalling).

Storage: backend/data/calibration_overrides.jsonl — one JSON object per
line, append-only. JSONL is durable under crashes, trivial to ingest
into any pandas / DuckDB / BigQuery pipeline later, and doesn't need a
DB dependency.

Each record shape:

  {
    "ts":              1717612800.123,
    "input_hash":      "sha256-hex",     # SHA-256 of the raw input
                                          # (lets us de-dup overrides on
                                          #  the same alert paste)
    "ai_verdict": {
      "threat_level": "MEDIUM",
      "confidence":   0.62,
      "summary":      "..."             # capped at 240 chars
    },
    "analyst_verdict": {
      "threat_level": "LOW",
      "reason":       "Internal admin tool, not C2",
    },
    "prompt_version": "g6753cc5",       # short SHA — see prompt_version()
    "alert_type":     "edr_audit",
    "agreed":         False             # False on every override row
                                         # (placeholder for future
                                         #  "I agree" thumbs-up rows)
  }

Stats endpoint groups by prompt_version + threat_level so a regression
shows up as a higher override rate for a specific (version, level)
cell.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


_LOG_PATH = Path(__file__).resolve().parents[1] / "data" / "calibration_overrides.jsonl"
_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


_prompt_version_cached = None  # type: Optional[str]


def prompt_version() -> str:
    """Short-SHA proxy for the current prompt version. We use the git
    HEAD because all our prompts live in the repo, so any prompt edit
    bumps the version automatically without manual constants to keep in
    sync. Falls back to "dev" if git isn't available (Docker image
    without .git history)."""
    global _prompt_version_cached
    if _prompt_version_cached is not None:
        return _prompt_version_cached
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=2,
            cwd=Path(__file__).resolve().parents[2],
        )
        v = (out.stdout or "").strip()
        _prompt_version_cached = ("g" + v) if v else "dev"
    except Exception:
        _prompt_version_cached = "dev"
    return _prompt_version_cached


def input_hash(raw_input: str) -> str:
    """Deterministic ID for a particular alert paste — lets us spot a
    re-overridden case across multiple analyses of the same input."""
    if not raw_input:
        return "empty"
    return hashlib.sha256(raw_input.encode("utf-8", errors="replace")).hexdigest()


def record_override(
    raw_input: str,
    ai_threat_level: str,
    ai_confidence: Optional[float],
    ai_summary: str,
    analyst_threat_level: str,
    analyst_reason: str = "",
    alert_type: Optional[str] = None,
) -> Dict[str, Any]:
    """Append a single override record. Returns the record for the
    caller (the HTTP handler echoes it so the UI can confirm)."""
    record = {
        "ts":            time.time(),
        "input_hash":    input_hash(raw_input or ""),
        "ai_verdict": {
            "threat_level": (ai_threat_level or "").upper() or "UNKNOWN",
            "confidence":   ai_confidence,
            "summary":      (ai_summary or "")[:240],
        },
        "analyst_verdict": {
            "threat_level": (analyst_threat_level or "").upper() or "UNKNOWN",
            "reason":       (analyst_reason or "")[:600],
        },
        "prompt_version": prompt_version(),
        "alert_type":     alert_type,
        "agreed":         (
            (ai_threat_level or "").upper() ==
            (analyst_threat_level or "").upper()
        ),
    }
    try:
        with open(_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        pass
    return record


def iter_records() -> List[Dict[str, Any]]:
    """Read every override record from the JSONL log. Public because
    scripts/eval_prompts.py and scripts/prompt_hygiene.py both consume
    the corpus. JSONL means we can stream this for big logs, but for
    the analyst tooling we just slurp — even 10 000 overrides parses
    in milliseconds."""
    if not _LOG_PATH.exists():
        return []
    out: List[Dict[str, Any]] = []
    try:
        with open(_LOG_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        pass
    return out
