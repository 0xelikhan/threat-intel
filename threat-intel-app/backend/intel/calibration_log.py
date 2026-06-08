"""
AI calibration tracking — record every analyst override of the AI verdict.

Each override is a labeled training signal: the AI said X, the human
said Y. We hold a per-process in-memory ring buffer so the running
operator can spot drift / regressions, but we DO NOT persist these
records (analyst-derived input hashes + reasons are out of scope for
the no-persistence policy that governs this platform). The buffer is
lost on restart by design.

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
import subprocess
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional


# In-memory ring buffer — last 5000 override records. Cleared on restart
# by design (analyst-derived data is not persisted; see the platform
# no-persistence policy).
_RECORDS: Deque[Dict[str, Any]] = deque(maxlen=5000)


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
    _RECORDS.append(record)
    return record


def iter_records() -> List[Dict[str, Any]]:
    """Return a snapshot of every override record held in memory. The
    eval / prompt-hygiene scripts that historically read the JSONL log
    now see whatever the live process has accumulated since startup."""
    return list(_RECORDS)
