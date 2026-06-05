#!/usr/bin/env python
"""
Backfill an analyst override into the calibration log.

Use when the AI miscalled an alert and you want the override recorded
even though the analysis is no longer live in the UI (the SSE stream
already closed, the case isn't in HistoryPanel, etc.). The same
JSONL log feeds /api/calibration/stats, so backfilled overrides count
toward agreement-rate trends.

Usage examples:

  # Interactive — paste alert text + choose levels
  python scripts/record_override.py

  # One-shot, alert text from a file
  python scripts/record_override.py \\
      --alert-file ./paste.txt \\
      --ai-level MEDIUM \\
      --analyst-level LOW \\
      --reason "Routine admin cleanup, expected on this host"

  # Pipe alert text from stdin
  cat paste.txt | python scripts/record_override.py \\
      --ai-level MEDIUM --analyst-level LOW \\
      --reason "Known internal admin workflow"

Levels (case-insensitive): CRITICAL HIGH MEDIUM LOW INFORMATIONAL
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Stand-alone import — the script lives one level above backend/ so it
# can be invoked from the repo root without setting PYTHONPATH.
_HERE = Path(__file__).resolve()
_BACKEND = _HERE.parent.parent / "backend"
sys.path.insert(0, str(_BACKEND))


_VALID_LEVELS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}


def _read_alert_text(args: argparse.Namespace) -> str:
    if args.alert_file:
        return Path(args.alert_file).read_text(encoding="utf-8")
    if not sys.stdin.isatty():
        return sys.stdin.read()
    print("Paste the alert text. End with Ctrl-D (Unix) or Ctrl-Z then Enter (Windows):")
    return sys.stdin.read()


def _interactive_level(prompt: str) -> str:
    while True:
        v = input(prompt).strip().upper()
        if v in _VALID_LEVELS:
            return v
        print(f"  Must be one of: {', '.join(sorted(_VALID_LEVELS))}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Record an analyst override into the calibration log.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--alert-file", help="Path to a file containing the alert text.")
    parser.add_argument("--ai-level", help="AI's threat level (e.g. MEDIUM).")
    parser.add_argument("--ai-confidence", type=float, default=None,
                        help="AI confidence 0.0-1.0 (optional).")
    parser.add_argument("--ai-summary", default="",
                        help="AI summary text (optional, capped at 240 chars).")
    parser.add_argument("--analyst-level", help="Your verdict (e.g. LOW).")
    parser.add_argument("--reason", default="",
                        help="Why you disagree (capped at 600 chars).")
    parser.add_argument("--alert-type", default=None,
                        help="Optional alert-type tag for filtering later.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the record JSON without writing it.")
    args = parser.parse_args()

    alert = _read_alert_text(args).strip()
    if not alert:
        print("error: alert text is required", file=sys.stderr)
        return 2

    ai_level      = (args.ai_level or "").upper()
    analyst_level = (args.analyst_level or "").upper()
    if ai_level and ai_level not in _VALID_LEVELS:
        print(f"error: --ai-level must be one of {sorted(_VALID_LEVELS)}", file=sys.stderr)
        return 2
    if analyst_level and analyst_level not in _VALID_LEVELS:
        print(f"error: --analyst-level must be one of {sorted(_VALID_LEVELS)}", file=sys.stderr)
        return 2
    if not ai_level:
        ai_level = _interactive_level("AI's verdict: ")
    if not analyst_level:
        analyst_level = _interactive_level("Your verdict:  ")

    if not args.reason and sys.stdin.isatty():
        reason = input("Reason (one line, optional): ").strip()
    else:
        reason = args.reason

    from intel.calibration_log import record_override
    record = record_override(
        raw_input            = alert,
        ai_threat_level      = ai_level,
        ai_confidence        = args.ai_confidence,
        ai_summary           = args.ai_summary,
        analyst_threat_level = analyst_level,
        analyst_reason       = reason,
        alert_type           = args.alert_type,
    )
    if args.dry_run:
        print("DRY RUN — would write:")
        print(json.dumps(record, indent=2, default=str))
        return 0
    agreed = record["agreed"]
    arrow  = "==" if agreed else "->"
    print(f"\nRecorded: {record['ai_verdict']['threat_level']} {arrow} "
          f"{record['analyst_verdict']['threat_level']}  "
          f"(prompt_version={record['prompt_version']}, "
          f"input_hash={record['input_hash'][:12]}...)")
    if not agreed:
        print(f"Override saved to backend/data/calibration_overrides.jsonl")
    return 0


if __name__ == "__main__":
    sys.exit(main())
