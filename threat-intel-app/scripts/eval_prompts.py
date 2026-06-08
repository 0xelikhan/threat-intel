#!/usr/bin/env python
"""
Eval harness — replay historical analyst overrides through the current
prompts to measure agreement-rate delta.

The calibration log (backend/data/calibration_overrides.jsonl) is a
labeled corpus: every record has (raw_input, AI verdict at the time,
analyst's corrected verdict). This script re-runs each record's
raw_input through the current AI pipeline, compares the NEW AI verdict
to the analyst's verdict, and reports:

  - Overall agreement rate now vs at original-record time
  - Per-level-pair shifts (e.g. MEDIUM->LOW cases that now resolve LOW)
  - Specific records where the new prompt got closer to / further from
    the analyst's judgement

Use cases:
  - Before merging a prompt change, run this against current main to
    see whether the change moves agreement up or down.
  - Quarterly review: spot drift between AI verdicts and historical
    analyst calls.

Cost note: this re-runs the LLM once per record. A 100-record corpus
at ~3 LLM calls per analysis = ~300 calls. Use --limit N to cap.

Usage:

  # Full replay
  python scripts/eval_prompts.py

  # Replay first 20 records (cost-bounded smoke test)
  python scripts/eval_prompts.py --limit 20

  # Output JSON for piping into another tool
  python scripts/eval_prompts.py --json

  # Replay only records where AI and analyst disagreed
  python scripts/eval_prompts.py --disagreements-only
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

_HERE    = Path(__file__).resolve()
_BACKEND = _HERE.parent.parent / "backend"
sys.path.insert(0, str(_BACKEND))


async def _run_pipeline(raw_input: str) -> Optional[str]:
    """Run the orchestrator end-to-end on the input and return the
    AI's threat_level. None on failure."""
    try:
        from agents.orchestrator import run_pipeline
    except Exception as e:
        print(f"  error: failed to import orchestrator: {e}", file=sys.stderr)
        return None
    state = {"raw_input": raw_input, "agent_trace": []}
    try:
        result = await run_pipeline(state)
    except Exception as e:
        print(f"  error: pipeline raised {type(e).__name__}: {e}", file=sys.stderr)
        return None
    return (result.get("threat_level") or "").upper() or None


def _classify_movement(orig_ai: str, orig_an: str, new_ai: str) -> str:
    """Categorise how the new AI verdict compares to the analyst's
    expected answer relative to the original AI verdict.

      AGREED_THEN_AGREES   — both then and now, the AI matches analyst
      AGREED_NOW           — was wrong, now right (improvement)
      DISAGREED_BOTH       — wrong then, wrong now (no movement)
      AGREED_BACK_OFF      — was right, now wrong (regression)
    """
    was_agreement  = (orig_ai == orig_an)
    is_agreement   = (new_ai  == orig_an)
    if was_agreement and is_agreement:    return "AGREED_THEN_AGREES"
    if not was_agreement and is_agreement: return "AGREED_NOW"
    if not was_agreement and not is_agreement: return "DISAGREED_BOTH"
    if was_agreement and not is_agreement: return "AGREED_BACK_OFF"
    return "UNKNOWN"


def _emoji(label: str) -> str:
    return {"AGREED_THEN_AGREES": "==",
            "AGREED_NOW":         "↑↑",
            "DISAGREED_BOTH":     "..",
            "AGREED_BACK_OFF":    "↓↓"}.get(label, "?")


async def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replay calibration overrides through the current prompts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--limit", type=int, default=None,
                        help="Cap replay at N most-recent records (cost guard).")
    parser.add_argument("--disagreements-only", action="store_true",
                        help="Replay only records where AI and analyst originally disagreed.")
    parser.add_argument("--json", action="store_true",
                        help="Emit structured JSON instead of the human-readable table.")
    args = parser.parse_args()

    from intel.calibration_log import iter_records, prompt_version
    records = iter_records()
    if not records:
        print("No override records in backend/data/calibration_overrides.jsonl.")
        print("Use scripts/record_override.py to seed some, then re-run.")
        return 0

    # Most-recent first
    records.sort(key=lambda r: r.get("ts", 0), reverse=True)

    if args.disagreements_only:
        records = [r for r in records if not r.get("agreed")]
    if args.limit:
        records = records[: args.limit]

    cur_prompt_version = prompt_version()
    print(f"Replaying {len(records)} record(s) against prompt_version="
          f"{cur_prompt_version}")
    print(f"(historical records span prompt versions: "
          f"{sorted({r.get('prompt_version', '?') for r in records})})")
    print()

    movements: Counter = Counter()
    pair_shifts: Dict[str, Counter] = defaultdict(Counter)
    rows: List[Dict[str, Any]] = []

    started = time.time()
    for i, rec in enumerate(records, 1):
        orig_ai = (rec.get("ai_verdict") or {}).get("threat_level", "?")
        orig_an = (rec.get("analyst_verdict") or {}).get("threat_level", "?")
        raw     = rec.get("raw_input") or ""
        if not raw:
            continue
        print(f"[{i}/{len(records)}] orig: {orig_ai} -> analyst said {orig_an}",
              end="  ", flush=True)
        new_ai = await _run_pipeline(raw[:8000])
        if new_ai is None:
            print("(pipeline failed)")
            continue
        cls = _classify_movement(orig_ai, orig_an, new_ai)
        print(f"now: {new_ai}  [{_emoji(cls)} {cls}]")
        movements[cls] += 1
        pair_shifts[f"{orig_ai}->{new_ai}"][orig_an] += 1
        rows.append({
            "ts":                 rec.get("ts"),
            "orig_prompt_version": rec.get("prompt_version"),
            "input_hash":         rec.get("input_hash"),
            "orig_ai_verdict":    orig_ai,
            "analyst_verdict":    orig_an,
            "new_ai_verdict":     new_ai,
            "movement":           cls,
        })

    elapsed = time.time() - started

    # ── Report ──────────────────────────────────────────────────────────
    total       = sum(movements.values())
    agree_now   = movements["AGREED_THEN_AGREES"] + movements["AGREED_NOW"]
    agree_rate  = (agree_now / total) if total else 0.0

    if args.json:
        print(json.dumps({
            "prompt_version":      cur_prompt_version,
            "records_replayed":    total,
            "current_agreement":   round(agree_rate, 3),
            "movements":           dict(movements),
            "elapsed_seconds":     round(elapsed, 1),
            "rows":                rows,
        }, indent=2, default=str))
        return 0

    print()
    print("=" * 70)
    print(f"Replay complete in {elapsed:.1f}s.")
    print(f"Current prompt_version: {cur_prompt_version}")
    print(f"Records replayed:       {total}")
    print(f"Current agreement rate: {agree_rate:.1%}")
    print()
    print("Movement breakdown:")
    for cls in ("AGREED_THEN_AGREES", "AGREED_NOW",
                "DISAGREED_BOTH", "AGREED_BACK_OFF"):
        n = movements.get(cls, 0)
        pct = (n / total * 100.0) if total else 0.0
        print(f"  {_emoji(cls)} {cls:22s} {n:4d}  ({pct:5.1f}%)")
    improvements = movements.get("AGREED_NOW", 0)
    regressions  = movements.get("AGREED_BACK_OFF", 0)
    net = improvements - regressions
    print()
    print(f"Net improvement (AGREED_NOW - AGREED_BACK_OFF): {net:+d}")
    if regressions:
        print()
        print("Regressions (AI was right, now wrong) — these need attention:")
        for row in rows:
            if row["movement"] == "AGREED_BACK_OFF":
                print(f"  {row['input_hash'][:12]}...  "
                      f"{row['orig_ai_verdict']} -> {row['new_ai_verdict']} "
                      f"(analyst: {row['analyst_verdict']})")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
