#!/usr/bin/env python
"""
Prompt-hygiene auto-detect — which FORBIDDEN rules in the LLM prompts
are still actually preventing bugs vs. which have become dead text?

How it works
============
Every prose-cleanup rule we've added to the prompts (anti-em-dash,
anti-duplication, anti-encoding-hallucination, etc.) is ALSO enforced
mechanically by code:

  intel/email_composer.py::_strip_em_dashes  ->  prompt: no em-dashes
  intel/prose_validator.py::cap_sentences    ->  prompt: MAX 2 sentences
  intel/prose_validator.py::drop_overlapping ->  prompt: no cross-field
                                                  paraphrase
  intel/prose_validator.py::strip_forbidden_keys -> prompt: no
                                                     log_correlation
  agents/triage.py::strip_defender_version_strings -> prompt: don't
                                                       claim IPs in
                                                       version strings

When the mechanical enforcer NEVER fires across N analyses, it means
either:
  (a) the model has internalised the rule and the prompt prose is dead
      weight (drop the rule to save tokens), or
  (b) the rule covers a class of bug the model rarely hits anyway
      (drop the rule unless the bug class is high-stakes).

When the enforcer fires frequently, the prompt rule IS needed -
keep it AND consider tightening.

This script runs the validator over every reconstructable AI output
in the calibration log and reports the per-rule trigger rate. Rules
with 0%% fire rate are candidates for prompt removal.

Limitation: we only have the FULL AI output for records the analyst
overrode (raw_input, ai_verdict.summary). We don't have the full
investigation_result dict in the override log, so we can only check
the subset of rules that operate on the summary string. That's still
the most token-heavy rule cluster.

Usage:
  python scripts/prompt_hygiene.py
  python scripts/prompt_hygiene.py --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

_HERE    = Path(__file__).resolve()
_BACKEND = _HERE.parent.parent / "backend"
sys.path.insert(0, str(_BACKEND))


# Each rule: (id, description, predicate(text) -> bool indicating fire).
# `text` is the AI's summary as stored in the override record.
def _rules():
    from intel.prose_validator import cap_sentences

    def _has_em_dash(s):       return "—" in (s or "") or "–" in (s or "")
    def _exceeds_2_sent(s):    return s != cap_sentences(s, 2) if s else False
    def _hallucinates_encode(s):
        if not s:
            return False
        low = s.lower()
        # AI-fabricated decode claim with no encoded content actually present
        triggers = ("base64-encoded", "encodes to", "decodes to",
                    "encoded payload")
        ascii_run = re.search(r"[A-Za-z0-9+/]{16,}={0,2}", s)
        return any(t in low for t in triggers) and not ascii_run
    def _restates_log_field(s):
        if not s:
            return False
        # Crude heuristic: sentence opens with "On <date>, at <time>" or
        # "User X did Y" - the analyst sees these in the raw log, so the
        # AI restating them is the canonical wasted-summary failure.
        return bool(re.match(r"\s*(On\s+\w+\s+\d+|At\s+\d{2}:\d{2}|"
                              r"The\s+user\s+\S+\s+(deleted|created|"
                              r"modified|accessed)|"
                              r"User\s+\S+\\\S+\s+\w+ed)",
                              s, re.IGNORECASE))

    return [
        ("no_em_dash",
         "Prompt rule: 'NEVER use em-dashes (—)' (~50 tokens)",
         _has_em_dash),
        ("max_2_sentence_summary",
         "Prompt rule: 'summary MAX 2 sentences' (~70 tokens)",
         _exceeds_2_sent),
        ("no_decode_hallucination",
         "Prompt rule: 'do NOT invent decode results' (~120 tokens)",
         _hallucinates_encode),
        ("no_log_restating",
         "Prompt rule: 'NEVER restate the raw alert content' (~80 tokens)",
         _restates_log_field),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Identify prompt rules whose mechanical enforcer never fires.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON instead of the human-readable report.")
    parser.add_argument("--threshold", type=float, default=0.02,
                        help="Fire-rate below which a rule is flagged as a "
                             "removal candidate. Default 0.02 (2%%).")
    args = parser.parse_args()

    from intel.calibration_log import iter_records
    records = iter_records()
    if not records:
        print("No override records in backend/data/calibration_overrides.jsonl.")
        print("Record some analyst overrides first via the UI or "
              "scripts/record_override.py.")
        return 0

    fired:  Counter = Counter()
    rules = _rules()

    n = 0
    for rec in records:
        summary = (rec.get("ai_verdict") or {}).get("summary") or ""
        if not summary:
            continue
        n += 1
        for rule_id, _, predicate in rules:
            try:
                if predicate(summary):
                    fired[rule_id] += 1
            except Exception:
                continue

    if args.json:
        out = []
        for rule_id, desc, _ in rules:
            count = fired.get(rule_id, 0)
            rate  = (count / n) if n else 0.0
            out.append({
                "rule":         rule_id,
                "description":  desc,
                "fire_count":   count,
                "sample_size":  n,
                "fire_rate":    round(rate, 4),
                "candidate_for_removal": rate < args.threshold,
            })
        print(json.dumps({
            "records_analyzed": n,
            "threshold":        args.threshold,
            "rules":            out,
        }, indent=2))
        return 0

    # Human-readable
    print(f"Prompt hygiene report — {n} AI-summary samples analysed")
    print(f"(removal candidate: fire rate < {args.threshold:.1%})")
    print()
    print(f"{'RULE':30s}  {'FIRES':>7s}  {'RATE':>7s}  {'STATUS':12s}  DESCRIPTION")
    print("-" * 110)
    for rule_id, desc, _ in rules:
        count = fired.get(rule_id, 0)
        rate  = (count / n) if n else 0.0
        if rate < args.threshold:
            status = "REMOVE?"
        elif rate < 0.10:
            status = "low usage"
        elif rate < 0.40:
            status = "active"
        else:
            status = "HIGH — keep"
        print(f"{rule_id:30s}  {count:7d}  {rate:6.1%}  {status:12s}  {desc}")

    candidates = [r[0] for r in rules
                  if (fired.get(r[0], 0) / n if n else 0) < args.threshold]
    if candidates:
        print()
        print(f"Removal candidates ({len(candidates)}): "
              f"{', '.join(candidates)}")
        print()
        print("Next step: open the prompt strings in agents/investigation.py,")
        print("drop the prose for the rules above, re-run the eval harness")
        print("(scripts/eval_prompts.py) to confirm agreement rate doesn't")
        print("regress, then ship.")
    else:
        print()
        print("Every rule is firing above the threshold - keep them all.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
