"""
Multi-log detection + splitting.

When an analyst pastes two or more log entries into the analyze input, the
pipeline previously treated them as a single blob of text. That meant the
AI investigation never explicitly correlated the events — it would just
produce one verdict over the union of fields, missing the "these two
events tell a coherent story" angle.

This module recognises multi-log input and splits it into individual
entries so the investigation prompt can hand the AI the structured list
plus instructions to correlate them.

Detection signals (any two = multi-log):
  • multiple timestamps (ISO8601, syslog RFC3164, US/UK date forms)
  • multiple Windows/Sentinel event headers (e.g. "EventID:", "Event ID 4624")
  • multiple JSON objects on separate lines
  • multiple "Alert:" / "Detection:" / "TimeGenerated:" headers
  • blank-line-delimited blocks where each block contains a header keyword
"""

from __future__ import annotations

import re
from typing import Any, Dict, List


_TS_PATTERNS = [
    # ISO 8601 — 2025-09-26T14:13:22Z, 2025-09-26 14:13:22
    re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[Z+\-]\d{0,4})?\b"),
    # Syslog RFC 3164 — Sep 26 14:13:22
    re.compile(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b"),
    # US-style with time — 09/26/2025 14:13:22
    re.compile(r"\b\d{1,2}/\d{1,2}/\d{2,4}\s+\d{1,2}:\d{2}(?::\d{2})?\b"),
]

# Line-start variants — require the timestamp to sit at the START of a line
# (with optional whitespace). A real multi-log paste has one log per entry
# where the timestamp begins the line; timestamps inside JSON values like
# `"submission_time": "2025-..."` or in "Last modified: 2025-..." key/value
# fields are NOT log-entry boundaries. We use these stricter patterns for
# COUNTING entries and let the loose patterns above handle anchor extraction.
_LINE_START_TS_PATTERNS = [
    re.compile(r"(?m)^\s*\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[Z+\-]\d{0,4})?\b"),
    re.compile(r"(?m)^\s*(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b"),
    re.compile(r"(?m)^\s*\d{1,2}/\d{1,2}/\d{2,4}\s+\d{1,2}:\d{2}(?::\d{2})?\b"),
]

_HEADER_PATTERNS = [
    re.compile(r"\bEvent[\s_]?ID\s*[:=]?\s*\d+\b", re.IGNORECASE),
    re.compile(r"\bAlert\s*[:#]\s*", re.IGNORECASE),
    re.compile(r"\bDetection\s*[:#]\s*", re.IGNORECASE),
    re.compile(r"\bTimeGenerated\b", re.IGNORECASE),
    re.compile(r"\b__index\b"),
    re.compile(r"\bAlertName\b", re.IGNORECASE),
    re.compile(r"\bRecord\s*\d+\s+of\s+\d+\b", re.IGNORECASE),
]


def _count_matches(text: str, patterns: List[re.Pattern]) -> int:
    total = 0
    for p in patterns:
        total += len(p.findall(text))
    return total


def detect_log_count(text: str) -> int:
    """Best-effort count of distinct log entries in the input. Returns 1
    when only a single log is present (or the heuristic can't tell)."""
    if not text or len(text.strip()) < 60:
        return 1

    # Line-start timestamps are the only reliable "new log entry" signal.
    # A timestamp inside a JSON value or as a `Last modified:` field is
    # not a log-entry boundary, so loose `_TS_PATTERNS` over-counts.
    line_start_ts = _count_matches(text, _LINE_START_TS_PATTERNS)
    header_hits   = _count_matches(text, _HEADER_PATTERNS)

    # Count blank-line-delimited blocks that each contain at least one
    # header or line-start timestamp.
    blocks = [b for b in re.split(r"\n\s*\n+", text) if b.strip()]
    structured_blocks = 0
    for b in blocks:
        if (_count_matches(b, _HEADER_PATTERNS) > 0
                or _count_matches(b, _LINE_START_TS_PATTERNS) > 0):
            structured_blocks += 1

    # Multiple JSON objects on separate lines (each starting with `{`).
    json_lines = sum(1 for ln in text.splitlines()
                       if ln.lstrip().startswith("{") and ln.rstrip().endswith("}"))

    # Strongest signal first. structured_blocks is the cleanest when each
    # log entry is its own blank-line-separated block. Otherwise we need
    # BOTH multiple line-start timestamps AND multiple headers — neither
    # signal alone is reliable: timestamps repeat inside field values,
    # headers like `EventLog Source ID` partially match.
    if structured_blocks >= 2:
        return structured_blocks
    if json_lines >= 2:
        return json_lines
    if line_start_ts >= 2 and header_hits >= 2:
        return min(line_start_ts, header_hits)
    return 1


def split_logs(text: str) -> List[str]:
    """Split the input into best-effort individual log entries. When the
    heuristic is uncertain, returns the whole input as a single entry.

    Strategy:
      1. If blank-line-delimited blocks each contain a header / timestamp,
         use those.
      2. Else if multiple lines start with `{` and end with `}`, treat each
         such line as a JSON record.
      3. Else if multiple timestamps are present, split immediately before
         each subsequent timestamp.
      4. Else, return [text].
    """
    text = text or ""
    if not text.strip():
        return [text]

    # Strategy 1 — blank-line-delimited blocks.
    blocks = [b.strip() for b in re.split(r"\n\s*\n+", text) if b.strip()]
    if len(blocks) >= 2:
        # Each block must contain SOME identifying signal — otherwise
        # they're paragraphs of one log.
        scored = [b for b in blocks
                  if _count_matches(b, _HEADER_PATTERNS) > 0
                     or _count_matches(b, _TS_PATTERNS) > 0]
        if len(scored) >= 2:
            return scored

    # Strategy 2 — JSON-per-line.
    json_blocks = []
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("{") and s.endswith("}"):
            json_blocks.append(s)
    if len(json_blocks) >= 2:
        return json_blocks

    # Strategy 3 — split before each subsequent timestamp. Only use the
    # LINE-START timestamp patterns here: splitting before a timestamp
    # that's mid-line (e.g. inside a JSON value or `Last modified:` field)
    # produces nonsense segments. Additionally require at least one
    # header pattern in the text so we don't carve up a single log just
    # because it has multiple timestamp fields.
    if _count_matches(text, _HEADER_PATTERNS) >= 1:
        splits: List[str] = []
        ts_locations: List[int] = []
        for pat in _LINE_START_TS_PATTERNS:
            for m in pat.finditer(text):
                ts_locations.append(m.start())
        ts_locations = sorted(set(ts_locations))
        if len(ts_locations) >= 2:
            prev = 0
            for pos in ts_locations[1:]:
                seg = text[prev:pos].strip()
                if seg:
                    splits.append(seg)
                prev = pos
            tail = text[prev:].strip()
            if tail:
                splits.append(tail)
            if len(splits) >= 2:
                return splits

    return [text]


def _grep_first(pattern: str, text: str, group: int = 1) -> str:
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(group).strip() if m else ""


def extract_log_anchors(text: str) -> Dict[str, str]:
    """Pull a small set of identifying anchors out of a single log entry
    so the relationship-detection layer has something concrete to compare
    across entries: timestamp, host, user, process, source_ip, event_id."""
    anchors: Dict[str, str] = {}
    # Timestamp — take the first one we find.
    for pat in _TS_PATTERNS:
        m = pat.search(text)
        if m:
            anchors["timestamp"] = m.group(0)
            break
    anchors["event_id"]    = _grep_first(r"\bEvent[\s_]?ID\s*[:=]?\s*(\d+)\b", text)
    anchors["host"]        = _grep_first(r"\b(?:Computer|Host(?:name)?|DeviceName|Workstation)\s*[:=]\s*([^\s,;|\r\n]+)", text)
    anchors["user"]        = _grep_first(r"\bUser(?:Name|Principal(?:Name)?)?\s*[:=]\s*([^\s,;|\r\n]+)", text)
    anchors["process"]     = _grep_first(r"\bProcess[\s_]?Name\s*[:=]\s*([^\r\n,;|]+)", text)
    anchors["source_ip"]   = _grep_first(r"\bSource\s*(?:IP|Address)\s*[:=]\s*([^\s,;|\r\n]+)", text)
    anchors["dest_ip"]     = _grep_first(r"\b(?:Destination|Dest)\s*(?:IP|Address)\s*[:=]\s*([^\s,;|\r\n]+)", text)
    return {k: v for k, v in anchors.items() if v}


def analyze_multi_log(text: str) -> Dict[str, Any]:
    """Top-level entry point. Returns a dict the pipeline stores in
    state['multi_log']. When only one entry is detected, log_count == 1
    and segments holds a single-element list; callers can short-circuit
    on log_count <= 1.
    """
    segments = split_logs(text)
    count = max(detect_log_count(text), len(segments))
    if count <= 1:
        return {
            "log_count":  1,
            "is_multi":   False,
            "segments":   [text],
            "anchors":    [extract_log_anchors(text)],
        }

    anchors = [extract_log_anchors(s) for s in segments]
    return {
        "log_count":  len(segments),
        "is_multi":   True,
        "segments":   segments,
        "anchors":    anchors,
    }


def to_prompt_block(multi: Dict[str, Any]) -> str:
    """Render the multi-log analysis as a labelled prompt block. Empty
    string when the input is single-log."""
    if not multi or not multi.get("is_multi"):
        return ""
    lines = [
        f"## MULTI-LOG INPUT DETECTED — {multi['log_count']} distinct log entries",
        "",
        "These were submitted in the SAME analyst input field. Treat them as a "
        "UNIFIED INCIDENT — not as independent unrelated events. You MUST:",
        "  1. Identify the relationships between the logs (shared host, user,",
        "     process, time window, IOC). State each relationship explicitly.",
        "  2. Decide whether one log explains / provides context for the other.",
        "  3. Reconstruct the chronological sequence the events form.",
        "  4. State the combined picture — what the logs together reveal that",
        "     neither alone would.",
        "",
        "Populate the log_correlation field of your JSON output with this",
        "analysis (see the schema). If the logs genuinely cannot be correlated,",
        "set log_correlation.related = false and explain why in the rationale.",
        "",
        "## INDIVIDUAL LOG ENTRIES",
    ]
    for i, seg in enumerate(multi.get("segments", []), 1):
        a = (multi.get("anchors") or [{}])[i - 1] if i <= len(multi.get("anchors", [])) else {}
        lines.append("")
        lines.append(f"### Log #{i}")
        if a:
            anchor_bits = [f"{k}={v}" for k, v in a.items()]
            lines.append("  ANCHORS: " + " · ".join(anchor_bits))
        lines.append("  CONTENT:")
        for ln in seg.splitlines()[:60]:   # cap to avoid runaway token use
            lines.append("    " + ln)
        if len(seg.splitlines()) > 60:
            lines.append(f"    [+ {len(seg.splitlines()) - 60} more lines truncated]")
    return "\n".join(lines)
