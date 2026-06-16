"""
Microsoft Defender EventLog parser (Event IDs 1116 / 1117).

Defender's detection events have a specific field layout that earlier
pipeline stages routinely misread — most notably the AI investigation
treating the "Process Name" field (almost always C:\\WINDOWS\\explorer.exe
or another legitimate triggering process) as the malware itself.

The real malware location is the Path field — e.g.
"file:_C:\\Users\\<u>\\AppData\\Local\\Programs\\PDF_Spark\\PDFSpark.exe".

This module parses the raw text into a structured dict with explicit
keys so downstream prompts can present them to the AI with unambiguous
labels (malware_name, infected_path, process_name, …) and the AI cannot
mistake the system process for the threat.

Recognised channels / providers:
  • "Microsoft-Windows-Windows Defender"
  • "Microsoft-Windows-Windows Defender/Operational"
  • EventID 1116 (threat detected)
  • EventID 1117 (action taken)
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional


_DEFENDER_HINTS = (
    "microsoft-windows-windows defender",
    "windows defender/operational",
    "eventid 1116",
    "eventid 1117",
    "event id 1116",
    "event id 1117",
    "windows defender alert",
    "antimalwareplatform",
    "name: trojan",
    "name: backdoor",
    "name: ransom",
    "security intelligence version",
)


def looks_like_defender_log(text: str) -> bool:
    """Cheap detector — sufficient hints OR Event ID anchor in the
    first kilobyte of the input. Two independent hints required so a
    one-line "Windows Defender" mention doesn't trigger the parser."""
    if not text:
        return False
    head = text[:2000].lower()
    hits = sum(1 for h in _DEFENDER_HINTS if h in head)
    # Event ID 1116 / 1117 are unambiguous on their own.
    if "1116" in head and "defender" in head:
        return True
    if "1117" in head and "defender" in head:
        return True
    return hits >= 2


# Field regexes — case-insensitive, line-anchored single-line value capture.
# Each pattern is anchored to the START of a line (after optional indentation)
# so multi-word keys like "Origin Name" / "Type Name" / "Severity Name" don't
# steal the bare "Name:" / "ID:" matches. Defender exports the records as
# one field per line; this matches both Event Viewer's text rendering and the
# PowerShell Get-WinEvent format.
def _f(value_pat: str = r"[^\r\n]+") -> str:
    return r"\s*[:=]\s*(" + value_pat + r")"


# Field-start anchor: beginning of input or beginning of a line, with optional
# leading whitespace. Prevents "Origin Name:" from matching the "Name:" regex.
_FS = r"(?:^|\n)[ \t]*"


_PATTERNS = {
    # The threat itself. "Name" must be the first word on its line.
    "malware_name":       re.compile(_FS + r"Name" + _f(), re.IGNORECASE),
    "threat_id":          re.compile(_FS + r"ID" + _f(r"\d+"), re.IGNORECASE),
    "severity":           re.compile(_FS + r"Severity(?:\s+Name|\s+Level)?" + _f(), re.IGNORECASE),
    "category":           re.compile(_FS + r"Category(?:\s+Name)?" + _f(), re.IGNORECASE),
    # Infected artifact — the actual malicious file location.
    "infected_path":      re.compile(_FS + r"Path" + _f(), re.IGNORECASE),
    # Where the detection fired (real-time, scheduled scan, manual scan).
    "detection_origin":   re.compile(_FS + r"(?:Detection\s+)?Origin(?:\s+Name)?" + _f(), re.IGNORECASE),
    "detection_type":     re.compile(_FS + r"(?:Detection\s+)?Type(?:\s+Name)?" + _f(), re.IGNORECASE),
    "detection_source":   re.compile(_FS + r"Detection\s+Source(?:\s+Name)?" + _f(), re.IGNORECASE),
    # Who was affected.
    "affected_user":      re.compile(_FS + r"User" + _f(r"[^\r\n,;]+"), re.IGNORECASE),
    # The legitimate process that triggered the scan — NOT the threat.
    "process_name":       re.compile(_FS + r"Process\s+Name" + _f(), re.IGNORECASE),
    # Defender platform context.
    "security_intelligence_version": re.compile(
        _FS + r"Security\s+Intelligence\s+Version" + _f(),
        re.IGNORECASE,
    ),
    "engine_version":     re.compile(_FS + r"Engine\s+Version" + _f(), re.IGNORECASE),
    "antimalware_platform_version": re.compile(
        _FS + r"Antimalware\s+(?:Client\s+)?Version" + _f(),
        re.IGNORECASE,
    ),
    "action_name":        re.compile(_FS + r"Action\s+Name" + _f(), re.IGNORECASE),
    "action_id":          re.compile(_FS + r"Action\s+ID" + _f(r"\d+"), re.IGNORECASE),
    "execution_name":     re.compile(_FS + r"Execution\s+Name" + _f(), re.IGNORECASE),
    "event_id":           re.compile(r"\bEvent\s*ID" + _f(r"\d+"), re.IGNORECASE),
}


# ─── Inline-Message field extraction ──────────────────────────────────────
# Some Defender exports (notably the Windows Event-Forwarding pipeline used
# by Sentinel / M365D) pack the entire field set onto one "Message:" line
# instead of breaking it one-field-per-line as Event Viewer's text render
# does. The line-anchored _PATTERNS above only see the multi-line form;
# this secondary pass handles the inline form by bounding each value with
# a lookahead to the next known field name or end of body.
#
# Inline values OVERRIDE line-anchored ones when both fire, because the
# Message body is the actual event payload. The top-level "User : SYSTEM"
# line is the audit subject (the local account that wrote the event), not
# the affected user — those are different people. The Message-body "User"
# is the analyst-relevant one.
_INLINE_FIELD_NAMES = (
    "Name", "ID", "Severity", "Category", "Path",
    "Detection Origin", "Detection Type", "Detection Source",
    "User", "Process Name",
    "Security intelligence Version", "Engine Version",
    "Antimalware Client Version", "Action Name", "Action ID",
    "Execution Name",
)


def _boundary() -> str:
    # Lookahead: next inline field key OR end of body. Each multi-word key
    # is re-anchored as \s+ to tolerate any whitespace run in the input.
    keys = "|".join(
        re.escape(n).replace(r"\ ", r"\s+") for n in _INLINE_FIELD_NAMES
    )
    return r"(?=\s+(?:" + keys + r")\s*:|\s*$)"


_INLINE_BOUNDARY = _boundary()
_INLINE_PATTERNS = {
    "malware_name":      r"\bName\s*:\s*(.+?)" + _INLINE_BOUNDARY,
    "threat_id":         r"\bID\s*:\s*(\d+)\b",
    "severity":          r"\bSeverity\s*:\s*(\S+)",
    "category":          r"\bCategory\s*:\s*(\S+)",
    "infected_path":     r"\bPath\s*:\s*(.+?)" + _INLINE_BOUNDARY,
    "detection_origin":  r"\bDetection\s+Origin\s*:\s*(.+?)" + _INLINE_BOUNDARY,
    "detection_type":    r"\bDetection\s+Type\s*:\s*(.+?)" + _INLINE_BOUNDARY,
    "detection_source":  r"\bDetection\s+Source\s*:\s*(.+?)" + _INLINE_BOUNDARY,
    "affected_user":     r"\bUser\s*:\s*(\S+?)" + _INLINE_BOUNDARY,
    "process_name":      r"\bProcess\s+Name\s*:\s*(.+?)" + _INLINE_BOUNDARY,
    "security_intelligence_version":
        r"\bSecurity\s+intelligence\s+Version\s*:\s*(.+?)" + _INLINE_BOUNDARY,
    "engine_version":    r"\bEngine\s+Version\s*:\s*(.+?)" + _INLINE_BOUNDARY,
}
_INLINE_COMPILED = {k: re.compile(p, re.IGNORECASE)
                    for k, p in _INLINE_PATTERNS.items()}

# Message body lives between "Message:" and the next top-level field key
# (Log Name / Level / Date / Action Type / Channel / Provider / Task / …)
# or end of input. DOTALL so the body can span wrapped physical lines.
_MESSAGE_BODY_RE = re.compile(
    r"(?:^|\n)[ \t]*Message\s*[:=]\s*(.+?)"
    r"(?=\n[ \t]*(?:Log\s+Name|Level|Date|Action\s+Type|Channel|"
    r"Provider|Task|Keywords|OpCode|Computer)\s*[:=]|\Z)",
    re.IGNORECASE | re.DOTALL,
)


# A few user-visible fields are routinely wrapped in quotes or trailing
# punctuation in real-world exports. Strip those before storing.
_TRIM_CHARS = " \t\"'.,;)|"


def _clean(raw: str) -> str:
    if raw is None:
        return ""
    return raw.strip().strip(_TRIM_CHARS).strip()


def parse_defender_event(text: str) -> Optional[Dict[str, Any]]:
    """Return a structured dict when the input matches a Defender Event
    1116/1117 layout, otherwise None. The dict has every key in _PATTERNS
    (empty string when not matched) plus a `summary_line` sentence the
    response/email layers can quote verbatim.

    Keys:
      malware_name, threat_id, severity, category,
      infected_path, detection_origin, detection_type, detection_source,
      affected_user, process_name,
      security_intelligence_version, engine_version,
      antimalware_platform_version, action_name, action_id, execution_name,
      event_id, summary_line, is_defender (bool).
    """
    if not looks_like_defender_log(text):
        return None

    out: Dict[str, Any] = {k: "" for k in _PATTERNS}
    for key, pat in _PATTERNS.items():
        m = pat.search(text)
        if m:
            out[key] = _clean(m.group(1))

    # Secondary pass — when the export packs the field set inline on a
    # "Message :" line, the line-anchored patterns above match nothing
    # (or worse, match the audit-pipeline top-level "User : SYSTEM"). Run
    # the inline patterns against the extracted Message body and override.
    msg_match = _MESSAGE_BODY_RE.search(text)
    msg_body = msg_match.group(1) if msg_match else ""
    if msg_body:
        for key, pat in _INLINE_COMPILED.items():
            m = pat.search(msg_body)
            if m:
                val = _clean(m.group(1))
                if val:
                    out[key] = val

    # Heuristic: when a "Path" hit ALSO carries a "file:" / "file:_" prefix
    # Defender attaches, strip it so the path looks like a normal Windows
    # filesystem path for downstream consumers (UI, email composer).
    if out.get("infected_path"):
        out["infected_path"] = re.sub(
            r"^file:[_]*", "", out["infected_path"]
        ).strip()

    # Detection-origin / detection-source / detection-type sometimes use the
    # raw event-data name like "Real-Time" — leave verbatim.

    # If Process Name was captured but is exactly equal to the infected path
    # (some custom Defender exports do this), null it so downstream code
    # doesn't double-count the malicious file as a process.
    if (out.get("process_name") and out.get("infected_path")
            and out["process_name"].lower() == out["infected_path"].lower()):
        out["process_name"] = ""

    out["is_defender"] = True
    out["summary_line"] = _build_summary_line(out)
    return out


def _build_summary_line(parsed: Dict[str, Any]) -> str:
    """One-sentence plain-English summary the response layer and AI prompt
    can quote without re-deriving the relationship between fields."""
    name = parsed.get("malware_name") or "an unspecified threat"
    path = parsed.get("infected_path") or "an unspecified path"
    # Filename only (drop directory) for the summary — fits inline.
    fname = path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] or path
    user = parsed.get("affected_user")
    bare_user = ""
    if user:
        bare_user = user.split("\\")[-1].split("@")[0]

    base = f"Microsoft Defender detected {name} in {fname}"
    if bare_user:
        base += f" belonging to user {bare_user}"
    action = parsed.get("action_name")
    if action and action.lower() not in ("", "none", "no action"):
        base += f" (Defender action: {action})"
    return base + "."


def to_prompt_block(parsed: Dict[str, Any]) -> str:
    """Format the parsed Defender record as a labelled prompt block. Each
    field is on its own line with an explicit role-explainer so the AI
    cannot confuse the legitimate triggering process with the malware."""
    if not parsed:
        return ""
    lines = [
        "## DEFENDER EVENT PARSE (authoritative field interpretation)",
        "",
        "READ CAREFULLY — these labels are NOT interchangeable:",
        "  * malware_name        — the malware family / signature Defender named. PRIMARY threat identifier.",
        "  * infected_path       — the malicious file's location. This IS the infected artifact.",
        "  * process_name        — the LEGITIMATE process that triggered the scan (e.g. explorer.exe).",
        "                          DO NOT call this the malware. It is the system process that opened, read,",
        "                          or executed the infected file. Naming it as the threat is incorrect.",
        "  * affected_user       — the user whose session encountered the threat (the victim).",
        "",
    ]
    field_order = [
        "malware_name", "threat_id", "severity", "category",
        "infected_path", "detection_origin", "detection_type", "detection_source",
        "affected_user", "process_name",
        "action_name", "action_id", "execution_name",
        "security_intelligence_version", "engine_version",
        "antimalware_platform_version", "event_id",
    ]
    for key in field_order:
        val = parsed.get(key, "")
        if val:
            lines.append(f"  {key:32s} = {val}")
    summary = parsed.get("summary_line")
    if summary:
        lines.append("")
        lines.append(f"  AUTHORITATIVE SUMMARY: {summary}")
    return "\n".join(lines)
