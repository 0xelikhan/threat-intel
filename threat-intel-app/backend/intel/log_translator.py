"""
AI log translator — spec §4.

Runs before IOC extraction. The AI identifies the log format, extracts every
security-relevant field, and flags anomalies. Output feeds the rest of triage
so behavioral extraction and IOC extraction operate on structured data, not
just raw text.

Uses the same Azure-aware OpenAI client pattern as the rest of the codebase.
Fails open — returns {detected_format: 'unknown', extracted_fields: {}, ...}
if the call fails so the pipeline never blocks on translation.
"""

from __future__ import annotations
import json
from typing import Optional, Dict


SYSTEM_PROMPT = """You are a SOC analyst with expertise in every log format used in enterprise environments. The analyst has pasted raw log data. Your job is to identify the log source and format, extract every security-relevant field, and return a structured JSON object.

Identify the format from these possibilities:
  Windows Event Log XML or text
  Syslog RFC 3164 or 5424
  Zeek TSV logs of any type
  Suricata EVE JSON
  CEF (Common Event Format)
  LEEF (Log Event Extended Format)
  JSON from any SIEM or EDR
  CSV exports from any tool
  firewall logs (Palo Alto / Fortinet / Cisco / Check Point)
  proxy logs (Zscaler / Bluecoat / Squid)
  endpoint logs (CrowdStrike / SentinelOne / Carbon Black / Defender / any EDR)
  cloud logs (AWS CloudTrail / Azure Activity / GCP Audit)
  email headers
  DNS query logs
  authentication logs (Active Directory / Okta / Azure AD)
  free-text alert descriptions

Extract every field relevant to threat detection: source IP, destination IP,
source port, destination port, protocol, process name, process path, process ID,
parent process, command line, user account, domain, file path, file hash, URL,
DNS query, action taken, bytes transferred, duration, timestamp, hostname,
event ID or rule name, and any other security-relevant fields present.

Flag any field value that looks anomalous: base64-encoded data, unusually long
strings, system process names in non-system paths, known malicious patterns,
suspicious user agents, hex blobs, etc.

Return strict JSON with these top-level keys:
  detected_format       — short string e.g. "Sysmon EventID 1", "Zscaler proxy", "CEF/Suricata"
  confidence            — 0.0–1.0 confidence in the format detection
  extracted_fields      — flat dict of {field_name: value}, no nesting
  anomalies             — list of {field, value, reason} for flagged values
  normalized_summary    — see "PLAIN-ENGLISH SUMMARY RULES" below

PLAIN-ENGLISH SUMMARY RULES (the normalized_summary field):
This is the FIRST thing an analyst reads. Treat it like a senior MDR analyst
briefing a teammate or writing a one-paragraph ticket note — Microsoft-Copilot-
for-Security style. It must be 3–4 short sentences and follow this exact
structure:

  1. WHAT HAPPENED — describe the activity in plain English, naming the real
     actors (process, user, host, target) but converting technical fields into
     readable prose. Translate process names + command lines into intent
     ("ran reg.exe to export a registry key", not "Process Path: reg.exe").
  2. CONTEXT — say what this kind of activity is commonly used for so the
     analyst has a baseline ("This is typical of security-hardening or
     maintenance scripts that back up the registry before changes").
  3. VERDICT — state whether the action was permitted/blocked/anomalous and
     whether the surrounding signals look benign, suspicious, or malicious.
  4. RECOMMENDATION — close with one short sentence: either "No further
     action required unless this is unexpected" / "Verify with the asset
     owner before clearing" / "Escalate — see [specific signal]".

Do NOT just restate field values. Do NOT list bullet points. Do NOT say
"the log shows" or "this event indicates" — write it as an analyst note to
another analyst. Lead with the action, not with metadata.

GOOD example:
  "The host executed reg.exe under the SYSTEM account to export the
   acomservice service key into a backup file under
   C:\\ProgramData\\Security\\UnquotedPathFix. This pattern is typical of
   automated security-hardening or maintenance routines that snapshot the
   registry before applying configuration changes. The action was permitted
   and no malicious indicators surfaced. No further action is required
   unless this change is unexpected to your team."

BAD example (don't do this — just restates fields):
  "The log shows reg.exe ran with command line 'export ... acomservice ...'
   under user NT AUTHORITY\\SYSTEM. Process Path was c:\\windows\\system32
   \\reg.exe. The Effective Action was None."

No markdown fences. No commentary outside the JSON.
"""


async def translate_log(raw: str, config) -> Optional[Dict]:
    """Run the log translator. Returns None if no OPENAI_API_KEY is configured
    or the call fails — caller falls back to legacy raw-text behavior."""
    if not raw or len(raw.strip()) < 8:
        return None

    key = config.get("OPENAI_API_KEY")
    if not key:
        return None

    try:
        from openai import AsyncAzureOpenAI, AsyncOpenAI
    except ImportError:
        return None

    base_url = config.get("OPENAI_BASE_URL", "")
    # Log-format normalization is a light, latency-sensitive step that runs first
    # in triage and blocks IOC extraction → fast model tier.
    model    = config.get_model(fast=True)
    try:
        if "openai.azure.com" in base_url:
            client = AsyncAzureOpenAI(
                api_key=key,
                azure_endpoint=base_url.rstrip("/"),
                api_version="2024-02-01",
                timeout=30.0, max_retries=1,   # triage is latency-critical — fail fast
            )
        else:
            client = AsyncOpenAI(api_key=key, base_url=base_url or "https://api.openai.com/v1",
                                 timeout=30.0, max_retries=1)
        resp = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": f"## Raw log\n```\n{raw[:6000]}\n```"},
            ],
            response_format={"type": "json_object"},
            temperature=0.0,
            max_tokens=600,   # normalized fields only — keeps this critical-path call fast
        )
        # Lenient parse: a truncated translation keeps its completed fields
        # rather than discarding the whole step (which gates IOC extraction).
        from agents.investigation import _loads_lenient
        out = _loads_lenient(resp.choices[0].message.content)
        # Defensive shape — ensure callers can always access expected keys
        return {
            "detected_format":    out.get("detected_format", "unknown"),
            "confidence":         out.get("confidence", 0.5),
            "extracted_fields":   out.get("extracted_fields") or {},
            "anomalies":          out.get("anomalies") or [],
            "normalized_summary": out.get("normalized_summary", ""),
        }
    except Exception as e:
        return {
            "detected_format":    "unknown",
            "confidence":         0.0,
            "extracted_fields":   {},
            "anomalies":          [],
            "normalized_summary": "",
            "error":              str(e),
        }


def fields_as_text(translation: Optional[Dict]) -> str:
    """Turn extracted_fields into a `key=value` block — fed into IOC extraction
    and behavioral analysis so they see structured data alongside the raw input."""
    if not translation:
        return ""
    fields = translation.get("extracted_fields") or {}
    if not fields:
        return ""
    return "\n".join(f"{k}={v}" for k, v in fields.items() if v not in (None, "", []))
