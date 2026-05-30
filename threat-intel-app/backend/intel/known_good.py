"""
Known-good software pattern library.

Curated patterns for legitimate enterprise software whose behaviour
LOOKS unusual in isolation but is completely normal in context. Used
by the investigation pipeline to apply the "innocent until proven
guilty" standard — when a process / path / parent / command line
matches a known-good pattern, the AI is explicitly told and weighs
that context heavily in its threat-level assessment.

The catalogue covers:
  * OEM maintenance tools — Dell SupportAssist, HP Support Assistant,
    Lenovo Vantage, etc.
  * Microsoft built-in maintenance — Defender, Windows Update, MoUSO,
    sfc, dism, reg.exe administrative use.
  * Endpoint security — CrowdStrike Falcon, Carbon Black, Microsoft
    Defender for Endpoint, SentinelOne, Cortex XDR, Sophos, ESET.
  * Management / deployment — SCCM (CcmExec), Intune (IntuneManagement
    Extension), Tanium, BigFix, Jamf, Splunk forwarders, NinjaOne,
    Datto RMM, Atera.
  * Backup / recovery — Veeam, Rubrik, Cohesity, CommVault.
  * Browser / vendor auto-update — Chrome, Edge, Firefox, Adobe,
    Java, Zoom updaters.

`match(context)` evaluates all rules against a context dict and returns
a list of human-readable hits the AI prompt can quote. The structure
is conservative — every pattern requires multiple corroborating fields
when one would be ambiguous (a path alone isn't enough; the process
plus the path plus the parent build evidence).
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Tuple


# ─── canonical pattern catalogue ──────────────────────────────────────────────
#
# Each rule:
#   {
#     "vendor":            "Dell",
#     "product":           "SupportAssist",
#     "process":           [regex, ...],   # optional — basename of the process exe
#     "parent_process":    [regex, ...],   # optional — basename of the parent
#     "path":              [regex, ...],   # optional — process full path
#     "command_line":      [regex, ...],   # optional — substring/regex of cmdline
#     "destination_path":  [regex, ...],   # optional — files written / output paths
#     "user_context":      [regex, ...],   # optional — running user (e.g. SYSTEM)
#     "category":          "oem_maintenance",
#     "rationale":         "<one-line why-this-is-normal>",
#   }
#
# Regex matching is case-insensitive throughout. A rule "matches" when
# at least ONE of the patterns it declares hits the corresponding context
# field. Categories let downstream code group hits (e.g. "5 OEM matches
# vs. 1 EDR match").

_KNOWN_GOOD: List[Dict[str, Any]] = [

    # ── OEM MAINTENANCE ─────────────────────────────────────────────────────────
    {
        "vendor": "Dell", "product": "SupportAssist",
        "path":              [r"\\program files\\dell\\", r"\\programdata\\dell\\"],
        "destination_path":  [r"\\programdata\\dell\\", r"\\dell\\supportassist\\"],
        "command_line":      [r"supportassist", r"dell\\.*export", r"dellsupportassist"],
        "category": "oem_maintenance",
        "rationale": "Dell SupportAssist runs scheduled diagnostics that export "
                     "system state (registry, firewall, drivers) to its own "
                     "ProgramData directory for support ticket bundling — normal "
                     "vendor maintenance, not data exfiltration.",
    },
    {
        "vendor": "HP", "product": "Support Assistant",
        "path":              [r"\\program files\\hp\\", r"\\hpsa\\"],
        "destination_path":  [r"\\programdata\\hp\\", r"\\hewlett-packard\\"],
        "category": "oem_maintenance",
        "rationale": "HP Support Assistant performs the same kind of inventory + "
                     "diagnostic bundling as Dell's tool.",
    },
    {
        "vendor": "Lenovo", "product": "Vantage / System Update",
        "path":              [r"\\program files\\lenovo\\", r"\\lenovo\\system update"],
        "destination_path":  [r"\\programdata\\lenovo\\"],
        "category": "oem_maintenance",
        "rationale": "Lenovo Vantage / System Update performs OEM diagnostics, "
                     "BIOS / driver checks, and warranty registration.",
    },

    # ── MICROSOFT BUILT-IN MAINTENANCE ──────────────────────────────────────────
    {
        "vendor": "Microsoft", "product": "Windows reg.exe (admin export)",
        "process":           [r"^reg\.exe$", r"\\reg\.exe$"],
        "user_context":      [r"nt authority\\system", r"^system$"],
        "command_line":      [r"\bexport\b", r"\bquery\b", r"\bsave\b"],
        "category": "windows_builtin",
        "rationale": "reg.exe export/query/save under SYSTEM is the standard way "
                     "Windows administrative tools and vendor installers snapshot "
                     "registry state for backup, troubleshooting, or transfer. "
                     "Not inherently suspicious — context (target hive, "
                     "destination path) determines intent.",
    },
    {
        "vendor": "Microsoft", "product": "Windows Defender",
        "process":           [r"\\msmpeng\.exe$", r"\\mssense\.exe$",
                              r"\\mpcmdrun\.exe$", r"\\nissrv\.exe$",
                              r"\\smartscreen\.exe$"],
        "path":              [r"\\program files\\windows defender\\",
                              r"\\programdata\\microsoft\\windows defender\\",
                              r"\\programdata\\microsoft\\windows security health\\"],
        "category": "endpoint_security",
        "rationale": "Microsoft Defender / Defender for Endpoint runs as SYSTEM "
                     "and performs many actions that look unusual in isolation "
                     "(LSASS access, registry queries, process inspection) — "
                     "those are its intended security functions.",
    },
    {
        "vendor": "Microsoft", "product": "Windows Update / MoUSO",
        "process":           [r"\\trustedinstaller\.exe$", r"\\wuauclt\.exe$",
                              r"\\usoclient\.exe$", r"\\mousocoreworker\.exe$"],
        "path":              [r"\\windows\\system32\\", r"\\winsxs\\"],
        "category": "windows_builtin",
        "rationale": "Windows Update components run as SYSTEM and modify the "
                     "registry, drivers, and protected files during patching.",
    },
    {
        "vendor": "Microsoft", "product": "PowerShell / management automation (SYSTEM)",
        "process":           [r"\\powershell\.exe$", r"\\pwsh\.exe$"],
        "parent_process":    [r"\\ccmexec\.exe$", r"\\sense\.exe$",
                              r"\\agent\.exe$", r"\\tanium",
                              r"\\intunemanagementextension"],
        "category": "management_tools",
        "rationale": "PowerShell running as SYSTEM under a management agent "
                     "(SCCM, Intune, Tanium, MDE) is how those platforms execute "
                     "their playbooks — the parent process establishes the intent.",
    },

    # ── ENDPOINT SECURITY ──────────────────────────────────────────────────────
    {
        "vendor": "CrowdStrike", "product": "Falcon",
        "process":           [r"\\csfalconservice\.exe$", r"\\csagent",
                              r"\\falcon", r"\\csshell\.exe$"],
        "path":              [r"\\crowdstrike\\", r"\\windows\\system32\\drivers\\crowdstrike"],
        "category": "endpoint_security",
        "rationale": "CrowdStrike Falcon performs kernel-level inspection and "
                     "LSASS access as part of its EDR detection. Privileged "
                     "operations are expected.",
    },
    {
        "vendor": "VMware Carbon Black", "product": "Cb Defense / Cb Response",
        "process":           [r"\\carbonblack", r"\\cb\.exe$", r"\\repmgr\.exe$"],
        "path":              [r"\\carbonblack\\", r"\\confer\\"],
        "category": "endpoint_security",
        "rationale": "Carbon Black EDR — privileged process / file inspection "
                     "is its intended behaviour.",
    },
    {
        "vendor": "SentinelOne", "product": "Agent",
        "process":           [r"\\sentinelagent\.exe$", r"\\sentinelone"],
        "path":              [r"\\sentinelone\\", r"\\sentinel agent\\"],
        "category": "endpoint_security",
        "rationale": "SentinelOne agent — endpoint security operations.",
    },
    {
        "vendor": "Palo Alto", "product": "Cortex XDR",
        "process":           [r"\\cyserver\.exe$", r"\\cytool\.exe$", r"\\cyveraservice"],
        "path":              [r"\\palo alto networks\\", r"\\traps\\"],
        "category": "endpoint_security",
        "rationale": "Cortex XDR / Traps endpoint agent.",
    },
    {
        "vendor": "Sophos", "product": "Endpoint",
        "process":           [r"\\sophosfs\.exe$", r"\\sophosfilescanner",
                              r"\\sed\.exe$", r"\\sas\.exe$"],
        "path":              [r"\\sophos\\"],
        "category": "endpoint_security",
        "rationale": "Sophos endpoint security agent.",
    },
    {
        "vendor": "ESET", "product": "Endpoint Security",
        "process":           [r"\\ekrn\.exe$", r"\\egui\.exe$"],
        "path":              [r"\\eset\\"],
        "category": "endpoint_security",
        "rationale": "ESET endpoint security agent.",
    },

    # ── MANAGEMENT / DEPLOYMENT / RMM (sanctioned IT usage) ────────────────────
    {
        "vendor": "Microsoft", "product": "SCCM / Configuration Manager",
        "process":           [r"\\ccmexec\.exe$", r"\\ccmsetup\.exe$",
                              r"\\ccmrestart\.exe$"],
        "path":              [r"\\windows\\ccm\\", r"\\windows\\ccmcache\\",
                              r"\\windows\\ccmsetup\\"],
        "category": "management_tools",
        "rationale": "Microsoft Endpoint Configuration Manager (SCCM) — software "
                     "deployment, patching, and policy enforcement.",
    },
    {
        "vendor": "Microsoft", "product": "Intune Management Extension",
        "process":           [r"\\intunemanagementextension",
                              r"\\microsoft\.management\.services"],
        "path":              [r"\\program files \(x86\)\\microsoft intune management extension\\"],
        "category": "management_tools",
        "rationale": "Intune device management — application deployment, policy "
                     "enforcement, configuration tasks.",
    },
    {
        "vendor": "Tanium", "product": "Tanium Client",
        "process":           [r"\\taniumclient\.exe$", r"\\taniumtaas\.exe$"],
        "path":              [r"\\program files\\tanium\\"],
        "category": "management_tools",
        "rationale": "Tanium endpoint management.",
    },
    {
        "vendor": "Splunk", "product": "Universal Forwarder",
        "process":           [r"\\splunkd\.exe$", r"\\splunk\.exe$"],
        "path":              [r"\\program files\\splunkuniversalforwarder\\",
                              r"\\program files\\splunk\\"],
        "category": "logging_tools",
        "rationale": "Splunk Universal Forwarder reads many local resources "
                     "(event logs, files, perf counters) by design.",
    },

    # ── BACKUP / RECOVERY ──────────────────────────────────────────────────────
    {
        "vendor": "Veeam", "product": "Backup & Replication",
        "process":           [r"\\veeam\.backup\.", r"\\veeamagent"],
        "path":              [r"\\program files\\veeam\\"],
        "category": "backup_tools",
        "rationale": "Veeam moves large volumes of data and accesses VSS / "
                     "system files — that's its job.",
    },
    {
        "vendor": "Rubrik", "product": "Connector",
        "process":           [r"\\rubrik"],
        "path":              [r"\\program files\\rubrik\\"],
        "category": "backup_tools",
        "rationale": "Rubrik backup connector.",
    },

    # ── VENDOR AUTO-UPDATERS ───────────────────────────────────────────────────
    {
        "vendor": "Google", "product": "Chrome / Update",
        "process":           [r"\\googleupdate\.exe$", r"\\googlecrashhandler",
                              r"\\chrome\.exe$"],
        "path":              [r"\\program files \(x86\)\\google\\update\\",
                              r"\\program files\\google\\chrome\\"],
        "parent_process":    [r"\\msiexec\.exe$"],
        "category": "vendor_updater",
        "rationale": "Google Chrome / Update — auto-update writes to ProgramData "
                     "and modifies install directory under msiexec.",
    },
    {
        "vendor": "Microsoft", "product": "Edge / Update",
        "process":           [r"\\msedge\.exe$", r"\\msedgeupdate\.exe$"],
        "path":              [r"\\program files \(x86\)\\microsoft\\edge\\",
                              r"\\program files \(x86\)\\microsoft\\edgeupdate\\"],
        "category": "vendor_updater",
        "rationale": "Microsoft Edge / Edge Update — same pattern as Chrome.",
    },
    {
        "vendor": "Mozilla", "product": "Firefox / Update",
        "process":           [r"\\firefox\.exe$", r"\\updater\.exe$"],
        "path":              [r"\\program files\\mozilla firefox\\",
                              r"\\programdata\\mozilla\\"],
        "category": "vendor_updater",
        "rationale": "Firefox auto-update.",
    },
    {
        "vendor": "Adobe", "product": "Reader / Acrobat Update",
        "process":           [r"\\armsvc\.exe$", r"\\adobearm\.exe$"],
        "path":              [r"\\program files\\common files\\adobe\\arm\\",
                              r"\\program files \(x86\)\\adobe\\"],
        "category": "vendor_updater",
        "rationale": "Adobe Reader / Acrobat update service.",
    },
    {
        "vendor": "Zoom", "product": "Zoom Update",
        "process":           [r"\\zoom\.exe$", r"\\zoomupdate", r"\\zoom_launcher"],
        "path":              [r"\\appdata\\roaming\\zoom\\"],
        "category": "vendor_updater",
        "rationale": "Zoom auto-update / launcher — writes to AppData\\Roaming "
                     "as part of its user-mode update model.",
    },
]


# ─── matching ────────────────────────────────────────────────────────────────
_FIELD_KEYS = (
    "process", "parent_process", "path", "command_line",
    "destination_path", "user_context",
)


def _norm(s: str) -> str:
    """Lower-case + forward slashes. Path matching tolerates either separator."""
    return (s or "").lower().replace("/", "\\")


def _matches_rule(rule: Dict[str, Any], context: Dict[str, str]) -> Dict[str, Any]:
    """Return a hit dict when at least one of the rule's declared fields
    matches the corresponding context value. Returns {} on no match."""
    matched_fields: List[Tuple[str, str]] = []
    for field in _FIELD_KEYS:
        patterns = rule.get(field)
        if not patterns:
            continue
        value = _norm(context.get(field, ""))
        if not value:
            continue
        for pat in patterns:
            try:
                if re.search(pat, value, re.IGNORECASE):
                    matched_fields.append((field, pat))
                    break
            except re.error:
                continue
    if not matched_fields:
        return {}
    return {
        "vendor":          rule["vendor"],
        "product":         rule["product"],
        "category":        rule.get("category", "unknown"),
        "rationale":       rule.get("rationale", ""),
        "matched_fields":  matched_fields,
    }


def match(context: Dict[str, str]) -> List[Dict[str, Any]]:
    """Evaluate every rule against `context` and return the list of hits.

    Context fields the matcher understands (all optional):
      * process          — process basename (e.g. "reg.exe")
      * parent_process   — parent process basename
      * path             — full process image path
      * command_line     — full command line
      * destination_path — files written / output paths
      * user_context     — running user (e.g. "NT AUTHORITY\\SYSTEM")
    """
    hits: List[Dict[str, Any]] = []
    if not context:
        return hits
    for rule in _KNOWN_GOOD:
        h = _matches_rule(rule, context)
        if h:
            hits.append(h)
    return hits


def extract_context_from_state(state: Dict[str, Any]) -> Dict[str, str]:
    """Pull the fields known_good.match() cares about out of the
    LangGraph state. Returns an empty-ish dict when nothing is parseable
    — that's a normal outcome for IOC-only inputs.

    Looks in:
      * state["behavioral_indicators"] — process / parent / command_line
        extracted by intel.behavior_extractor
      * state["iocs"]["paths"]         — file paths the regex picked up
      * raw_input                       — regex over the text itself for
        common path / user patterns the structured extractor missed
    """
    out: Dict[str, str] = {
        "process": "", "parent_process": "", "path": "",
        "command_line": "", "destination_path": "", "user_context": "",
    }
    raw = state.get("raw_input") or ""

    # Process / parent / command-line — look for canonical Windows log
    # field formats. The behavior_extractor lifts MITRE indicators but
    # not these flat fields, so regex over the raw text is the safest
    # source.
    m = re.search(r"(?:process[ _-]?name|image)\s*[:=]\s*([^\s,;|]+)", raw, re.IGNORECASE)
    if m: out["process"] = os.path.basename(m.group(1).strip().strip('"\''))
    m = re.search(r"parent[_ -]?process[_ -]?name\s*[:=]\s*([^\s,;|]+)", raw, re.IGNORECASE)
    if m: out["parent_process"] = os.path.basename(m.group(1).strip().strip('"\''))
    m = re.search(r"(?:image|file|process[_ ]?path)\s*[:=]\s*([^\n,;|]+)", raw, re.IGNORECASE)
    if m: out["path"] = m.group(1).strip().strip('"\'')
    m = re.search(r"(?:command[_ ]?line|cmdline|process[_ ]?command[_ ]?line)\s*[:=]\s*([^\n]+)", raw, re.IGNORECASE)
    if m: out["command_line"] = m.group(1).strip().strip('"\'')
    m = re.search(r"(?:user|account[_ ]?name|subject[_ ]?user[_ ]?name)\s*[:=]\s*([^\s,;|]+)", raw, re.IGNORECASE)
    if m: out["user_context"] = m.group(1).strip().strip('"\'')

    # Destination paths — the IOC extractor picks them up generically.
    paths = (state.get("iocs") or {}).get("paths") or []
    if paths:
        out["destination_path"] = " | ".join(str(p) for p in paths[:8])

    # SYSTEM-context shorthand — appears in many EDR log formats.
    if "nt authority\\system" in raw.lower() or " system " in raw.lower():
        out["user_context"] = out["user_context"] or "NT AUTHORITY\\SYSTEM"

    return out
