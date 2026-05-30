"""
Email composer — RECON port of TL.MDR.email (C# WPF).

ThreatLocker branding has been stripped throughout: template text replaces
`ThreatLocker MDR Team` / `ThreatLocker MDR` / `Threatlocker` references with
the configurable placeholders `{{TeamName}}` / `{{FromAddress}}` and removes
vendor-specific URLs and product-policy IDs (e.g. `TL.CD.090`). The signature
block is fully configurable from RECON settings (`EMAIL_FROM_NAME`,
`EMAIL_FROM_ADDRESS`, `EMAIL_SIGNATURE`).

Public API:
  parse_log(text)                              -> dict (ParsedAlertLog)
  list_alert_types()                           -> list[(id, label)]
  load_template(alert_id) / list_templates()
  compose(alert_id, parsed, options, signature)-> {"text": ..., "html": ...,
                                                    "subject": ...}
  send_smtp(subject, body_html, body_text,
            to, cc, config)                    -> {"sent": True} or {error}

Each public function has zero loss of functionality from the original WPF tool.
"""

from __future__ import annotations
import json
import re
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape as html_escape
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ─── alert type catalog (ported from Models/AlertType.cs, branding-scrubbed) ───
# (id_value, display_label, category) — id used as URL/JSON key, label as UI text.
# Two ThreatLocker-specific enum values renamed:
#   NetStopThreatLocker          → disable_security_agent
#   TlUninstallScriptExecution   → uninstall_script_execution
ALERT_TYPES: List[Tuple[str, str, str]] = [
    ("user_at_risk",                "User at Risk",                          "cloud"),
    ("impossible_travel",           "Impossible Travel",                     "cloud"),
    ("anonymized_ip",               "Anonymized IP",                         "cloud"),
    ("password_spray",              "Password Spray",                        "cloud"),
    ("unfamiliar_signin",           "Unfamiliar Sign-In Properties",         "cloud"),
    ("login_to_disabled_account",   "Login to Disabled Account",             "cloud"),
    ("temporary_access_pass",       "Temporary Access Pass",                 "cloud"),
    ("creation_of_admin_account",   "Creation of Admin Account",             "cloud"),
    ("privileged_role",             "Privileged Role Assignment",            "cloud"),
    ("forwarding_rule",             "Email Forwarding Rule",                 "cloud"),
    ("defender_detection",          "Microsoft Defender Detection",          "endpoint"),
    ("defender_exclusion_created",  "Defender Exclusion Created",            "endpoint"),
    ("sentinel_one_detection",      "SentinelOne Detection",                 "endpoint"),
    ("powershell_policy_bypass",    "PowerShell Policy Bypass",              "endpoint"),
    ("bitlocker_disable",           "BitLocker Disabled",                    "endpoint"),
    ("reg_export",                  "Registry Export",                       "endpoint"),
    ("enumeration",                 "System / Network Enumeration",          "endpoint"),
    ("ransomware",                  "Ransomware Behavior",                   "endpoint"),
    ("disable_security_agent",      "Security Agent Disable Attempt",        "endpoint"),
    ("uninstall_script_execution",  "Uninstall Script Execution",            "endpoint"),
    ("disable_protection",          "Microsoft Defender Disabled",           "endpoint"),
    ("user_added_to_local_admin",   "User Added to Local Admin Group",       "endpoint"),
    ("public_rdp_connection",       "Public RDP Connection",                 "endpoint"),
    ("cleared_security_logs",       "Cleared Security/Critical Event Logs",  "endpoint"),
    ("vulnerable_driver",           "Vulnerable Driver Detected",            "endpoint"),
]

ALERT_LABEL_BY_ID = {a[0]: a[1] for a in ALERT_TYPES}

# Response actions (ported from Models/ResponseAction.cs)
RESPONSE_ACTIONS = [
    ("clearing_alert",                  "Clearing Alert"),
    ("escalating",                      "Escalating"),
    ("isolating",                       "Isolating"),
    ("lockdown",                        "Lockdown"),
    ("lock_account",                    "Lock Account"),
    ("lock_account_and_revoke_session", "Lock Account and Revoke Session"),
]


# ─── log parser (ported from Services/LogParserService.cs) ────────────────────
def parse_log(log_text: str) -> Dict:
    """Parse a pasted security log into a flat dict of every field the
    composer might reference. Mirrors the C# LogParserService.Parse() —
    every field, every alias cascade, every regex fallback."""
    if not log_text or not log_text.strip():
        return {"_error": "Log text is empty.", "raw_fields": {}}

    lines = log_text.split("\n")
    raw_fields: Dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line or ":" not in line:
            continue
        sep = line.find(":")
        key = line[:sep].strip()
        val = line[sep + 1:].strip()
        if key and key not in raw_fields:
            raw_fields[key] = val

    def get(*keys) -> str:
        for wanted in keys:
            for k, v in raw_fields.items():
                if k.lower() == wanted.lower() and v:
                    return v
        return ""

    out: Dict[str, str] = {
        "id":                  get("id"),
        "request_id":          get("requestId"),
        "correlation_id":      get("correlationId"),
        "risk_event_type":     get("riskEventType", "RiskType", "Operation"),
        "risk_state":          get("riskState", "Resultstatus"),
        "risk_level":          get("riskLevel"),
        "risk_detail":         get("riskDetail", "EventDescription", "LogonError"),
        "source":              get("source", "Workload", "EventLog Description"),
        "detection_timing":    get("detectionTimingType"),
        "activity":            get("activity", "Operation", "Action Type"),
        "token_issuer":        get("tokenIssuerType"),
        "activity_dt_raw":     get("activityDateTime", "Date", "date", "IssuedAtTime"),
        "detected_dt_raw":     get("detectedDateTime", "CreationTime", "Date", "date"),
        "last_updated_raw":    get("lastUpdatedDateTime"),
        "user_id":             get("userId", "userid", "UserKey"),
        "forwarding_address":  _extract_parameter_value(lines, "ForwardingSmtpAddress"),
        "user_principal_name": get("userPrincipalName", "user principal name", "upn",
                                   "accountUpn", "account", "user", "userPrincipal",
                                   "UserName", "UserId"),
        "user_display_name":   get("userDisplayName", "user display name", "displayName",
                                   "accountDisplayName", "username", "userName",
                                   "identity", "accountName", "UserName"),
    }

    # Privileged role — modifiedProperties newValue, with targetResources fallback
    out["privileged_role_object_id"] = (_extract_modified_property_new_value(lines, "Role.ObjectID")
                                        or _extract_role_target_resource_id(lines))
    out["privileged_role_display_name"] = (_extract_modified_property_new_value(lines, "Role.DisplayName")
                                           or _extract_role_target_resource_display_name(lines))
    out["privileged_role_template_id"] = (_extract_modified_property_new_value(lines, "Role.TemplateId")
                                          or _extract_additional_detail_value(lines, "TemplateId"))
    out["privileged_role_well_known"] = (_extract_modified_property_new_value(lines, "Role.WellKnownObjectName")
                                         or _extract_additional_detail_value(lines, "RoleDefinitionOriginId"))

    out["target_user_display_name"]   = _extract_target_resource_display_name(lines)
    out["target_user_principal_name"] = _extract_target_resource_upn(lines)

    # TAP fields
    out["tap_initiated_by_display_name"] = _extract_initiated_by_value(lines, "displayName")
    out["tap_initiated_by_upn"]          = _extract_initiated_by_value(lines, "userPrincipalName")
    out["tap_start_raw"] = _extract_modified_property_new_value(lines, "TemporaryAccessPass.TemporaryAccessPass.StartDateTime")
    out["tap_end_raw"]   = _extract_modified_property_new_value(lines, "TemporaryAccessPass.TemporaryAccessPass.EndTime")

    out["asset_name"] = get("assetName", "asset name", "AssetName", "MachineName",
                            "machineName", "hostName", "deviceName", "device",
                            "Endpoint", "Host", "Computer")

    out["first_login_ip"]  = get("FirstLoginIp", "firstLoginIp", "firstloginip",
                                 "First Login IP", "first login ip")
    out["second_login_ip"] = get("SecondLoginIp", "secondLoginIp", "secondloginip",
                                 "Second Login IP", "second login ip")

    out["first_login_created_raw"]  = _extract_section_value(lines, "FirstLogin", "CreatedDate")
    out["second_login_created_raw"] = _extract_section_value(lines, "SecondLogin", "CreatedDate")
    out["first_login_city"]    = _extract_section_value(lines, "FirstLogin", "City")
    out["first_login_region"]  = _extract_section_value(lines, "FirstLogin", "Region")
    out["first_login_country"] = _extract_section_value(lines, "FirstLogin", "Country")
    out["second_login_city"]    = _extract_section_value(lines, "SecondLogin", "City")
    out["second_login_region"]  = _extract_section_value(lines, "SecondLogin", "Region")
    out["second_login_country"] = _extract_section_value(lines, "SecondLogin", "Country")

    out["location_city"]    = _extract_section_value(lines, "location", "city")
    out["location_state"]   = _extract_section_value(lines, "location", "state")
    out["location_country"] = (_extract_section_value(lines, "location", "countryOrRegion")
                               or _extract_section_value(lines, "location", "country"))
    # Single-line "Location: City, State, Country" — many SIEM/EDR exports emit
    # location on one line instead of a structured block, which the section
    # parser above can't read. Split it into city/state/country as a fallback.
    if not out["location_city"] and not out["location_country"]:
        m = re.search(r"^\s*location\s*:\s*(\S.*)$", log_text, re.IGNORECASE | re.MULTILINE)
        if m:
            parts = [p.strip() for p in m.group(1).split(",") if p.strip()]
            if len(parts) >= 3:
                out["location_city"], out["location_state"], out["location_country"] = parts[0], parts[1], parts[-1]
            elif len(parts) == 2:
                out["location_city"], out["location_country"] = parts
            elif len(parts) == 1:
                out["location_country"] = parts[0]

    # IP address — alias cascade then 3 increasingly desperate regex fallbacks
    ip = get("ClientIP", "clientIp", "clientIP", "ipAddress", "IPAddress", "ip",
             "IP Address", "SourceIPAddress", "sourceIpAddress", "sourceIPAddress",
             "remoteIpAddress", "remoteIP", "address", "ipaddr", "Source IP Address")
    if not ip:
        ip = _extract_additional_detail_value(lines, "ipaddr")
    if not ip or ip == "-":
        m = re.search(r"key\s*:\s*ipaddr\s*[\r\n]+\s*value\s*:\s*(?P<ip>[0-9a-fA-F\.:]+)",
                      log_text, re.IGNORECASE)
        if m and m.group("ip").strip() != "-":
            ip = m.group("ip").strip()
    if not ip or ip == "-":
        m = re.search(r"key\s*:\s*ipaddr.*?value\s*:\s*(?P<ip>[0-9a-fA-F\.:]+)",
                      log_text, re.IGNORECASE | re.DOTALL)
        if m and m.group("ip").strip() != "-":
            ip = m.group("ip").strip()
    if not ip or ip == "-":
        for m in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log_text):
            if m.group(0) not in ("0.0.0.0", "127.0.0.1"):
                ip = m.group(0)
                break
    out["ip_address"] = ip

    out["fallback_city"]    = get("City", "city")
    out["fallback_region"]  = get("Region", "region")
    out["fallback_country"] = get("Country", "country")

    # Unfamiliar sign-in additional info (JSON block + fallback regex)
    additional_json = _extract_multiline_json_block(lines, "additionalInfo") or get("additionalInfo")
    if additional_json:
        info = _parse_additional_info(additional_json)
        out["additional_info"]              = info["formatted"]
        out["additional_info_risk_reasons"] = info["risk_reasons"]
        out["additional_info_user_agent"]   = info["user_agent"]

    # Endpoint fields
    out["ep_process_path"]        = get("Process Path", "ProcessPath")
    out["ep_full_path"]           = get("Full Path", "FullPath")
    out["ep_date"]                = get("Date", "date")
    out["ep_cmd_line"]            = get("Cmd Line Parameters", "CmdLineParameters",
                                        "Process Path With CmdLine", "ProcessPathWithCmdLine")
    out["ep_sha256"]              = get("SHA256", "sha256")
    out["ep_application_name"]    = get("Application Name", "ApplicationName", "Policy Name")
    out["ep_process_id"]          = get("Process ID", "ProcessID")
    out["ep_tlhash"]              = get("TLHash", "tlhash")
    out["ep_parent_tlhash"]       = get("Parent Process TLHash", "ParentProcessTLHash")
    out["ep_message"]             = get("Message", "message")
    out["ep_sentinel_one_type"]   = get("Log Name", "LogName")
    out["ep_log_name"]            = out["ep_sentinel_one_type"] or out["ep_full_path"]
    out["ep_event_log_source_id"] = get("EventLog Source ID", "EventLogSourceId")
    out["ep_created_by_process"]  = get("Created By Process", "CreatedByProcess")

    raw_cert = get("Certificate", "certificate")
    if raw_cert and "cn=" in raw_cert.lower():
        m = re.search(r"(?:CN|cn)=([^,]+)", raw_cert, re.IGNORECASE)
        out["ep_certificate"] = m.group(1).strip() if m else raw_cert
    else:
        out["ep_certificate"] = raw_cert

    out["ep_admin_alert_title"] = _extract_admin_alert_title(lines)
    ep_full_with_cmd = get("Full Path With CmdLine", "Process Path With CmdLine",
                           "ProcessPathWithCmdLine")

    if out["ep_message"]:
        msg = out["ep_message"]
        out["ep_subject_account_name"]    = _extract_subject_account_name(msg)
        out["ep_subject_account_domain"]  = _extract_subject_account_domain(msg)
        out["ep_member_account_name"]     = _extract_member_account_name(msg)
        out["ep_group_name"]              = _extract_group_name(msg)
        out["ep_admin_group_name"]        = out["ep_group_name"]
        out["ep_added_member_dn"]         = _extract_added_member_dn(msg)
        out["ep_added_member_name"]       = _extract_added_member_name(
            out["ep_added_member_dn"], out["ep_member_account_name"])

        # Cleared security logs special-case
        if "the audit log was cleared" in msg.lower():
            cleared = _extract_inline_value(msg, "Account Name:", "Domain Name:")
            if cleared and cleared not in ("-", "N/A"):
                out["ep_subject_account_name"] = cleared

        # Defender threat name parse from "Name: ... ID:"
        name_idx = msg.lower().find("name:")
        if name_idx >= 0:
            after = msg[name_idx + 5:].strip()
            id_idx = after.lower().find("id:")
            full_type = after[:id_idx].strip() if id_idx > 0 else after
            out["ep_defender_type"] = full_type
            if full_type:
                colon = full_type.find(":")
                if colon >= 0:
                    out["ep_defender_type1"] = full_type[:colon].strip()
                    out["ep_defender_type2"] = full_type[colon + 1:].strip()
                else:
                    out["ep_defender_type1"] = full_type

        # Defender file path
        fp = _extract_inline_value(msg, "Path:", "Detection Origin:")
        if fp:
            parts = [p.strip() for p in fp.split(";") if p.strip()]
            if parts:
                out["ep_defender_file"] = (";\n\n".join(parts) + ";")

        # Defender process path
        pn_idx = msg.lower().find("process name:")
        if pn_idx >= 0:
            after = msg[pn_idx + 13:].strip()
            markers = ["Action:", "Action Status:", "Error Code:", "Error description:",
                       "Security intelligence Version:", "Detection Origin:",
                       "Detection Type:", "Detection Source:"]
            end_idx = -1
            for marker in markers:
                idx = after.lower().find(marker.lower())
                if idx >= 0 and (end_idx == -1 or idx < end_idx):
                    end_idx = idx
            out["ep_defender_path"] = after[:end_idx].strip() if end_idx >= 0 else after

        # Truncate message at "Security intelligence Version:"
        sec_idx = msg.lower().find("security intelligence version:")
        if sec_idx > 0:
            out["ep_message"] = msg[:sec_idx].strip()

        # Defender exclusion newValue
        exclusion_val = _extract_inline_value(msg, "New value:", "")
        if exclusion_val:
            prefixes = [
                r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\\",
                r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes\\",
                r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions\\",
                r"HKLM\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard"
                r"\Controlled Folder Access\AllowedApplications\\",
            ]
            for pref in prefixes:
                if exclusion_val.lower().startswith(pref.lower()):
                    exclusion_val = exclusion_val[len(pref):]
                    break
            suf = exclusion_val.lower().rfind(" = 0x0")
            if suf >= 0:
                exclusion_val = exclusion_val[:suf].strip()
            out["ep_defender_exclusion_new_value"] = exclusion_val.strip()

        # SentinelOne markers
        out["ep_true_context_id"]   = _extract_inline_value(msg, "True Context ID:", "Name:")
        out["ep_sentinel_one_path"] = _extract_inline_value(msg, "Path:", "Detection engine:")

        # Defender configuration change → property name
        if "microsoft defender antivirus configuration has changed" in msg.lower():
            out["ep_defender_type2"] = _extract_defender_property_name(msg)

        # SentinelOne abbreviated message
        bang = msg.find("!")
        out["ep_message_sentinel_one"] = msg[:bang].strip() if bang >= 0 else msg.strip()

    # localgroup add command parser
    grp, mem = _try_extract_local_group_add(out.get("ep_cmd_line", ""))
    if not grp:
        grp, mem = _try_extract_local_group_add(ep_full_with_cmd)
    if grp:
        out["ep_group_name"] = out.get("ep_group_name") or grp
        out["ep_added_member_name"] = out.get("ep_added_member_name") or mem
        out["target_user_principal_name"] = out.get("target_user_principal_name") or mem

    # DOMAIN\User parsing
    user_raw = get("User", "user", "UserName", "UserDisplayName")
    if user_raw:
        if "\\" in user_raw:
            parts = user_raw.split("\\", 1)
            out["ep_domain"], out["ep_user"] = parts[0], parts[1]
        elif "@" in user_raw:
            parts = user_raw.split("@", 1)
            out["ep_user"], out["ep_domain"] = parts[0], parts[1]
        else:
            out["ep_user"] = user_raw

    # Final fallbacks
    if not out.get("user_display_name") and out.get("ep_user"):
        out["user_display_name"] = out["ep_user"]
    if not out.get("user_principal_name") and user_raw:
        out["user_principal_name"] = user_raw
    if not out.get("target_user_principal_name") and out.get("ep_added_member_name"):
        out["target_user_principal_name"] = out["ep_added_member_name"]
    if not out.get("risk_event_type") and out.get("ep_admin_alert_title"):
        out["risk_event_type"] = out["ep_admin_alert_title"]
    if not out.get("ip_address") and out.get("first_login_ip"):
        out["ip_address"] = out["first_login_ip"]
    if not out.get("ip_address") and out.get("ep_member_account_name"):
        try:
            import ipaddress
            ipaddress.ip_address(out["ep_member_account_name"])
            out["ip_address"] = out["ep_member_account_name"]
        except ValueError:
            pass
    if not out.get("user_display_name") and out.get("user_principal_name"):
        out["user_display_name"] = out["user_principal_name"]
    if not out.get("user_principal_name") and out.get("user_display_name"):
        out["user_principal_name"] = out["user_display_name"]
    if out.get("user_display_name") and "@" in out["user_display_name"]:
        left = out["user_display_name"].split("@")[0]
        out["user_display_name"] = left.replace(".", " ").replace("_", " ").strip()
    if out.get("ep_subject_account_name") and out["ep_subject_account_name"] not in ("N/A", "-"):
        out["user_display_name"] = out["ep_subject_account_name"]

    out["raw_fields"] = raw_fields
    suggested = suggest_alert_type(log_text, out)
    if suggested:
        out["suggested_alert_type"] = suggested
        out["_alert_label"] = ALERT_LABEL_BY_ID.get(suggested, suggested)
        action = suggest_response_action(suggested)
        if action:
            out["suggested_response_action"] = action
    return out


# ─── alert-type heuristic ─────────────────────────────────────────────────────
# Keyword → alert_type id. First match wins. Ordering matters — narrower
# patterns ("defender exclusion") must precede broader ones ("defender").
_ALERT_TYPE_KEYWORDS: List[Tuple[str, str]] = [
    # Cloud / identity
    ("impossible travel",                "impossible_travel"),
    ("anonymizedipaddress",              "anonymized_ip"),
    ("anonymized ip",                    "anonymized_ip"),
    ("tor exit",                         "anonymized_ip"),
    ("password spray",                   "password_spray"),
    ("passwordspray",                    "password_spray"),
    ("unfamiliar sign",                  "unfamiliar_signin"),
    ("unfamiliarfeatures",               "unfamiliar_signin"),
    ("login to disabled",                "login_to_disabled_account"),
    ("disabled account",                 "login_to_disabled_account"),
    ("temporary access pass",            "temporary_access_pass"),
    ("temporaryaccesspass",              "temporary_access_pass"),
    ("creation of admin",                "creation_of_admin_account"),
    ("admin account created",            "creation_of_admin_account"),
    ("privileged role",                  "privileged_role"),
    ("role assignment",                  "privileged_role"),
    ("forwarding rule",                  "forwarding_rule"),
    ("inboxrule",                        "forwarding_rule"),
    ("forwardto",                        "forwarding_rule"),
    ("user at risk",                     "user_at_risk"),
    ("riskystate",                       "user_at_risk"),
    ("risky sign-in",                    "user_at_risk"),
    ("risky signin",                     "user_at_risk"),
    ("risky sign in",                    "user_at_risk"),
    ("risk detection",                   "user_at_risk"),

    # Endpoint — defender / sentinel
    ("defender exclusion",               "defender_exclusion_created"),
    ("add-mppreference",                 "defender_exclusion_created"),
    ("defender disabled",                "disable_protection"),
    ("disableantispyware",               "disable_protection"),
    ("set-mppreference",                 "disable_protection"),
    ("microsoft defender",               "defender_detection"),
    ("defender atp",                     "defender_detection"),
    ("windows defender",                 "defender_detection"),
    ("sentinelone",                      "sentinel_one_detection"),
    ("sentinel one",                     "sentinel_one_detection"),

    # Endpoint — behavioral
    ("powershell",                       "powershell_policy_bypass"),
    ("executionpolicy bypass",           "powershell_policy_bypass"),
    ("-encodedcommand",                  "powershell_policy_bypass"),
    ("bitlocker",                        "bitlocker_disable"),
    ("manage-bde -off",                  "bitlocker_disable"),
    ("disable-bitlocker",                "bitlocker_disable"),
    ("reg export",                       "reg_export"),
    ("reg.exe export",                   "reg_export"),
    ("wevtutil cl",                      "cleared_security_logs"),
    ("clear-eventlog",                   "cleared_security_logs"),
    ("vulnerable driver",                "vulnerable_driver"),
    ("loldrivers",                       "vulnerable_driver"),
    ("byovd",                            "vulnerable_driver"),
    ("ransomware",                       "ransomware"),
    ("encrypted",                        "ransomware"),
    ("ransom note",                      "ransomware"),
    ("net localgroup administrators",    "user_added_to_local_admin"),
    ("local administrators",             "user_added_to_local_admin"),
    ("public rdp",                       "public_rdp_connection"),
    ("rdp from internet",                "public_rdp_connection"),
    ("uninstall script",                 "uninstall_script_execution"),
    ("msiexec /uninstall",               "uninstall_script_execution"),
    ("uninstall.exe",                    "uninstall_script_execution"),
    ("disable security",                 "disable_security_agent"),
    ("net stop",                         "disable_security_agent"),
    ("sc stop",                          "disable_security_agent"),
    ("stop-service",                     "disable_security_agent"),

    # Enumeration tradecraft
    ("ipconfig /all",                    "enumeration"),
    ("net view",                         "enumeration"),
    ("nltest /dclist",                   "enumeration"),
    ("whoami /priv",                     "enumeration"),
    ("netstat -ano",                     "enumeration"),
    ("arp -a",                           "enumeration"),
    ("systeminfo",                       "enumeration"),
    ("tasklist",                         "enumeration"),
]


def suggest_alert_type(log_text: str, parsed: Optional[Dict] = None) -> Optional[str]:
    """Pick the most likely alert type from log content. Returns an id from
    ALERT_TYPES or None when no keyword fires."""
    lower = (log_text or "").lower()
    for kw, alert_id in _ALERT_TYPE_KEYWORDS:
        if kw in lower:
            return alert_id
    # Field-based fallback when no keyword hit
    if parsed:
        if parsed.get("risk_event_type", "").lower() in ("anonymizedipaddress", "tor"):
            return "anonymized_ip"
        # A risk level on an authenticated IP is a user-at-risk sign-in. (Was
        # gated on parsed["location"], a key the parser never emits — it stores
        # location_city/state/country — so this fallback never fired.)
        if parsed.get("risk_level") and parsed.get("ip_address"):
            return "user_at_risk"
        if parsed.get("threat_name") or parsed.get("ep_admin_alert_title"):
            return "defender_detection"
    return None


# Alert-type → recommended response action. Mirrors how a senior SOC analyst
# would pre-pick the dropdown: ransomware/RDP-from-internet/vulnerable driver
# → contain the host; identity-side risk → lock the account; defender tamper /
# log clearing / privilege change → escalate to a human reviewer.
_DEFAULT_RESPONSE_BY_ALERT = {
    # Identity / cloud
    "user_at_risk":                "lock_account",
    "impossible_travel":           "lock_account_and_revoke_session",
    "anonymized_ip":               "lock_account_and_revoke_session",
    "password_spray":              "lock_account_and_revoke_session",
    "unfamiliar_signin":           "lock_account",
    "login_to_disabled_account":   "escalating",
    "temporary_access_pass":       "escalating",
    "creation_of_admin_account":   "escalating",
    "privileged_role":             "escalating",
    "forwarding_rule":             "lock_account_and_revoke_session",
    # Endpoint — contain
    "ransomware":                  "isolating",
    "public_rdp_connection":       "isolating",
    "vulnerable_driver":           "isolating",
    "bitlocker_disable":           "isolating",
    "uninstall_script_execution":  "isolating",
    "disable_security_agent":      "isolating",
    "sentinel_one_detection":      "isolating",
    # Endpoint — escalate (needs review, not auto-containment)
    "defender_detection":          "escalating",
    "defender_exclusion_created":  "escalating",
    "disable_protection":          "escalating",
    "powershell_policy_bypass":    "escalating",
    "reg_export":                  "escalating",
    "enumeration":                 "escalating",
    "user_added_to_local_admin":   "escalating",
    "cleared_security_logs":       "escalating",
}


def suggest_response_action(alert_type: Optional[str]) -> Optional[str]:
    """Map an alert-type id to the response-action id a SOC analyst would
    usually pick. Returns ``None`` when there's no strong default — caller
    should leave the dropdown empty rather than guess."""
    if not alert_type:
        return None
    return _DEFAULT_RESPONSE_BY_ALERT.get(alert_type)


# ─── parser helpers ────────────────────────────────────────────────────────────
def _extract_parameter_value(lines, name):
    cur = ""
    for raw in lines:
        line = raw.strip()
        if ":" not in line: continue
        k, _, v = line.partition(":")
        k, v = k.strip(), v.strip()
        if k.lower() == "name":
            cur = v
        elif k.lower() == "value" and cur.lower() == name.lower():
            return v[5:].strip() if v.lower().startswith("smtp:") else v
    return ""


def _extract_section_value(lines, section, target):
    in_target = False
    boundaries = {"firstlogin", "secondlogin", "location", "modifiedproperties",
                  "targetresources", "additionaldetails", "initiatedby"}
    for raw in lines:
        line = raw.strip()
        if line.lower() in (f"{section.lower()} :", f"{section.lower()}:"):
            in_target = True
            continue
        if not in_target: continue
        ll = line.lower()
        is_other = ll in boundaries or ll in (f"{b} :" for b in boundaries) or \
                   ll in (f"{b}:" for b in boundaries)
        if is_other and not ll.startswith(section.lower()):
            break
        if ":" not in line: continue
        k, _, v = line.partition(":")
        if k.strip().lower() == target.lower():
            return v.strip()
    return ""


def _walk_modified_properties(lines, target_display, key="newValue"):
    """Shared walker for modifiedProperties blocks. Returns trimmed newValue."""
    in_block = False
    cur_display = cur_val = ""
    for raw in lines:
        line = raw.strip()
        if line.lower() in ("modifiedproperties :", "modifiedproperties:"):
            if (in_block and cur_display.lower() == target_display.lower() and cur_val):
                return _trim_wrapped_quotes(cur_val)
            in_block, cur_display, cur_val = True, "", ""
            continue
        if not in_block: continue
        if line.lower() in ("targetresources :", "targetresources:",
                            "additionaldetails :", "additionaldetails:",
                            "initiatedby :", "initiatedby:"):
            if cur_display.lower() == target_display.lower() and cur_val:
                return _trim_wrapped_quotes(cur_val)
            in_block = False
            continue
        if ":" not in line: continue
        k, _, v = line.partition(":")
        k, v = k.strip(), v.strip()
        if k.lower() == "displayname": cur_display = v
        elif k.lower() == key: cur_val = v
    if in_block and cur_display.lower() == target_display.lower() and cur_val:
        return _trim_wrapped_quotes(cur_val)
    return ""


def _extract_modified_property_new_value(lines, name):
    return _walk_modified_properties(lines, name, "newValue")


def _walk_target_resources(lines, want_type, want_field):
    in_block = False
    cur_type = cur_val = ""
    for raw in lines:
        line = raw.strip()
        if line.lower() in ("targetresources :", "targetresources:"):
            if (in_block and cur_type.lower() == want_type.lower() and cur_val
                and cur_val != "-"):
                return _trim_wrapped_quotes(cur_val)
            in_block, cur_type, cur_val = True, "", ""
            continue
        if not in_block: continue
        if line.lower() in ("modifiedproperties :", "modifiedproperties:",
                            "additionaldetails :", "additionaldetails:",
                            "initiatedby :", "initiatedby:"):
            if (cur_type.lower() == want_type.lower() and cur_val and cur_val != "-"):
                return _trim_wrapped_quotes(cur_val)
            in_block = False
            continue
        if ":" not in line: continue
        k, _, v = line.partition(":")
        k, v = k.strip(), v.strip()
        if k.lower() == "type": cur_type = v
        elif k.lower() == want_field: cur_val = v
    if in_block and cur_type.lower() == want_type.lower() and cur_val and cur_val != "-":
        return _trim_wrapped_quotes(cur_val)
    return ""


def _extract_role_target_resource_id(lines):
    return _walk_target_resources(lines, "Role", "id")


def _extract_role_target_resource_display_name(lines):
    return _walk_target_resources(lines, "Role", "displayName")


def _extract_target_resource_display_name(lines):
    return _walk_target_resources(lines, "User", "displayName")


def _extract_target_resource_upn(lines):
    return _walk_target_resources(lines, "User", "userPrincipalName")


def _extract_additional_detail_value(lines, target_key):
    in_block = False
    cur_key = ""
    for raw in lines:
        line = raw.strip()
        if line.lower() in ("additionaldetails :", "additionaldetails:"):
            in_block, cur_key = True, ""
            continue
        if not in_block: continue
        if line.lower() in ("targetresources :", "targetresources:",
                            "modifiedproperties :", "modifiedproperties:",
                            "initiatedby :", "initiatedby:"):
            in_block = False
            continue
        if ":" not in line: continue
        k, _, v = line.partition(":")
        k, v = k.strip(), v.strip()
        if k.lower() == "key": cur_key = v
        elif k.lower() == "value" and cur_key.lower() == target_key.lower():
            return v
    return ""


def _extract_initiated_by_value(lines, target_key):
    in_init = in_user = False
    for raw in lines:
        line = raw.strip()
        if line.lower() in ("initiatedby :", "initiatedby:"):
            in_init = True
            continue
        if not in_init: continue
        if line.lower() in ("user :", "user:"):
            in_user = True
            continue
        if line.lower() in ("app :", "app:", "targetresources :", "targetresources:"):
            break
        if not in_user: continue
        if ":" not in line: continue
        k, _, v = line.partition(":")
        if k.strip().lower() == target_key.lower():
            return v.strip()
    return ""


def _extract_inline_value(source, start_marker, end_marker):
    if not source: return ""
    idx = source.lower().find(start_marker.lower())
    if idx < 0: return ""
    remainder = source[idx + len(start_marker):].strip()
    if not end_marker: return remainder
    end_idx = remainder.lower().find(end_marker.lower())
    return remainder[:end_idx].strip() if end_idx >= 0 else remainder.strip()


def _extract_between_markers(source, start_marker, end_marker):
    if not source: return ""
    idx = source.lower().find(start_marker.lower())
    if idx < 0: return ""
    remainder = source[idx + len(start_marker):].strip()
    end_idx = remainder.lower().find(end_marker.lower())
    return remainder[:end_idx].strip() if end_idx >= 0 else remainder.strip()


def _extract_section_account_value(section, marker):
    if not section: return ""
    idx = section.lower().find(marker.lower())
    if idx < 0: return ""
    remainder = section[idx + len(marker):].strip()
    next_markers = [" Account ", " Domain Name:", " Logon ID:", " Group Name:", " Security ID:"]
    end_idx = -1
    for nm in next_markers:
        i = remainder.lower().find(nm.lower())
        if i >= 0 and (end_idx == -1 or i < end_idx):
            end_idx = i
    val = remainder[:end_idx].strip() if end_idx >= 0 else remainder.strip()
    return "N/A" if val == "-" else val


def _extract_subject_account_name(msg):
    return _extract_section_account_value(
        _extract_between_markers(msg, "Subject:", "Member:"), "Account Name:")


def _extract_subject_account_domain(msg):
    return _extract_section_account_value(
        _extract_between_markers(msg, "Subject:", "Member:"), "Account Domain:")


def _extract_member_account_name(msg):
    return _extract_section_account_value(
        _extract_between_markers(msg, "Member:", "Group:"), "Account Name:")


def _extract_group_name(msg):
    if not msg: return ""
    g = (_extract_between_markers(msg, "Group Name:", "Group Domain:")
         or _extract_between_markers(msg, "Group Name:", "Additional Information:"))
    if g: return g
    group_sec = _extract_between_markers(msg, "Group:", "Additional Information:")
    if not group_sec: return ""
    matches = re.findall(
        r"Account Name:\s*(.+?)(?=\s+Account Domain:|\s+Additional Information:|$)",
        group_sec, re.IGNORECASE)
    return matches[-1].strip() if matches else ""


def _extract_added_member_dn(msg):
    if not msg: return ""
    member_sec = _extract_between_markers(msg, "Member:", "Group:")
    if not member_sec: return ""
    m = re.search(r"Account Name:\s*(.*?)(?=\s+Account Domain:|\s+Group:|$)",
                  member_sec, re.IGNORECASE)
    extracted = m.group(1).strip() if m else ""
    if not extracted or extracted == "-":
        cn = re.search(r"(?:CN|cn)=([^,]+)", member_sec, re.IGNORECASE)
        return cn.group(0) if cn else ""
    return extracted


def _extract_added_member_name(dn, member_account_name):
    if not dn:
        return "N/A" if (not member_account_name or member_account_name == "-") else member_account_name
    m = re.search(r"(?:CN|cn)=([^,]+)", dn, re.IGNORECASE)
    if m: return m.group(1).strip()
    return "N/A" if dn == "-" else dn


def _try_extract_local_group_add(cmd):
    if not cmd: return "", ""
    m = re.search(
        r'localgroup\s+(?:"(?P<group>[^"]+)"|(?P<group2>\S+))'
        r'\s+(?:"(?P<member>[^"]+)"|(?P<member2>\S+))\s+/add\b',
        cmd, re.IGNORECASE)
    if not m: return "", ""
    grp = m.group("group") or m.group("group2") or ""
    mem = m.group("member") or m.group("member2") or ""
    return ("N/A" if grp == "-" else grp), ("N/A" if mem == "-" else mem)


def _trim_wrapped_quotes(v):
    if not v: return ""
    s = v.strip()
    return s[1:-1] if len(s) >= 2 and s.startswith('"') and s.endswith('"') else s


def _extract_admin_alert_title(lines):
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("="): continue
        if "creation of" in line.lower() and "admin account" in line.lower():
            return " ".join(w.capitalize() for w in line.split())
    return ""


def _extract_defender_property_name(msg):
    if not msg: return ""
    new_val = _extract_inline_value(msg, "New value:", "")
    if not new_val: return "N/A"
    path = new_val.split("=")[0].strip()
    last_bs = path.rfind("\\")
    return path[last_bs + 1:].strip() if last_bs >= 0 else path


def _extract_multiline_json_block(lines, key_name):
    """Walk forward from `key:` collecting non-section-header lines until the
    block ends. Used for `additionalInfo` which spans multiple lines."""
    for i, raw in enumerate(lines):
        trimmed = raw.strip()
        if ":" not in trimmed: continue
        cur_key, _, first_val = trimmed.partition(":")
        if cur_key.strip().lower() != key_name.lower(): continue
        builder = [first_val.strip()] if first_val.strip() else []
        for j in range(i + 1, len(lines)):
            cand = lines[j].strip()
            if not cand: continue
            # Standalone section header = `key :` with no value
            if ":" in cand and not cand.split(":", 1)[1].strip():
                break
            builder.append(cand)
        return "".join(builder)
    return ""


_REASON_DISPLAY = {
    "unfamiliarasn":             "Unfamiliar ASN",
    "unfamiliarbrowser":         "Unfamiliar Browser",
    "unfamiliardevice":          "Unfamiliar Device",
    "unfamiliareasid":           "Unfamiliar EAS ID",
    "unfamiliarip":              "Unfamiliar IP",
    "unfamiliarlocation":        "Unfamiliar Location",
    "unfamiliartenantipsubnet":  "Unfamiliar Tenant IP Subnet",
}


def _parse_additional_info(text):
    reasons, user_agent = [], ""
    try:
        doc = json.loads(text)
        if isinstance(doc, list):
            for item in doc:
                k, v = item.get("Key"), item.get("Value")
                if not k: continue
                if k.lower() == "riskreasons" and isinstance(v, list):
                    reasons.extend(r for r in v if r)
                elif k.lower() == "useragent" and isinstance(v, str):
                    user_agent = v
    except Exception:
        # Regex fallback
        m = re.search(r'"Key"\s*:\s*"riskReasons"\s*,\s*"Value"\s*:\s*\[(.*?)\]',
                      text, re.IGNORECASE | re.DOTALL)
        if m:
            for vm in re.finditer(r'"([^"]+)"', m.group(1)):
                if vm.group(1).strip(): reasons.append(vm.group(1).strip())
        ua = re.search(r'"Key"\s*:\s*"userAgent"\s*,\s*"Value"\s*:\s*"(.*?)"(?=,\s*\{|\s*\])',
                       text, re.IGNORECASE | re.DOTALL)
        if ua: user_agent = ua.group(1).strip()
    user_agent = re.sub(r"\s+", " ", user_agent).strip()
    formatted = []
    seen = set()
    for r in reasons:
        rd = _REASON_DISPLAY.get(r.lower()) or re.sub(
            r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", " ", r).strip()
        if rd.lower() not in seen:
            seen.add(rd.lower())
            formatted.append(rd)
    risk_reasons_display = "\n".join(f"- {r}" for r in formatted)
    bullets = list(formatted)
    if user_agent: bullets.append(f"User Agent: {user_agent}")
    return {"risk_reasons": risk_reasons_display, "user_agent": user_agent,
            "formatted": ", ".join(bullets)}


# ─── composer ─────────────────────────────────────────────────────────────────
_TEMPLATES_DIR = Path(__file__).resolve().parent / "email_templates"

# Per-analyst drafts + rolling send history live under backend/data/.
_DATA_DIR     = Path(__file__).resolve().parent.parent / "data"
_DRAFTS_DIR   = _DATA_DIR / "email_drafts"
_HISTORY_FILE = _DATA_DIR / "email_history.json"
_HISTORY_CAP  = 200


def _slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9_-]", "_", (s or "").lower())[:48]


def _drafts_dir() -> Path:
    _DRAFTS_DIR.mkdir(parents=True, exist_ok=True)
    return _DRAFTS_DIR


def save_draft(payload: Dict) -> Dict:
    """Persist a composed email + its compose options. Returns the saved record."""
    d = _drafts_dir()
    now = datetime.utcnow()
    alert = _slugify(payload.get("alert_type") or "generic")
    draft_id = f"{now.strftime('%Y%m%dT%H%M%S')}_{alert}"
    record = {
        "id":          draft_id,
        "saved_at":    now.isoformat(timespec="seconds") + "Z",
        "alert_type":  payload.get("alert_type"),
        "subject":     payload.get("subject", ""),
        "text":        payload.get("text", ""),
        "html":        payload.get("html", ""),
        "to":          payload.get("to", ""),
        "cc":          payload.get("cc", ""),
        "parsed":      payload.get("parsed") or {},
        "options":     payload.get("options") or {},
    }
    (d / f"{draft_id}.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def list_drafts() -> List[Dict]:
    d = _drafts_dir()
    out = []
    for p in sorted(d.glob("*.json"), reverse=True):
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
            out.append({
                "id":         rec.get("id", p.stem),
                "saved_at":   rec.get("saved_at"),
                "alert_type": rec.get("alert_type"),
                "subject":    rec.get("subject", ""),
                "to":         rec.get("to", ""),
            })
        except Exception:
            continue
    return out


def load_draft(draft_id: str) -> Optional[Dict]:
    safe = _slugify(draft_id)
    p = _drafts_dir() / f"{safe}.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def delete_draft(draft_id: str) -> bool:
    safe = _slugify(draft_id)
    p = _drafts_dir() / f"{safe}.json"
    if not p.exists():
        return False
    p.unlink()
    return True


def read_history() -> List[Dict]:
    if not _HISTORY_FILE.exists():
        return []
    try:
        data = json.loads(_HISTORY_FILE.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
    except Exception:
        return []
    return []


def append_history(entry: Dict) -> None:
    """Append a send-attempt record. Capped at _HISTORY_CAP, newest-first."""
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    hist = read_history()
    record = {
        "ts":      datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "to":      entry.get("to", ""),
        "cc":      entry.get("cc", ""),
        "subject": entry.get("subject", ""),
        "sent":    bool(entry.get("sent")),
        "error":   entry.get("error"),
    }
    hist.insert(0, record)
    if len(hist) > _HISTORY_CAP:
        hist = hist[:_HISTORY_CAP]
    _HISTORY_FILE.write_text(json.dumps(hist, indent=2), encoding="utf-8")


def _value_or_na(v):
    return v if v and str(v).strip() else "N/A"


def _defang_ip(v):
    if not v: return "N/A"
    return str(v).replace(".", "[.]").replace(":", "[:]")


def _defang_if_iplike(v):
    if not v: return "N/A"
    s = str(v)
    return _defang_ip(s) if ("." in s or ":" in s) else s


# Body-level IOC defanger — sanitizes a generated email body so raw IOCs
# (IPs the analyst pulled from a SIEM, attacker C2 domains, etc.) can't be
# clicked by the recipient. Three rules govern what we touch:
#   * Raw IPs                  -> always defanged (almost always IOCs in this
#                                  context; no legitimate reason to ship a
#                                  raw IPv4 in a client email).
#   * Domains / URL hostnames  -> defanged only when the registrable domain
#                                  isn't on the safe-list below. Subdomains
#                                  of safe-listed domains (support.microsoft
#                                  .com, learn.microsoft.com, etc.) inherit
#                                  the safe-list status.
#   * Email addresses          -> never defanged (recipient/sender refs).
# The safe-list is the union of: Microsoft / Google / Apple infrastructure,
# vendor KB and reference URLs we routinely link to, security-research / CTI
# portals analysts cite by name, and standards bodies.
_IOC_URL_RE    = re.compile(r"\bhttps?://[^\s<>'\"`]+", re.IGNORECASE)
_IOC_IP_RE     = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IOC_DOMAIN_RE = re.compile(
    r"(?<![@\w.-])"                                # not preceded by @ (skip emails) or a domain char
    r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|co|xyz|info|ru|cn|tk|top|click|pw|us|uk|de|fr|jp|cc|biz|online|site|shop|app|dev|me|tv|gov|edu))"
    r"(?!\.?\w)",                                  # not a longer multi-level domain (sentence period OK)
    re.IGNORECASE,
)
_DEFANG_SAFE_DOMAINS = {
    # Microsoft surface (KB, learn, support, docs, telemetry)
    "microsoft.com", "msft.net", "windows.com", "office.com", "office365.com",
    "outlook.com", "live.com", "azure.com", "azureedge.net", "msftncsi.com",
    "msauth.net", "msftauth.net", "msidentity.com", "windowsupdate.com",
    # Google / Apple infra
    "google.com", "gstatic.com", "googleapis.com", "googleusercontent.com",
    "gmail.com", "apple.com", "icloud.com",
    # Standards / web platform
    "schema.org", "w3.org", "iana.org", "ietf.org",
    # CVE / vuln databases
    "nist.gov", "nvd.nist.gov", "cve.org", "cve.mitre.org",
    "mitre.org", "attack.mitre.org", "d3fend.mitre.org",
    "cisa.gov", "first.org", "cert.org", "cert.eu", "ncsc.gov.uk", "cyber.gov.au",
    # Security vendors analysts reference by name in client comms
    "virustotal.com", "abuseipdb.com", "alienvault.com", "otx.alienvault.com",
    "urlscan.io", "shodan.io", "censys.io", "greynoise.io", "abuse.ch",
    "threatfox.abuse.ch", "bazaar.abuse.ch", "malwarebazaar.com",
    "spamhaus.org", "phishtank.com",
    # AV / EDR vendors (often linked in detection writeups)
    "crowdstrike.com", "sentinelone.com", "trendmicro.com", "kaspersky.com",
    "sophos.com", "eset.com", "mandiant.com", "fireeye.com", "symantec.com",
    "broadcom.com", "paloaltonetworks.com", "unit42.paloaltonetworks.com",
    # Misc reference / docs
    "github.com", "githubusercontent.com", "stackoverflow.com",
}


def _registrable_domain(host: str) -> str:
    """Return the last two labels of a hostname (rough effective-TLD strip).
    Good enough for safe-list matching: support.microsoft.com -> microsoft.com,
    learn.microsoft.com -> microsoft.com, github.io -> github.io. Doesn't try
    to handle gov.uk-style two-part TLDs because none of the safe-listed
    entries use them; if one is ever added, special-case it here."""
    host = (host or "").lower().split(":", 1)[0]  # drop :port if present
    parts = host.strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _is_safe_host(host: str) -> bool:
    """True when the host (or its registrable parent) is on the safe-list."""
    if not host:
        return False
    h = host.lower()
    return h in _DEFANG_SAFE_DOMAINS or _registrable_domain(h) in _DEFANG_SAFE_DOMAINS


def _defang_url(url: str) -> str:
    """Defang an http(s):// URL UNLESS its hostname is a safe-listed vendor.
    Leaves the full URL intact for Microsoft KB, MITRE ATT&CK, VirusTotal,
    etc. — clicking those is desirable, not dangerous."""
    # Extract hostname (between :// and the next /, ?, or end).
    m = re.match(r"^(https?)://([^/?#\s]+)(.*)$", url, re.IGNORECASE)
    if not m:
        return url
    scheme, host, rest = m.group(1), m.group(2), m.group(3)
    if _is_safe_host(host):
        return url
    new_scheme = "hxxps" if scheme.lower() == "https" else "hxxp"
    return f"{new_scheme}://{host.replace('.', '[.]')}{rest.replace('.', '[.]')}"


# Em/en dashes are the single most reliable "this was AI-written" giveaway in
# customer-facing email. The system prompt forbids them, but models still slip
# them in, so we strip on the way out as a belt-and-braces guard. Replacement
# rules picked for grammatical safety across the most common patterns:
#   "...quickly — and as always..."        -> "...quickly, and as always..."   (clause join)
#   "first IP 1.2.3.4 — clean reputation"  -> "first IP 1.2.3.4: clean ..."     (label + detail)
#   "8–14 lines"                           -> "8 to 14 lines"                   (numeric range)
#   "anti–virus"                           -> "anti-virus"                       (compound word)
_EM_OR_EN = "[—–]"
def _strip_em_dashes(text: str) -> str:
    if not text:
        return text
    out = text
    # Numeric range with en/em dash (no surrounding spaces): "8–14" -> "8 to 14".
    out = re.sub(rf"(\d)\s*{_EM_OR_EN}\s*(\d)", r"\1 to \2", out)
    # Space-padded dash separating clauses: " — " or " – " -> ", ".
    out = re.sub(rf"\s+{_EM_OR_EN}\s+", ", ", out)
    # Dash used inline with one-sided spacing (rarer): drop to comma + space.
    out = re.sub(rf"\s+{_EM_OR_EN}", ",", out)
    out = re.sub(rf"{_EM_OR_EN}\s+", ", ", out)
    # Bare dash inside a word (compound) -> regular hyphen.
    out = out.replace("—", "-").replace("–", "-")
    return out


def _defang_body_iocs(text: str) -> str:
    """Replace clickable IOCs in a body of text with their defanged forms.
    Rules in priority order:
      1. URLs whose hostname is safe-listed -> left intact (vendor KB, MITRE,
         CVE, VirusTotal, etc.).
      2. Raw IPv4 -> always defanged.
      3. Bare domains whose registrable parent is safe-listed -> left intact;
         everything else gets dots replaced with [.].
      4. Email addresses are never touched (the lookbehind in the domain
         regex skips anything preceded by @)."""
    if not text:
        return text
    out = _IOC_URL_RE.sub(lambda m: _defang_url(m.group(0)), text)
    out = _IOC_IP_RE.sub(lambda m: m.group(0).replace(".", "[.]"), out)

    def _maybe_defang_domain(m):
        d = m.group(0)
        return d if _is_safe_host(d) else d.replace(".", "[.]")
    out = _IOC_DOMAIN_RE.sub(_maybe_defang_domain, out)
    return out


def _build_location_display(parsed):
    parts = [p for p in (parsed.get("location_city"), parsed.get("location_state"),
                          parsed.get("location_country")) if p]
    return ", ".join(parts) if parts else "N/A"


def _build_response_footer(action_id, include_exclusion=False, include_escalation=False):
    escalate_text = "We're escalating this alert back for further review."
    exclusion_text = "An exclusion has been added for this detection."
    if include_escalation:
        return f"{escalate_text} {exclusion_text}" if include_exclusion else escalate_text
    footer = {
        "clearing_alert":
            "At this time, we have determined there is no immediate threat to this asset; "
            "however, we recommend confirming this is expected behavior.",
        "escalating":
            "At this time, the alert is being escalated for additional review and "
            "investigation. We will continue to monitor this asset for any additional "
            "indicators of compromise.",
        "isolating":
            "At this time, the affected endpoint is being isolated as a precautionary "
            "containment measure while the activity is investigated further.",
        "lockdown":
            "At this time, containment actions have been initiated and the impacted "
            "environment has been placed into lockdown to prevent additional unauthorized "
            "activity.",
        "lock_account":
            "At this time, the account has been locked as a precautionary measure pending "
            "validation of the observed activity.",
        "lock_account_and_revoke_session":
            "At this time, the account has been locked and active sessions have been "
            "revoked as a precautionary measure pending further investigation.",
    }.get(action_id, "")
    if include_exclusion:
        footer = exclusion_text if not footer else f"{footer} {exclusion_text}"
    return footer


def _calculate_tap_duration(start_raw, end_raw):
    if not (start_raw and end_raw): return "N/A"
    try:
        s = datetime.fromisoformat(start_raw.replace("Z", "+00:00"))
        e = datetime.fromisoformat(end_raw.replace("Z", "+00:00"))
        dur = e - s
        hours = dur.total_seconds() / 3600
        if hours >= 1: return f"{int(hours)} Hours"
        mins = dur.total_seconds() / 60
        if mins >= 1: return f"{int(mins)} Minutes"
        return f"{dur.total_seconds()} Seconds"
    except Exception:
        return "N/A"


def _build_replacement_map(parsed, options, signature_html, ip1, ip2):
    asset = options.get("asset_name") or parsed.get("asset_name") or ""
    org   = options.get("organization") or ""
    maintenance = ""
    if options.get("is_secure_mode"):
        maintenance = "This device is currently in Secure Mode."
    elif options.get("is_learning_monitor_mode"):
        maintenance = ("This device is not in Secure Mode, as such, any application "
                       "being executed will be permitted.")
    response_action_label = next((lbl for aid, lbl in RESPONSE_ACTIONS
                                  if aid == options.get("response_action")), "")
    response_footer = _build_response_footer(
        options.get("response_action") or "",
        options.get("include_exclusion") or False,
        options.get("include_escalation") or False,
    )
    runbook_blurb_text = (
        "We recommend updating the runbook for this organization. Having an up-to-date "
        "runbook significantly enhances our response time and quality of communication "
        "for critical alerts."
    )
    ip1 = ip1 or {}
    ip2 = ip2 or {}
    # Domain-joined explainer — only present when the parsed log has an
    # asset_name (e.g. a hybrid-AAD-joined endpoint surfaced in the alert).
    # Renders as a standalone paragraph that explains why this class of
    # alert is usually a false positive on managed devices, so the analyst
    # doesn't have to type the same context every time. Empty string when
    # asset_name is missing — the post-render blank-line collapse in
    # compose()/compose_ai() flattens the stray "{{DomainJoinedNote}}\n\n"
    # gap so absent-asset emails don't show an empty paragraph.
    domain_joined_note = ""
    if asset:
        domain_joined_note = (
            "When domain-joined assets trigger \"impossible travel\" alerts in systems "
            "like Microsoft Entra ID Protection, it is usually caused by cloud "
            "proxies/VPNs, split-tunneling, or inaccurate geolocation databases. "
            "Even securely managed or Hybrid Azure AD-joined devices can generate "
            "these false-positive anomalies if network traffic routing masks the "
            "actual location of the physical machine."
        )

    return {
        "{{TeamName}}":            options.get("team_name") or "the MDR analyst team",
        "{{FromAddress}}":         options.get("from_address") or "",
        "{{Ip1}}":                 _defang_if_iplike(ip1.get("ip_address")),
        "{{Ip2}}":                 _defang_if_iplike(ip2.get("ip_address")),
        "{{AlertType}}":           ALERT_LABEL_BY_ID.get(options.get("alert_type", ""), ""),
        "{{AssetName}}":           _value_or_na(asset),
        "{{DomainJoinedNote}}":    domain_joined_note,
        "{{Organization}}":        _value_or_na(org),
        "{{Id}}":                  parsed.get("id", ""),
        "{{RequestId}}":           parsed.get("request_id", ""),
        "{{CorrelationId}}":       parsed.get("correlation_id", ""),
        "{{RiskEventType}}":       parsed.get("risk_event_type", ""),
        "{{RiskState}}":           parsed.get("risk_state", ""),
        "{{RiskLevel}}":           parsed.get("risk_level", ""),
        "{{RiskDetail}}":          parsed.get("risk_detail", ""),
        "{{Source}}":              parsed.get("source", ""),
        "{{DetectionTimingType}}": parsed.get("detection_timing", ""),
        "{{Activity}}":            parsed.get("activity", ""),
        "{{TokenIssuerType}}":     parsed.get("token_issuer", ""),
        "{{UserId}}":              parsed.get("user_id", ""),
        "{{UserDisplayName}}":     parsed.get("user_display_name", ""),
        "{{UserPrincipalName}}":   parsed.get("user_principal_name", ""),
        "{{ForwardingAddress}}":   _value_or_na(parsed.get("forwarding_address")),
        "{{TargetUserDisplayName}}":          _value_or_na(parsed.get("target_user_display_name")),
        "{{TargetUserPrincipalName}}":        _value_or_na(parsed.get("target_user_principal_name")),
        "{{PrivilegedRoleDisplayName}}":      _value_or_na(parsed.get("privileged_role_display_name")),
        "{{PrivilegedRoleObjectId}}":         _value_or_na(parsed.get("privileged_role_object_id")),
        "{{PrivilegedRoleTemplateId}}":       _value_or_na(parsed.get("privileged_role_template_id")),
        "{{PrivilegedRoleWellKnownObjectName}}": _value_or_na(parsed.get("privileged_role_well_known")),
        "{{LocationCity}}":        _value_or_na(parsed.get("location_city")),
        "{{LocationState}}":       _value_or_na(parsed.get("location_state")),
        "{{LocationCountry}}":     _value_or_na(parsed.get("location_country")),
        "{{LocationDisplay}}":     _build_location_display(parsed),
        "{{username}}":            parsed.get("user_display_name", ""),
        "{{TargetGroup}}":         options.get("target_group") or "N/A",
        "{{hostname}}":            _value_or_na(options.get("asset_name")),
        "{{organization}}":        _value_or_na(org),
        "{{epOrg}}":               _value_or_na(org),
        "{{epDomain}}":            _value_or_na(parsed.get("ep_domain")),
        "{{epUser}}":              _value_or_na(parsed.get("ep_user")),
        "{{epDate}}":              _value_or_na(parsed.get("ep_date")),
        "{{epProcesspath}}":       _value_or_na(parsed.get("ep_process_path")),
        "{{epFullpath}}":          _value_or_na(parsed.get("ep_full_path")),
        "{{epCmdline}}":           _value_or_na(parsed.get("ep_cmd_line")),
        "{{epSha256}}":            _value_or_na(parsed.get("ep_sha256")),
        "{{epApplicationname}}":   _value_or_na(parsed.get("ep_application_name")),
        "{{epProcessid}}":         _value_or_na(parsed.get("ep_process_id")),
        "{{epMessage}}":           _value_or_na(parsed.get("ep_message")),
        "{{epDefendertype}}":      _value_or_na(parsed.get("ep_defender_type")),
        "{{epDefenderType1}}":     _value_or_na(parsed.get("ep_defender_type1")),
        "{{epDefenderType2}}":     _value_or_na(parsed.get("ep_defender_type2")),
        "{{epDefenderfile}}":      _value_or_na(parsed.get("ep_defender_file")),
        "{{epDefenderpath}}":      _value_or_na(parsed.get("ep_defender_path")),
        "{{epDefenderExclusionNewValue}}":   _value_or_na(parsed.get("ep_defender_exclusion_new_value")),
        "{{epDefenderaction}}":    _value_or_na(options.get("defender_action")),
        "{{epEnumerationType}}":   _value_or_na(options.get("enumeration_type")),
        "{{epSentineloneaction}}": _value_or_na(options.get("sentinel_one_action")),
        "{{epTruecontextid}}":     _value_or_na(parsed.get("ep_true_context_id")),
        "{{epSentinelonetype}}":   _value_or_na(parsed.get("ep_sentinel_one_type")),
        "{{epSentinelonepath}}":   _value_or_na(parsed.get("ep_sentinel_one_path")),
        "{{epMessagesentinelone}}": _value_or_na(parsed.get("ep_message_sentinel_one")),
        "{{epAdminalerttitle}}":   _value_or_na(parsed.get("ep_admin_alert_title")),
        "{{epAdmingroupname}}":    _value_or_na(parsed.get("ep_admin_group_name")),
        "{{epAddedmembername}}":   _value_or_na(parsed.get("ep_added_member_name")),
        "{{epAddedmemberdn}}":     _value_or_na(parsed.get("ep_added_member_dn")),
        "{{epEventlogsourceid}}":  _value_or_na(parsed.get("ep_event_log_source_id")),
        "{{epLogname}}":           _value_or_na(parsed.get("ep_log_name")),
        "{{epSubjectaccountname}}": _value_or_na(parsed.get("ep_subject_account_name")),
        "{{epSubjectaccountdomain}}": _value_or_na(parsed.get("ep_subject_account_domain")),
        "{{epMemberaccountname}}":  _value_or_na(parsed.get("ep_member_account_name")),
        "{{epGroupname}}":         _value_or_na(parsed.get("ep_group_name")),
        "{{epCreatedByProcess}}":  _value_or_na(parsed.get("ep_created_by_process")),
        "{{epCertificate}}":       _value_or_na(parsed.get("ep_certificate")),
        "{{ActivityDateTimeUtc}}": parsed.get("activity_dt_raw") or "N/A",
        "{{DetectedDateTimeUtc}}": parsed.get("detected_dt_raw") or "N/A",
        "{{LastUpdatedDateTimeUtc}}": parsed.get("last_updated_raw") or "N/A",
        "{{FirstLoginCreatedDate}}":  _value_or_na(parsed.get("first_login_created_raw")),
        "{{SecondLoginCreatedDate}}": _value_or_na(parsed.get("second_login_created_raw")),
        "{{Ip1Location}}":         _value_or_na(ip1.get("location_display")),
        "{{Ip1Country}}":          _value_or_na(ip1.get("country")),
        "{{Ip1Region}}":           _value_or_na(ip1.get("region")),
        "{{Ip1City}}":             _value_or_na(ip1.get("city")),
        "{{Ip1isp}}":              _value_or_na(ip1.get("isp")),
        "{{Ip1AbuseScore}}":       str(ip1.get("abuse_confidence_score")) if ip1.get("abuse_confidence_score") is not None else "N/A",
        "{{Ip1AbuseReports}}":     str(ip1.get("total_reports")) if ip1.get("total_reports") is not None else "N/A",
        "{{Ip1AbuseSummary}}":     _value_or_na(ip1.get("abuse_summary")),
        "{{Ip1VirusTotalMalicious}}":  str(ip1.get("malicious_count")) if ip1.get("malicious_count") is not None else "N/A",
        "{{Ip1VirusTotalSuspicious}}": str(ip1.get("suspicious_count")) if ip1.get("suspicious_count") is not None else "N/A",
        "{{Ip1VirusTotalVerdict}}":     _value_or_na(ip1.get("virustotal_verdict")),
        "{{Ip1VirusTotalAttackHistory}}": _value_or_na(ip1.get("virustotal_attack_history")),
        "{{VTattackhistory}}":     _value_or_na(ip1.get("virustotal_attack_history")),
        "{{Ip1ProxyCheckVpnStatus}}": _value_or_na(ip1.get("proxy_vpn_status")),
        "{{ProxyCheckVpnStatus}}": _value_or_na(ip1.get("proxy_vpn_status")),
        "{{AdditionalInfo}}":      _value_or_na(parsed.get("additional_info")),
        "{{AdditionalInfoRiskReasons}}": _value_or_na(parsed.get("additional_info_risk_reasons")),
        "{{AdditionalInfoUserAgent}}":   _value_or_na(parsed.get("additional_info_user_agent")),
        "{{TapInitiatedByDisplayName}}": _value_or_na(parsed.get("tap_initiated_by_display_name")),
        "{{TapInitiatedByUserPrincipalName}}": _value_or_na(parsed.get("tap_initiated_by_upn")),
        "{{TapDuration}}":         _calculate_tap_duration(parsed.get("tap_start_raw"), parsed.get("tap_end_raw")),
        "{{Ip2Location}}":         _value_or_na(ip2.get("location_display")),
        "{{Ip2Country}}":          _value_or_na(ip2.get("country")),
        "{{Ip2Region}}":           _value_or_na(ip2.get("region")),
        "{{Ip2City}}":             _value_or_na(ip2.get("city")),
        "{{Ip2isp}}":              _value_or_na(ip2.get("isp")),
        "{{Ip2AbuseScore}}":       str(ip2.get("abuse_confidence_score")) if ip2.get("abuse_confidence_score") is not None else "N/A",
        "{{Ip2AbuseReports}}":     str(ip2.get("total_reports")) if ip2.get("total_reports") is not None else "N/A",
        "{{Ip2AbuseSummary}}":     _value_or_na(ip2.get("abuse_summary")),
        "{{Ip2VirusTotalMalicious}}":  str(ip2.get("malicious_count")) if ip2.get("malicious_count") is not None else "N/A",
        "{{Ip2VirusTotalSuspicious}}": str(ip2.get("suspicious_count")) if ip2.get("suspicious_count") is not None else "N/A",
        "{{Ip2VirusTotalVerdict}}":     _value_or_na(ip2.get("virustotal_verdict")),
        "{{Ip2VirusTotalAttackHistory}}": _value_or_na(ip2.get("virustotal_attack_history")),
        "{{Ip2ProxyCheckVpnStatus}}": _value_or_na(ip2.get("proxy_vpn_status")),
        "{{ResponseAction}}":      response_action_label,
        "{{ResponseFooter}}":      response_footer,
        "{{Signature}}":           signature_html or "",
        "{{RunbookBlurb}}":        runbook_blurb_text if options.get("include_runbook_blurb") else "",
        "{{ExclusionAddedBlurb}}": "An exclusion has been added for this detection." if options.get("include_exclusion") else "",
        "{{MaintenanceStatus}}":   maintenance,
    }


def _render_subject(alert_type_id, options, parsed):
    label = ALERT_LABEL_BY_ID.get(alert_type_id, "Security Alert")
    org = options.get("organization") or "Organization"
    asset = options.get("asset_name") or parsed.get("asset_name") or ""
    if asset:
        return f"[MDR Alert] {label} — {org} — {asset}"
    return f"[MDR Alert] {label} — {org}"


def _render_html(template_text, replacements, signature_html, include_runbook):
    """Render line-by-line, wrap each line in <div>, encode tokens as <strong>,
    inject signature HTML raw."""
    runbook_blurb = (
        "We recommend updating the runbook for this organization. Having an up-to-date "
        "runbook significantly enhances our response time and quality of communication "
        "for critical alerts."
    )
    normalized = template_text.replace("\r\n", "\n")
    lines = normalized.split("\n")
    html_parts: List[str] = []
    signature_injected = False
    for raw_line in lines:
        line = raw_line or ""
        if line.strip() == "{{Signature}}":
            if include_runbook and "{{RunbookBlurb}}" not in template_text:
                html_parts.append(
                    f'<div style="margin:0; line-height:1.4;">{html_escape(runbook_blurb)}</div><br>'
                )
            html_parts.append(signature_html or "")
            signature_injected = True
            continue
        if not line.strip():
            html_parts.append('<div style="margin:0; line-height:1.4;"><br></div>')
            continue
        line_html = ""
        position = 0
        while position < len(line):
            token_start = line.find("{{", position)
            if token_start < 0:
                line_html += html_escape(line[position:])
                break
            if token_start > position:
                line_html += html_escape(line[position:token_start])
            token_end = line.find("}}", token_start)
            if token_end < 0:
                line_html += html_escape(line[token_start:])
                break
            token = line[token_start:token_end + 2]
            if token in replacements:
                value = replacements[token]
                if token == "{{Signature}}":
                    if include_runbook and "{{RunbookBlurb}}" not in template_text:
                        line_html += f'<div>{html_escape(runbook_blurb)}</div><br>'
                    line_html += signature_html or ""
                    signature_injected = True
                elif token == "{{RunbookBlurb}}":
                    if value:
                        line_html += f'<div>{html_escape(value)}</div><br>'
                elif token == "{{MaintenanceStatus}}":
                    if value:
                        encoded = html_escape(value).replace("\n", "<br>")
                        line_html += f'<div>{encoded}</div>'
                else:
                    display = value if (value and str(value).strip()) else "N/A"
                    encoded = (html_escape(str(display))
                               .replace("\n", "<br>")
                               .replace("  ", " &nbsp;"))
                    line_html += f'<strong>{encoded}</strong>'
            else:
                line_html += html_escape(token)
            position = token_end + 2
        html_parts.append(
            f'<div style="margin:0; line-height:1.4; background:transparent;">{line_html}</div>'
        )
    if not signature_injected and signature_html:
        if include_runbook:
            html_parts.append(f'<br>{html_escape(runbook_blurb)}<br>')
        html_parts.append(f'<br>{signature_html}')
    return "".join(html_parts)


def _build_signature_html(config) -> str:
    """Build the signature block from RECON settings.

    If EMAIL_SIGNATURE is set: honor it verbatim (HTML or plain).
    Otherwise: render a minimal block with just the configured name/address —
    no hardcoded role title, no fallback name. If nothing is configured at
    all, return an empty string so the email ends cleanly."""
    name = (config.get("EMAIL_FROM_NAME") or "").strip()
    addr = (config.get("EMAIL_FROM_ADDRESS") or "").strip()
    custom = config.get("EMAIL_SIGNATURE") or ""
    if custom.strip():
        if "<" in custom and ">" in custom:
            return custom
        lines = [html_escape(l) for l in custom.split("\n")]
        return ('<div style="font-family:\'IBM Plex Sans\', Arial, sans-serif; '
                'font-size:13px; line-height:1.4; margin-top:20px;">' +
                "".join(f'<div style="margin:0;">{l}</div>' for l in lines) +
                "</div>")
    if not name and not addr:
        return ""
    parts = ['<div style="font-family:\'IBM Plex Sans\', Arial, sans-serif; '
             'font-size:13px; line-height:1.4; margin-top:20px;">']
    if name:
        parts.append('<div style="margin:0;">Best regards,</div>')
        parts.append(f'<div style="font-weight:700; font-size:14px; margin:0;">{html_escape(name)}</div>')
    if addr:
        parts.append(f'<div style="margin:0;"><a href="mailto:{html_escape(addr)}" '
                     f'style="color:#0fbcff; text-decoration:none;">{html_escape(addr)}</a></div>')
    parts.append("</div>")
    return "".join(parts)


# ─── template store ──────────────────────────────────────────────────────────
def _ensure_templates_dir():
    _TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    # Seed from defaults if missing
    for alert_id, _label, _cat in ALERT_TYPES:
        path = _TEMPLATES_DIR / f"{alert_id}.txt"
        if not path.exists():
            path.write_text(_DEFAULT_TEMPLATES.get(alert_id, _DEFAULT_TEMPLATES["_generic"]),
                            encoding="utf-8")


def list_templates() -> List[Dict]:
    _ensure_templates_dir()
    out = []
    for alert_id, label, cat in ALERT_TYPES:
        out.append({"id": alert_id, "label": label, "category": cat,
                    "filename": f"{alert_id}.txt"})
    return out


def load_template(alert_id: str) -> str:
    _ensure_templates_dir()
    path = _TEMPLATES_DIR / f"{alert_id}.txt"
    if path.exists():
        return path.read_text(encoding="utf-8")
    return _DEFAULT_TEMPLATES.get(alert_id, _DEFAULT_TEMPLATES["_generic"])


def save_template(alert_id: str, body: str) -> bool:
    """Let analysts edit templates from the UI."""
    safe = re.sub(r"[^a-z0-9_]", "_", alert_id.lower())
    if safe not in {a[0] for a in ALERT_TYPES}:
        return False
    _ensure_templates_dir()
    (_TEMPLATES_DIR / f"{safe}.txt").write_text(body, encoding="utf-8")
    return True


# ─── compose (public) ─────────────────────────────────────────────────────────
def compose(alert_type: str, parsed: Dict, options: Dict, config,
            ip1: Optional[Dict] = None, ip2: Optional[Dict] = None) -> Dict:
    """Render the email — returns {subject, text, html}."""
    template = load_template(alert_type)
    options = {**options, "alert_type": alert_type}
    signature_html = _build_signature_html(config)
    replacements = _build_replacement_map(parsed or {}, options, signature_html, ip1, ip2)

    text = template
    for k, v in replacements.items():
        if k == "{{Signature}}":
            text = text.replace(k, _signature_plain(config))
        else:
            text = text.replace(k, v if v is not None else "")

    html = _render_html(template, replacements, signature_html,
                        options.get("include_runbook_blurb") or False)
    subject = _render_subject(alert_type, options, parsed or {})
    text = _strip_closing_block(text)
    html = _strip_closing_block_html(html)
    text = _inject_closing_text(text, _signature_plain(config))
    html = _inject_closing_html(html, signature_html)
    # Last-pass dash strip — catches anything injected after the AI body
    # was first sanitized (closing statement, signature line, future templates).
    text = _strip_em_dashes(text)
    html = _strip_em_dashes(html)
    subject = _strip_em_dashes(subject)
    # Collapse 3+ consecutive newlines down to a single blank line so empty
    # conditional placeholders ({{DomainJoinedNote}} etc.) don't leave a
    # double-spaced gap when they render as "".
    text = re.sub(r"\n{3,}", "\n\n", text)
    return {"subject": subject, "text": text, "html": html, "template_used": alert_type}


# Matches all phrasings of the "If you have any questions..." closing line
# we ship in defaults, regardless of what middle phrase a template uses.
_CLOSING_RE = re.compile(
    r"\n*If you have (?:any )?questions[^\n]*?(?:reach out|contact)[^\n]*\n*",
    re.IGNORECASE,
)

# Generic closing statement appended to every composed email, right before
# the signature. Mirrors the original tool's per-template closers but is
# vendor-neutral.
_CLOSING_STATEMENT = (
    "We'll continue monitoring your environment for any related activity. "
    "If this activity looks unfamiliar or unauthorized, please contact us right "
    "away so we can act quickly, and as always, we're here for any questions."
)


def _strip_closing_block(text: str) -> str:
    """Drop the canned 'If you have questions, reach out to ...' line from
    plain-text output. Templates often append this right before the signature;
    analysts asked to remove it because their signature already invites reply."""
    return _CLOSING_RE.sub("\n", text or "").rstrip() + "\n"


def _strip_closing_block_html(html: str) -> str:
    """Same idea for HTML — the renderer wraps each line in <div>...</div>,
    so we drop any div whose text starts with 'If you have ... questions'."""
    return re.sub(
        r'<div[^>]*>\s*If you have (?:any )?questions[^<]*?(?:reach out|contact)[^<]*</div>',
        "",
        html or "",
        flags=re.IGNORECASE,
    )


def _inject_closing_text(text: str, sig_plain: str) -> str:
    """Insert the generic closing statement before the signature in plain text.
    Falls back to appending at the end when there's no signature block."""
    closing = "\n\n" + _CLOSING_STATEMENT
    if sig_plain and sig_plain in (text or ""):
        return text.replace(sig_plain, closing + sig_plain, 1)
    return (text or "").rstrip() + closing + "\n"


def _inject_closing_html(html: str, sig_html: str) -> str:
    """Insert the generic closing statement before the signature in HTML."""
    closing = (f'<div style="margin:16px 0 0; line-height:1.4;">'
               f'{html_escape(_CLOSING_STATEMENT)}</div>')
    if sig_html and sig_html in (html or ""):
        return html.replace(sig_html, closing + sig_html, 1)
    return (html or "") + closing


def _signature_plain(config) -> str:
    name = (config.get("EMAIL_FROM_NAME") or "").strip()
    addr = (config.get("EMAIL_FROM_ADDRESS") or "").strip()
    custom = config.get("EMAIL_SIGNATURE") or ""
    if custom.strip() and "<" not in custom:
        return "\n" + custom
    if not name and not addr:
        return ""
    lines = [""]
    if name:
        lines += ["Best regards,", name]
    if addr:
        lines.append(addr)
    return "\n".join(lines)


# ─── AI-generated templates ───────────────────────────────────────────────────
# Few-shot generator that produces a customer-facing email tailored to the
# specific log content. Existing static templates serve as style/tone models.

# Default inspiration set spanning identity and endpoint alert classes so the
# AI sees both phrasing styles. When the analyst's log triggers a specific
# detected alert type, the matching template is prepended to this list (same-
# category siblings auto-included via _category_siblings).
_AI_EXAMPLE_IDS = [
    "impossible_travel",
    "defender_detection",
    "powershell_policy_bypass",
    "ransomware",
    "user_added_to_local_admin",
]


def _category_for(alert_id: str) -> str:
    for aid, _label, cat in ALERT_TYPES:
        if aid == alert_id:
            return cat
    return ""


def _category_siblings(alert_id: str, k: int = 4) -> list:
    """Up to k other alert ids in the same category — used so the inspiration
    set leans toward the analyst's actual alert class. Skip the alert itself."""
    cat = _category_for(alert_id)
    if not cat:
        return []
    sibs = [aid for aid, _label, c in ALERT_TYPES if c == cat and aid != alert_id]
    return sibs[:k]


def _ai_example_block(priority_alert_type: str = "",
                      context_substitutions: dict | None = None) -> str:
    """Render in-repo templates as inspiration. When `priority_alert_type` is
    set, lead with that template + same-category siblings so the AI's style
    leans toward the analyst's actual alert. All examples are framed as
    inspiration — the prompt explicitly tells the AI not to copy verbatim.

    Always loads via `load_template` so analyst-edited templates flow through
    too (not just the hardcoded _DEFAULT_TEMPLATES). That's the whole point:
    when the team's wording norms or policy text changes, the templates
    change and the AI naturally adapts.

    `context_substitutions` is an optional {{placeholder}} -> value map for
    CONTEXTUAL placeholders that carry semantic content the AI should
    actually pick up (e.g. {{DomainJoinedNote}} on impossible-travel when
    the alert has an asset_name). Without substitution the AI would see
    the raw "{{DomainJoinedNote}}" token in the inspiration and either
    ignore it or echo it verbatim. With substitution it sees the paragraph
    in the template and naturally adopts the voice/content. Trivial
    placeholders ({{Ip1}}, {{UserDisplayName}}, etc.) are scrubbed at the
    end so the AI doesn't see template-syntax noise either way."""
    # Build the inspiration set: priority + same-category siblings + a couple
    # of broad anchors so the model sees both identity and endpoint voices.
    ids: list = []
    if priority_alert_type and priority_alert_type in ALERT_LABEL_BY_ID:
        ids.append(priority_alert_type)
        for sib in _category_siblings(priority_alert_type, k=3):
            if sib not in ids:
                ids.append(sib)
    # Top up with the broad anchor set so identity AND endpoint voices are in
    # context even when the alert is in one category.
    for fallback in _AI_EXAMPLE_IDS:
        if fallback not in ids:
            ids.append(fallback)
        if len(ids) >= 6:
            break

    subs = context_substitutions or {}
    parts = []
    for aid in ids:
        body = load_template(aid)
        if not body:
            continue
        # Apply contextual substitutions first so semantic placeholders
        # (e.g. {{DomainJoinedNote}}) become the actual paragraph the AI
        # should pick up. Empty values drop the placeholder entirely.
        for key, val in subs.items():
            body = body.replace(key, val or "")
        # Collapse the gap left by an empty contextual substitution so the
        # inspiration doesn't show two blank lines in a row.
        body = re.sub(r"\n{3,}", "\n\n", body)
        # Scrub remaining {{Placeholder}} tokens so the AI doesn't echo
        # template syntax. <field-name> reads to the model as a natural
        # "fill in the alert's value here" hint without leaking literal
        # curly braces into the output.
        body = re.sub(r"\{\{(\w+)\}\}",
                      lambda m: f"<{m.group(1).lower()}>", body)
        label = ALERT_LABEL_BY_ID.get(aid, aid)
        parts.append(f"## Inspiration: {label}\n```\n{body[:1100]}\n```")
    return "\n\n".join(parts)


def _ai_context_substitutions(parsed: dict, options: dict) -> dict:
    """Build the {{placeholder}} -> value map for contextual content that
    needs to land in the AI-generated email when the underlying log has
    the right fields. Add new ones here as they're introduced."""
    subs: dict = {}
    asset = (options or {}).get("asset_name") or (parsed or {}).get("asset_name") or ""
    if asset:
        # Same explainer paragraph the static template uses. Centralised in
        # _build_replacement_map; pulling it from there avoids two copies
        # drifting out of sync.
        subs["{{DomainJoinedNote}}"] = (
            "When domain-joined assets trigger \"impossible travel\" alerts in systems "
            "like Microsoft Entra ID Protection, it is usually caused by cloud "
            "proxies/VPNs, split-tunneling, or inaccurate geolocation databases. "
            "Even securely managed or Hybrid Azure AD-joined devices can generate "
            "these false-positive anomalies if network traffic routing masks the "
            "actual location of the physical machine."
        )
    else:
        subs["{{DomainJoinedNote}}"] = ""
    return subs


_AI_SYSTEM = """You are a senior MDR security analyst drafting customer-facing
email notifications about security alerts. The example templates below are
INSPIRATION ONLY: match their tone, voice, level of technical detail, and
section ordering, but adapt the content to the specific evidence in the raw
log at hand. Do NOT copy phrases verbatim. If the alert type is unfamiliar,
synthesize a fresh template by combining the closest stylistic matches.

Hard rules:
- Output ONLY the email body. No subject line. No commentary.
- Never invent values not present in the log. If a value is unknown, omit
  the field rather than writing "N/A".
- Do NOT include a closing line like "If you have any questions, reach out
  to..." (the analyst's signature handles that).
- Do NOT include a signature block (no "Best regards," / name / title).
  The system appends one automatically.
- Plain text only, no markdown formatting, no asterisks, no underscores.
- Keep it concise (8 to 14 lines including blank lines).
- The first line should be a greeting (e.g. "Greetings,").
- DASH RULES (this is how editors spot AI-written copy, so it matters):
    * Do NOT use em dashes (the long dash). Use a comma, a colon, a period,
      or rewrite the sentence so no dash is needed.
    * Do NOT use en dashes (the medium dash).
    * Hyphens are allowed only inside compound words (e.g. "in-flight",
      "anti-virus", "two-factor"). Never as a sentence-level separator.
"""


async def compose_ai(log_text: str, parsed: Optional[Dict], options: Dict,
                     config) -> Dict:
    """Generate a fresh template body via AI, then run it through the same
    render pipeline so the signature, subject, and HTML wrapping match the
    static-template flow. Returns {subject, text, html, template_used}."""
    if not log_text or not log_text.strip():
        return {"error": "log_text required"}

    key = config.get("OPENAI_API_KEY")
    if not key:
        return {"error": "OPENAI_API_KEY not configured"}

    # Short customer-facing email — light, latency-sensitive → fast model tier.
    # NOTE: `config` here is a plain dict (passed from the endpoint), not the
    # ConfigManager, so resolve the fast model via dict access, not get_model().
    model    = config.get("FAST_AI_MODEL") or config.get("AI_MODEL") or "gpt-4o-mini"
    parsed   = parsed or {}
    options  = options or {}

    # Compact parsed-fields summary for the AI (drop empty + housekeeping keys)
    parsed_view = {k: v for k, v in parsed.items()
                   if v not in (None, "", "N/A") and not k.startswith("_")
                   and k not in ("raw_fields", "suggested_alert_type")}
    parsed_block = "\n".join(f"- {k}: {v}" for k, v in list(parsed_view.items())[:30])

    response_action = options.get("response_action") or ""
    action_hint = ""
    if response_action:
        for rid, rlabel in RESPONSE_ACTIONS:
            if rid == response_action:
                action_hint = f"\n\nAction we took: {rlabel}"
                break

    # Template-aware inspiration: when triage detected an alert type, the
    # matching template is included first in the inspiration set (plus same-
    # category siblings via _category_siblings). The AI is told to use them
    # as voice/structure inspiration and adapt to the actual log, not copy.
    # When the alert type is unfamiliar (not in the catalog), the broad
    # anchor set still surfaces both identity and endpoint voices so the AI
    # can synthesize a fresh template by combining styles.
    detected_alert_type = parsed.get("suggested_alert_type") or options.get("alert_type") or ""
    classified_as = (f"This alert was classified as '{ALERT_LABEL_BY_ID[detected_alert_type]}'. "
                     if detected_alert_type and detected_alert_type in ALERT_LABEL_BY_ID
                     else "This alert type wasn't recognized by triage, so synthesize a fresh template "
                          "using the closest stylistic matches below. ")

    # Contextual placeholders that carry actual content (currently
    # {{DomainJoinedNote}} for impossible-travel-with-asset). These get
    # substituted into the inspiration templates BEFORE the AI sees them,
    # so the AI naturally picks the paragraph up as part of the alert
    # class's voice. An additional MUST-INCLUDE rule for any non-empty
    # substitution makes sure the paragraph survives even if the model
    # tries to compress.
    context_subs = _ai_context_substitutions(parsed, options)
    inspiration  = _ai_example_block(priority_alert_type=detected_alert_type,
                                     context_substitutions=context_subs)
    must_include = "\n".join(
        f"- Must include this paragraph (verbatim or lightly rephrased): {v}"
        for v in context_subs.values() if v
    )
    must_include_block = (f"\n\nADDITIONAL RULES FOR THIS ALERT:\n{must_include}\n"
                          if must_include else "")

    user_prompt = (
        f"{inspiration}\n\n"
        "## Now write an email for THIS alert\n"
        f"{classified_as}Use the inspiration above for voice and structure, "
        "but write a fresh email adapted to the evidence in the raw log. Do not "
        "copy any sentence verbatim from the examples."
        f"{must_include_block}\n\n"
        "Raw log:\n```\n"
        f"{log_text[:5000]}\n```\n\n"
        f"Extracted fields:\n{parsed_block or '(none)'}"
        f"{action_hint}\n\n"
        "Write the email body only. Plain text. No subject line. No signature. "
        "No em dashes or en dashes anywhere in the output."
    )

    from providers import get_provider
    provider = get_provider()
    resp = await provider.complete(
        model=model,
        messages=[
            {"role": "system", "content": _AI_SYSTEM},
            {"role": "user",   "content": user_prompt},
        ],
        temperature=0.4,
        max_tokens=900,
    )
    if resp.error:
        return {"error": f"AI call failed: {resp.error}"}
    body = (resp.message or "").strip()
    if not body:
        return {"error": "AI returned empty body"}

    # Strip em/en dashes (belt-and-braces — the prompt also forbids them, but
    # models still occasionally produce them and they're the #1 AI-giveaway in
    # customer-facing email).
    body = _strip_em_dashes(body)

    # Defang URLs / IPs / domains the AI emitted so the recipient can't click
    # a live IOC out of a security email. Opt-out via options.defang=false for
    # internal-only audiences that already strip in their mail client.
    if options.get("defang", True):
        body = _defang_body_iocs(body)

    # Run the AI body through the same render pipeline so subject + signature
    # + HTML wrapping stay consistent with template-based composes.
    signature_html = _build_signature_html(config)
    replacements   = _build_replacement_map(parsed, {**options, "alert_type": "ai"},
                                            signature_html, None, None)
    text_body = body + "{{Signature}}"
    text = text_body
    for k, v in replacements.items():
        if k == "{{Signature}}":
            text = text.replace(k, _signature_plain(config))
        else:
            text = text.replace(k, v if v is not None else "")
    html = _render_html(text_body, replacements, signature_html, False)
    subject = _render_subject_ai(log_text, parsed)
    text = _strip_closing_block(text)
    html = _strip_closing_block_html(html)
    text = _inject_closing_text(text, _signature_plain(config))
    html = _inject_closing_html(html, signature_html)
    # Last-pass dash strip — catches anything injected after the AI body
    # was first sanitized (closing statement, signature line, future templates).
    text = _strip_em_dashes(text)
    html = _strip_em_dashes(html)
    subject = _strip_em_dashes(subject)
    # Collapse 3+ consecutive newlines down to a single blank line so empty
    # conditional placeholders ({{DomainJoinedNote}} etc.) don't leave a
    # double-spaced gap when they render as "".
    text = re.sub(r"\n{3,}", "\n\n", text)
    return {"subject": subject, "text": text, "html": html, "template_used": "ai_generated"}


def _render_subject_ai(log_text: str, parsed: Dict) -> str:
    """Heuristic subject for AI-generated emails — re-uses the alert-type
    suggester to pick a label, falls back to a generic security-alert line."""
    suggested = suggest_alert_type(log_text, parsed)
    label = ALERT_LABEL_BY_ID.get(suggested) if suggested else None
    # Org hint: prefer an explicit org name, else derive from the user's email
    # domain (identifies the customer). Never emit the literal "Organization"
    # placeholder — drop the suffix entirely when we can't determine an org.
    org = parsed.get("organization_name")
    if not org:
        upn = (parsed.get("user_principal_name") or parsed.get("target_user_principal_name") or "")
        if "@" in upn:
            dom = upn.split("@")[-1].strip().lower()
            if dom and dom not in ("gmail.com", "outlook.com", "hotmail.com",
                                   "yahoo.com", "icloud.com", "live.com", "aol.com"):
                org = dom
    base = f"[MDR Alert] {label or 'Security Alert'}"
    return f"{base} — {org}" if org else base


# ─── SMTP send ────────────────────────────────────────────────────────────────
def send_smtp(subject: str, body_html: str, body_text: str, to: str,
              cc: str, config) -> Dict:
    host = config.get("EMAIL_SMTP_HOST")
    port = int(config.get("EMAIL_SMTP_PORT") or 587)
    user = config.get("EMAIL_SMTP_USER")
    password = config.get("EMAIL_SMTP_PASSWORD")
    from_addr = config.get("EMAIL_FROM_ADDRESS") or user
    from_name = config.get("EMAIL_FROM_NAME") or ""
    if not (host and from_addr and to):
        return {"sent": False, "error": "SMTP not fully configured (need EMAIL_SMTP_HOST, "
                                        "EMAIL_FROM_ADDRESS, and a recipient)"}

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{from_name} <{from_addr}>"
    msg["To"] = to
    recipients = [r.strip() for r in to.split(",") if r.strip()]
    cc_list = [c.strip() for c in (cc or "").split(",") if c.strip()]
    if cc_list:
        msg["Cc"] = ", ".join(cc_list)
        recipients += cc_list
    msg.attach(MIMEText(body_text or "", "plain", "utf-8"))
    msg.attach(MIMEText(body_html or "", "html",  "utf-8"))
    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=20) as s:
                if user and password: s.login(user, password)
                s.sendmail(from_addr, recipients, msg.as_string())
        else:
            with smtplib.SMTP(host, port, timeout=20) as s:
                s.starttls()
                if user and password: s.login(user, password)
                s.sendmail(from_addr, recipients, msg.as_string())
    except Exception as e:
        return {"sent": False, "error": str(e)[:300]}
    return {"sent": True, "recipients": recipients}


def list_alert_types():
    return [{"id": a[0], "label": a[1], "category": a[2]} for a in ALERT_TYPES]


def list_response_actions():
    return [{"id": a[0], "label": a[1]} for a in RESPONSE_ACTIONS]


# ─── Default templates (ThreatLocker branding stripped) ───────────────────────
# Source: TL.MDR.email/Templates/*.txt, scrubbed per email-tool-audit.md.
# Patterns applied globally:
#   "ThreatLocker MDR Team"               → "{{TeamName}}"
#   "ThreatLocker MDR has identified"     → "Our MDR team has identified"
#   "Threatlocker" / "ThreatLocker"       → dropped or replaced contextually
#   "TL.CD.090 - ThreatLocker"            → ""
#   "ThreatLocker Response Center"        → "the MDR console"
#   "ThreatLocker Support / LiveChat"     → "the on-call analyst"
#   "the ThreatLocker service"            → "the endpoint security agent"
_DEFAULT_TEMPLATES: Dict[str, str] = {
    "_generic": (
        "Greetings,\n\n"
        "Our MDR team has identified a security event of interest within {{epOrg}} on "
        "{{epDate}}(UTC) involving {{AssetName}}.\n\n"
        "Detection Details:\n"
        "- Endpoint: {{AssetName}}\n"
        "- User: {{epUser}}\n"
        "- Detected Time: {{epDate}} (UTC)\n"
        "- Message: {{epMessage}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{MaintenanceStatus}}\n"
        "{{ResponseFooter}}\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "user_at_risk": (
        "Greetings,\n\n"
        "Microsoft has identified a user-at-risk alert associated with one of your "
        "user accounts.\n\n"
        "Detection Details:\n"
        "- User: {{UserDisplayName}}\n"
        "- UPN: {{UserPrincipalName}}\n"
        "- User ID: {{UserId}}\n"
        "- Risk Event Type: {{RiskEventType}}\n"
        "- Risk Level: {{RiskLevel}}\n"
        "- Risk State: {{RiskState}}\n"
        "- Risk Detail: {{RiskDetail}}\n"
        "- Activity: {{Activity}}\n"
        "- Detected Time: {{DetectedDateTimeUtc}} (UTC)\n"
        "- Last Updated: {{LastUpdatedDateTimeUtc}} (UTC)\n"
        "- Observed IP: {{Ip1}}\n"
        "- Location: {{Ip1Location}}\n"
        "- AbuseIPDB Summary: {{Ip1AbuseSummary}}\n"
        "- VirusTotal Verdict: {{Ip1VirusTotalVerdict}}\n"
        "- Request ID: {{RequestId}}\n"
        "- Correlation ID: {{CorrelationId}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{ResponseFooter}}\n\n"
        "If you have any questions or require further technical details, please reach "
        "out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "impossible_travel": (
        "Greetings,\n\n"
        "At approximately {{FirstLoginCreatedDate}} UTC, we received an alert for the "
        "Microsoft 365 account {{UserPrincipalName}} (display name: {{UserDisplayName}}) "
        "indicating impossible travel. The user logged in from two geographically "
        "distinct locations within an impossible time period. The first login originated "
        "from the IP {{Ip1}} which traces back to {{Ip1Location}} from {{Ip1isp}}. The "
        "second login originated from the IP {{Ip2}} which traces back to {{Ip2Location}} "
        "from {{Ip2isp}}.\n\n"
        "First IP {{Ip1}}: {{Ip1VirusTotalAttackHistory}}\n"
        "Second IP {{Ip2}}: {{Ip2VirusTotalAttackHistory}}\n\n"
        "{{DomainJoinedNote}}\n\n"
        "{{ResponseFooter}}\n\n"
        "If you have any questions or concerns, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "anonymized_ip": (
        "Greetings,\n\n"
        "Microsoft has identified an anonymized IP alert associated with one of your "
        "accounts. The activity involved a sign-in or action tied to an IP address that "
        "traces back to {{Ip1Location}}.\n\n"
        "Detection Details:\n"
        "- User: {{UserDisplayName}}\n"
        "- UPN: {{UserPrincipalName}}\n"
        "- Risk Event Type: {{RiskEventType}}\n"
        "- Risk Level: {{RiskLevel}}\n"
        "- Risk State: {{RiskState}}\n"
        "- Activity: {{Activity}}\n"
        "- Source: {{Source}}\n"
        "- Detected Time: {{DetectedDateTimeUtc}} (UTC)\n"
        "- Observed IP: {{Ip1}}\n"
        "- Location: {{Ip1Location}}\n"
        "- ISP: {{Ip1isp}}\n"
        "- Proxy/VPN Status: {{ProxyCheckVpnStatus}}\n"
        "- AbuseIPDB Summary: {{Ip1AbuseSummary}}\n"
        "- VirusTotal Verdict: {{Ip1VirusTotalVerdict}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{ResponseFooter}}\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "password_spray": (
        "Greetings,\n\n"
        "Microsoft has identified a password spray alert involving one of your user "
        "accounts.\n\n"
        "Detection Details:\n"
        "- User: {{UserDisplayName}}\n"
        "- UPN: {{UserPrincipalName}}\n"
        "- Risk Event Type: {{RiskEventType}}\n"
        "- Risk Level: {{RiskLevel}}\n"
        "- Risk State: {{RiskState}}\n"
        "- Activity: {{Activity}}\n"
        "- Detected Time: {{DetectedDateTimeUtc}} (UTC)\n"
        "- Observed IP: {{Ip1}}\n"
        "- Location: {{Ip1Location}}\n"
        "- AbuseIPDB Summary: {{Ip1AbuseSummary}}\n"
        "- VirusTotal Verdict: {{Ip1VirusTotalVerdict}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{ResponseFooter}}\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "unfamiliar_signin": (
        "Greetings,\n\n"
        "Microsoft has identified an unfamiliar sign-in alert involving one of your "
        "user accounts.\n\n"
        "Detection Details:\n"
        "- User: {{UserDisplayName}}\n"
        "- UPN: {{UserPrincipalName}}\n"
        "- Risk Event Type: {{RiskEventType}}\n"
        "- Risk Level: {{RiskLevel}}\n"
        "- Risk State: {{RiskState}}\n"
        "- Activity: {{Activity}}\n"
        "- Activity Time: {{ActivityDateTimeUtc}} (UTC)\n"
        "- Observed IP: {{Ip1}}\n"
        "- Location: {{Ip1Location}}\n"
        "- AbuseIPDB Summary: {{Ip1AbuseSummary}}\n"
        "- VirusTotal Verdict: {{Ip1VirusTotalVerdict}}\n"
        "- Unfamiliar Properties:\n"
        "{{AdditionalInfo}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{ResponseFooter}}\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "login_to_disabled_account": (
        "Greetings,\n\n"
        "Microsoft has identified a login to a disabled account involving one of your "
        "user accounts.\n\n"
        "Detection Details:\n"
        "- User: {{UserDisplayName}}\n"
        "- UPN: {{UserPrincipalName}}\n"
        "- Activity: {{Activity}}\n"
        "- Detected Time: {{DetectedDateTimeUtc}} (UTC)\n"
        "- Observed IP: {{Ip1}}\n"
        "- Location: {{Ip1Location}}\n"
        "- AbuseIPDB Summary: {{Ip1AbuseSummary}}\n"
        "- VirusTotal Verdict: {{Ip1VirusTotalVerdict}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{ResponseFooter}}\n\n"
        "This account arrived in a locked state and can currently be unlocked through "
        "the Entra portal. If this login attempt was not authorized, we recommend "
        "validating the activity with the user and confirming that any active session "
        "tokens are withdrawn.\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "temporary_access_pass": (
        "Greetings,\n\n"
        "Microsoft has identified a Temporary Access Pass related alert involving one "
        "of your user accounts.\n\n"
        "Detection Details:\n"
        "- Initiated by: {{TapInitiatedByDisplayName}}\n"
        "- Given To: {{TargetUserDisplayName}}\n"
        "- Duration: {{TapDuration}}\n"
        "- Observed IP: {{Ip1}}\n"
        "- Location: {{Ip1Location}}\n"
        "- AbuseIPDB Summary: {{Ip1AbuseSummary}}\n"
        "- VirusTotal Verdict: {{Ip1VirusTotalVerdict}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{ResponseFooter}}\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "creation_of_admin_account": (
        "Greetings,\n\n"
        "Our MDR team has identified activity consistent with privileged group "
        "membership being granted to an administrative account within {{epOrg}} on "
        "endpoint {{AssetName}}.\n\n"
        "Detection Details:\n"
        "- Admin Tier Added: {{epAdmingroupname}}\n"
        "- Added Member: {{epAddedmembername}}\n"
        "- Initiating User: {{UserDisplayName}}\n"
        "- Event ID: {{epEventlogsourceid}}\n"
        "- Activity: {{Activity}}\n"
        "- Source: {{Source}}\n"
        "- Detected Time: {{DetectedDateTimeUtc}} (UTC)\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{MaintenanceStatus}}\n"
        "{{ResponseFooter}}\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "privileged_role": (
        "Greetings,\n\n"
        "Microsoft has identified a privileged role alert involving the account "
        "{{TargetUserPrincipalName}}.\n\n"
        "Detection Details:\n"
        "- Target User: {{TargetUserPrincipalName}}\n"
        "- Initiated By: {{UserPrincipalName}}\n"
        "- Role Name: {{PrivilegedRoleDisplayName}}\n"
        "- Role Well-Known Name: {{PrivilegedRoleWellKnownObjectName}}\n"
        "- Observed IP: {{Ip1}}\n"
        "- AbuseIPDB Summary: {{Ip1AbuseSummary}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{ResponseFooter}}\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "forwarding_rule": (
        "Greetings,\n\n"
        "Our MDR team has identified a new email forwarding rule created within your "
        "environment.\n\n"
        "Detection Details:\n"
        "- User: {{UserId}}\n"
        "- Detected Time: {{ActivityDateTimeUtc}}\n"
        "- Client IP: {{Ip1}}\n"
        "- Forwarding Address: {{ForwardingAddress}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{ResponseFooter}}\n\n"
        "Please review this event and confirm whether this forwarding rule was expected "
        "and authorized.\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "defender_detection": (
        "Greetings,\n\n"
        "Microsoft Defender Antivirus has identified a potential security threat on one "
        "of your endpoints. The detection is of {{epDefenderType1}} for {{epOrg}} on "
        "endpoint {{AssetName}} on {{epDate}}(UTC).\n\n"
        "Detection Details:\n"
        "- Endpoint: {{AssetName}}\n"
        "- User: {{epUser}}\n"
        "- Malware Family: {{epDefenderType1}}:{{epDefenderType2}}\n"
        "- Detected Time: {{epDate}} (UTC)\n"
        "- Action Taken: {{epDefenderaction}}\n"
        "- File Path: {{epDefenderfile}}\n"
        "- Process Path: {{epDefenderpath}}\n\n"
        "{{MaintenanceStatus}}\n"
        "{{ResponseFooter}}\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "defender_exclusion_created": (
        "Greetings,\n\n"
        "Microsoft Defender has identified a configuration change involving an exclusion "
        "on {{AssetName}} within {{epOrg}} on {{epDate}}(UTC).\n\n"
        "Detection Details:\n"
        "- User: {{UserPrincipalName}}\n"
        "- Detected Time: {{DetectedDateTimeUtc}}\n"
        "- New Value: {{epDefenderExclusionNewValue}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{MaintenanceStatus}}\n"
        "{{ResponseFooter}}\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "sentinel_one_detection": (
        "Greetings,\n\n"
        "On {{epDate}} UTC, we received an alert from hostname {{AssetName}} within "
        "{{epOrg}} for a SentinelOne detection, classified as {{epSentinelonetype}}.\n\n"
        "SentinelOne has identified a potential security threat on one of your "
        "endpoints.\n"
        "Detection Details:\n"
        "\tEndpoint: {{AssetName}}\n"
        "\tUser Account: {{epUser}}\n"
        "\tDetected Time: {{epDate}} (UTC)\n"
        "\tAction Result: {{epSentineloneaction}}\n"
        "\tTrue Context ID: {{epTruecontextid}}\n"
        "\tPath: {{epSentinelonepath}}\n"
        "\tAlert Message: {{epMessagesentinelone}}\n"
        "\tDetection Classifier: {{epSentinelonetype}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{MaintenanceStatus}}\n"
        "{{ResponseFooter}}\n\n"
        "We recommend a thorough review of activity on this host. Please confirm if any "
        "authorized maintenance or specialized administrative tasks were being performed "
        "at the time of this alert.\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "powershell_policy_bypass": (
        "Greetings,\n\n"
        "Our MDR team has identified a PowerShell execution policy bypass event on "
        "{{AssetName}} within {{epOrg}} on {{epDate}}(UTC). The use of the "
        "`-ExecutionPolicy Bypass` flag can be legitimate in some development or "
        "deployment workflows, but it can also indicate an attempt to execute "
        "unauthorized scripts.\n\n"
        "Detection Details:\n"
        "- Endpoint: {{AssetName}}\n"
        "- Domain: {{epDomain}}\n"
        "- User Account: {{epUser}}\n"
        "- Application: {{epApplicationname}}\n"
        "- Detected Time: {{DetectedDateTimeUtc}} (UTC)\n\n"
        "Execution Context:\n"
        "- Process Path: {{epProcesspath}}\n"
        "- Full Path: {{epFullpath}}\n"
        "- Command Line: {{epCmdline}}\n"
        "- Process ID: {{epProcessid}}\n"
        "- File Hash (SHA256): {{epSha256}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{MaintenanceStatus}}\n"
        "{{ResponseFooter}}\n\n"
        "We are notifying you of this event to ensure it aligns with your standard "
        "administrative or developer workflows. If this activity was not initiated by "
        "the user or is not consistent with their normal duties, further investigation "
        "may be required.\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "bitlocker_disable": (
        "Greetings,\n\n"
        "Our MDR team has identified activity consistent with BitLocker being disabled "
        "on {{AssetName}} within {{epOrg}} on {{epDate}}(UTC).\n\n"
        "Detection Details:\n"
        "- Date: {{epDate}}\n"
        "- User: {{epUser}}\n"
        "- Message: {{epMessage}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{MaintenanceStatus}}\n"
        "{{ResponseFooter}}\n\n"
        "Please review this event and confirm whether disabling BitLocker was expected "
        "administrative activity on this device.\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "reg_export": (
        "Greetings,\n\n"
        "Our MDR team has identified activity consistent with a registry export "
        "operation on {{AssetName}} within {{epOrg}} on {{epDate}}(UTC).\n\n"
        "Detection Details:\n"
        "- Endpoint: {{AssetName}}\n"
        "- Domain: {{epDomain}}\n"
        "- User Account: {{epUser}}\n"
        "- Detected Time: {{epDate}} (UTC)\n\n"
        "Execution Context:\n"
        "- Process Path: {{epProcesspath}}\n"
        "- Full Path: {{epFullpath}}\n"
        "- Command Line: {{epCmdline}}\n"
        "- Process ID: {{epProcessid}}\n"
        "- File Hash (SHA256): {{epSha256}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{MaintenanceStatus}}\n"
        "{{ResponseFooter}}\n\n"
        "Please review this event and confirm whether the registry export was expected "
        "administrative or troubleshooting activity on this device.\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "enumeration": (
        "Greetings,\n\n"
        "Our MDR team has identified activity consistent with system or network "
        "enumeration on {{AssetName}} within {{epOrg}} on {{epDate}}(UTC).\n\n"
        "Detection Details:\n"
        "- Detected Time: {{epDate}} (UTC)\n"
        "- Endpoint: {{AssetName}}\n"
        "- User Account: {{epUser}}\n"
        "- Process Path: {{epProcesspath}}\n"
        "- Full Path: {{epFullpath}}\n"
        "- Command Line: {{epCmdline}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{MaintenanceStatus}}\n"
        "{{ResponseFooter}}\n\n"
        "Please review this activity and confirm whether this enumeration behavior was "
        "expected and authorized on this device.\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "ransomware": (
        "Greetings,\n\n"
        "Our MDR team has identified activity consistent with ransomware-related "
        "behavior on {{AssetName}} within {{epOrg}} on {{epDate}}(UTC).\n\n"
        "Detection Details:\n"
        "- Endpoint: {{AssetName}}\n"
        "- Domain: {{epDomain}}\n"
        "- User Account: {{epUser}}\n"
        "- Application: {{epApplicationname}}\n"
        "- Detected Time: {{epDate}} (UTC)\n"
        "- Message: {{epMessage}}\n\n"
        "Execution Context:\n"
        "- Process Path: {{epProcesspath}}\n"
        "- Full Path: {{epFullpath}}\n"
        "- Command Line: {{epCmdline}}\n"
        "- Process ID: {{epProcessid}}\n"
        "- File Hash (SHA256): {{epSha256}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{MaintenanceStatus}}\n"
        "{{ResponseFooter}}\n\n"
        "Please review this event and confirm whether this activity was expected. If "
        "not, additional investigation and containment may be required.\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "disable_security_agent": (
        "Greetings,\n\n"
        "Our MDR team has identified activity consistent with an attempt to stop the "
        "endpoint security agent on {{AssetName}} within {{epOrg}} on {{epDate}}(UTC).\n\n"
        "Detection Details:\n"
        "- Detected Time: {{epDate}} (UTC)\n"
        "- Endpoint: {{AssetName}}\n"
        "- User Account: {{epUser}}\n"
        "- Process Path: {{epProcesspath}}\n"
        "- Full Path: {{epFullpath}}\n"
        "- Command Line: {{epCmdline}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{MaintenanceStatus}}\n"
        "The action failed as Tamper Protection is still enabled. {{ResponseFooter}}\n\n"
        "Please review this activity and confirm whether this behavior was expected and "
        "authorized on this device.\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "uninstall_script_execution": (
        "Greetings,\n\n"
        "Our MDR team has identified the execution of an uninstaller script on "
        "{{AssetName}} within {{epOrg}} on {{epDate}}(UTC).\n\n"
        "Detection Details:\n"
        "- Detected Time: {{epDate}} (UTC)\n"
        "- Endpoint: {{AssetName}}\n"
        "- User Account: {{epUser}}\n"
        "- Process Path: {{epProcesspath}}\n"
        "- Full Path: {{epFullpath}}\n"
        "- Command Line: {{epCmdline}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{MaintenanceStatus}}\n"
        "The action failed as Tamper Protection is still enabled. {{ResponseFooter}}\n\n"
        "Please review this activity and confirm whether this behavior was expected and "
        "authorized on this device.\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "disable_protection": (
        "Greetings,\n\n"
        "Our MDR team has identified activity consistent with Microsoft Defender being "
        "disabled on {{AssetName}} within {{epOrg}} on {{epDate}}(UTC).\n\n"
        "Detection Details:\n"
        "- Date: {{epDate}}\n"
        "- User: {{epUser}}\n"
        "- Configuration Changed: {{epDefenderType2}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{MaintenanceStatus}}\n"
        "{{ResponseFooter}}\n\n"
        "Please review this event and confirm whether disabling Microsoft Defender was "
        "expected and authorized on this device.\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "user_added_to_local_admin": (
        "Greetings,\n\n"
        "Our MDR team identified activity consistent with a user being added to the "
        "local administrators group on {{AssetName}} within {{epOrg}} on "
        "{{epDate}}(UTC).\n\n"
        "Detection Details:\n"
        "- Initiating User: {{epUser}}\n"
        "- Initiating Domain: {{epDomain}}\n"
        "- Added Account: {{epAddedmembername}}\n"
        "- Local Group: {{epGroupname}}\n"
        "- Detected Time: {{epDate}} (UTC)\n"
        "- Process Path: {{epProcesspath}}\n"
        "- Full Path: {{epFullpath}}\n"
        "- Command Line: {{epCmdline}}\n"
        "- Process ID: {{epProcessid}}\n"
        "- SHA256: {{epSha256}}\n"
        "- Event ID: {{epEventlogsourceid}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{MaintenanceStatus}}\n\n"
        "{{ResponseFooter}}\n\n"
        "Please review this event and confirm whether this local administrator group "
        "change was expected.\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "public_rdp_connection": (
        "Greetings,\n\n"
        "Microsoft Defender Antivirus has identified a potential security threat on "
        "one of your endpoints. The detection is an RDP connection from {{Ip1}} for "
        "{{epOrg}} on endpoint {{AssetName}} on {{epDate}}(UTC).\n\n"
        "Detection Details:\n"
        "- User: {{epUser}}\n"
        "- Date: {{epDate}}\n"
        "- Source: {{Ip1}}\n"
        "- AbuseIPDB Summary: {{Ip1AbuseSummary}}\n"
        "- VirusTotal Verdict: {{Ip1VirusTotalVerdict}}\n"
        "- Proxy/VPN Status: {{Ip1ProxyCheckVpnStatus}}\n"
        "- Location: {{Ip1Location}}\n"
        "- ISP: {{Ip1isp}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{MaintenanceStatus}}\n"
        "{{ResponseFooter}}\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "cleared_security_logs": (
        "Greetings,\n\n"
        "Our MDR team has identified activity consistent with security or event logs "
        "being cleared on {{AssetName}} within {{epOrg}} on {{epDate}}(UTC).\n\n"
        "Detection Details:\n"
        "- Date: {{epDate}}\n"
        "- User: {{UserDisplayName}}\n"
        "- Log Name: {{epLogname}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{MaintenanceStatus}}\n"
        "{{ResponseFooter}}\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
    "vulnerable_driver": (
        "Greetings,\n\n"
        "Our MDR team has identified activity consistent with a vulnerable driver "
        "being installed or executed on {{AssetName}} within {{epOrg}} on "
        "{{epDate}}(UTC).\n\n"
        "Detection Details:\n"
        "- Date: {{epDate}}\n"
        "- Policy Name: {{epApplicationname}}\n"
        "- Process Path: {{epProcesspath}}\n"
        "- Full Path: {{epFullpath}}\n"
        "- SHA256: {{epSha256}}\n"
        "- Created By Process: {{epCreatedByProcess}}\n"
        "- Certificate: {{epCertificate}}\n\n"
        "Action Taken: {{ResponseAction}}\n\n"
        "{{MaintenanceStatus}}\n"
        "{{ResponseFooter}}\n\n"
        "If you have any questions, please reach out to {{TeamName}}.\n\n"
        "{{Signature}}\n"
    ),
}
