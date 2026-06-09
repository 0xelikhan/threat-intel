"""
Email composer — generates customer-facing alert emails from analysis output.

All MDR-team identity is parameterized via configurable placeholders
(`{{TeamName}}` / `{{FromAddress}}`); the signature block is fully
configurable from RECON settings (`EMAIL_FROM_NAME`, `EMAIL_FROM_ADDRESS`,
`EMAIL_SIGNATURE`).

Public API:
  parse_log(text)                              -> dict (ParsedAlertLog)
  list_alert_types()                           -> list[(id, label)]
  load_template(alert_id) / list_templates()
  compose(alert_id, parsed, options, signature)-> {"text": ..., "html": ...,
                                                    "subject": ...}
  send_smtp(subject, body_html, body_text,
            to, cc, config)                    -> {"sent": True} or {error}

"""

from __future__ import annotations
import json
import re
import smtplib
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape as html_escape
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ─── alert type catalog ───────────────────────────────────────────────────────
# (id_value, display_label, category) — id used as URL/JSON key, label as UI text.
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

    # Microsoft 365 / Azure AD audit logs use a "section header + Name/Value"
    # pattern for repeated property bags:
    #
    #   ExtendedProperties :
    #   Name : UserAgent
    #   Value : BAV2ROPC
    #
    #   ExtendedProperties :
    #   Name : RequestType
    #   Value : OAuth2:Token
    #
    # The naive "first occurrence wins" loop kept only the first
    # Name/Value pair and silently dropped everything else, so analyst-
    # critical signals like the UserAgent or OAuth flow never reached
    # the email body. Walk the lines with a one-line lookahead and
    # when we see `Name : X` immediately followed by `Value : Y`,
    # promote X → Y into raw_fields directly. The literal `Name` /
    # `Value` rows are then skipped so the dict isn't polluted with
    # the placeholder keys.
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line and ":" in line:
            sep = line.find(":")
            key = line[:sep].strip()
            val = line[sep + 1:].strip()
            # Section header (key only, value empty) — skip
            if key and not val:
                pass
            # Name → Value pair, look ahead one line
            elif key.lower() in ("name", "key") and i + 1 < len(lines):
                nxt = lines[i + 1].strip()
                if nxt.lower().startswith(("value :", "value:")):
                    nxt_val = nxt.split(":", 1)[1].strip()
                    if val and nxt_val and val not in raw_fields:
                        raw_fields[val] = nxt_val
                    i += 2
                    continue
            elif key and key.lower() not in ("name", "key", "value") and key not in raw_fields:
                raw_fields[key] = val
        i += 1

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
    # Many impossible-travel exports surface the two login IPs inside the
    # FirstLogin / SecondLogin sub-sections (SourceIp / IpAddress fields)
    # rather than at the top level. Fall back into the sections so the
    # facts block + AI summary actually see the IPs.
    if not out.get("first_login_ip"):
        out["first_login_ip"] = (
            _extract_section_value(lines, "FirstLogin", "SourceIp")
            or _extract_section_value(lines, "FirstLogin", "IpAddress")
            or _extract_section_value(lines, "FirstLogin", "IP")
        )
    if not out.get("second_login_ip"):
        out["second_login_ip"] = (
            _extract_section_value(lines, "SecondLogin", "SourceIp")
            or _extract_section_value(lines, "SecondLogin", "IpAddress")
            or _extract_section_value(lines, "SecondLogin", "IP")
        )

    # Per-login ASN + ASN name — used by the AI summary to flag VPN /
    # bulletproof / anonymising provider names (PacketHub, Cogent abuse
    # ranges, etc.) without requiring an enrichment-source call.
    out["first_login_asn"]      = _extract_section_value(lines, "FirstLogin", "ASN")
    out["first_login_asn_name"] = _extract_section_value(lines, "FirstLogin", "ASNName")
    out["second_login_asn"]      = _extract_section_value(lines, "SecondLogin", "ASN")
    out["second_login_asn_name"] = _extract_section_value(lines, "SecondLogin", "ASNName")

    # AssetNamePair often holds "Unknown,RealHost" or "RealHost,Unknown"
    # — pick the non-Unknown side over the literal "Unknown" the section
    # parser would otherwise return. Same trick for the IPv6/IPv4 pair.
    pair = raw_fields.get("AssetNamePair") or raw_fields.get("assetNamePair") or ""
    if pair and "," in pair:
        sides = [s.strip() for s in pair.split(",", 1)]
        real = next((s for s in sides if s and s.lower() != "unknown"), "")
        if real and (not out.get("asset_name")
                     or out["asset_name"].lower() == "unknown"):
            out["asset_name"] = real
    # Promote per-section AssetName when the top-level one was "Unknown".
    if (not out.get("asset_name") or out["asset_name"].lower() == "unknown"):
        for sec in ("SecondLogin", "FirstLogin"):
            v = _extract_section_value(lines, sec, "AssetName")
            if v and v.lower() != "unknown":
                out["asset_name"] = v
                break

    # Impossible-travel signal — both logins present, different cities or
    # countries, both within a short window. Computed cheaply here so the
    # AI prompt doesn't have to derive it.
    out["impossible_travel"] = bool(
        out.get("first_login_ip") and out.get("second_login_ip")
        and (
            (out.get("first_login_city") and out.get("second_login_city")
             and out["first_login_city"].lower() != out["second_login_city"].lower())
            or (out.get("first_login_country") and out.get("second_login_country")
                and out["first_login_country"].lower() != out["second_login_country"].lower())
        )
    )

    # Known VPN / anonymising / bulletproof ASN-name fragments. Lifted
    # from the second-login ASN name when present (that's typically the
    # follow-up suspicious login). Used by the AI prompt as a "flag this"
    # hint without needing live TI enrichment.
    _VPN_ASN_KEYWORDS = (
        "packethub", "vpn", "njalla", "1337 services", "cogent abuse",
        "ddos-guard", "stark industries", "frantech", "abelohost",
        "buyvm", "private internet access", "nordvpn", "expressvpn",
        "mullvad", "proton vpn", "surfshark", "ipvanish", "windscribe",
        "warp", "cloudflare warp", "datacamp",
    )
    _second_asn = (out.get("second_login_asn_name") or "").lower()
    out["second_login_is_vpn"] = any(
        kw in _second_asn for kw in _VPN_ASN_KEYWORDS
    ) if _second_asn else False

    # ep_date / timestamp aliases — the template-field timeline toggle
    # reads these, so populate them from whichever login timestamp the
    # parser captured first.
    if not out.get("ep_date"):
        out["ep_date"] = (out.get("first_login_created_raw")
                          or out.get("second_login_created_raw")
                          or out.get("detected_dt_raw")
                          or out.get("activity_dt_raw")
                          or "")

    if not out.get("ip_address") and out.get("first_login_ip"):
        out["ip_address"] = out["first_login_ip"]
    if not out.get("ip_address") and out.get("second_login_ip"):
        # Promote the second-login IP when the first wasn't extracted —
        # otherwise the Source IP row stays empty even though we have a
        # perfectly good IP from the second leg of an impossible-travel
        # event.
        out["ip_address"] = out["second_login_ip"]
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
    # Category breakdown of every present field — the frontend renders one
    # toggle per category and sends enabled_categories back on compose to
    # control which categories make it into the email body.
    try:
        out["_categorized"] = categorize_parsed(out)
    except Exception:
        out["_categorized"] = {}
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


_AD_INLINE_RE = re.compile(
    r"key\s*:\s*(?P<key>[A-Za-z][A-Za-z0-9_]*?)\s*value\s*:\s*(?P<val>[^\r\n]*?)"
    r"(?=(?:\s+key\s*:\s*[A-Za-z]|\s*$|\s*additionalDetails\s*:))",
    re.IGNORECASE,
)


def _extract_additional_detail_value(lines, target_key):
    """Pull a value from `additionalDetails` blocks.

    Two real-world shapes are accepted:

      multi-line (PowerShell pretty-print):
          additionalDetails :
          key : ipaddr
          value : 89.104.236.4

      concatenated (Entra ID PIM export / 'select-object -expandproperty'
      output / browser-copy-from-table — all the bits land on one
      physical line with no separator):
          additionalDetails :key : ipaddrvalue : 89.104.236.4

    The concatenated form was previously missed entirely because the
    block-detector looked for a line that equalled 'additionaldetails :'
    verbatim — concatenated PIM logs (the most common Entra alert paste)
    have every field on the same line and slipped right past.
    """
    target_l = (target_key or "").lower()

    # Pass 1 — multi-line shape (original behaviour, kept for back-compat
    # with logs that already came in nicely formatted).
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
        elif k.lower() == "value" and cur_key.lower() == target_l:
            return v

    # Pass 2 — concatenated shape. Walk every line and pull out each
    # (key, value) pair inline. First exact-key match wins.
    for raw in lines:
        for m in _AD_INLINE_RE.finditer(raw):
            if (m.group("key") or "").strip().lower() == target_l:
                return (m.group("val") or "").strip()
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

# Per-analyst drafts + rolling send history are kept IN MEMORY ONLY.
# Email subjects / bodies / recipients contain analyst-derived data and
# must never land on disk — see the no-persistence policy. State is lost
# on container restart by design.
_HISTORY_CAP  = 200
_DRAFTS_CAP   = 200
_drafts_mem:   "dict[str, Dict]" = {}
_history_mem:  "list[Dict]"      = []


def _slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9_-]", "_", (s or "").lower())[:48]


def save_draft(payload: Dict) -> Dict:
    """Stash a composed email + its compose options in memory. Returns the
    saved record. Lost on restart — never persisted."""
    now = datetime.now(timezone.utc)
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
    _drafts_mem[draft_id] = record
    # Cheap FIFO eviction — newest insertion order preserved.
    if len(_drafts_mem) > _DRAFTS_CAP:
        for k in list(_drafts_mem.keys())[:-_DRAFTS_CAP]:
            _drafts_mem.pop(k, None)
    return record


def list_drafts() -> List[Dict]:
    out = []
    for rec in sorted(_drafts_mem.values(),
                      key=lambda r: r.get("saved_at") or "", reverse=True):
        out.append({
            "id":         rec.get("id"),
            "saved_at":   rec.get("saved_at"),
            "alert_type": rec.get("alert_type"),
            "subject":    rec.get("subject", ""),
            "to":         rec.get("to", ""),
        })
    return out


def load_draft(draft_id: str) -> Optional[Dict]:
    return _drafts_mem.get(_slugify(draft_id)) or _drafts_mem.get(draft_id)


def delete_draft(draft_id: str) -> bool:
    safe = _slugify(draft_id)
    if safe in _drafts_mem:
        _drafts_mem.pop(safe)
        return True
    if draft_id in _drafts_mem:
        _drafts_mem.pop(draft_id)
        return True
    return False


def read_history() -> List[Dict]:
    return list(_history_mem)


def append_history(entry: Dict) -> None:
    """Append a send-attempt record to the in-memory list. Capped at
    _HISTORY_CAP, newest-first. Lost on restart by design."""
    record = {
        "ts":      datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "to":      entry.get("to", ""),
        "cc":      entry.get("cc", ""),
        "subject": entry.get("subject", ""),
        "sent":    bool(entry.get("sent")),
        "error":   entry.get("error"),
    }
    _history_mem.insert(0, record)
    if len(_history_mem) > _HISTORY_CAP:
        del _history_mem[_HISTORY_CAP:]


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
    "urlscan.io", "censys.io", "greynoise.io", "abuse.ch",
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
    # Many SIEMs (Microsoft Entra ID exports, for example) populate the
    # AssetName field with the literal string "Unknown" / "-" / "N/A" when
    # the asset is NOT domain-joined. Treat those as absent — otherwise the
    # domain-joined explainer paragraph injects on every impossible-travel
    # alert regardless of whether either login was on a managed device.
    asset_norm = asset.strip().lower() if isinstance(asset, str) else ""
    is_real_asset = asset_norm and asset_norm not in {
        "unknown", "-", "n/a", "na", "none", "null", "(empty)", "",
    }
    if is_real_asset:
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


_AI_SYSTEM = """You are a senior security analyst writing the body of a
customer-facing notification about a security alert. Write the way an
experienced practitioner would explain the situation to a peer at the
customer site: direct, technical, informative, SCANNABLE. The example
templates below are INSPIRATION ONLY for tone — do NOT copy them.

THE BODY HAS EXACTLY TWO SECTIONS:

──────────────────────────────────────────────────────────────────────────
SECTION 1 — DETAILS (structured facts block, NOT prose narration)
──────────────────────────────────────────────────────────────────────────
Render the parsed facts as a clean block of labelled lines, one fact per
line, in this format:

    Label: value

No bullets, no dashes, no markdown, no asterisks. Just labelled lines.
Only include labels that actually have data in the log — skip empty
fields entirely. Pick from this set (in this rough order of relevance,
ignore the ones that don't apply):

    User
    Source IP                 (one or two — for impossible-travel etc.)
    Source location           (city, country — when geolocation is known)
    Time                      (UTC timestamp)
    Asset / Host
    Process
    Parent process
    Command line              (truncated to ~120 chars when long)
    File / Hash
    Destination / URL / Domain
    Error code                (with the one-line meaning in parens)
    User agent
    Auth method
    Device compliance         (compliant/non-compliant)
    Response action           (what was already done about it)

Follow the facts block with EXACTLY ONE short sentence (no more than 25
words) that names what this alert IS in plain language. Not a paragraph.
One sentence. Example: "Sign-in failure for a disabled account — most
likely a stale automation still calling the deactivated identity."

Then one blank line and Section 2.

──────────────────────────────────────────────────────────────────────────
SECTION 2 — INVESTIGATE AND REMEDIATE (tight prose, one paragraph)
──────────────────────────────────────────────────────────────────────────
ONE paragraph (3-5 sentences) covering the investigation steps,
containment, remediation, and detection guidance that actually apply to
this alert. Write it as natural prose, not as subsections. Reference the
specific artefacts by name. Be DIRECTLY actionable: "Confirm in Entra ID
whether hou-paton-storage1@... is intentionally disabled and review the
last 30 days of SigninLogs for any success by the same UPN. If similar
failures keep recurring, find and retire the workflow still calling the
account." That's what one looks like.

For a genuine incident, you may use UP TO TWO paragraphs but keep each
tight. For a clearing / false-positive notification, ONE sentence is
enough ("if similar failures recur, confirm the account state in Entra
ID before re-enabling").

──────────────────────────────────────────────────────────────────────────
NO third section. NO closing courtesy line. The signature is appended
automatically and IS the closing.

LENGTH:
* Clearing / false positive: facts block + 1-sentence summary + 1-sentence
  guidance. Total 8-14 lines.
* Routine informational: facts block + summary sentence + 1 prose
  paragraph. Total 14-22 lines.
* Genuine incident: facts block + summary sentence + up to 2 tight
  paragraphs. Total 22-32 lines.

CALIBRATION — do NOT over-state the threat:
* If the evidence shows a clean hash, a known vendor maintenance pattern,
  expected service-account activity, a disabled-account login failure, or
  any other recognised legitimate / benign condition, say so explicitly in
  the DETAILS section. The investigate/remediate guidance becomes
  verification, not containment.
* Only describe an event as a confirmed threat when concrete evidence
  supports it (known-bad hash, named malware family, malicious
  infrastructure callout, lateral movement, credential access, confirmed
  unauthorized access). Suspicious-LOOKING activity without one of these
  is "the activity is consistent with legitimate operations, but it is
  worth confirming X".

VOICE:
* Direct active voice. "The endpoint connected to ..." not "We observed
  an endpoint that appears to have connected to ...".
* Speak to one technical reader. No second-person plurals.
* No corporate filler. No hedging where the evidence is clear.
* When something is genuinely uncertain, say so plainly.

ROBOTIC PHRASES TO AVOID (these read as ChatGPT-generated noise):
* "indicates that"           → "shows" / "means" / just state the fact
* "associated with this event" → just describe the field directly
* "noted by the logon error code" → "Error: 50057 (account disabled)"
* "identified for this request was" → "User agent: BAV2ROPC"
* "the authentication method utilized was" → "Auth: OAuth2:Token"
* "ensure that"              → just say "do X"
* "consider whether"         → "check whether" / "decide if"
* "in terms of"              → cut the phrase, restate directly
* "to enhance detection capabilities" → "to catch repeats"
* "in your environment"      → "in Entra ID" / "in your SIEM" (be specific)
* "may be necessary"         → "do X" or "skip X" (commit)
* "potential patterns of unauthorized access" → "unauthorized access"
* "for any related activity" → cut entirely
* "as always"                → cut entirely
* "right away"               → cut, or use "immediately" if it matters
* "to act quickly"           → cut
* "we'll continue to monitor" → cut entirely

NEVER write any of these:
* References to "our team", "the team", "our MDR team", "our analysts",
  "our SOC", "our security team", or any group self-reference. State what
  happened or what should be done, not who did it. Use passive voice for
  actions taken on the customer's side ("the account was disabled") OR
  describe the action plainly without naming an actor.
* A closing courtesy line: "please reach out if you need anything further
  from us", "let us know if you have any questions", "feel free to contact
  us", "happy to assist", "do not hesitate", "we are here to help". The
  signature handles the closing.
* Generic reassurance: "no action is required" paired with action items;
  "monitor for similar activity" without naming what to watch for.
* "In response to this alert" / "In light of this" / similar lead-ins.
  Just state what was done or what should be done.
* Repeating the DETAILS facts a second time inside the investigate /
  remediate section.

HARD FORMAT RULES:
* Output the email body ONLY. No subject line. No commentary outside the body.
* Never invent values not in the log. Omit unknown values.
* NO bullets, NO numbered lists, NO dash-prefixed items. Paragraphs only.
* NO em dashes, NO en dashes. Hyphens only inside compound words
  (anti-virus, two-factor). Never as a sentence-level separator.
* Plain text only — no markdown, no asterisks for emphasis, no underscores.
* NO signature block. NO "Best regards" / name / title. The system appends
  the signature automatically.
* NO greeting. Do NOT start with "Hi", "Hello", "Hi team", "Greetings",
  "Dear team", "Good morning", or any other salutation. The first line of
  the body is the first line of the DETAILS section — go straight in.

REDUNDANT OPENERS TO AVOID:
* "I am writing to inform you that"
* "Please be advised that"
* "It has come to our attention that"
* "At this time we have"
* "Going forward"
* "Should you have any further questions or concerns please do not hesitate"
* "Rest assured"
* "We wanted to reach out"
* "In response to this alert"
* "We'll continue monitoring your environment"
Strip these openers; replace with the direct statement they were padding.

EXAMPLE — the format you should produce:

  User: hou-paton-storage1@patoncontrols.com
  Source IP: 108.249.198.145
  Time: 13:31:01 UTC on May 30, 2026
  Error: 50057 (account is disabled)
  User agent: BAV2ROPC
  Auth: OAuth2:Token
  Device: non-compliant, unmanaged

  Sign-in failure against a disabled account — most likely a stale
  automation still calling the deactivated identity.

  Confirm in Entra ID whether hou-paton-storage1@patoncontrols.com is
  intentionally disabled and review the last 30 days of SigninLogs for any
  success by the same UPN. If similar failures keep recurring against a
  disabled account, find and retire the workflow still calling it; if the
  account needs to come back, rotate the credential, enforce MFA, and check
  conditional-access before re-enabling.

That's the whole body. Not "robotic narration of each field" — clean labelled
facts on top, one sentence of context, one paragraph of action.
"""


_LIST_MARKER_RE = re.compile(r"^[\s]*(?:[-•*]|\d{1,2}[.)])\s+", re.MULTILINE)


def _strip_list_markers(body: str) -> str:
    """Convert any bullet / numbered-list lines back into flowing prose.
    Groups of adjacent list lines become one paragraph joined by '. '.
    Safety-net against models that ignore the no-bullets instruction."""
    if not body:
        return body
    lines = body.split("\n")
    out: list[str] = []
    buf: list[str] = []
    for line in lines:
        if _LIST_MARKER_RE.match(line):
            cleaned = _LIST_MARKER_RE.sub("", line, count=1).strip()
            if cleaned:
                # Drop trailing period to avoid ".." when joining.
                cleaned = cleaned.rstrip(". ")
                buf.append(cleaned)
        else:
            if buf:
                out.append(". ".join(buf) + ".")
                buf = []
            out.append(line)
    if buf:
        out.append(". ".join(buf) + ".")
    return "\n".join(out)


# Redundant filler phrases, greetings, closing-courtesy lines, and team
# self-references the AI keeps reaching for in customer email even after the
# prompt forbids them. Each (pattern, replacement) pair runs case-insensitively
# over the body once. Order matters: greeting strip runs first (anchored to the
# top), then opener strips, then in-body team-reference rewrites, then closing
# strips, then whitespace cleanup.
_FILLER_SUBS = [
    # ── Greetings — strip ANY salutation at the very top of the body ─────
    # Matches: "Hi team,", "Hello,", "Hi,", "Greetings,", "Dear team,",
    # "Good morning,", "Hi <Name>,", with optional trailing newlines.
    (re.compile(
        r"\A\s*(?:hi(?:\s+\w+)?|hello(?:\s+\w+)?|greetings|dear\s+\w+(?:\s+\w+)?|"
        r"good\s+(?:morning|afternoon|evening))\s*,?\s*\n+",
        re.IGNORECASE), ""),

    # ── Stale redundant openers ──────────────────────────────────────────
    (re.compile(r"\bI am writing to inform you (?:that\s+)?", re.IGNORECASE), ""),
    (re.compile(r"\bI'?m writing to (?:let you know|inform you)(?:\s+that)?\s+", re.IGNORECASE), ""),
    (re.compile(r"\bPlease be (?:advised|informed)(?:\s+that)?\s+", re.IGNORECASE), ""),
    (re.compile(r"\bIt has come to our attention that\s+", re.IGNORECASE), ""),
    (re.compile(r"\bAt this (?:time|point)(?:\s+we have)?\s*,?\s*", re.IGNORECASE), ""),
    (re.compile(r"\bGoing forward,?\s*", re.IGNORECASE), ""),
    (re.compile(r"\bWe wanted to (?:reach out|let you know)(?:\s+to inform you)?\s+", re.IGNORECASE), ""),
    (re.compile(r"\bRest assured\s*,?\s*", re.IGNORECASE), ""),
    (re.compile(r"\bIn response to (?:this|the)\s+(?:alert|notification),?\s*", re.IGNORECASE), ""),
    (re.compile(r"\bIn light of (?:this|the)\s+\w+,?\s*", re.IGNORECASE), ""),

    # ── Team self-references — rewrite to passive voice without the actor ─
    # The AI keeps producing "our MDR team has cleared the notification" /
    # "our team confirmed the alert" — the user wants no group self-reference.
    # Rewrite to passive: "the notification was cleared" / "the alert was
    # confirmed". The {verb}ed pattern catches common past-tense verbs the
    # model uses (cleared, confirmed, identified, reviewed, determined,
    # noted, observed, detected, investigated, verified).
    #
    # Step 1: rewrite "[optional preface,] (our|the) [adj]* team [has|have]?
    # {verbed} (the|this)? {noun}" -> "the {noun} was {verbed}".
    (re.compile(
        r"(?:\bin\s+response\s+to\s+this\s+(?:alert|notification|event),?\s+)?"
        r"\b(?:our|the)\s+(?:MDR\s+|SOC\s+|security\s+|analyst\s+)*"
        r"team(?:\s+of\s+analysts)?\s+(?:has\s+|have\s+)?(\w+ed)\s+"
        r"(?:the\s+|this\s+|that\s+)(\w+)",
        re.IGNORECASE),
     lambda m: f"the {m.group(2).lower()} was {m.group(1).lower()}"),
    # Same shape but for "our analysts ..." instead of "our team ..."
    (re.compile(
        r"(?:\bin\s+response\s+to\s+this\s+(?:alert|notification|event),?\s+)?"
        r"\bour\s+(?:MDR\s+|SOC\s+)?analysts?\s+(?:have\s+|has\s+)?(\w+ed)\s+"
        r"(?:the\s+|this\s+|that\s+)(\w+)",
        re.IGNORECASE),
     lambda m: f"the {m.group(2).lower()} was {m.group(1).lower()}"),
    # Step 2: plain team-strip fallback — catches "our team is monitoring",
    # "the team reviewed", and any remaining mid-sentence references the
    # verb-rewrite missed.
    (re.compile(
        r"\b(?:our|the)\s+(?:MDR\s+|SOC\s+|security\s+|analyst\s+)*"
        r"team(?:\s+of\s+analysts)?\s+",
        re.IGNORECASE), ""),
    (re.compile(r"\b(?:our|the)\s+(?:MDR|SOC)\s+analysts?\s+", re.IGNORECASE), ""),
    (re.compile(r"\bour\s+analysts?\s+", re.IGNORECASE), ""),

    # ── Closing-courtesy lines — kill the WHOLE sentence containing the
    # offending phrase. Uses a lookbehind for the leading sentence boundary
    # so re.sub can find adjacent closing sentences on a second pass; if
    # the boundary were consumed, only the first of two back-to-back
    # closing sentences would be stripped.
    (re.compile(
        r"(?<=[.\n])\s*[^.\n]*\b(?:please\s+(?:reach\s+out|contact\s+us|let\s+us\s+know)|"
        r"feel\s+free\s+to\s+(?:contact|reach|ask)|"
        r"happy\s+to\s+assist|"
        r"do\s+not\s+hesitate\s+to\s+(?:contact|reach|ask)|"
        r"don'?t\s+hesitate\s+to\s+(?:contact|reach|ask)|"
        r"we\s+are\s+here\s+(?:to\s+help|for\s+any\s+questions)|"
        r"we'?re\s+here\s+(?:to\s+help|for\s+any\s+questions)|"
        r"we'?ll\s+continue\s+(?:to\s+)?monitor(?:ing)?|"
        r"we\s+will\s+continue\s+(?:to\s+)?monitor(?:ing)?|"
        r"if\s+you\s+have\s+any\s+(?:further\s+)?questions|"
        r"should\s+you\s+have\s+any\s+(?:further\s+)?questions)"
        r"[^.\n]*\.?",
        re.IGNORECASE), ""),
    # Also catch a closing-courtesy sentence at the very TOP of the body
    # (no preceding boundary because there's nothing before it). The
    # lookbehind above misses position 0 when the sentence is the first
    # thing in the body.
    (re.compile(
        r"\A\s*[^.\n]*\b(?:please\s+(?:reach\s+out|contact\s+us|let\s+us\s+know)|"
        r"feel\s+free\s+to\s+(?:contact|reach|ask)|"
        r"we'?re\s+here\s+(?:to\s+help|for\s+any\s+questions)|"
        r"we'?ll\s+continue\s+(?:to\s+)?monitor(?:ing)?)"
        r"[^.\n]*\.?\s*",
        re.IGNORECASE), ""),

    # ── Robotic phrases — surgical word-level rewrites that don't kill
    # whole sentences, just strip the chatgpt-isms. Order matters: the
    # longer patterns come first so "may be necessary" matches before
    # "be necessary" would fire.
    (re.compile(r"\bin\s+terms\s+of\s+\w+\s*,?\s*", re.IGNORECASE), ""),
    (re.compile(r"\bensure\s+that\s+", re.IGNORECASE), ""),
    (re.compile(r"\bconsider\s+whether\s+", re.IGNORECASE), "check whether "),
    (re.compile(r"\bto\s+enhance\s+detection\s+capabilities\s*,?\s*", re.IGNORECASE), "to catch repeats, "),
    (re.compile(r"\bmay\s+be\s+necessary\b", re.IGNORECASE), "is needed"),
    (re.compile(r"\bpotential\s+patterns\s+of\s+unauthorized\s+access\b", re.IGNORECASE), "unauthorized access"),
    (re.compile(r"\bfor\s+any\s+related\s+activity\b", re.IGNORECASE), ""),
    (re.compile(r"\bas\s+always,?\s*", re.IGNORECASE), ""),
    (re.compile(r"\bright\s+away\b", re.IGNORECASE), ""),
    (re.compile(r"\bto\s+act\s+quickly\b", re.IGNORECASE), ""),
    # "the X identified for this request was Y" -> "X: Y" — drops the
    # robotic restatement; the structured-facts block above carries the
    # actual data. But only fire mid-sentence so we don't break the
    # labelled lines themselves.
    (re.compile(r"\b(?:the\s+)?user\s+agent\s+identified\s+(?:for\s+this\s+request\s+)?was\s+", re.IGNORECASE), "User agent: "),
    (re.compile(r"\b(?:the\s+)?authentication\s+method\s+utili[sz]ed\s+was\s+", re.IGNORECASE), "Auth: "),
    (re.compile(r"\bnoted\s+by\s+the\s+logon\s+error\s+code\s+", re.IGNORECASE), "Error code "),
    (re.compile(r"\bassociated\s+with\s+this\s+event\s+", re.IGNORECASE), ""),
    (re.compile(r"\bindicates\s+that\s+", re.IGNORECASE), "means "),

    # ── Whitespace cleanup ───────────────────────────────────────────────
    # Collapse any stray ", " left at line start by the rewrites above.
    (re.compile(r"^[\s]*,\s*", re.MULTILINE), ""),
    # Collapse "  has cleared" -> " cleared" (when "team" was scrubbed mid-sentence)
    (re.compile(r"\s{2,}has\s+", re.IGNORECASE), " has "),
]


# Auxiliary verbs left orphaned at sentence start by mid-sentence scrubs
# ("our team is monitoring" -> " is monitoring"). When a sentence starts with
# one of these, drop the whole sentence rather than leaving a fragment.
_ORPHAN_SENTENCE_RE = re.compile(
    r"(?:^|(?<=[.!?]\s))\s*(?:is|are|was|were|has|have|had|will|would|"
    r"should|may|might|can|could|do|does|did)\s+\w+[^.!?\n]*[.!?]",
    re.IGNORECASE,
)


def _strip_filler_phrases(body: str) -> str:
    """Apply the filler regex list; collapse multiple blank lines and fix
    capitalisation at sentence starts (the scrubs lowercase as they
    rewrite). Also drops any orphan sentences left starting with a bare
    auxiliary verb."""
    if not body:
        return body
    out = body
    for pat, repl in _FILLER_SUBS:
        out = pat.sub(repl, out)

    # Drop orphan sentences that start with a bare auxiliary verb (the
    # team-strip fallback leaves "The team is monitoring" -> " is monitoring").
    out = _ORPHAN_SENTENCE_RE.sub("", out)

    # Re-capitalise the first letter of every sentence (the verb-rewrite
    # produces "the notification was cleared" — that should be "The
    # notification was cleared" when it sits at the start of a sentence).
    def _cap(match):
        return match.group(1) + match.group(2).upper()
    out = re.sub(r"(^|[.!?]\s+)([a-z])", _cap, out)

    # Collapse 3+ blank lines down to one
    out = re.sub(r"\n{3,}", "\n\n", out)
    # Collapse runs of spaces left by mid-sentence removals
    out = re.sub(r" {2,}", " ", out)
    return out.strip()


# ─── Deterministic facts-block renderer ──────────────────────────────────────
#
# The LLM is unreliable at producing the clean "Label: value" structured
# block we want at the top of every alert email — even with strong prompt
# rules and post-processor scrubs, it keeps falling back to "A failed
# login attempt was recorded for ..." style robotic narration.
#
# Solution: take the formatting concern away from the LLM entirely. We
# already extracted every field in /api/email/parse — render them directly
# as labelled lines server-side. The LLM is then asked for ONLY two small
# things it cannot screw up: a one-sentence plain-language summary and a
# one-paragraph action block. The body is assembled by concatenation, not
# by prompting the LLM to format anything.
#
# Field ordering follows the natural triage flow: WHO -> WHERE -> WHAT ->
# OUTCOME -> WHEN. Within each group, the most specific field wins (e.g.
# user_principal_name beats user_display_name when both are present).
# Semantic categories the analyst toggles in the UI. Each fact field now
# declares its category; enabled_categories on the compose request filters
# the facts block (and, transitively, what the AI summary references).
#
# Categories:
#   Identity   — user / account / asset / host
#   Network    — IPs, ASN, location, user-agent
#   Process    — process name / path / cmdline / id
#   File       — file path, hash, artifact
#   Detection  — alert name, rule name, malware family, risk type/level
#   Time       — timestamps
#   Action     — what was done about the event (response action, forwarding)
#   Other      — privileged role / TAP / risk reasons / catch-all
ALL_CATEGORIES = (
    "Identity", "Network", "Process", "File", "Detection",
    "Time", "Action", "Other",
)

_FACT_FIELDS = (
    # (label, [candidate keys in priority order], optional formatter, category)
    ("User",                 ["user_principal_name", "ep_user", "user_display_name"], None, "Identity"),
    ("User display name",    ["user_display_name"], lambda v, p: v if (p.get("user_principal_name")
                                                                        or p.get("ep_user"))
                                                                        and v != (p.get("user_principal_name")
                                                                                  or p.get("ep_user"))
                                                                        else None, "Identity"),
    ("Target user",          ["target_user_principal_name"], None, "Identity"),
    # `ep_domain` is the Windows AD domain prefix from `User: DOMAIN\name`,
    # NOT a hostname. Falling back to it for Asset/Host populated the
    # asset card with the AD domain (which often shares a name with the
    # company / tenant), making it look like the platform misidentified
    # the host. Only show a real asset_name; otherwise leave blank.
    ("Asset",                ["asset_name"], None, "Identity"),
    ("Process",              ["ep_application_name"], None, "Process"),
    ("Process path",         ["ep_process_path", "ep_full_path"], None, "Process"),
    ("Process ID",           ["ep_process_id"], None, "Process"),
    ("Command line",         ["ep_cmd_line"], lambda v, p: (v[:200] + "...") if isinstance(v, str) and len(v) > 200 else v, "Process"),
    ("File path",            ["ep_defender_path", "ep_defender_file"], None, "File"),
    ("File hash (SHA-256)",  ["ep_sha256"], None, "File"),
    ("Detection",            ["ep_defender_type", "ep_message", "ep_admin_alert_title"], None, "Detection"),
    ("Source IP",            ["ip_address"], None, "Network"),
    ("First login IP",       ["first_login_ip"], None, "Network"),
    ("Second login IP",      ["second_login_ip"], None, "Network"),
    ("First login location", ["first_login_city", "first_login_country"],
        lambda v, p: ", ".join([x for x in (p.get("first_login_city"),
                                             p.get("first_login_country")) if x]) or None,
        "Network"),
    ("Second login location",["second_login_city", "second_login_country"],
        lambda v, p: ", ".join([x for x in (p.get("second_login_city"),
                                             p.get("second_login_country")) if x]) or None,
        "Network"),
    ("First login ASN",      ["first_login_asn_name"], None, "Network"),
    ("Second login ASN",     ["second_login_asn_name"], None, "Network"),
    ("Source location",      ["location_city", "location_country"], lambda v, p: _join_location(p), "Network"),
    ("User agent",           ["additional_info_user_agent"], None, "Network"),
    ("Risk type",            ["risk_event_type"], None, "Detection"),
    ("Risk level",           ["risk_level"], None, "Detection"),
    ("Risk state",           ["risk_state"], None, "Detection"),
    ("Risk reasons",         ["additional_info_risk_reasons"], None, "Other"),
    ("Forwarding to",        ["forwarding_address"], None, "Action"),
    ("Privileged role",      ["privileged_role_display_name", "privileged_role_well_known"], None, "Other"),
    ("Time",                 ["ep_date"], None, "Time"),
    ("First login time",     ["first_login_created_raw"], None, "Time"),
    ("Second login time",    ["second_login_created_raw"], None, "Time"),
)


# Keyword → category for the catch-all "Other parsed fields" classifier.
# Used when we see a raw_field key the hardcoded _FACT_FIELDS doesn't
# cover — keeps the categorisation working on arbitrary log formats.
_CATEGORY_KEYWORDS = (
    ("Network",    ("ip", "addr", "host", "url", "domain", "asn",
                    "country", "city", "region", "latitude", "longitude",
                    "useragent", "user_agent", "port", "dns", "netflow",
                    "geo")),
    ("Identity",   ("user", "account", "upn", "principal", "subject",
                    "target", "asset", "machine", "device", "workstation",
                    "endpoint", "computer", "tenant")),
    ("Process",    ("process", "cmd", "command", "exec", "parent", "pid",
                    "image")),
    ("File",       ("file", "hash", "sha1", "sha256", "sha512", "md5",
                    "imphash", "filename", "filepath", "path", "size")),
    ("Detection",  ("alert", "detect", "rule", "signature", "policy",
                    "malware", "threat", "verdict", "severity", "risk",
                    "category", "vendor", "ttp", "mitre")),
    ("Time",       ("date", "time", "created", "modified", "issued",
                    "timestamp", "when", "duration")),
    ("Action",     ("action", "response", "remediation", "blocked",
                    "permit", "allow", "deny", "quarantine", "remediated")),
)


def _categorize_key(key: str) -> str:
    """Best-effort category guess from a raw_field key name. Falls back
    to 'Other' so nothing gets dropped on the floor."""
    k = (key or "").lower().replace("-", "_")
    for cat, kws in _CATEGORY_KEYWORDS:
        if any(kw in k for kw in kws):
            return cat
    return "Other"


def categorize_parsed(parsed: dict) -> dict:
    """Return {category: [{key, label, value}, ...]} for every parsed field
    that has a non-trivial value. Combines the hardcoded _FACT_FIELDS
    (rendered with their human labels) AND every raw_fields entry the
    parser didn't already cover (classified via keyword heuristics).

    Empty when parsed is empty / has no usable values."""
    if not parsed:
        return {}
    out: dict = {c: [] for c in ALL_CATEGORIES}
    covered_keys: set = set()

    # Pass 1 — hardcoded fact fields with formatters + canonical labels.
    for entry in _FACT_FIELDS:
        label, keys = entry[0], entry[1]
        fmt = entry[2] if len(entry) > 2 else None
        cat = entry[3] if len(entry) > 3 else _categorize_key(keys[0] if keys else "")
        for k in keys:
            covered_keys.add(k)
            raw = parsed.get(k)
            if not _is_real_value(raw):
                continue
            v = fmt(raw, parsed) if fmt else raw
            if not _is_real_value(v):
                continue
            out.setdefault(cat, []).append({
                "key":   keys[0],
                "label": label,
                "value": str(v),
            })
            break

    # Pass 2 — every other raw_fields key that the hardcoded list didn't
    # already cover. Lets arbitrary log shapes still surface their fields.
    raw_fields = parsed.get("raw_fields") or {}
    for raw_key, raw_val in raw_fields.items():
        if not _is_real_value(raw_val):
            continue
        if raw_key.lower() in {k.lower() for k in covered_keys}:
            continue
        cat = _categorize_key(raw_key)
        out.setdefault(cat, []).append({
            "key":   raw_key,
            "label": raw_key,
            "value": str(raw_val)[:200],
        })

    # Drop empty buckets so the frontend doesn't render zero-item toggles.
    return {c: items for c, items in out.items() if items}


def _join_location(p: dict) -> str:
    """Combine city + state + country into 'City, ST, Country' when present."""
    parts = []
    for k in ("location_city", "location_state", "location_country"):
        v = (p or {}).get(k)
        if v and str(v).strip() and str(v).strip().lower() not in {"unknown", "-", "n/a"}:
            parts.append(str(v).strip())
    return ", ".join(parts) if parts else ""


def _is_real_value(v) -> bool:
    """Empty / placeholder values shouldn't render as facts."""
    if v in (None, "", "N/A", "-"):
        return False
    s = str(v).strip()
    if not s or s.lower() in {"unknown", "n/a", "na", "-", "(empty)", "null", "none"}:
        return False
    return True


# ─── Custom email templates (spec §8) ────────────────────────────────────────
# Map a template field-id (the UI's toggle name) to the list of parsed-dict
# keys it controls. When `options["enabled_fields"]` is a non-empty list,
# `_filter_parsed_for_template()` keeps ONLY keys mentioned by enabled
# field-ids — disabled fields are completely excluded from the rendered
# email body and from the AI prompt, not just visually hidden.
TEMPLATE_FIELD_TO_KEYS = {
    "alert_summary":       [],   # rendered by the AI summary sentence, not a parsed key
    # Do NOT fall back to ep_domain — it's the Windows AD domain prefix
    # from "DOMAIN\username", not a hostname. Using it as a host source
    # made the email body claim "affected host: SEC" when SEC was really
    # just the AD domain shared across every user record.
    "affected_host":       ["asset_name"],
    "severity":            ["severity", "threat_level"],
    "malware_name":        ["ep_defender_type", "ep_admin_alert_title", "ep_message",
                            "malware_name", "threat_name"],
    "file_path":           ["ep_defender_path", "ep_defender_file", "ep_full_path",
                            "infected_path"],
    "source_ip":           ["ip_address", "first_login_ip", "second_login_ip",
                            "source_ip"],
    "destination_ip":      ["destination_ip", "dest_ip"],
    "username":            ["user_principal_name", "ep_user", "user_display_name",
                            "target_user_principal_name"],
    "process_path":        ["ep_process_path"],
    "process_name":        ["ep_application_name", "process_name"],
    "action_taken":        ["response_action", "action_name"],
    "detection_source":    ["detection_source", "ep_defender_source",
                            "ep_admin_alert_provider"],
    "timeline":            ["ep_date", "timestamp"],
    "mitre_techniques":    ["mitre_techniques"],
    "enrichment_summary":  ["enrichment_summary"],
    "recommended_actions": ["recommended_actions"],
    "technical_details":   ["ep_cmd_line", "ep_process_id", "ep_sha256",
                            "additional_info_user_agent",
                            "risk_event_type", "risk_level", "risk_state",
                            "additional_info_risk_reasons",
                            "privileged_role_display_name",
                            "privileged_role_well_known",
                            "forwarding_address",
                            "location_city", "location_state", "location_country"],
}

# Field-ids the analyst sees in the UI. Order matters for the rendered
# email body — kept aligned with the natural triage flow.
TEMPLATE_FIELD_ORDER = (
    "alert_summary", "severity", "malware_name", "affected_host",
    "username", "source_ip", "destination_ip",
    "file_path", "process_name", "process_path",
    "action_taken", "detection_source", "timeline",
    "mitre_techniques", "enrichment_summary",
    "recommended_actions", "technical_details",
)


def _filter_parsed_for_template(parsed: dict, enabled_fields) -> dict:
    """Return a copy of `parsed` containing only keys mapped to enabled
    field-ids. When `enabled_fields` is None / empty / not a list, no
    filtering happens (the email keeps the original full-detail behaviour
    so existing callers are unaffected)."""
    if not enabled_fields or not isinstance(enabled_fields, (list, tuple, set)):
        return dict(parsed or {})
    enabled = {str(f) for f in enabled_fields}
    keep = set()
    for fid, keys in TEMPLATE_FIELD_TO_KEYS.items():
        if fid in enabled:
            keep.update(keys)
    # Always keep housekeeping keys the renderer uses (raw_fields,
    # suggested_alert_type) and any key under control of a field that has
    # no parsed mapping (e.g. alert_summary is AI-rendered, not parsed).
    out = {}
    for k, v in (parsed or {}).items():
        if k.startswith("_") or k in ("raw_fields", "suggested_alert_type"):
            out[k] = v
            continue
        if k in keep:
            out[k] = v
    return out


def _render_facts_block(parsed: dict, options: dict) -> str:
    """Build the labelled 'Label: value' block from parsed alert fields.
    Returns a multi-line string ready to slot at the top of the email body.
    Returns "" when the parser produced nothing usable.

    The LLM never produces this content — it's deterministic, so we never
    have to worry about robotic narration or hallucinated fields."""
    p = parsed or {}
    o = options or {}
    # Custom-template filtering — when options carries an enabled_fields
    # list, drop every parsed key that isn't mapped to an enabled field-id
    # so disabled fields are excluded from the rendered email entirely.
    enabled_fields = (options or {}).get("enabled_fields")
    if enabled_fields:
        p = _filter_parsed_for_template(p, enabled_fields)
    # Category-toggle filtering — when options carries enabled_categories,
    # render ONLY the fact rows + raw_fields entries whose category is on.
    # Lets the analyst dynamically include/exclude whole groups (Identity,
    # Network, Process, etc.) without editing the per-field list. When
    # enabled_categories is None or empty list it acts as "all categories
    # on" (no filtering).
    enabled_categories = (options or {}).get("enabled_categories")
    if enabled_categories:
        enabled_set = {str(c).strip() for c in enabled_categories}
        categorized = categorize_parsed(p)
        # Build a fresh dict containing only the keys the categorizer
        # placed under an enabled category. Everything else gets dropped.
        kept_keys: set = set()
        for cat, items in categorized.items():
            if cat in enabled_set:
                for it in items:
                    kept_keys.add(it["key"])
                    # _FACT_FIELDS sometimes has multiple candidate keys
                    # per row; widen the keep-set to all keys the row
                    # might pull from.
                    for entry in _FACT_FIELDS:
                        if it["key"] == entry[1][0]:
                            for k in entry[1]:
                                kept_keys.add(k)
        # Always preserve housekeeping + raw_fields so downstream renderers
        # (suggest_alert_type, AI context) still have what they need.
        always_keep = {"raw_fields", "suggested_alert_type", "_alert_label",
                       "suggested_response_action"}
        new_parsed = {}
        for k, v in p.items():
            if k.startswith("_") or k in always_keep or k in kept_keys:
                new_parsed[k] = v
        # raw_fields gets pruned to matching-category keys only.
        if isinstance(new_parsed.get("raw_fields"), dict):
            new_parsed["raw_fields"] = {
                rk: rv for rk, rv in new_parsed["raw_fields"].items()
                if rk in kept_keys
                or _categorize_key(rk) in enabled_set
            }
        p = new_parsed
    seen_values = set()
    lines = []

    for entry in _FACT_FIELDS:
        label, keys = entry[0], entry[1]
        formatter   = entry[2] if len(entry) > 2 else None

        # Pick first key that has a real value
        raw = None
        for k in keys:
            if _is_real_value(p.get(k)):
                raw = p.get(k)
                break
        if raw is None:
            continue

        value = formatter(raw, p) if formatter else raw
        if not _is_real_value(value):
            continue
        value_str = str(value).strip()

        # Dedup: if a value has already been emitted under a different
        # label (e.g. ep_user == user_principal_name), skip it.
        if value_str in seen_values:
            continue
        seen_values.add(value_str)
        lines.append(f"{label}: {value_str}")

    # Catch-all — any raw_fields key the hardcoded _FACT_FIELDS list didn't
    # cover but whose category survived the enabled-categories filter still
    # gets a row. Keeps the email accurate for arbitrary log shapes without
    # requiring every new log format to be hardcoded.
    covered_keys = set()
    for entry in _FACT_FIELDS:
        for k in entry[1]:
            covered_keys.add(k.lower())
    raw_fields = p.get("raw_fields") or {}
    for raw_key, raw_val in raw_fields.items():
        if not _is_real_value(raw_val):
            continue
        if raw_key.lower() in covered_keys:
            continue
        value_str = str(raw_val).strip()[:200]
        if value_str in seen_values:
            continue
        # Skip housekeeping-shaped keys (long opaque IDs the analyst
        # doesn't want in the body).
        if len(raw_key) > 60:
            continue
        seen_values.add(value_str)
        lines.append(f"{raw_key}: {value_str}")

    # Response action — what was already done about the alert, if anything
    response_action = (o or {}).get("response_action") or ""
    if response_action:
        for rid, rlabel in RESPONSE_ACTIONS:
            if rid == response_action and rid:
                lines.append(f"Response action: {rlabel}")
                break

    return "\n".join(lines)


# ─── OSINT enrichment fan-out for emails ─────────────────────────────────────
#
# Analyst feedback: customer emails should include the OSINT context we
# already have (AbuseIPDB risk score, ISP/ASN, country, VirusTotal
# detections, WHOIS age, etc.) instead of just echoing what the alert log
# itself contained. The compose_ai flow now extracts IOCs from the raw
# log, runs the same enrichment fan-out the analyze pipeline uses, and
# renders a compact 'Threat intelligence' subsection in the facts block
# AND feeds the same data to the AI so the analysis paragraph can
# reference specific findings.
#
# Caps the fan-out to keep latency bounded — emails are interactive,
# analysts don't want a 30-second compose. Max 4 IPs / 3 domains / 2
# hashes / 2 URLs gets us 90% of useful context for <8s overhead.

_EMAIL_ENR_MAX_IPS     = 4
_EMAIL_ENR_MAX_DOMAINS = 3
_EMAIL_ENR_MAX_HASHES  = 2
_EMAIL_ENR_MAX_URLS    = 2

# IOCs commonly embedded in MDR alerts that are NOT analyst-actionable.
# Local network ranges + Microsoft / Cloudflare / Google infra hostnames
# get filtered before fan-out to avoid spammy lookups.
_ENR_SKIP_DOMAINS = {
    "microsoft.com", "windows.com", "office.com", "outlook.com",
    "live.com", "azure.com", "office365.com", "msftncsi.com",
    "windowsupdate.com", "msauth.net", "msftauth.net",
    "google.com", "googleapis.com", "gstatic.com", "gmail.com",
    "cloudflare.com", "cloudflare-dns.com",
    "apple.com", "icloud.com",
}


def _is_private_or_local_ip(ip: str) -> bool:
    """Skip RFC1918 / loopback / link-local before enrichment."""
    try:
        octets = [int(x) for x in ip.split(".")]
        if len(octets) != 4:
            return True
        a, b = octets[0], octets[1]
        if a == 10:                       return True
        if a == 172 and 16 <= b <= 31:    return True
        if a == 192 and b == 168:         return True
        if a == 127:                      return True
        if a == 169 and b == 254:         return True
        if a == 0 or a >= 224:            return True
    except Exception:
        return True
    return False


def _extract_iocs_from_log(log_text: str, parsed: Dict) -> Dict[str, List[str]]:
    """Pull IPs / domains / hashes / URLs out of the raw log + parsed
    fields. Caps each type and skips well-known benign infrastructure.
    Defender version strings (AV: 1.451.195.0) and in-path version
    directories (\\app\\6.35.0.35\\service\\) get stripped before IP
    extraction so they don't surface as fake IOCs."""
    iocs: Dict[str, List[str]] = {"ips": [], "domains": [], "hashes": [], "urls": []}
    seen = {"ips": set(), "domains": set(), "hashes": set(), "urls": set()}

    def _add(kind, value):
        v = (value or "").strip()
        if not v or v in seen[kind]:
            return
        if kind == "ips" and _is_private_or_local_ip(v):
            return
        if kind == "ips" and not _valid_v4_octets(v):
            return
        if kind == "domains" and v.lower() in _ENR_SKIP_DOMAINS:
            return
        seen[kind].add(v)
        iocs[kind].append(v)

    # Strip software version strings BEFORE IP extraction so the regex
    # doesn't see them. Re-uses the triage scrubbers when the package is
    # importable; falls back to local regexes otherwise so the email
    # composer never depends on the triage agent.
    cleaned = (log_text or "")
    try:
        from agents.triage import strip_defender_version_strings as _strip_ver
        cleaned = _strip_ver(cleaned)
    except Exception:
        # Fallback — strip `\X.Y.Z.W\` / `/X.Y.Z.W/` path versions and
        # `AV: 1.451.195.0` Defender version K-V lines.
        cleaned = re.sub(r"(?<=[\\/])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?=[\\/])", " ", cleaned)
        cleaned = re.sub(r"\b(?:AV|AS|NIS|AM)\s*:\s*\d{1,5}(?:\.\d{1,5}){2,3}\b", " ", cleaned)

    # Browser version numbers inside User-Agent strings look exactly like
    # IPv4 addresses (Chrome/148.0.0.0, Edg/149.0.0.0, Firefox/120.0.0.0).
    # iocextract / our IP regex were extracting them and enriching the
    # Chrome version number as if it were the user's source IP — emails
    # then carried bogus 'Vodafone Turkey' / 'Compañía Dominicana de
    # Teléfonos' lines for a user-agent string. Strip the
    # 'Token/X.Y.Z.W' pattern (any product token followed by 4-octet
    # version) before IP extraction.
    cleaned = re.sub(
        r"\b[A-Za-z][A-Za-z0-9_\-]+/\d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,4}\b",
        " ", cleaned,
    )

    # Microsoft Defender TLHash / Parent Process TLHash fields are
    # 32-char hex strings shaped exactly like MD5s but they are NOT
    # file hashes (Microsoft internal TrieList hash). They were being
    # extracted as MD5 hashes and pushed to VirusTotal, where they
    # sometimes coincidentally collided with real malware hashes and
    # came back as 'malicious'. Strip them before hash extraction.
    cleaned = re.sub(
        r"^[ \t]*(?:Parent\s+Process\s+)?TLHash\s*:[^\r\n]*",
        " ", cleaned, flags=re.IGNORECASE | re.MULTILINE,
    )

    # Microsoft / Entra ID alert identifiers are 64-char hex strings
    # shaped exactly like a SHA-256 (e.g. 'id : 29644c05947ac6...').
    # They were being extracted as file hashes, pushed to VirusTotal,
    # and the empty-result was then narrated by the AI as 'the file
    # hash has no malicious reputation' — misleading because it's not
    # a file hash, just an alert ID. Strip any line where the key
    # ends with 'Id' / 'ID' / 'id' and the value is a long hex blob.
    cleaned = re.sub(
        r"^[ \t]*[\w\s]*[Ii][Dd]\s*:\s*[a-fA-F0-9]{32,64}[ \t]*$",
        " ", cleaned, flags=re.MULTILINE,
    )

    # Documentation / KB links inside an alert message (go.microsoft.com,
    # learn.microsoft.com, docs.microsoft.com, ...) are not customer
    # IOCs — they're just where Microsoft hosts the help page for the
    # detection. They were getting enriched as if they were attacker
    # infrastructure. Strip any documentation-shaped URL pattern.
    cleaned = re.sub(
        r"https?://(?:go|learn|docs|support|aka|technet)\.microsoft\.com[^\s\"'<>]*",
        " ", cleaned, flags=re.IGNORECASE,
    )

    # IPs — log body
    for m in _IOC_IP_RE.finditer(cleaned):
        _add("ips", m.group(0))
        if len(iocs["ips"]) >= _EMAIL_ENR_MAX_IPS:
            break
    # IPs — parsed (covers source_ip, dest_ip, first_login_ip, etc.)
    for k, v in (parsed or {}).items():
        if isinstance(v, str) and _IOC_IP_RE.fullmatch(v.strip() or ""):
            _add("ips", v.strip())
            if len(iocs["ips"]) >= _EMAIL_ENR_MAX_IPS:
                break

    # Domains
    for m in _IOC_DOMAIN_RE.finditer(cleaned):
        _add("domains", m.group(1).lower())
        if len(iocs["domains"]) >= _EMAIL_ENR_MAX_DOMAINS:
            break

    # URLs
    for m in _IOC_URL_RE.finditer(cleaned):
        _add("urls", m.group(0).rstrip(".,;)\"'"))
        if len(iocs["urls"]) >= _EMAIL_ENR_MAX_URLS:
            break

    # Hashes — md5, sha1, sha256 from log + parsed
    _HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
    for m in _HASH_RE.finditer(cleaned):
        h = m.group(0).lower()
        if len(h) in (32, 40, 64):
            _add("hashes", h)
            if len(iocs["hashes"]) >= _EMAIL_ENR_MAX_HASHES:
                break
    return iocs


def _valid_v4_octets(s: str) -> bool:
    """Every octet in a dotted-quad must be 0-255. Defender version
    strings + in-path versions usually have an octet > 255 (e.g.
    1.451.195.0) but some legitimately look like IPs (6.35.0.35); the
    Defender/path scrubbers handle those upstream."""
    try:
        return all(0 <= int(x) <= 255 for x in s.split("."))
    except Exception:
        return False


def _strip_asn_prefix(org: str) -> Tuple[str, str]:
    """Split an IPInfo-style 'AS7018 AT&T Enterprises, LLC' string into
    ('AT&T Enterprises, LLC', 'AS7018'). When the prefix isn't present,
    returns (org, '')."""
    s = (org or "").strip()
    m = re.match(r"^(AS\d+)\s+(.+)$", s)
    if m:
        return m.group(2).strip(), m.group(1).strip()
    return s, ""


def _fmt_ip_enrichment(ip: str, data: Dict) -> str:
    """Client-readable summary paragraph for an IP. Pulls from every
    API source we have — AbuseIPDB, VirusTotal, IPInfo, GreyNoise,
    Maltiverse, Pulsedive, Shodan, ASN reputation, Tor — and renders
    as natural-language sentences so the customer can read it without
    decoding CLI-style fragments."""
    if not data or not isinstance(data, dict):
        return ""

    abuse = data.get("abuseipdb") or {}
    ipinfo = data.get("ipinfo") or {}
    vt     = data.get("virustotal") or {}
    gn     = data.get("greynoise") or {}
    mal_t  = data.get("maltiverse") or {}
    pd     = data.get("pulsedive") or {}
    asn_rep= data.get("asn_reputation") or {}
    censys = data.get("censys") or {}
    crowdsec = data.get("crowdsec") or {}
    proxycheck = data.get("proxycheck") or {}
    criminal_ip = data.get("criminal_ip") or {}
    feodo = data.get("feodo_tracker") or {}
    bgp = (data.get("osint") or {}).get("bgp_ranking") or {}
    # enrich_ip returns tor as {'isExitNode': bool} — not a bare bool.
    # The naive bool(data.get('tor')) check treated every non-empty dict
    # as Truthy and labelled every IP as a Tor exit. Use the inner flag.
    _tor_blob = data.get("tor") or {}
    tor    = bool(_tor_blob.get("isExitNode")) if isinstance(_tor_blob, dict) else bool(_tor_blob)

    # ── Identity sentence: org + location + ASN + reverse DNS ─────────────
    org_raw  = (ipinfo.get("org") or "").strip()
    org, asn = _strip_asn_prefix(org_raw)
    country  = (ipinfo.get("country") or abuse.get("country") or "").strip()
    city     = (ipinfo.get("city") or "").strip()
    region   = (ipinfo.get("region") or "").strip()
    hostname = (ipinfo.get("hostname") or "").strip()
    if not org and abuse.get("isp"):
        org = abuse["isp"].strip()

    loc_bits = [b for b in (city, region, country) if b]
    if loc_bits:
        # dedupe ("Houston, Texas, US" -> "Houston, US" if region matches)
        seen = []
        for b in loc_bits:
            if b not in seen:
                seen.append(b)
        loc = ", ".join(seen[:3])
    else:
        loc = ""

    if org and loc:
        identity_sentence = f"It is registered to {org} in {loc}"
    elif org:
        identity_sentence = f"It is registered to {org}"
    elif loc:
        identity_sentence = f"It is located in {loc}"
    else:
        identity_sentence = ""
    if asn:
        identity_sentence += f" (autonomous system {asn})" if identity_sentence \
                              else f"It is on autonomous system {asn}"
    if hostname:
        identity_sentence += f", reverse DNS {hostname}"
    if identity_sentence:
        identity_sentence += "."

    # ── Usage / behavioural context ───────────────────────────────────────
    usage = (abuse.get("usageType") or "").strip()
    behaviour_bits = []
    if usage:
        behaviour_bits.append(f"Usage classification: {usage}.")
    if tor:
        behaviour_bits.append("It is a known Tor exit node.")
    if asn_rep.get("severity") in ("high", "medium") and asn_rep.get("hits"):
        descs = [h.get("description") for h in asn_rep["hits"][:1] if h.get("description")]
        if descs:
            behaviour_bits.append(
                f"The hosting ASN has been flagged as abuse-friendly: {descs[0]}.")
    # ── Reputation findings ───────────────────────────────────────────────
    reputation_bits = []
    score = abuse.get("abuseScore") if abuse else None
    reports = abuse.get("totalReports") if abuse else None
    last_reported = (abuse.get("lastReportedAt") or "")[:10] if abuse else ""
    if score is not None:
        if score > 0 or (reports or 0) > 0:
            piece = f"AbuseIPDB rates the IP at {score}% confidence"
            if reports:
                piece += f" backed by {reports} community report{'s' if reports != 1 else ''}"
            if last_reported:
                piece += f" (most recent {last_reported})"
            reputation_bits.append(piece + ".")
        else:
            reputation_bits.append("AbuseIPDB has no abuse reports on file.")

    if vt and not vt.get("error"):
        mal = vt.get("malicious", 0) or 0
        susp = vt.get("suspicious", 0) or 0
        total = (vt.get("harmless", 0) or 0) + (vt.get("undetected", 0) or 0) + mal + susp
        if total:
            if mal or susp:
                reputation_bits.append(
                    f"VirusTotal shows {mal + susp} of {total} engines flagging the IP.")
            else:
                reputation_bits.append(
                    f"VirusTotal shows the IP clean across {total} engines.")

    if gn and not gn.get("error"):
        cls = (gn.get("classification") or "").strip().lower()
        name = (gn.get("name") or "").strip()
        # GreyNoise sometimes reports an actor 'name' of 'unknown' which
        # adds no information — skip the parenthetical in that case.
        named = name if name and name.lower() != "unknown" else ""
        if cls in ("malicious", "suspicious"):
            reputation_bits.append(
                f"GreyNoise classifies it as {cls}"
                + (f" ({named})" if named else "") + ".")
        elif cls == "benign":
            reputation_bits.append(
                f"GreyNoise recognises it as benign Internet noise"
                + (f" ({named})" if named else "") + ".")

    if mal_t and not mal_t.get("error"):
        cls = (mal_t.get("classification") or "").strip().lower()
        if cls in ("malicious", "suspicious"):
            tags = mal_t.get("tag") or []
            tag_str = f" ({', '.join(tags[:3])})" if tags else ""
            reputation_bits.append(f"Maltiverse classifies it as {cls}{tag_str}.")

    if pd and not pd.get("error"):
        risk = (pd.get("risk") or pd.get("risk_factor") or "").strip().lower()
        threats = pd.get("threats") or []
        if risk in ("critical", "high", "medium"):
            piece = f"Pulsedive risk score: {risk}"
            if threats:
                piece += f" (associated threats: {', '.join(threats[:3])})"
            reputation_bits.append(piece + ".")

    # CrowdSec CTI — aggregated score from the crowdsourced security
    # network. Returns a 0-5 score + behaviour list (crawler, brute-force,
    # web-scan, etc.). High-signal when behaviours include credential or
    # exploit-attempt tags.
    if crowdsec and not crowdsec.get("error"):
        score = crowdsec.get("background_noise_score") or crowdsec.get("score")
        behaviours = crowdsec.get("behaviors") or []
        if score and score > 0:
            piece = f"CrowdSec CTI reports a malicious-activity score of {score}/5"
            if behaviours:
                names = [b.get("name") or str(b) for b in behaviours[:3] if b]
                piece += f" with observed behaviours: {', '.join(names)}"
            reputation_bits.append(piece + ".")

    # Criminal IP — paid TI service with inbound/outbound threat scores
    # + VPN/proxy/scanner/Tor classification flags.
    if criminal_ip and not criminal_ip.get("error"):
        inb = criminal_ip.get("inbound_score")
        outb = criminal_ip.get("outbound_score")
        flags = []
        if criminal_ip.get("is_tor"):      flags.append("Tor")
        if criminal_ip.get("is_vpn") or criminal_ip.get("is_anonymous_vpn"): flags.append("VPN")
        if criminal_ip.get("is_proxy"):    flags.append("proxy")
        if criminal_ip.get("is_scanner"):  flags.append("scanner")
        if inb in ("critical", "dangerous", "moderate") or outb in ("critical", "dangerous", "moderate") or flags:
            piece = "Criminal IP rates the IP"
            if inb and outb:
                piece += f" inbound {inb} / outbound {outb}"
            elif inb:
                piece += f" inbound threat {inb}"
            elif outb:
                piece += f" outbound threat {outb}"
            if flags:
                piece += f" with {', '.join(flags)} flags"
            reputation_bits.append(piece + ".")

    # ProxyCheck — VPN / proxy / Tor classification. When the IP is
    # flagged as a proxy or VPN, that's high-signal context for any
    # alert (user logging in from a VPN, C2 traffic via a proxy, etc.).
    if proxycheck and not proxycheck.get("error"):
        if proxycheck.get("proxy"):
            piece = "ProxyCheck flags this IP as a proxy"
            if proxycheck.get("type"):
                piece += f" of type {proxycheck['type']}"
            if proxycheck.get("provider"):
                piece += f" ({proxycheck['provider']})"
            risk = proxycheck.get("risk")
            if risk is not None and isinstance(risk, (int, float)) and risk > 50:
                piece += f", risk score {risk}/100"
            reputation_bits.append(piece + ".")

    # Feodo Tracker — abuse.ch botnet C2 tracker. Hits are high-signal.
    if feodo:
        family = feodo.get("malware") or feodo.get("family") or "a known botnet"
        first_seen = feodo.get("first_seen") or ""
        piece = f"Feodo Tracker lists this IP as active {family} C2 infrastructure"
        if first_seen:
            piece += f" (first observed {first_seen[:10]})"
        reputation_bits.append(piece + ".")

    # BGP Ranking (CIRCL) — ASN-level reputation rank. Lower rank = worse
    # standing. Only mention when the rank is meaningfully bad.
    if bgp and not bgp.get("error"):
        rank = bgp.get("rank")
        if rank is not None and isinstance(rank, (int, float)) and rank < 5:
            asn_desc = bgp.get("asn_description") or ""
            piece = f"BGP Ranking flags the hosting ASN ({asn_desc or 'unknown'}) with a poor reputation rank of {rank}"
            reputation_bits.append(piece + ".")

    # Censys — observed open services + TLS cert when present.
    if censys and not censys.get("error"):
        services = censys.get("services") or []
        if services:
            ports = [str(s.get("port")) for s in services[:8] if s.get("port")]
            if ports:
                reputation_bits.append(
                    f"Censys observes services on ports {', '.join(ports)} "
                    f"({len(services)} total).")
        cert = censys.get("ssl_cert") or {}
        subject = cert.get("subject")
        if subject:
            reputation_bits.append(f"Censys-observed TLS certificate subject: {subject[:80]}.")

    sentences = [s for s in [identity_sentence] + behaviour_bits + reputation_bits if s]
    if not sentences:
        return ""
    return f"- {ip}\n  " + " ".join(sentences)


def _join_clauses(clauses: List[str]) -> str:
    """Join a list of clauses into a single readable phrase. One clause
    → as-is; two → 'X and Y'; three+ → 'X, Y, and Z'."""
    cleaned = [c.strip() for c in clauses if c and c.strip()]
    if not cleaned:
        return ""
    if len(cleaned) == 1:
        return cleaned[0]
    if len(cleaned) == 2:
        return f"{cleaned[0]} and {cleaned[1]}"
    return ", ".join(cleaned[:-1]) + f", and {cleaned[-1]}"


def _clean_summary_phrase(sources: List[str]) -> str:
    """Render 'no reputation hits on X' phrasing. Avoid the 'clean
    across X / Y' jargon."""
    s = [src for src in sources if src]
    if not s:
        return ""
    if len(s) == 1:
        return f"no reputation hits on {s[0]}"
    if len(s) == 2:
        return f"no reputation hits on {s[0]} or {s[1]}"
    return "no reputation hits on " + ", ".join(s[:-1]) + f", or {s[-1]}"


def _fmt_domain_enrichment(domain: str, data: Dict) -> str:
    """Client-readable summary paragraph for a domain. Surfaces every
    relevant signal we collect: WHOIS registration date and registrar,
    VirusTotal reputation, Spamhaus DBL listing, OTX threat pulses,
    Maltiverse classification, URLScan history, Wayback archive
    presence, Cert Transparency subdomain count, Pulsedive risk."""
    if not data or not isinstance(data, dict):
        return ""

    whois = data.get("whois") or {}
    vt = data.get("virustotal") or {}
    spam = data.get("spamhaus_dbl") or {}
    otx = data.get("otx") or {}
    mal_t = data.get("maltiverse") or {}
    urlscan = data.get("urlscan") or {}
    wayback = data.get("wayback") or {}
    crt = data.get("certTransparency") or {}
    pd = data.get("pulsedive") or {}
    heur = data.get("heuristics") or {}

    sentences: List[str] = []

    # WHOIS — age + registrar + registrant
    if whois and not whois.get("error"):
        age = whois.get("age_days")
        registrar = (whois.get("registrar") or "").strip()
        created = (whois.get("created") or "")[:10]
        registrant = (whois.get("registrant_org") or "").strip()
        country = (whois.get("registrant_country") or "").strip()
        bits = []
        if age is not None:
            if age < 30:
                bits.append(f"registered {age} day{'s' if age != 1 else ''} ago")
            elif age < 365:
                bits.append(f"registered {age} days ago")
            else:
                yr = age // 365
                bits.append(f"registered about {yr} year{'s' if yr != 1 else ''} ago")
        if created:
            bits.append(f"on {created}")
        if registrar:
            bits.append(f"through {registrar}")
        if registrant:
            tail = f"under registrant {registrant}"
            if country:
                tail += f" ({country})"
            bits.append(tail)
        if bits:
            sentence = "The domain was " + " ".join(bits)
            # Avoid 'Namecheap, Inc..' double periods when the registrar
            # field already ends with a period.
            sentences.append(sentence.rstrip(".") + ".")
        if whois.get("privacy_protected"):
            sentences.append("WHOIS registrant details are privacy-redacted.")

    # Heuristic flags (NRD / DGA / IDN)
    nrd = (heur or {}).get("nrd") or {}
    if nrd.get("is_same_day"):
        sentences.append(
            "Domain age is under 24 hours, a top-tier phishing indicator.")
    elif nrd.get("is_this_week"):
        sentences.append(
            f"Domain age is {nrd.get('age_days')} days, "
            "a strong newly-registered-domain (NRD) phishing indicator.")
    # DGA heuristic — suppress for known-legitimate auto-generated tenant
    # subdomains. Microsoft 365 tenants are auto-named 'netorgft#######'
    # or '<random>.onmicrosoft.com'; the DGA scorer correctly flags the
    # random label, but in this context it's a legitimate tenant name,
    # not malware infrastructure.
    _is_known_generated = (
        domain.endswith(".onmicrosoft.com")
        or domain.endswith(".sharepoint.com")
        or domain.endswith(".azurewebsites.net")
        or domain.endswith(".cloudapp.azure.com")
        or domain.endswith(".cloudfront.net")
        or domain.endswith(".amazonaws.com")
    )
    if (heur or {}).get("dga", {}).get("flagged") and not _is_known_generated:
        sentences.append(
            "The domain label scores high on DGA heuristics, suggesting an "
            "algorithmically-generated name.")
    if (heur or {}).get("idn"):
        sentences.append(
            "Internationalised-domain analysis flagged punycode or homoglyph "
            "characters that could spoof a legitimate brand.")

    # VirusTotal
    if vt and not vt.get("error"):
        mal = vt.get("malicious", 0) or 0
        susp = vt.get("suspicious", 0) or 0
        total = (vt.get("harmless", 0) or 0) + (vt.get("undetected", 0) or 0) + mal + susp
        if total:
            if mal or susp:
                sentences.append(
                    f"VirusTotal shows {mal + susp} of {total} engines flagging "
                    "the domain.")
            else:
                sentences.append(
                    f"VirusTotal shows the domain clean across {total} engines.")

    # Spamhaus DBL — independent authoritative listing
    if spam.get("hit"):
        v = spam.get("verdict") or "listed"
        sentences.append(
            f"Spamhaus DBL lists the domain ({v}), an independent confirmation "
            "from an authoritative blocklist.")

    # OTX pulses
    if otx and not otx.get("error"):
        c = otx.get("pulseCount") or otx.get("pulse_count") or 0
        if c:
            sentences.append(
                f"AlienVault OTX has {c} threat pulse{'s' if c != 1 else ''} "
                "associating the domain with reported campaigns.")

    # Maltiverse
    if mal_t and not mal_t.get("error"):
        cls = (mal_t.get("classification") or "").strip().lower()
        if cls in ("malicious", "suspicious"):
            tags = mal_t.get("tag") or []
            tail = f" (tagged {', '.join(tags[:3])})" if tags else ""
            sentences.append(f"Maltiverse classifies it as {cls}{tail}.")

    # Pulsedive risk
    if pd and not pd.get("error"):
        risk = (pd.get("risk") or "").strip().lower()
        threats = pd.get("threats") or []
        if risk in ("critical", "high", "medium"):
            piece = f"Pulsedive risk score is {risk}"
            if threats:
                piece += f" (threat associations: {', '.join(threats[:3])})"
            sentences.append(piece + ".")

    # URLScan history
    if urlscan and not urlscan.get("error"):
        total = urlscan.get("total")
        if total:
            mal_s = urlscan.get("malicious") or 0
            last = (urlscan.get("last_scan_date") or "")[:10]
            piece = f"URLScan has {total} prior submission{'s' if total != 1 else ''}"
            if last:
                piece += f" (most recent {last})"
            if mal_s:
                piece += f", {mal_s} flagged malicious"
            sentences.append(piece + ".")

    # Wayback Machine
    if wayback:
        if wayback.get("has_snapshots") is False and not _is_known_generated:
            sentences.append(
                "The Wayback Machine has no archived snapshots — unusual for "
                "an established business domain.")
        elif wayback.get("first_snapshot"):
            sentences.append(
                f"The Wayback Machine first archived the domain on "
                f"{str(wayback.get('first_snapshot'))[:10]}.")

    # Cert Transparency — useful when many subdomains hint at infra reuse
    if crt and not crt.get("error"):
        subs = crt.get("subdomains") or []
        certs = crt.get("totalCerts")
        if certs and certs >= 100:
            sentences.append(
                f"Certificate Transparency logs show {certs} certificates "
                f"issued across {len(subs)} subdomains, indicating active "
                "TLS infrastructure.")

    # FullHunt — attack-surface inventory
    fh = data.get("fullhunt") or {}
    if fh and not fh.get("error"):
        sub_count = fh.get("subdomain_count")
        ports = fh.get("ports") or []
        if sub_count or ports:
            bits = []
            if sub_count: bits.append(f"{sub_count} subdomains")
            if ports:     bits.append(f"open ports {', '.join(str(p) for p in ports[:6])}")
            sentences.append(
                "FullHunt's attack-surface scan reports " + " and ".join(bits) + ".")

    if not sentences:
        return ""
    return f"- {domain}\n  " + " ".join(sentences)


def _fmt_hash_enrichment(h: str, data: Dict) -> str:
    """Client-readable summary for a file hash. Pulls VirusTotal,
    MalwareBazaar, Hybrid Analysis, and any signing / family / size
    context we have."""
    if not data or not isinstance(data, dict):
        return ""

    vt = data.get("virustotal") or {}
    mb = data.get("malwarebazaar") or {}
    ha = data.get("hybrid_analysis") or {}

    sentences: List[str] = []

    # VirusTotal — engine ratio + family + signer + dates
    if vt and not vt.get("error"):
        mal = vt.get("malicious", 0) or 0
        susp = vt.get("suspicious", 0) or 0
        total = (vt.get("harmless", 0) or 0) + (vt.get("undetected", 0) or 0) + mal + susp
        if total and (mal or susp):
            verdict = "malicious" if mal else "suspicious"
            sentences.append(
                f"VirusTotal flags the file as {verdict}, "
                f"with {mal + susp} of {total} engines detecting it.")
            fam = (vt.get("family") or vt.get("popular_name") or "").strip()
            if fam:
                sentences.append(f"VirusTotal labels the family as {fam}.")
        elif total:
            sentences.append(
                f"VirusTotal shows the file clean across {total} engines.")
        first = (vt.get("first_seen") or vt.get("first_submission_date") or "")
        if first:
            sentences.append(
                f"It was first submitted to VirusTotal on {str(first)[:10]}.")
        signer = (vt.get("signer") or vt.get("signature_info", {}).get("signer") or "")
        if signer:
            sentences.append(f"The file is digitally signed by {signer}.")

    # MalwareBazaar — confirmation + tags
    if mb.get("found"):
        family = mb.get("malware_family") or mb.get("signature")
        tags = mb.get("tags") or []
        piece = f"MalwareBazaar has the file catalogued"
        if family:
            piece += f" as {family}"
        if tags:
            piece += f" (tagged {', '.join(tags[:3])})"
        sentences.append(piece + ".")

    # Hybrid Analysis
    if ha and not ha.get("error"):
        v = (ha.get("verdict") or "").strip().lower()
        score = ha.get("threat_score")
        if v in ("malicious", "suspicious", "ambiguous"):
            piece = f"Hybrid Analysis sandboxing rates the verdict as {v}"
            if score is not None:
                piece += f" (threat score {score})"
            sentences.append(piece + ".")

    if not sentences:
        return ""
    return f"- {h[:16]}…\n  " + " ".join(sentences)


def _fmt_url_enrichment(url: str, data: Dict) -> str:
    """Client-readable summary for a URL."""
    if not data or not isinstance(data, dict):
        return ""

    vt = data.get("virustotal") or {}
    us = data.get("urlscan") or {}

    sentences: List[str] = []

    if vt and not vt.get("error"):
        mal = vt.get("malicious", 0) or 0
        susp = vt.get("suspicious", 0) or 0
        total = (vt.get("harmless", 0) or 0) + (vt.get("undetected", 0) or 0) + mal + susp
        if total and (mal or susp):
            sentences.append(
                f"VirusTotal shows {mal + susp} of {total} engines flagging "
                "the URL.")
        elif total:
            sentences.append(
                f"VirusTotal shows the URL clean across {total} engines.")

    if us and not us.get("error"):
        v = (us.get("verdict") or "").strip().lower()
        if v in ("malicious", "suspicious"):
            page_title = (us.get("page_title") or "").strip()
            piece = f"URLScan rates the URL as {v}"
            if page_title:
                piece += f" (page title \"{page_title[:60]}\")"
            sentences.append(piece + ".")
        elif us.get("country") and us.get("page_server"):
            sentences.append(
                f"URLScan recorded the destination as hosted in "
                f"{us['country']} on {us['page_server']}.")

    short_url = url if len(url) <= 80 else url[:77] + "…"
    if not sentences:
        return ""
    return f"- {short_url}\n  " + " ".join(sentences)


# ─── Detection summary block ────────────────────────────────────────────────
#
# Compact 4-7 bullet 'Detection summary' that sits between the verbose
# facts block at the top and the AI prose paragraph below. Lets the
# customer scan the most decision-relevant fields at a glance without
# parsing the full facts list.
#
# Bullet selection is alert-type aware:
#   malware-detection logs → Endpoint / User context / Detection / File / Action
#   sign-in logs           → Account / Source IP+ASN / Outcome / Client / Action
#   exchange logs          → Mailbox / Operation / Source IP / Action
#   role-change logs       → User / Role / Operation / Source IP / Action
#   network / process logs → Endpoint / User / Process / Destination / Action
#   generic fallback       → use whatever 4+ canonical fields are present
#
# Returns an empty string when fewer than 4 meaningful bullets are
# available so sparse logs don't get a half-empty block.


# Well-known Azure / Entra ID role GUIDs — keep in sync with the AI prompt's
# role list. Used to render 'Role: Global Administrator' instead of a raw GUID.
_AZURE_ROLE_GUIDS = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
    "8329153b-31d0-4727-b945-745eb3bc5f31": "Exchange Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Recipient Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
}


def _g(parsed: dict, *keys: str) -> str:
    """First non-empty value across the candidate key list. Match is
    case-insensitive AND treats underscores / spaces as equivalent so
    'process_path' matches 'Process Path', 'destination_ip' matches
    'Destination IP', etc. — saves us listing every alias variant."""
    if not parsed:
        return ""
    def _norm(s: str) -> str:
        return (s or "").lower().replace(" ", "").replace("_", "").replace("-", "")
    norm_keys = [_norm(k) for k in keys]
    for k, nk in zip(keys, norm_keys):
        v = parsed.get(k)
        if isinstance(v, str) and v.strip() and v.strip() != "-":
            return v.strip()
        # also check normalized variants in parsed
        for pk, pv in parsed.items():
            if _norm(pk) == nk and isinstance(pv, str) and pv.strip() and pv.strip() != "-":
                return pv.strip()
    raw = (parsed.get("raw_fields") or {}) if isinstance(parsed, dict) else {}
    for nk in norm_keys:
        for rk, rv in raw.items():
            if _norm(rk) == nk and isinstance(rv, str) and rv.strip() and rv.strip() != "-":
                return rv.strip()
    return ""


def _classify_alert(parsed: dict, log_text: str) -> str:
    """Pick the bullet template that fits the input. Order matters — most
    specific patterns first."""
    raw_lower = (log_text or "").lower()
    rf = (parsed.get("raw_fields") or {}) if isinstance(parsed, dict) else {}
    rf_lower = {k.lower(): str(v).lower() for k, v in rf.items() if isinstance(v, str)}

    # Exchange / mailbox operations — BEC indicators
    if rf_lower.get("workload") == "exchange":
        return "exchange"
    if any(op in raw_lower for op in
           ("set-mailbox", "new-inboxrule", "set-inboxrule",
            "add-mailboxpermission", "disable-mailbox", "remove-mailbox")):
        return "exchange"

    # PIM / role changes
    if "pim" in raw_lower or "privileged role" in raw_lower:
        return "role_change"
    if any(s in raw_lower for s in ("add member to role", "addrolemember",
                                     "rolemanagement", "add owner to")):
        return "role_change"

    # Impossible-travel sign-in
    if parsed.get("first_login_ip") or parsed.get("second_login_ip"):
        return "impossible_travel"
    if "impossible travel" in raw_lower:
        return "impossible_travel"

    # Identity Protection / sign-in
    if rf_lower.get("source") == "identityprotection":
        return "signin"
    if any(k in rf_lower for k in ("riskeventtype", "risktype", "risklevel", "riskstate")):
        return "signin"
    if rf_lower.get("workload") == "azureactivedirectory":
        return "signin"

    # AV / malware detection
    if any(s in raw_lower for s in (
            "microsoft-windows-windows defender", "windows defender",
            "sentinelone", "crowdstrike", "carbon black",
            "microsoftdefenderforendpoint",
        )) and ("malware" in raw_lower or "detection:" in raw_lower
                or "trojan" in raw_lower or "ransomware" in raw_lower
                or "monitoringtool" in raw_lower):
        return "malware"

    # Process execution / behavioral
    if _g(parsed, "command_line") or _g(parsed, "process_path", "processPath"):
        return "process_exec"

    # Network connection
    if _g(parsed, "dest_ip", "destination_ip", "remoteIp",
          "Destination", "Dest", "remote_ip"):
        return "network"

    return "generic"


def _abbreviate_value(v: str, max_len: int = 110) -> str:
    """Truncate long values so a single bullet doesn't wrap awkwardly."""
    s = (v or "").strip()
    if len(s) <= max_len:
        return s
    return s[:max_len - 1] + "…"


def _render_detection_summary(parsed: dict, log_text: str,
                              enrichment_raw: Optional[Dict] = None) -> str:
    """Build the bullet block. Returns empty string when fewer than 4
    bullets can be filled — half-empty summaries look worse than none."""
    parsed = parsed or {}
    rf = (parsed.get("raw_fields") or {}) if isinstance(parsed, dict) else {}
    bullets: List[tuple] = []
    alert_type = _classify_alert(parsed, log_text)

    # ── Common fields used across many templates ─────────────────────────
    endpoint = _g(parsed, "asset_name", "assetName", "hostName", "DeviceName",
                  "Computer", "Asset", "deviceDnsName", "host", "MachineName")
    user_id  = _g(parsed, "user_principal_name", "userPrincipalName",
                  "user_id", "userId", "UserName", "UserId", "User")
    user_disp= _g(parsed, "user_display_name", "userDisplayName", "displayName")
    src_ip   = _g(parsed, "ip_address", "ClientIP", "ClientIp", "ipAddress",
                  "Source IP", "sourceIp", "source_ip", "ActorIpAddress")
    workload = _g(parsed, "workload", "Workload")
    response_action = _g(parsed, "response_action") or rf.get("Response action", "")

    def _ip_with_loc(ip: str) -> str:
        """ASN + location suffix on an IP using already-fetched enrichment data."""
        if not ip or not enrichment_raw:
            return ip
        ipd = (enrichment_raw.get("ips") or {}).get(ip) or {}
        org = (ipd.get("ipinfo") or {}).get("org") or ""
        country = (ipd.get("ipinfo") or {}).get("country") or ""
        city = (ipd.get("ipinfo") or {}).get("city") or ""
        org_clean, _asn = _strip_asn_prefix(org)
        loc_bits = [b for b in (city, country) if b]
        suffix_bits = [b for b in (org_clean, ", ".join(loc_bits)) if b]
        if suffix_bits:
            return f"{ip} ({' · '.join(suffix_bits)})"
        return ip

    # ── Per-template bullet builders ─────────────────────────────────────
    if alert_type == "malware":
        detection = _g(parsed, "detection", "Detection") or _g(parsed, "ThreatName", "Name")
        file_path = (_g(parsed, "file_path", "filePath", "Full Path", "File path",
                        "Path", "path",
                        "process_path", "Process Path")
                     or _g(parsed, "fileName"))
        eventlog_desc = _g(parsed, "EventLog Description", "eventlog_description")
        engine = "Microsoft Defender" if "defender" in (eventlog_desc + " " + (log_text or "")).lower() \
                 else ("SentinelOne" if "sentinelone" in (log_text or "").lower()
                       else ("CrowdStrike" if "crowdstrike" in (log_text or "").lower()
                             else "EDR"))
        if endpoint:  bullets.append(("Endpoint", endpoint))
        if user_id:   bullets.append(("User context", user_id))
        if detection:
            label = f"{detection} ({engine})" if engine and engine.lower() not in detection.lower() \
                    else detection
            bullets.append(("Detection", label))
        if file_path: bullets.append(("File", _abbreviate_value(file_path)))
        if response_action:
            bullets.append(("Action", response_action))

    elif alert_type == "signin":
        account = user_id or user_disp
        risk_event = _g(parsed, "risk_event_type", "riskEventType",
                        "risk_type", "RiskType", "EventDescription")
        risk_state = _g(parsed, "risk_state", "riskState", "Resultstatus")
        risk_level = _g(parsed, "risk_level", "riskLevel")
        risk_detail = _g(parsed, "risk_detail", "riskDetail", "LogonError")
        ua = _g(parsed, "UserAgent", "user_agent") or rf.get("User agent", "")
        req_type = _g(parsed, "RequestType")
        loc_city = _g(parsed, "location_city", "city", "first_login_city")
        loc_country = _g(parsed, "location_country", "countryOrRegion", "first_login_country")
        if account: bullets.append(("Account", account))
        if src_ip:  bullets.append(("Source IP", _ip_with_loc(src_ip)))
        if loc_city or loc_country:
            loc_str = ", ".join([x for x in (loc_city, loc_country) if x])
            if loc_str and src_ip and loc_str not in bullets[-1][1]:
                bullets.append(("Reported location", loc_str))
        outcome_bits = [b for b in (risk_state, risk_event, risk_detail) if b]
        if outcome_bits:
            bullets.append(("Outcome", _abbreviate_value(" / ".join(outcome_bits[:2]))))
        elif risk_level:
            bullets.append(("Outcome", f"risk level {risk_level}"))
        client_bits = []
        if req_type: client_bits.append(req_type)
        if ua:
            # Trim the user-agent — full UA strings are massive
            client_bits.append(_abbreviate_value(ua, 80))
        if client_bits:
            bullets.append(("Client", " / ".join(client_bits)))
        if response_action:
            bullets.append(("Action", response_action))

    elif alert_type == "impossible_travel":
        account = user_id or user_disp
        first_ip = _g(parsed, "first_login_ip")
        second_ip = _g(parsed, "second_login_ip")
        first_loc = ", ".join([x for x in (
            _g(parsed, "first_login_city"),
            _g(parsed, "first_login_country"),
        ) if x])
        second_loc = ", ".join([x for x in (
            _g(parsed, "second_login_city"),
            _g(parsed, "second_login_country"),
        ) if x])
        if account: bullets.append(("Account", account))
        if first_ip:
            label = f"{_ip_with_loc(first_ip)}" + (f" — {first_loc}" if first_loc and first_loc not in _ip_with_loc(first_ip) else "")
            bullets.append(("First login", label))
        if second_ip:
            label = f"{_ip_with_loc(second_ip)}" + (f" — {second_loc}" if second_loc and second_loc not in _ip_with_loc(second_ip) else "")
            bullets.append(("Second login", label))
        bullets.append(("Pattern", "Impossible travel between two geographies in a short window"))
        if response_action:
            bullets.append(("Action", response_action))

    elif alert_type == "exchange":
        operation = _g(parsed, "Operation", "activity", "operationType", "activityDisplayName")
        mailbox = _g(parsed, "Identity", "Mailbox", "ObjectId") or user_id
        fwd = _g(parsed, "ForwardingAddress", "ForwardingSmtpAddress", "forwarding_address")
        if mailbox:  bullets.append(("Mailbox", mailbox))
        if operation:bullets.append(("Operation", operation))
        if fwd:      bullets.append(("Forward target", fwd))
        if src_ip:   bullets.append(("Source IP", _ip_with_loc(src_ip)))
        if response_action:
            bullets.append(("Action", response_action))

    elif alert_type == "role_change":
        # Resolve role GUID to a friendly name when we have it
        role_id = _g(parsed, "privileged_role_object_id",
                     "privileged_role_template_id", "newValue", "wids",
                     "Privileged role", "Privileged Role", "PrivilegedRole")
        role_name = _g(parsed, "privileged_role_display_name", "RoleDisplayName")
        # Strip any wrapping quotes the log may have
        role_id_clean = role_id.strip('"').split(",")[0].strip()
        if not role_name and role_id_clean in _AZURE_ROLE_GUIDS:
            role_name = _AZURE_ROLE_GUIDS[role_id_clean]
        operation = _g(parsed, "activity", "Operation", "activityDisplayName", "ActionType")
        if user_id:  bullets.append(("User", user_id))
        if role_name:bullets.append(("Role", role_name))
        elif role_id_clean: bullets.append(("Role", f"GUID {role_id_clean}"))
        if operation: bullets.append(("Operation", operation))
        if src_ip:    bullets.append(("Source IP", _ip_with_loc(src_ip)))
        if response_action:
            bullets.append(("Action", response_action))

    elif alert_type == "network":
        dest_ip = _g(parsed, "dest_ip", "destination_ip", "remoteIp") \
                  or _g(parsed, "Destination", "Dest")
        dest_port = _g(parsed, "Destination Port", "destinationPort", "remotePort")
        process = _g(parsed, "Process", "Process Path", "process_path", "fileName")
        if endpoint:bullets.append(("Endpoint", endpoint))
        if user_id: bullets.append(("User", user_id))
        if process: bullets.append(("Process", _abbreviate_value(process)))
        if dest_ip:
            dest_label = _ip_with_loc(dest_ip)
            if dest_port:
                dest_label += f":{dest_port}"
            bullets.append(("Destination", dest_label))
        if response_action:
            bullets.append(("Action", response_action))

    elif alert_type == "process_exec":
        cmd = _g(parsed, "command_line", "Command line", "Cmd Line Parameters",
                 "processCommandLine")
        proc = _g(parsed, "process_path", "Process Path", "Process",
                  "fileName")
        # Process-execution alerts often carry a network destination
        # too (the process being executed is making outbound network
        # I/O). Surface both bullets when present.
        dest_ip = _g(parsed, "dest_ip", "destination_ip", "remoteIp",
                     "Destination", "Dest")
        dest_port = _g(parsed, "destination_port", "remotePort")
        if endpoint: bullets.append(("Endpoint", endpoint))
        if user_id:  bullets.append(("User", user_id))
        if proc:     bullets.append(("Process", _abbreviate_value(proc)))
        if cmd:      bullets.append(("Command", _abbreviate_value(cmd, 130)))
        if dest_ip:
            dest_label = _ip_with_loc(dest_ip)
            if dest_port:
                dest_label += f":{dest_port}"
            bullets.append(("Destination", dest_label))
        if response_action:
            bullets.append(("Action", response_action))

    else:  # generic
        if endpoint: bullets.append(("Endpoint", endpoint))
        if user_id:  bullets.append(("User", user_id))
        if src_ip:   bullets.append(("Source IP", _ip_with_loc(src_ip)))
        if workload: bullets.append(("Workload", workload))
        if response_action:
            bullets.append(("Action", response_action))

    # De-dupe by label (in case two field aliases resolved to the same key)
    seen = set()
    dedup = []
    for k, v in bullets:
        if k not in seen and v:
            seen.add(k)
            dedup.append((k, v))

    if len(dedup) < 4:
        return ""

    lines = ["Detection summary"]
    for k, v in dedup[:7]:   # cap at 7 — past that it's facts-block territory
        lines.append(f"- {k}: {v}")
    return "\n".join(lines)


async def _gather_email_enrichment(log_text: str, parsed: Dict,
                                    config) -> Dict[str, Any]:
    """Run enrichment for IOCs found in the email log. Returns a dict
    with 'lines' (rendered facts-block subsection) and 'raw' (the raw
    per-IOC enrichment dicts, for the AI prompt). Returns empty dict on
    any error — the email compose flow must never break because of
    enrichment failures."""
    try:
        iocs = _extract_iocs_from_log(log_text, parsed)
        if not any(iocs.values()):
            return {"lines": "", "raw": {}}

        # Snapshot the keys we need into a plain dict so enrichment can
        # read them without going through ConfigManager. The keys
        # mirror the URL-scan endpoint's set so we get the same
        # coverage.
        keys = {k: (config.get(k) or "") for k in (
            "VIRUSTOTAL_KEY", "ABUSEIPDB_KEY", "OTX_KEY", "URLSCAN_KEY",
            "GREYNOISE_KEY", "PULSEDIVE_KEY", "MALTIVERSE_KEY",
            "IPINFO_TOKEN", "WHOISXML_KEY", "GOOGLE_API_KEY",
            "HYBRID_ANALYSIS_KEY",
        )}

        import aiohttp as _aiohttp
        from agents.enrichment import (
            enrich_ip as _enr_ip,
            enrich_domain as _enr_dom,
            enrich_hash as _enr_hash,
            enrich_url as _enr_url,
        )

        # 20s outer cap on the whole fan-out — emails are interactive
        # so we'd rather ship a partial enrichment than block the
        # analyst for 60+ seconds.
        outer_timeout = 20

        async def _do():
            async with _aiohttp.ClientSession(
                timeout=_aiohttp.ClientTimeout(total=outer_timeout),
            ) as session:
                tasks = []
                ip_idx, dom_idx, hash_idx, url_idx = [], [], [], []
                for ip in iocs["ips"]:
                    ip_idx.append(("ip", ip, len(tasks)))
                    tasks.append(_enr_ip(session, ip, keys))
                for d in iocs["domains"]:
                    dom_idx.append(("domain", d, len(tasks)))
                    tasks.append(_enr_dom(session, d, keys))
                for h in iocs["hashes"]:
                    hash_idx.append(("hash", h, len(tasks)))
                    tasks.append(_enr_hash(session, h, keys))
                for u in iocs["urls"]:
                    url_idx.append(("url", u, len(tasks)))
                    tasks.append(_enr_url(session, u, keys))
                if not tasks:
                    return {}
                import asyncio as _asyncio
                results = await _asyncio.gather(*tasks, return_exceptions=True)
                out: Dict[str, Any] = {"ips": {}, "domains": {},
                                        "hashes": {}, "urls": {}}
                for kind, value, idx in (ip_idx + dom_idx + hash_idx + url_idx):
                    r = results[idx]
                    if isinstance(r, Exception) or not isinstance(r, dict):
                        continue
                    bucket = {"ip": "ips", "domain": "domains",
                              "hash": "hashes", "url": "urls"}[kind]
                    out[bucket][value] = r
                return out

        import asyncio as _asyncio
        try:
            raw = await _asyncio.wait_for(_do(), timeout=outer_timeout + 2)
        except _asyncio.TimeoutError:
            raw = {}

        # Render compact lines
        lines = []
        for ip, d in (raw.get("ips") or {}).items():
            line = _fmt_ip_enrichment(ip, d)
            if line:
                lines.append(line)
        for dom, d in (raw.get("domains") or {}).items():
            line = _fmt_domain_enrichment(dom, d)
            if line:
                lines.append(line)
        for h, d in (raw.get("hashes") or {}).items():
            line = _fmt_hash_enrichment(h, d)
            if line:
                lines.append(line)
        for u, d in (raw.get("urls") or {}).items():
            line = _fmt_url_enrichment(u, d)
            if line:
                lines.append(line)

        return {"lines": "\n".join(lines), "raw": raw}
    except Exception:
        # Never break compose because of an enrichment hiccup. The AI
        # still has the parsed fields + raw log to work from.
        return {"lines": "", "raw": {}}


async def compose_ai(log_text: str, parsed: Optional[Dict], options: Dict,
                     config) -> Dict:
    """Generate a customer-facing email body.

    Body structure (assembled server-side, NOT by the LLM):
      1. Deterministic facts block (Label: value lines) — rendered from
         parsed fields directly. The LLM never touches this.
      2. AI summary — ONE plain-language sentence naming what the alert is.
      3. AI guidance — ONE tight paragraph of investigate + remediate.
      4. Signature — appended by the existing render pipeline.

    The LLM scope is limited to producing JSON {summary, guidance} which
    is small enough that prompt-following stays reliable. This replaces
    the prior approach of asking the LLM to format the entire body,
    which kept producing robotic prose narration regardless of how
    strongly the prompt forbade it."""
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

    # Custom-template filtering — when the analyst picked a template that
    # disables certain fields (e.g. "Defender Alerts" with username +
    # process_path off), drop those parsed keys BEFORE the AI sees them so
    # the model can't hallucinate content for fields the template excludes.
    enabled_fields = options.get("enabled_fields")
    if enabled_fields:
        parsed = _filter_parsed_for_template(parsed, enabled_fields)

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

    # ── Server-side facts block (deterministic, no LLM involvement) ──────
    facts_block = _render_facts_block(parsed, options)

    # ── OSINT enrichment fan-out ─────────────────────────────────────────
    # Pull AbuseIPDB / VirusTotal / IPInfo / Maltiverse / GreyNoise / WHOIS
    # context for IOCs found in the log. Append the rendered lines to the
    # facts block as a 'Threat intelligence' subsection AND pass the
    # compact rendering into the AI prompt so the analysis paragraph can
    # weave specific findings in (ISP, ASN, country, risk score, etc.).
    # Bounded by an outer 20s timeout — failures degrade gracefully to
    # "no enrichment available" so the email always renders.
    enr_bundle = await _gather_email_enrichment(log_text, parsed, config)
    enr_lines = (enr_bundle or {}).get("lines", "")
    enr_raw   = (enr_bundle or {}).get("raw", {})
    if enr_lines:
        facts_block = (facts_block + "\n\nThreat intelligence:\n"
                       + enr_lines) if facts_block else \
                      ("Threat intelligence:\n" + enr_lines)

    # Detection summary — 4-7 bullet block tailored per alert type, sits
    # between the verbose facts block and the AI prose. Built AFTER
    # enrichment so source-IP bullets can carry ASN + location inline.
    # Returns "" when fewer than 4 meaningful bullets are available, in
    # which case the summary block is skipped entirely (sparse logs
    # would otherwise produce a half-empty section).
    summary_block = _render_detection_summary(parsed, log_text, enr_raw)

    # ── Tiny LLM scope: ONLY a summary sentence + a guidance paragraph ──
    # The prompt asks for strict JSON {summary, guidance} — both fields are
    # small, so prompt-following stays reliable. The model never has the
    # chance to robotic-narrate the facts (because we render them itself).
    sys_msg = (
        "OUTPUT STYLE (hard rule): Write in plain ASCII. NEVER use em-dashes (—), "
        "en-dashes (–), or curly quotes. Use hyphens (-), commas, or restructure. "
        "Customers immediately spot AI text by the em-dash and lose trust in the "
        "analysis.\n\n"
        "You are a senior SOC analyst writing the body of a customer alert "
        "email. Output STRICT JSON with exactly one string field: "
        "'analysis'. No other keys. No markdown fences.\n\n"
        "The analysis paragraph is the ENTIRE email body the customer reads "
        "below the facts block. The signature is appended afterwards.\n\n"
        "FACTS ONLY — NO ASSUMPTIONS. The analyst rejects emails that "
        "speculate. STRICT rules:\n"
        "  1. State only what the log + enrichment data literally show. "
        "Walk through the events in chronological order using the actual "
        "field values (user, IPs, host, process, hash, timestamps).\n"
        "  2. Do NOT invent motives, intent, attribution, or 'likely' "
        "scenarios. Do NOT speculate about whether the user 'was indeed in "
        "both locations', whether activity 'is common for legitimate users', "
        "or whether something 'could be' anything. None of those.\n"
        "  3. Do NOT ask the recipient leading questions about the user's "
        "whereabouts, intent, or expected behaviour. A facts-only verification "
        "ask is fine ('confirm whether the second-IP login was authorized'); "
        "open-ended speculation ('verify if the user was in both locations') "
        "is forbidden.\n"
        "  4. The closing sentence is one concrete verification ask if there "
        "is one named question the customer can answer, OR a single direct "
        "statement of what to do next. No 'monitor for further activity', "
        "no 'please reach out', no soft hedging.\n"
        "  5. 4-6 sentences total. Each sentence must reference a specific "
        "value from the facts block or raw log. No filler.\n\n"
        "WRITING STYLE — read carefully:\n"
        "* Connect the sentences. Use transitions (then, after, when, "
        "because, while) so the reader experiences ONE flowing paragraph, "
        "not a list of disjoint fact-statements joined by periods.\n"
        "* Vary sentence length. Don't write the same subject-verb-object "
        "structure four times in a row.\n"
        "* Use the SUBJECT-FIRST active voice. \"powershell.exe spawned by "
        "msbuild.exe under SYSTEM…\" beats \"There was a process where…\". "
        "Make the user / host / process the active subject of the sentence.\n"
        "* When two facts share a subject, combine them into one sentence "
        "instead of repeating the subject. 'jdoe@contoso.com signed in from "
        "Bengaluru at 10:23 UTC, then again from Seattle at 13:46 UTC' beats "
        "'jdoe signed in from Bengaluru. jdoe signed in from Seattle.'\n"
        "* No bullet points. No numbered lists. No section headings inside "
        "the analysis. Just a single coherent paragraph.\n\n"
        "GROUNDING:\n"
        "* Every claim MUST trace back to a parsed field, the raw log, OR "
        "the enrichment block (AbuseIPDB / VirusTotal / IPInfo / WHOIS / "
        "Maltiverse / GreyNoise / Spamhaus / etc.). Do not invent IPs, "
        "hashes, users, processes, malware names, or campaigns that "
        "aren't in the input.\n"
        "* When the enrichment block contains relevant context (an IP's "
        "ASN/ISP/country, an AbuseIPDB score with report count, a VT "
        "detection ratio, a WHOIS registration age, etc.), reference "
        "those specific values in the analysis paragraph so the customer "
        "sees the OSINT picture, not just the raw alert. State the "
        "source explicitly ('AbuseIPDB rates the source IP at 87% with "
        "42 abuse reports', 'VirusTotal shows 8/86 engines flagging the "
        "domain', 'WHOIS records show the domain was registered 4 days "
        "ago via Namecheap').\n"
        "* De-conflict when sources disagree — if AbuseIPDB scores the IP "
        "high but VT shows it clean, mention BOTH so the recipient sees "
        "the full picture.\n"
        "* Never reference a TI source that isn't in the enrichment "
        "block. If no enrichment is present, do not pretend there is.\n\n"
        "CALIBRATION:\n"
        "* Known-good vendor patterns (Dell SupportAssist, Microsoft "
        "Defender, SCCM, CrowdStrike, etc.) — say so plainly and state "
        "the verification needed before clearing.\n"
        "* Confirmed-malicious — multiple corroborating signals such as\n"
        "    - a hash matching a known malware family (VirusTotal multi-\n"
        "      engine flag, MalwareBazaar / Hybrid Analysis verdict)\n"
        "    - an IP that GreyNoise / Maltiverse / AbuseIPDB classify as\n"
        "      malicious, especially when it overlaps with Tor exits or\n"
        "      known C2 infrastructure\n"
        "    - Office → PowerShell -enc / cmd / wscript spawn chains\n"
        "    - newly-registered brand-impersonation domains on Spamhaus\n"
        "      DBL or with VT engine hits\n"
        "    - lateral movement / credential access primitives\n"
        "  When two or more of those signals are present, do NOT close\n"
        "  with a soft 'please confirm whether this was authorized'. State\n"
        "  the verdict plainly ('this is a confirmed compromise', 'this\n"
        "  matches a ransomware deployment pattern') and close with a\n"
        "  CONCRETE containment action the customer should take now —\n"
        "  isolate the host, kill the process, block the destination IP,\n"
        "  reset the user's credentials, quarantine the file. The closing\n"
        "  is action-oriented, not permission-seeking.\n"
        "* Evidence is weaker (single TI source, no enrichment, ambiguous\n"
        "  process chain): state the facts and the single verification\n"
        "  step the customer can answer.\n"
        "* SUSPICIOUS authentication patterns to call out by name when "
        "present in the parsed fields:\n"
        "  - UserAgent 'BAV2ROPC' (Basic Auth / Resource Owner Password "
        "    Credentials flow) — strongly associated with password spray "
        "    and credential-stuffing attacks against M365 / Azure AD.\n"
        "  - RequestType 'OAuth2:Token' from BAV2ROPC or unknown clients "
        "    — same ROPC abuse pattern, often paired with legacy auth.\n"
        "  - LogonError / ErrorNumber 50053, 50057, 50126 on accounts "
        "    that are disabled / locked / wrong-password — single events "
        "    are routine, but if multiple users are seeing this pattern "
        "    from one IP, flag it as potential password spray.\n"
        "  - User-Agent strings that name an automation framework "
        "    (curl, python-requests, postman, ROPC, MSAL.NET) on "
        "    interactive-user accounts — surface for verification.\n\n"
        "* DUAL-USE administrative tools — do NOT lead with 'malicious' "
        "  even when VirusTotal flags the file. The following are widely-"
        "  used IT admin / penetration-testing tools that legitimate "
        "  administrators run daily; AV engines flag them because they "
        "  are equally useful to attackers:\n"
        "    - SoftPerfect Network Scanner (netscan.exe)\n"
        "    - Advanced IP Scanner (advanced_ip_scanner.exe)\n"
        "    - Nmap, Zenmap, masscan\n"
        "    - Angry IP Scanner\n"
        "    - PsExec, PsLoggedOn, the wider Sysinternals suite\n"
        "    - PuTTY family — putty.exe, plink.exe, pscp.exe, psftp.exe\n"
        "      (legit SSH / SCP / SFTP clients, also used to tunnel /\n"
        "      exfil)\n"
        "    - OpenSSH client (ssh.exe, scp.exe, sftp.exe)\n"
        "    - PowerShell Empire / Cobalt Strike artefacts (these ARE\n"
        "      offensive frameworks — treat as malicious unless the\n"
        "      customer's red team has scheduled an engagement)\n"
        "    - ProcDump, ProcessHacker (legit + LSASS dump abuse)\n"
        "    - RemCom, paexec, BloodHound, SharpHound\n"
        "    - WinRAR / 7zip command-line in odd locations (legit\n"
        "      compressors, also used to stage data for exfil)\n"
        "    - rclone, megasync, rsync (legit sync clients, also used\n"
        "      to exfil to attacker-controlled cloud storage)\n"
        "  When the parsed log shows one of these tools, the analysis\n"
        "  should EXPLAIN the dual-use status to the customer:\n"
        "    'SoftPerfect Network Scanner (netscan.exe) is a widely-used\n"
        "     network discovery tool that IT teams use for inventory and\n"
        "     pen-testers / attackers use for reconnaissance. The high\n"
        "     VirusTotal detection ratio reflects this dual-use status,\n"
        "     not a definitive malicious verdict.'\n"
        "  Calibrate based on context:\n"
        "    - Executed from C:\\Tools\\, C:\\Program Files\\..., or by\n"
        "      a known admin account during business hours: probably\n"
        "      legitimate — confirm with IT.\n"
        "    - Executed from Desktop, Downloads, AppData\\Local\\Temp,\n"
        "      by an unprivileged user, after-hours, or following a\n"
        "      suspicious sign-in: treat as serious — that's the\n"
        "      reconnaissance phase of a real intrusion.\n"
        "  Never write 'this file is malicious' for these tools without\n"
        "  the secondary context above.\n\n"
        "* SASE / cloud egress proxies — many enterprises route ALL "
        "  employee traffic through a cloud security proxy. When an "
        "  'Impossible Travel' alert pairs a normal user IP with an IP "
        "  belonging to one of these services, the second IP is almost "
        "  always the company's egress, not a different user. Flag this "
        "  to the customer:\n"
        "    - Netskope (AS55256, AS393792)\n"
        "    - Zscaler (AS22616, AS40384, AS62597, AS53813)\n"
        "    - Cloudflare WARP / Access (AS13335)\n"
        "    - Cisco Umbrella / OpenDNS (AS36692)\n"
        "    - Palo Alto Prisma Access / GlobalProtect Cloud (AS54994)\n"
        "    - iboss, Symantec WSS, Forcepoint, Menlo Security cloud\n"
        "  When one IP in an impossible-travel pair belongs to one of\n"
        "  these services, the analysis MUST state explicitly:\n"
        "    'The second IP belongs to <provider>, a cloud security\n"
        "     proxy / SASE service. If your organization routes user\n"
        "     traffic through <provider>, this impossible-travel alert\n"
        "     is most likely the same session being egressed through\n"
        "     the proxy rather than a real geographic anomaly. Confirm\n"
        "     whether <provider> is your egress provider before\n"
        "     treating this as a compromise.'\n"
        "  Do NOT suppress the alert — surface the context so the\n"
        "  customer can dismiss with confidence.\n\n"
        "* ROUTINE system operations that look alarming in raw logs:\n"
        "    - svchost.exe (eventlog service, args -k localservice\n"
        "      networkrestricted -p -s eventlog) deleting / truncating\n"
        "      Microsoft-Windows-AppLocker / Security / Application\n"
        "      .evtx files: this is Windows EventLog rotation, NOT\n"
        "      log tampering. Treat as normal. Only suspicious when\n"
        "      paired with another deletion event from a non-system\n"
        "      account, or wevtutil.exe cl <log> from a user shell.\n"
        "    - Dell SupportAssist (DellSupportAssistRemediationService\n"
        "      .exe) flagged as MonitoringTool:Win32/Spector by\n"
        "      Microsoft Defender: well-known false positive. Dell\n"
        "      ships a remediation utility that triggers Defender's\n"
        "      spyware heuristic; vendor-signed. Treat as benign.\n"
        "    - HP Image Assistant, Lenovo Vantage, vendor OEM agents\n"
        "      flagged by AV: usually vendor-signed monitoring agents\n"
        "      legitimately reporting hardware telemetry.\n"
        "    - svchost.exe (any args) doing network I/O during Windows\n"
        "      Update windows: routine update traffic.\n"
        "  Lead with the routine-operation callout when these patterns\n"
        "  appear so the customer understands the context.\n\n"
        "* DO NOT NARRATE the following technical IDs in customer-\n"
        "  facing prose — they don't help the recipient decide:\n"
        "    - File sizes in bytes (unless unusual for the file type:\n"
        "      a 50KB .exe might be a loader, a 500MB \"document\"\n"
        "      might be a memory dump). Routine file sizes add noise.\n"
        "    - Object IDs / Application IDs / Tenant IDs / Correlation\n"
        "      IDs / Request IDs / Session IDs as GUIDs.\n"
        "    - Process IDs, Event Source IDs, Serial Numbers, TLHashes.\n"
        "    - Sub-second timestamp precision and timezone offsets when\n"
        "      a date + minute precision is sufficient.\n"
        "  These are fine in the facts block at the top of the email\n"
        "  for reference, but should not be re-narrated in the analysis\n"
        "  paragraph unless one of them is the actual decision point.\n\n"
        "* WELL-KNOWN Azure / Entra ID role GUIDs — when a role-change\n"
        "  operation references one of these GUIDs, resolve the name\n"
        "  inline so the customer doesn't have to look it up:\n"
        "    62e90394-69f5-4237-9190-012177145e10 → Global Administrator\n"
        "    194ae4cb-b126-40b2-bd5b-6091b380977d → Security Administrator\n"
        "    e8611ab8-c189-46e8-94e1-60213ab1f814 → Privileged Role Administrator\n"
        "    7be44c8a-adaf-4e2a-84d6-ab2649e08a13 → Privileged Authentication Administrator\n"
        "    fe930be7-5e62-47db-91af-98c3a49a38b1 → User Administrator\n"
        "    158c047a-c907-4556-b7ef-446551a6b5f7 → Cloud Application Administrator\n"
        "    966707d0-3269-4727-9be2-8c3a10f19b9d → Password Administrator\n"
        "    8329153b-31d0-4727-b945-745eb3bc5f31 → Exchange Administrator\n"
        "  Assignments to Global / Privileged Role / Privileged Auth / \n"
        "  Security Administrator are TIER-0 changes — flag explicitly\n"
        "  ('This grants tenant-wide control') and require change-ticket\n"
        "  confirmation regardless of stated reason.\n\n"
        "* SUSPICIOUS mailbox / Exchange operations — these are TOP "
        "  Business Email Compromise (BEC) indicators. When the parsed "
        "  log includes one of these Workload=Exchange operations, name "
        "  the pattern in the analysis and treat the action as suspect "
        "  until the customer confirms:\n"
        "  - Set-Mailbox + ForwardingAddress / ForwardingSmtpAddress / "
        "    DeliverToMailboxAndForward — external auto-forward rule is "
        "    the #1 BEC indicator. Adversaries set this to exfiltrate "
        "    invoices / contract emails after credential theft. Always "
        "    flag and ask whether the forward target is intended.\n"
        "  - New-InboxRule / Set-InboxRule with deleteMessage / "
        "    moveToFolder=Deleted Items / forwardTo external — same "
        "    BEC stealth pattern; the rule auto-deletes incoming "
        "    threads so the victim doesn't see the adversary's "
        "    interception.\n"
        "  - Add-MailboxPermission / Add-MailboxFolderPermission with "
        "    FullAccess / SendAs to an external account — mailbox "
        "    delegation grant; flag as account-takeover indicator.\n"
        "  - Disable-Mailbox / Remove-Mailbox immediately after a "
        "    suspicious sign-in — destruction-of-evidence pattern.\n"
        "  When any of these patterns appears, do NOT close with a soft "
        "  'confirm whether this was authorized'. Lead with the BEC "
        "  callout ('Auto-forward rules to an external address are the "
        "  #1 BEC indicator') and close with a directive action "
        "  ('remove the forwarding rule, force a password reset and MFA "
        "  re-enrolment for this account, audit recent Sent / Deleted "
        "  Items for adversary correspondence').\n\n"
        "BANNED PHRASES (auto-reject): 'indicates that', 'associated with', "
        "'in terms of', 'ensure that', 'consider whether', 'may be "
        "necessary', 'to enhance detection capabilities', 'we will "
        "continue monitoring', 'we are here to help', 'please contact "
        "us', 'feel free to', 'do not hesitate', 'rest assured', 'as "
        "always', 'in light of', 'in response to this alert', 'verify if', "
        "'could be', 'might be', 'potentially', 'suggests that', "
        "'common behavior for legitimate users', 'commonly observed', "
        "'often associated with'.\n\n"
        "NO references to 'our team', 'the team', 'our analysts', or any "
        "group self-reference. NO greeting. NO em/en dashes."
    )

    # When a custom email template is active, tell the AI which fields are
    # ENABLED. The AI must not generate content for disabled fields (it
    # would hallucinate values the template explicitly wants excluded).
    template_hint = ""
    if enabled_fields:
        enabled_str = ", ".join(sorted(str(f) for f in enabled_fields))
        template_hint = (
            "\n\n## TEMPLATE: only these fields are enabled for this email — "
            f"{enabled_str}.\n"
            "Do NOT generate content for fields outside this list. If a "
            "disabled field would normally be mentioned (e.g. process path), "
            "omit it entirely rather than describing it."
        )

    # Impossible-travel / VPN-anonymiser hint — derived deterministically
    # in parse_log() so the AI summary calls it out instead of saying
    # "common behaviour for legitimate users" when two logins clearly came
    # from geographically incompatible locations within hours.
    impossible_travel_hint = ""
    if parsed.get("impossible_travel"):
        first_loc = ", ".join([x for x in (
            parsed.get("first_login_city"),
            parsed.get("first_login_country"),
        ) if x]) or "unknown location"
        second_loc = ", ".join([x for x in (
            parsed.get("second_login_city"),
            parsed.get("second_login_country"),
        ) if x]) or "unknown location"
        first_ts   = parsed.get("first_login_created_raw") or ""
        second_ts  = parsed.get("second_login_created_raw") or ""
        first_ip   = parsed.get("first_login_ip") or "(unknown IP)"
        second_ip  = parsed.get("second_login_ip") or "(unknown IP)"
        second_asn = (parsed.get("second_login_asn_name") or "").strip()
        is_vpn     = bool(parsed.get("second_login_is_vpn"))

        first_at  = f" at {first_ts}"  if first_ts  else ""
        second_at = f" at {second_ts}" if second_ts else ""
        asn_tag   = f" (ASN: {second_asn})" if second_asn else ""
        vpn_line  = (
            "The second-login ASN matches a known VPN / anonymising "
            "provider — name it explicitly in the summary as a "
            "credibility hit.\n"
        ) if is_vpn else ""

        impossible_travel_hint = (
            "\n\n## IMPOSSIBLE-TRAVEL SIGNAL (server-derived — facts only)\n"
            f"First login: {first_loc}{first_at} from {first_ip}.\n"
            f"Second login: {second_loc}{second_at} from {second_ip}{asn_tag}.\n"
            f"{vpn_line}"
            "STATE these two logins and the geographic / time delta as "
            "FACTS in the analysis. Do not speculate about user behaviour, "
            "do not ask whether the user 'was in both locations', do not "
            "guess at legitimacy. The verification ask, if any, is one "
            "concrete operator question (e.g. 'confirm whether the "
            "second-IP login was authorized for this user'). Do NOT use "
            "the phrase 'common behavior for legitimate users'."
        )

    user_msg = (
        f"## Alert facts (already rendered as the email's top block — DO NOT "
        "re-narrate the field list back; refer to specific values from it)\n"
        f"{facts_block or '(no structured fields)'}\n\n"
        + (f"## Detection summary (already rendered above the analysis as a "
           "scannable bullet list — DO NOT repeat these bullets verbatim. "
           "Your paragraph should EXPLAIN what these bullets mean for the "
           "customer and CLOSE with the recommended next step.)\n"
           f"{summary_block}\n\n" if summary_block else "")
        + f"## Raw log (for context only)\n"
        f"```\n{log_text[:3500]}\n```\n"
        f"{action_hint}{template_hint}{impossible_travel_hint}\n\n"
        f"{classified_as}Return ONLY the JSON object with a single "
        "'analysis' string key."
    )

    from providers import get_provider
    import json as _json
    provider = get_provider()
    resp = await provider.complete(
        model=model,
        messages=[
            {"role": "system", "content": sys_msg},
            {"role": "user",   "content": user_msg},
        ],
        response_format={"type": "json_object"},
        temperature=0.2,
        max_tokens=500,
    )
    if resp.error:
        return {"error": f"AI call failed: {resp.error}"}

    try:
        parsed_ai = _json.loads(resp.message or "{}")
    except Exception:
        parsed_ai = {}

    # New single-field schema: one analysis paragraph that covers what
    # happened, the verdict, and the verification ask. Falls back to the
    # old summary+guidance pair when older clients / older models still
    # emit that shape.
    analysis = str(parsed_ai.get("analysis") or "").strip()
    if not analysis:
        s = str(parsed_ai.get("summary") or "").strip()
        g = str(parsed_ai.get("guidance") or "").strip()
        analysis = (s + ("\n\n" + g if g else "")).strip()

    # Scrub the LLM output for any banned phrases that slipped through.
    analysis = _strip_filler_phrases(_strip_em_dashes(_strip_list_markers(analysis)))

    body_parts = []
    if facts_block:
        body_parts.append(facts_block)
    if summary_block:
        # 'Detection summary' block sits between the facts and the AI
        # prose. When empty (sparse log → fewer than 4 useful bullets)
        # it gets skipped so the email goes facts → prose with no gap.
        body_parts.append(summary_block)
    if analysis:
        body_parts.append(analysis)
    body = "\n\n".join(body_parts) if body_parts else (
        # Defensive fallback — if both the facts and the LLM produced nothing
        # the email is empty, which is worse than a curt fallback.
        "The alert details could not be parsed automatically. Review the raw "
        "log directly to determine impact and next steps."
    )

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
    # Drop any "If you have questions, reach out..." line the AI body OR the
    # template inheritance produced. The compose_ai flow no longer injects
    # the canned _CLOSING_STATEMENT — the analyst's signature handles the
    # closing on its own (per repeated user feedback).
    text = _strip_closing_block(text)
    html = _strip_closing_block_html(html)
    # Last-pass dash strip — catches anything injected after the AI body
    # was first sanitized (signature line, future templates).
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


# ─── Default templates ────────────────────────────────────────────────────────
# Generic MDR alert email templates. Vendor identity is parameterized via the
# {{TeamName}} / {{FromAddress}} placeholders configured in RECON settings.
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
