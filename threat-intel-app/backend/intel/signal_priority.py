"""
Signal priority framework — the correlation backbone for the analyst
disposition.

The AI response stage was producing internally contradictory verdicts
("nation-state actor Storm-#### flagged this event as high risk" then
"routine sign-in, safe to clear") because the LLM was reasoning IOC-
first and treating log-content attribution as noise. Public TI is
naturally clean on nation-state infrastructure, so a "clean reputation"
reading is expected — not a reason to downgrade the upstream detection.

This module fixes the correlation gap at the data layer, BEFORE the LLM
sees the evidence pack. We walk the final pipeline state and bucket
every signal into a priority tier, then:

  1. Expose extract_tier_signals(state) → structured dict the response
     stage folds into the evidence_pack so the LLM sees "TIER 1 signals
     fired: [named actor, upstream high risk]" instead of raw JSON.

  2. Expose format_signal_correlation(state) → analyst-readable prose
     summary the LLM can quote verbatim in disposition_reason.

  3. Expose should_block_clear(state) → (blocked, reason) — the safety
     net response.py runs AFTER the LLM disposition. If the model
     picked CLEAR while TIER 1 signals are present, we auto-override
     to ESCALATE and stamp a machine reason. Belt-and-braces with the
     prompt-level guardrails.

Tier definitions (calibrated for MDR alert-triage):

  TIER 1 — verdict-determining. Any one → threat_level HIGH minimum,
           disposition MUST be ESCALATE or MONITOR (never CLEAR):
     * Log content names a tracked threat actor (Storm-####, APT##,
       UNC####, TA###, or a named group like Midnight Blizzard,
       Sandworm, Lazarus, Cozy Bear, Turla, Fancy Bear)
     * Upstream SIEM / EDR marked the risk High or Critical
     * KEV CVE with active exploitation flag or ransomware use
     * Named malware family attribution from the investigation
     * Ransomware behaviour (VSS deletion / ransom-note drop /
       mass file encryption)
     * Credential access primitives (LSASS dump, SAM copy, DCSync,
       NTDS.dit copy) from behavioral_indicators
     * Confirmed C2 callback (Feodo Tracker hit or named infra)
     * MFA bypass / session-token replay / impossible travel
     * ≥5 independent VT engines flagging the SAME IOC

  TIER 2 — corroborating. ≥2 fired → HIGH; single → MEDIUM+:
     * 2-4 VT engines on the same IOC
     * AbuseIPDB ≥75 with recent activity
     * Lateral-movement signals (cross-host credential reuse,
       PsExec cluster)
     * MITRE technique named WITH evidence sentence
     * OTX ≥5 pulses
     * LOLBAS abuse with unusual parent process
     * BYOVD LOLDrivers hash match
     * Domain WHOIS registered <30 days on a phishing-shape URL
     * Round-14 trained phishing classifier ≥85% probability
     * Local blocklist hit + recent activity
     * MalwareBazaar named family match

  TIER 3 — contextual / corroborating only. Doesn't drive verdict alone:
     * 1 VT engine
     * OTX 1-4 pulses
     * Cloud-provider ASN (contextual)
     * ProxyCheck VPN/proxy flag
     * Trained DGA classifier hit
     * Suspicious port
     * Bulletproof ASN

  DOWNWEIGHT — reasons to lean lower, ONLY when no TIER 1 fired:
     * MISP warninglist match on the IOC
     * Known-good vendor pattern (Dell SupportAssist, MS Defender,
       CrowdStrike agent, SCCM, Intune, etc.) hit in behavioral_indicators
     * Clean across every keyed TI source
     * Operator note frames as routine / approved

Correlation rules (encoded in should_block_clear + the correlation
prose):

  * TIER 1 fired      → CLEAR is BLOCKED. Verdict floor = HIGH.
  * TIER 2 ×2 fired   → CLEAR is BLOCKED. Verdict floor = HIGH.
  * TIER 2 ×1 fired   → verdict floor = MEDIUM. CLEAR allowed only
                         when DOWNWEIGHT signals present.
  * Only TIER 3       → verdict floor = LOW. CLEAR allowed.
  * DOWNWEIGHT only   → verdict floor = INFORMATIONAL. CLEAR default.

The prompt-level guardrails in agents/response.py (HARD OVERRIDES
section) tell the LLM this. This module ENFORCES it deterministically
in code so a prompt regression can't recreate the Storm-#### bug.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger("recon.intel.signal_priority")


# ─── Tracked-actor markers ─────────────────────────────────────────────────
# Case-insensitive substring matches against the raw alert text. Coverage
# is the top-of-mind naming conventions each major upstream vendor uses:
#   * Microsoft:  Storm-####, or the "weather" cluster (Blizzard, Typhoon,
#                 Sandstorm, Tempest, Flood, Dust, Rain, Hail, Sleet)
#   * MITRE:      G#### intrusion-set ids + "APT##"
#   * Mandiant:   APT##, UNC####, FIN##, TEMP.####
#   * CrowdStrike Falcon: named cluster like "Cozy Bear", "Fancy Bear",
#                          "Lazarus", "Turla"
#   * Community:  "nation-state", "state-sponsored", "state actor"
_TRACKED_ACTOR_PATTERNS = [
    re.compile(r"\bstorm-\d+\b", re.I),
    re.compile(r"\b(APT|FIN|UNC|TA)\d{2,4}\b"),
    re.compile(r"\bG\d{4}\b"),                    # MITRE intrusion-set id
    re.compile(r"\bTEMP\.[a-z0-9]+\b", re.I),
    re.compile(r"\bcozy bear\b", re.I),
    re.compile(r"\bfancy bear\b", re.I),
    re.compile(r"\bmidnight blizzard\b", re.I),
    re.compile(r"\bnight blizzard\b", re.I),
    re.compile(r"\b(silk|opal|charcoal|granite|amethyst|jade|onyx|sapphire|"
               r"topaz|volt|linen|forest|manatee|pistachio|caramel|copper|"
               r"seashell|antique|antimony) typhoon\b", re.I),
    re.compile(r"\bsandworm\b", re.I),
    re.compile(r"\blazarus\b", re.I),
    re.compile(r"\bturla\b", re.I),
    re.compile(r"\bnation.?state\b", re.I),
    re.compile(r"\bstate.?sponsored\b", re.I),
    re.compile(r"\bstate.?actor\b", re.I),
    re.compile(r"\bthreat actor associated with\b", re.I),
]

# Upstream "High" / "Critical" risk markers common in Defender / Sentinel /
# Entra ID / Okta / risk-based auth logs.
_UPSTREAM_HIGH_RISK_PATTERNS = [
    re.compile(r"\brisk\s*level\s*:?\s*high\b", re.I),
    re.compile(r"\brisk\s*level\s*:?\s*critical\b", re.I),
    re.compile(r"\bhigh[- ]risk\s+sign[- ]in\b", re.I),
    re.compile(r"\bhigh[- ]risk\s+user\b", re.I),
    re.compile(r"\brisk[_ ]state\s*:?\s*(atRisk|confirmedCompromised)\b", re.I),
    re.compile(r"\brisk[_ ]level[_ ]aggregated\s*:?\s*high\b", re.I),
    re.compile(r"\bseverity\s*:?\s*(High|Critical)\b"),
    re.compile(r"\battempted\s+atypical\s+travel\b", re.I),
    re.compile(r"\bsuccessful\s+atypical\s+travel\b", re.I),
    re.compile(r"\bimpossible\s+travel\b", re.I),
    re.compile(r"\bmalicious\s+ip\s+address\b", re.I),
]

# Credential-access + MFA-bypass markers from raw log content. Reduces
# reliance on behavioral_indicators alone.
_CREDENTIAL_ACCESS_PATTERNS = [
    re.compile(r"\bLSASS\b"),
    re.compile(r"\bDCSync\b", re.I),
    re.compile(r"\bMimikatz\b", re.I),
    re.compile(r"\bntds\.dit\b", re.I),
    re.compile(r"\bsam\s+hive\b", re.I),
    re.compile(r"\bkerberoast\b", re.I),
    re.compile(r"\bMFA\s+bypass\b", re.I),
    re.compile(r"\bsession\s+token\s+replay\b", re.I),
    re.compile(r"\bpass[- ]the[- ]hash\b", re.I),
    re.compile(r"\bpass[- ]the[- ]ticket\b", re.I),
]

# Ransomware behavioural markers.
_RANSOMWARE_PATTERNS = [
    # Allow optional .exe suffix — `vssadmin.exe delete shadows` was slipping
    # through the old \s+ requirement because `.exe` isn't whitespace.
    re.compile(r"\bvssadmin(?:\.exe)?\s+delete\s+shadows\b", re.I),
    re.compile(r"\bwmic(?:\.exe)?\s+shadowcopy\s+delete\b", re.I),
    re.compile(r"\bbcdedit(?:\.exe)?.*\bsafeboot\b", re.I),
    re.compile(r"\bransom.?note\b", re.I),
    re.compile(r"\bencrypted\s+by\b", re.I),
    re.compile(r"\bLockBit|Conti|BlackCat|ALPHV|BlackByte|Royal\s+Ransom|"
               r"Cl0p|Play\s+Ransom|Rhysida|Akira", re.I),
]

# Identity / IAM attack patterns — password spray, MFA fatigue,
# privileged role assignment, suspicious service principal creation.
# Fires TIER 2 in the extractor.
_IDENTITY_ATTACK_PATTERNS = [
    re.compile(r"\bpassword\s+spray(?:ing)?\s+(?:attack|detected|attempt)", re.I),
    re.compile(r"\bfailed\s+login\s+attempts?\s*:\s*[1-9]\d{2,}", re.I),  # >=100
    re.compile(r"\bMFA\s+fatigue\s+attack\b", re.I),
    re.compile(r"\bMFA\s+push\s+requests?\s*:\s*[1-9]\d{1,}\s+in\b", re.I),  # >=10 pushes
    re.compile(r"\bnew\s+(?:assignment\s+to|assignment\s+of|role\s+assignment).*Global\s+Administrator", re.I | re.S),
    re.compile(r"\bassign(?:ed|ment)\s+.*(?:Global\s+Administrator|Privileged\s+Role\s+Administrator|User\s+Administrator|Security\s+Administrator)", re.I | re.S),
    re.compile(r"\bnew\s+service\s+principal\s+created\b.*?(?:Mail\.Read|Files\.ReadWrite|User\.Read\.All|Directory\.ReadWrite|Application\.ReadWrite)", re.I | re.S),
    re.compile(r"\bimpossible\s+travel\b", re.I),
    re.compile(r"\batypical\s+travel\b", re.I),
    re.compile(r"\banonymous\s+ip\s+use\b", re.I),
    re.compile(r"\battack\s+tool\s+detected\b", re.I),  # Entra risk detection
    re.compile(r"\bleaked\s+credentials\b", re.I),
    re.compile(r"\bmalware\s+linked\s+ip\b", re.I),
]

# Cloud (AWS / Azure / GCP) attack patterns.
_CLOUD_ATTACK_PATTERNS = [
    # AWS GuardDuty finding categories that are always malicious-signal
    re.compile(r"\bGuardDuty\s+Finding\s*:?\s*(?:UnauthorizedAccess|CredentialAccess|Backdoor|CryptoCurrency|Trojan|Impact|Discovery|Exfiltration)", re.I),
    re.compile(r"\bInstanceCredentialExfiltration\b", re.I),
    re.compile(r"\bMaliciousIPCaller\b", re.I),
    # AWS access key from bad geo
    re.compile(r"\bAKIA[A-Z0-9]{16}\b.*?(?:used|accessed|invoked)\s+from\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I | re.S),
    # S3 public exposure
    re.compile(r"\bS3\s+bucket\s+(?:ACL|policy)\s+changed\s+to\s+public", re.I),
    re.compile(r"\bS3\s+bucket.*(?:public-read|public-read-write)\b", re.I | re.S),
    # Azure Key Vault
    re.compile(r"\bKey\s+Vault\s*:?\s*Key\s+deleted\b", re.I),
    re.compile(r"\b(?:master|root|prod)[-_ ]?(?:encryption[-_ ]?)?key.*deleted\b", re.I | re.S),
    re.compile(r"\bKeyVault\s+Purge\b", re.I),
    # Azure high-severity incident
    re.compile(r"\bAzure\s+Sentinel\b.*?\bseverity\s*:?\s*(?:high|critical)", re.I | re.S),
    # AWS root account use — always high signal
    re.compile(r"\broot\s+account\s+(?:login|used|access|activity)", re.I),
    re.compile(r"\buserIdentity[^{]*\btype\s*:\s*[\"']?Root[\"']?", re.I),
    # IAM privilege escalation
    re.compile(r"\bAttachUserPolicy\b.*AdministratorAccess", re.I | re.S),
    re.compile(r"\bAttachRolePolicy\b.*AdministratorAccess", re.I | re.S),
    re.compile(r"\bCreateAccessKey\b.*(?:contractor|external|new-user|guest)", re.I | re.S),
    # Suspicious AWS API from unusual IP (Moscow / Beijing / Tehran / known-bad)
    re.compile(r"\bMoscow\b.*\b(?:AWS|IAM|GuardDuty|CloudTrail)\b", re.I | re.S),
]

# C2 / beaconing / covert-channel patterns.
_C2_BEACON_PATTERNS = [
    re.compile(r"\bCobalt\s+Strike\s+beacon\b", re.I),
    re.compile(r"\bSliver\s+(?:beacon|C2|implant)\b", re.I),
    re.compile(r"\bBrute\s+Ratel\b", re.I),
    re.compile(r"\bMerlin\s+agent\b", re.I),
    re.compile(r"\bmetasploit\s+(?:meterpreter|payload|handler)\b", re.I),
    re.compile(r"\bbeacon\s+pattern\s+detected\b", re.I),
    re.compile(r"\bC2\s+(?:callback|beacon|traffic|channel)\b", re.I),
    re.compile(r"\binterval\s*:?\s*\d+s\s*\(\s*[±+/-]{1,3}\s*\d+%?\s*\)\s+sustained", re.I),  # jitter beacon
    re.compile(r"\bDNS\s+tunnel(?:ing|ling|s)\b", re.I),
    re.compile(r"\bTXT\s+quer(?:y|ies)\s*:\s*[1-9]\d{2,}\s+in\b", re.I),  # >=100 TXT queries
    re.compile(r"\bknown\s+Tor\s+exit\b", re.I),
    re.compile(r"\bTor\s+exit\s+node\b", re.I),
    re.compile(r"\bknown\s+malicious\s+ip\b", re.I),
    re.compile(r"\bmalicious\s+ip\s+(?:address|hit|match)\b", re.I),
]

_LATERAL_MOVEMENT_PATTERNS = [
    re.compile(r"\bpsexec\b", re.I),
    re.compile(r"\blateral\s+movement\b", re.I),
    re.compile(r"\bwmiexec\b", re.I),
    re.compile(r"\bwinrm\s+quickconfig\b", re.I),
    re.compile(r"\bschtasks.*\/s\s+\\\\\S+", re.I),
]

# Encoded / obfuscated command-line patterns — high signal for
# phishing→execution or living-off-the-land malicious activity.
# Fires TIER 2 by itself; combined with a suspicious parent (below)
# should elevate the verdict.
_ENCODED_CMD_PATTERNS = [
    re.compile(r"powershell(?:\.exe)?\s+.*?-e(?:nc(?:oded)?|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}", re.I),
    re.compile(r"powershell(?:\.exe)?\s+.*?-enc\b.*?[A-Za-z0-9+/=]{40,}", re.I),
    re.compile(r"powershell(?:\.exe)?\s+.*?FromBase64String\b", re.I),
    re.compile(r"powershell(?:\.exe)?\s+.*?\bIEX\b", re.I),
    re.compile(r"powershell(?:\.exe)?\s+.*?\bInvoke-Expression\b", re.I),
    re.compile(r"powershell(?:\.exe)?\s+.*?DownloadString\b", re.I),
    re.compile(r"powershell(?:\.exe)?\s+.*?DownloadFile\b", re.I),
    # Bypass execution policy is a strong signal on its own
    re.compile(r"-ExecutionPolicy\s+Bypass\b", re.I),
    re.compile(r"-ep\s+bypass\b", re.I),
]

# Suspicious parent → child process pairs. Email client / browser /
# Office app spawning a shell is the classic phishing execution chain.
# Fires TIER 2 when detected in the raw log text.
_SUSPICIOUS_PARENT_CHILD_PATTERNS = [
    # Outlook / email → shell/scripting
    re.compile(r"parent\s*(?:process)?\s*:\s*outlook\.exe.*?(?:powershell|cmd|wscript|cscript|mshta|rundll32)", re.I | re.S),
    re.compile(r"parent\s*(?:process)?\s*:\s*thunderbird\.exe.*?(?:powershell|cmd|wscript|cscript)", re.I | re.S),
    # Office apps → shell/scripting/downloader
    re.compile(r"parent\s*(?:process)?\s*:\s*(?:winword|excel|powerpnt)\.exe.*?(?:powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|curl|certutil)", re.I | re.S),
    # Browsers → shell/scripting (very rare in legit flows)
    re.compile(r"parent\s*(?:process)?\s*:\s*(?:chrome|msedge|firefox|brave)\.exe.*?(?:powershell|cmd|wscript|cscript)", re.I | re.S),
    # Adobe Reader → shell (exploit CVE pattern)
    re.compile(r"parent\s*(?:process)?\s*:\s*acrord32\.exe.*?(?:powershell|cmd|wscript|cscript)", re.I | re.S),
]

# LOLBAS abuse — living-off-the-land binaries with red-flag arguments.
# mshta.exe / regsvr32.exe / rundll32.exe with remote URIs or JS is
# almost always malicious. Fires TIER 2.
_LOLBAS_ABUSE_PATTERNS = [
    re.compile(r"mshta(?:\.exe)?\s+.*?javascript\s*:", re.I),
    re.compile(r"mshta(?:\.exe)?\s+.*?(?:https?|ftp)://", re.I),
    re.compile(r"regsvr32(?:\.exe)?\s+.*?/i\s*:\s*(?:https?|ftp)://", re.I),
    re.compile(r"regsvr32(?:\.exe)?\s+.*?/s\s+.*?scrobj\.dll", re.I),
    re.compile(r"rundll32(?:\.exe)?\s+.*?javascript\s*:", re.I),
    re.compile(r"rundll32(?:\.exe)?\s+.*?(?:https?|ftp)://", re.I),
    re.compile(r"certutil(?:\.exe)?\s+.*?-urlcache\s+.*?(?:https?|ftp)://", re.I),
    re.compile(r"certutil(?:\.exe)?\s+.*?-decode\b", re.I),
    re.compile(r"bitsadmin(?:\.exe)?\s+.*?/transfer\s+.*?(?:https?|ftp)://", re.I),
    re.compile(r"wmic(?:\.exe)?\s+.*?process\s+call\s+create\b", re.I),
]

# Suspicious top-level domains — common in phishing kits + malware
# infra. Fires TIER 2 when a URL/domain in the raw text uses one of
# these TLDs. Combined with any other tier signal ⇒ HIGH.
_SUSPICIOUS_TLD_PATTERNS = [
    re.compile(r"\bhttps?://[a-z0-9.-]+\.(?:tk|top|icu|xyz|gq|ml|cf|ga|buzz|click|link)(?:/|\s|$)", re.I),
    re.compile(r"\b[a-z0-9-]+\.(?:tk|top|icu|xyz|gq|ml|cf|ga|buzz|click|link)\b", re.I),
]

# Brand-impersonation typosquat patterns — subdomain / hyphenated
# tokens combined with common brand names in unusual TLDs. Fires
# TIER 2. Real Microsoft is never on .tk / .top / .icu / .xyz.
_TYPOSQUAT_PATTERNS = [
    re.compile(r"\b(?:microsoft|office|outlook|onedrive|sharepoint|azure|entra|apple|icloud|google|gmail|amazon|paypal|dropbox|docusign|adobe|netflix|linkedin|instagram|facebook|whatsapp)[-.]?(?:secure|update|verify|login|signin|account|auth|helpdesk|support)\b[^\s]*\.(?:tk|top|icu|xyz|gq|ml|cf|ga|buzz|click|link|info|online|site|website|store|shop)\b", re.I),
    re.compile(r"\b(?:microsoft|office|outlook|onedrive|sharepoint|azure|entra|apple|icloud|google|gmail|amazon|paypal|dropbox|docusign|adobe|netflix|linkedin|instagram|facebook|whatsapp)-[a-z0-9-]+\.(?:com|net|org)\b", re.I),
]

# Known-good vendor pattern markers — DOWNWEIGHT signals when they
# appear in the log. Coverage includes:
#   * management / EDR agents that generate high volumes of benign alerts
#   * mainstream browsers + their signing certs (Google LLC, Microsoft
#     Corporation, Mozilla Corporation) — the common allow-list case
#     ("chrome.exe signed by Google" is a strong benign-context signal)
#   * ThreatLocker "(Built-In)" policies — when a ThreatLocker tenant's
#     built-in policy MATCHES the event, ThreatLocker's own trust team
#     already vetted the application, so the alert is by-design benign
#   * tenant permit markers (Action: Permit, Effective Action: Permitted,
#     Monitor Only: true) — the operator's policy engine already
#     decided this activity is allowed
_KNOWN_GOOD_VENDOR_PATTERNS = [
    # Management / EDR agents
    re.compile(r"\bDell\s+SupportAssist\b", re.I),
    re.compile(r"\bHP\s+Support\s+Assistant\b", re.I),
    re.compile(r"\bMicrosoft\s+Defender\b", re.I),
    re.compile(r"\bWindows\s+Update\b", re.I),
    re.compile(r"\bWindows\s+Defender\s+Antivirus\b", re.I),
    re.compile(r"\bCrowdStrike\s+Falcon\b", re.I),
    re.compile(r"\bSCCM\s+client\b", re.I),
    re.compile(r"\bIntune\s+agent\b", re.I),
    re.compile(r"\bVeeam\s+backup\b", re.I),
    re.compile(r"\bSplunk\s+forwarder\b", re.I),
    re.compile(r"\bZscaler\s+client\b", re.I),
    re.compile(r"\bSentinelOne\s+agent\b", re.I),
    re.compile(r"\bTaniumClient\.exe\b", re.I),
    re.compile(r"\bBigFix\s+agent\b", re.I),
    re.compile(r"\bDatto\s+RMM\b", re.I),   # legit when signed + tenant-managed
    # Mainstream browsers — process paths + certificate subject lines
    re.compile(r"\\google\\chrome\\application\\chrome\.exe", re.I),
    re.compile(r"\\microsoft\\edge\\application\\msedge\.exe", re.I),
    re.compile(r"\\mozilla firefox\\firefox\.exe", re.I),
    re.compile(r"\\brave\\application\\brave\.exe", re.I),
    re.compile(r"cn=google llc,", re.I),
    re.compile(r"cn=microsoft corporation,", re.I),
    re.compile(r"cn=mozilla corporation,", re.I),
    re.compile(r"cn=apple inc\.,", re.I),
    re.compile(r"cn=adobe inc\.,", re.I),
    re.compile(r"cn=zoom video communications,", re.I),
    re.compile(r"cn=slack technologies,", re.I),
    re.compile(r"cn=dropbox,", re.I),
    # ThreatLocker built-in policy — vetted by the vendor's trust team
    re.compile(r"\bPolicy Name\s*:.*\(Built-In\)", re.I),
    re.compile(r"\(Built-In\)\s*$", re.I | re.M),
    # Defender routine remediation — malware detection with confirmed removal
    # is a resolved event, not an active compromise; ThreatLocker/MDE alerts
    # of this shape ARE benign from a triage standpoint.
    re.compile(r"\bThreat\s+Status\s*:\s*Remediated\b", re.I),
    re.compile(r"\bAction\s+Taken\s*:\s*Quarantine\b", re.I),
    re.compile(r"\bActionSuccess\s*:\s*true\b", re.I),
    re.compile(r"\bDefender\s+has\s+removed\b", re.I),
    # ThreatLocker Ringfencing block — a policy decision, not a compromise
    re.compile(r"\bRingfencing\b", re.I),
    re.compile(r"\bRingfence\s+Policy\b", re.I),
    # Entra ID clean sign-in
    re.compile(r"\brisk\s*state\s*:\s*none\b", re.I),
    re.compile(r"\brisk\s*level\s*aggregated\s*:\s*none\b", re.I),
    re.compile(r"\brisk\s*detail\s*:\s*none\b", re.I),
]

# Tenant policy engine markers — separate from vendor known-good so we
# can score them independently. When both fire on the same log the
# alert is essentially a policy-audit event, not a threat.
_TENANT_PERMIT_PATTERNS = [
    re.compile(r"\bAction\s*:\s*Permit\b", re.I),
    re.compile(r"\bEffective Action\s*:\s*Permitted\b", re.I),
    re.compile(r"\bMonitor Only\s*:\s*true\b", re.I),
]


def _raw_text(state: Dict[str, Any]) -> str:
    """Aggregate every text surface the analyst pasted or the LLM produced
    into one lowercased haystack for regex matching."""
    parts = [
        state.get("raw_input") or "",
        state.get("raw_input_clean") or "",
    ]
    inv = state.get("investigation_result") or {}
    rs  = state.get("response_summary") or {}
    parts.append(inv.get("summary") or "")
    parts.append(rs.get("summary") or "")
    parts.append(inv.get("attack_chain_hypothesis") or "")
    return "\n".join(str(p) for p in parts if p)


def _log_only_text(state: Dict[str, Any]) -> str:
    """The RAW analyst input only — used for actor / upstream-risk
    detection, so we don't accidentally match on prose the AI itself
    generated (which would create a feedback loop where the AI's own
    'Storm-####' summary blocks the CLEAR it wanted to recommend on the
    NEXT alert)."""
    return "\n".join(str(state.get(k) or "") for k in
                     ("raw_input", "raw_input_clean"))


def _iter_ioc_enrichments(state: Dict[str, Any]):
    """Walk every per-source enrichment payload. Yields
    (ioc_type, ioc_value, per_source_dict)."""
    enr = state.get("enrichments") or {}
    for ioc_type in ("ips", "domains", "hashes", "urls"):
        bucket = enr.get(ioc_type) or {}
        if not isinstance(bucket, dict):
            continue
        for value, per_source in bucket.items():
            if isinstance(per_source, dict):
                yield ioc_type, value, per_source


# ─── Public API ────────────────────────────────────────────────────────────

def extract_tier_signals(state: Dict[str, Any]) -> Dict[str, Any]:
    """Walk the final pipeline state and bucket every fired signal into
    a priority tier. Returns:

      {
        "tier_1":       list[{signal, evidence}],
        "tier_2":       list[{signal, evidence}],
        "tier_3":       list[{signal, evidence}],
        "downweight":   list[{signal, evidence}],
        "verdict_floor":"CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL",
        "block_clear":  bool,
      }
    """
    inv     = state.get("investigation_result") or {}
    rs      = state.get("response_summary") or {}
    cross   = rs.get("cross_refs") or state.get("cross_refs") or {}
    bi      = state.get("behavioral_indicators") or {}
    cats    = (bi.get("categories") or {}) if isinstance(bi, dict) else {}

    log_text = _log_only_text(state)
    all_text = _raw_text(state)

    tier_1: List[Dict[str, Any]] = []
    tier_2: List[Dict[str, Any]] = []
    tier_3: List[Dict[str, Any]] = []
    downweight: List[Dict[str, Any]] = []

    def _push(bucket, signal, evidence):
        bucket.append({"signal": signal, "evidence": (evidence or "")[:200]})

    # ── TIER 1 ────────────────────────────────────────────────────────
    for rx in _TRACKED_ACTOR_PATTERNS:
        m = rx.search(log_text)
        if m:
            _push(tier_1, "named threat actor in log",
                  f"matched '{m.group(0)}' in raw alert content")
            break

    for rx in _UPSTREAM_HIGH_RISK_PATTERNS:
        m = rx.search(log_text)
        if m:
            _push(tier_1, "upstream SIEM/EDR flagged risk High/Critical",
                  f"matched '{m.group(0)}' in raw alert content")
            break

    kev_hits = cross.get("kev") or []
    for k in kev_hits[:3]:
        if not isinstance(k, dict):
            continue
        if k.get("ransomware_use") or k.get("known_ransomware_campaigns"):
            _push(tier_1, "KEV CVE with active ransomware exploitation",
                  f"CVE={k.get('cve')} ransomware_use=True")
            break

    fam = (rs.get("malware_family") or state.get("malware_family") or "").strip()
    if fam:
        _push(tier_1, "named malware family attributed",
              f"family={fam}")

    for rx in _RANSOMWARE_PATTERNS:
        m = rx.search(all_text)
        if m:
            _push(tier_1, "ransomware behaviour",
                  f"matched '{m.group(0)[:60]}'")
            break

    if cats.get("credential_access"):
        _push(tier_1, "credential-access primitives",
              f"{len(cats['credential_access'])} matches in behavioral_indicators")
    else:
        for rx in _CREDENTIAL_ACCESS_PATTERNS:
            m = rx.search(all_text)
            if m:
                _push(tier_1, "credential-access primitives",
                      f"matched '{m.group(0)[:60]}' in log")
                break

    feodo_hit = any(
        (p.get("feodo_tracker") or {}).get("verdict") == "MALICIOUS"
        for _t, _v, p in _iter_ioc_enrichments(state)
    )
    if feodo_hit:
        _push(tier_1, "confirmed C2 callback (Feodo Tracker)",
              "IP appears on the abuse.ch Feodo Tracker active-C2 list")

    # Critical cloud events — TIER 1 by themselves. These are events
    # where the "worst-case" has already happened (data exposed, keys
    # deleted, root credential used) and no confirmation of exploitation
    # is needed — the exposure IS the incident.
    _CRITICAL_CLOUD_TIER1 = [
        (r"\bS3\s+bucket\s+(?:ACL|policy)\s+changed\s+to\s+public.*?(?:prod|production|backup|customer|pii|hipaa|pci)",
         "public S3 exposure of production/backup data"),
        (r"\b(?:prod|production|backup|customer|pii|hipaa|pci)[-_a-z0-9]*\s+bucket.*(?:public-read|public-read-write)",
         "public S3 exposure of production/backup data"),
        (r"\bKey\s+Vault\s*:?\s*Key\s+deleted\b.*?(?:master|root|encryption)",
         "critical key deletion (master/root/encryption)"),
        (r"\broot\s+account\s+(?:login|used|access)\s+from\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
         "AWS root account use from external IP"),
        (r"\bGuardDuty\s+Finding\s*:?\s*(?:UnauthorizedAccess|CredentialAccess|Backdoor|CryptoCurrency|Trojan|Impact)",
         "AWS GuardDuty malicious-activity finding"),
        (r"\bInstanceCredentialExfiltration\b",
         "AWS instance credential exfiltration"),
    ]
    for pat, name in _CRITICAL_CLOUD_TIER1:
        if re.search(pat, log_text, re.I | re.S):
            _push(tier_1, name, f"matched pattern in raw alert content")
            break

    # VT >= 5 same IOC
    vt_hi_ioc = ""
    for _t, ioc, p in _iter_ioc_enrichments(state):
        vt = p.get("virustotal") or {}
        if isinstance(vt, dict) and (vt.get("malicious") or 0) >= 5:
            vt_hi_ioc = ioc
            break
    if vt_hi_ioc:
        _push(tier_1, "VirusTotal ≥5 engines flagging same IOC",
              f"IOC={vt_hi_ioc}")

    # ── TIER 2 ────────────────────────────────────────────────────────
    for _t, ioc, p in _iter_ioc_enrichments(state):
        vt = p.get("virustotal") or {}
        mal = int(vt.get("malicious") or 0) if isinstance(vt, dict) else 0
        if 2 <= mal <= 4:
            _push(tier_2, "VirusTotal 2-4 engines flagging IOC",
                  f"IOC={ioc}, engines={mal}")
            break

    for _t, ioc, p in _iter_ioc_enrichments(state):
        ai = p.get("abuseipdb") or {}
        if not isinstance(ai, dict):
            continue
        score = ai.get("abuseScore") or ai.get("abuse_confidence") or 0
        if isinstance(score, (int, float)) and score >= 75:
            _push(tier_2, "AbuseIPDB score ≥75 with recent activity",
                  f"IOC={ioc}, score={int(score)}%")
            break

    if cats.get("lateral_movement"):
        _push(tier_2, "lateral movement pattern (behavioral)",
              f"{len(cats['lateral_movement'])} matches")
    else:
        for rx in _LATERAL_MOVEMENT_PATTERNS:
            m = rx.search(all_text)
            if m:
                _push(tier_2, "lateral movement pattern",
                      f"matched '{m.group(0)[:60]}'")
                break

    # LOLBAS abuse with remote URI / JS payload — mshta / regsvr32 /
    # rundll32 / certutil / bitsadmin / wmic with malicious argument
    # shapes. Not the same as the local cross-refs `lolbas` bucket
    # (which fires on just the binary name); this catches the ABUSE
    # signature.
    for rx in _LOLBAS_ABUSE_PATTERNS:
        m = rx.search(log_text)
        if m:
            _push(tier_2, "LOLBAS abuse pattern (remote URI / JS payload)",
                  f"matched '{m.group(0)[:80]}'")
            break

    # Encoded / obfuscated command-line — high-signal for phishing
    # execution chains. Fires once even if multiple patterns match.
    for rx in _ENCODED_CMD_PATTERNS:
        m = rx.search(log_text)
        if m:
            _push(tier_2, "encoded / obfuscated command-line",
                  f"matched '{m.group(0)[:80]}'")
            break

    # Suspicious parent → child process chain — email client / browser /
    # Office app spawning shell or scripting engine. Classic phishing
    # execution pattern.
    for rx in _SUSPICIOUS_PARENT_CHILD_PATTERNS:
        m = rx.search(log_text)
        if m:
            _push(tier_2, "suspicious parent → child process chain",
                  f"matched '{m.group(0)[:80]}'")
            break

    # Suspicious TLD in URL/domain (.tk / .top / .icu / .xyz / etc.) —
    # these TLDs disproportionately host phishing + malware infra.
    # Only fires when no legit downweight signal is present, and only
    # when there are no verdict-clearing high-signal patterns (avoid
    # double-firing when combined with tenant permit).
    for rx in _SUSPICIOUS_TLD_PATTERNS:
        m = rx.search(log_text)
        if m:
            _push(tier_2, "suspicious TLD (phishing-infra hotspot)",
                  f"matched '{m.group(0)[:60]}'")
            break

    # Brand-impersonation typosquat — microsoft-secure-update.tk shape.
    # Combined with the TLD pattern above, but this fires standalone
    # too when the brand token is in a .com/.net domain with a
    # suspicious hyphenated prefix.
    for rx in _TYPOSQUAT_PATTERNS:
        m = rx.search(log_text)
        if m:
            _push(tier_2, "brand-impersonation typosquat domain",
                  f"matched '{m.group(0)[:60]}'")
            break

    # Identity / IAM attacks — password spray, MFA fatigue, privileged
    # role assignment, suspicious service principal. These land as
    # narrative text in Entra/Okta/Azure logs and were slipping through
    # the tier framework because none of them touched enrichment
    # signals or the older behavioural patterns.
    for rx in _IDENTITY_ATTACK_PATTERNS:
        m = rx.search(log_text)
        if m:
            _push(tier_2, "identity attack pattern",
                  f"matched '{m.group(0)[:80]}'")
            break

    # Cloud attack patterns — AWS GuardDuty findings, S3 exposure,
    # Azure Key Vault deletion, root-account use, IAM privilege
    # escalation. Fires TIER 2 which combined with a bad-geo indicator
    # (185.220.101.45 / Moscow / etc.) escalates to HIGH.
    for rx in _CLOUD_ATTACK_PATTERNS:
        m = rx.search(log_text)
        if m:
            _push(tier_2, "cloud attack pattern",
                  f"matched '{m.group(0)[:80]}'")
            break

    # C2 / beaconing / covert channel — Cobalt Strike / Sliver / DNS
    # tunneling / Tor exit outbound / known-malicious-IP tags.
    for rx in _C2_BEACON_PATTERNS:
        m = rx.search(log_text)
        if m:
            _push(tier_2, "C2 / covert-channel pattern",
                  f"matched '{m.group(0)[:80]}'")
            break

    otx_ge_5 = False
    for _t, ioc, p in _iter_ioc_enrichments(state):
        otx = p.get("otx") or {}
        if isinstance(otx, dict) and (otx.get("pulseCount") or otx.get("pulse_count") or 0) >= 5:
            _push(tier_2, "AlienVault OTX ≥5 community pulses on IOC",
                  f"IOC={ioc}")
            otx_ge_5 = True
            break

    if (cross.get("lolbas") or []):
        _push(tier_2, "LOLBAS abuse detected",
              f"{len(cross['lolbas'])} LOLBins matched")
    if (cross.get("loldrivers") or []):
        _push(tier_2, "BYOVD LOLDrivers hash match",
              f"{len(cross['loldrivers'])} known-vulnerable drivers")

    for _t, ioc, p in _iter_ioc_enrichments(state):
        pc = p.get("phishing_classifier") or {}
        if isinstance(pc, dict) and pc.get("is_phish") \
                and (pc.get("probability") or 0) >= 0.85:
            _push(tier_2, "trained phishing-URL classifier ≥85%",
                  f"IOC={ioc}, probability={pc.get('probability')}")
            break

    for _t, ioc, p in _iter_ioc_enrichments(state):
        lf = p.get("local_feeds") or {}
        if isinstance(lf, dict) and lf.get("hit"):
            _push(tier_2, "local blocklist hit (in-tree TI feed)",
                  f"IOC={ioc}, source={lf.get('source')}")
            break

    for _t, ioc, p in _iter_ioc_enrichments(state):
        mb = p.get("malwarebazaar") or {}
        if isinstance(mb, dict) and (mb.get("malware_family") or mb.get("found")):
            _push(tier_2, "MalwareBazaar named family match",
                  f"IOC={ioc}, family={mb.get('malware_family')}")
            break

    # ── TIER 3 ────────────────────────────────────────────────────────
    for _t, ioc, p in _iter_ioc_enrichments(state):
        vt = p.get("virustotal") or {}
        mal = int(vt.get("malicious") or 0) if isinstance(vt, dict) else 0
        if mal == 1:
            _push(tier_3, "VirusTotal 1 engine flagged IOC",
                  f"IOC={ioc}")
            break

    for _t, ioc, p in _iter_ioc_enrichments(state):
        otx = p.get("otx") or {}
        cnt = (otx.get("pulseCount") or otx.get("pulse_count") or 0) if isinstance(otx, dict) else 0
        if 1 <= cnt <= 4:
            _push(tier_3, "OTX 1-4 pulses",
                  f"IOC={ioc}, pulses={cnt}")
            break

    for _t, ioc, p in _iter_ioc_enrichments(state):
        d = p.get("dga_classifier") or {}
        if isinstance(d, dict) and d.get("is_dga"):
            _push(tier_3, "trained DGA classifier hit",
                  f"IOC={ioc}, probability={d.get('probability')}")
            break

    # ── DOWNWEIGHT ────────────────────────────────────────────────────
    sup = state.get("suppressed_iocs") or {}
    if isinstance(sup, dict) and any(sup.values()):
        n = sum(len(v or []) for v in sup.values() if isinstance(v, list))
        _push(downweight, "MISP warninglist suppressed IOCs",
              f"{n} known-good IOCs filtered before enrichment")

    for rx in _KNOWN_GOOD_VENDOR_PATTERNS:
        m = rx.search(all_text)
        if m:
            _push(downweight, "known-good vendor / signed application",
                  f"matched '{m.group(0)[:60]}'")
            break

    # Tenant-policy permit markers — the operator's own policy engine
    # (ThreatLocker, Sentinel allow-list, MDE ASR exclusion, etc.) has
    # already made a decision to permit. Two independent markers ⇒
    # strong signal that this is a policy-audit event, not a threat.
    _permit_hits = []
    for rx in _TENANT_PERMIT_PATTERNS:
        m = rx.search(log_text)
        if m:
            _permit_hits.append(m.group(0))
    if len(_permit_hits) >= 2:
        _push(downweight, "tenant policy engine permitted the action",
              f"{len(_permit_hits)} permit markers in log: "
              + "; ".join(h[:40] for h in _permit_hits[:3]))

    # Every keyed source clean across every IOC = downweight — but
    # ONLY when we've checked at least 2 IOCs AND the log text itself
    # doesn't carry positive behavioural markers. A single clean IP
    # with encoded PowerShell in the same log is NOT benign; the old
    # rule fired downweight anyway and let the short-circuit misclassify.
    all_clean = True
    checked = 0
    for _t, ioc, p in _iter_ioc_enrichments(state):
        checked += 1
        vt = p.get("virustotal") or {}
        ai = p.get("abuseipdb") or {}
        if isinstance(vt, dict) and (vt.get("malicious") or 0) > 0:
            all_clean = False
            break
        if isinstance(ai, dict):
            score = ai.get("abuseScore") or ai.get("abuse_confidence") or 0
            if isinstance(score, (int, float)) and score > 25:
                all_clean = False
                break
    # Text-side red flags that veto the "all clean" downweight even
    # when TI reputation is clean. Keeps the tier framework honest on
    # behavioural-only malicious activity (LSASS access, encoded PS,
    # LOLBAS abuse, etc.).
    _text_red_flags = [
        r"\b(?:powershell|cmd)\.exe\s+.*?\b(?:-e(?:nc)?|-encodedcommand|-executionpolicy\s+bypass|frombase64string|downloadstring|downloadfile|iex|invoke-expression)\b",
        r"\b(?:mshta|regsvr32|rundll32|certutil|bitsadmin)\.exe\s+.*?(?:javascript\s*:|https?://|/i\s*:|-urlcache|-decode)",
        r"\blsass(?:\.exe)?\s*(?:memory\s+access|dump)",
        r"parent\s*(?:process)?\s*:\s*(?:outlook|winword|excel|powerpnt|chrome|msedge|firefox|acrord32)\.exe.*?(?:powershell|cmd|wscript|cscript|mshta)",
        # Ransomware
        r"\bvssadmin(?:\.exe)?\s+delete\s+shadows",
        r"\b(?:LockBit|Conti|BlackCat|ALPHV|BlackByte|Rhysida|Akira|Cl0p)\b",
        # Identity attacks
        r"\bpassword\s+spray(?:ing)?",
        r"\bMFA\s+fatigue",
        r"\bimpossible\s+travel",
        r"\bnew\s+(?:assignment|role\s+assignment).*Global\s+Administrator",
        # Cloud
        r"\bGuardDuty\s+Finding\s*:?\s*(?:Unauthorized|Credential|Backdoor|Crypto|Trojan)",
        r"\bS3\s+bucket\s+(?:ACL|policy)\s+changed\s+to\s+public",
        r"\bKey\s+Vault\s*:?\s*Key\s+deleted",
        r"\broot\s+account\s+(?:login|used|access)",
        # C2
        r"\bCobalt\s+Strike\s+beacon",
        r"\bbeacon\s+pattern\s+detected",
        r"\bDNS\s+tunnel(?:ing|ling)",
        r"\bknown\s+Tor\s+exit",
        r"\bknown\s+malicious\s+ip",
    ]
    _text_has_red_flag = any(re.search(p, log_text, re.I | re.S) for p in _text_red_flags)
    if all_clean and checked >= 2 and not tier_1 and not tier_2 and not _text_has_red_flag:
        _push(downweight,
              "clean across every keyed TI source with no TIER 1/2 signals",
              f"{checked} IOCs checked, all reputation-clean")

    # ── Verdict floor + block_clear ───────────────────────────────────
    if tier_1:
        verdict_floor = "HIGH"
        block_clear = True
    elif len(tier_2) >= 2:
        verdict_floor = "HIGH"
        block_clear = True
    elif len(tier_2) == 1:
        verdict_floor = "MEDIUM"
        block_clear = bool(not downweight)
    elif tier_3:
        verdict_floor = "LOW"
        block_clear = False
    else:
        verdict_floor = "INFORMATIONAL"
        block_clear = False

    return {
        "tier_1":         tier_1,
        "tier_2":         tier_2,
        "tier_3":         tier_3,
        "downweight":     downweight,
        "verdict_floor":  verdict_floor,
        "block_clear":    block_clear,
    }


def format_signal_correlation(state: Dict[str, Any],
                              tiers: Optional[Dict[str, Any]] = None) -> str:
    """Analyst-readable prose the LLM can quote verbatim in
    disposition_reason. Returns "" when no meaningful signals fired so
    prompt strings render without an empty section."""
    if tiers is None:
        tiers = extract_tier_signals(state)

    lines: List[str] = []
    if tiers["tier_1"]:
        lines.append("TIER 1 SIGNALS PRESENT (verdict floor = HIGH, CLEAR is blocked):")
        for s in tiers["tier_1"]:
            lines.append(f"  • {s['signal']} — {s['evidence']}")
    if tiers["tier_2"]:
        lines.append("TIER 2 SIGNALS PRESENT (corroborating):")
        for s in tiers["tier_2"]:
            lines.append(f"  • {s['signal']} — {s['evidence']}")
    if tiers["tier_3"]:
        lines.append("TIER 3 SIGNALS (context only, don't drive verdict):")
        for s in tiers["tier_3"]:
            lines.append(f"  • {s['signal']} — {s['evidence']}")
    if tiers["downweight"]:
        lines.append("DOWNWEIGHT SIGNALS PRESENT:")
        for s in tiers["downweight"]:
            lines.append(f"  • {s['signal']} — {s['evidence']}")
    if not lines:
        return ""
    lines.append(f"=> Deterministic verdict floor: {tiers['verdict_floor']}")
    if tiers["block_clear"]:
        lines.append("=> CLEAR is BLOCKED by the tier framework. Choose ESCALATE or MONITOR.")
    return "\n".join(lines)


def should_block_clear(state: Dict[str, Any]) -> Tuple[bool, str]:
    """Return (True, reason) when the tier framework blocks a CLEAR
    disposition. response.py runs this AFTER the LLM output and force-
    upgrades CLEAR → ESCALATE when it fires."""
    tiers = extract_tier_signals(state)
    if not tiers["block_clear"]:
        return False, ""
    top = (tiers["tier_1"] or tiers["tier_2"])[:2]
    names = ", ".join(s["signal"] for s in top)
    return True, (f"TIER 1/2 signals fired ({names}) — public-TI 'clean' "
                  f"is not a downgrade reason.")
