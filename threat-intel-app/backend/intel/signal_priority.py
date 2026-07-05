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
# NOTE the `[_ -]?` between compound tokens — Entra emits camelCase
# (`riskState`, `riskLevel`), Sentinel emits snake_case (`risk_state`),
# and some SIEMs emit space-separated. Make separators optional so all
# three shapes match.
_UPSTREAM_HIGH_RISK_PATTERNS = [
    re.compile(r"\brisk[_ -]?level\s*:?\s*high\b", re.I),
    re.compile(r"\brisk[_ -]?level\s*:?\s*critical\b", re.I),
    re.compile(r"\bhigh[- ]risk\s+sign[- ]in\b", re.I),
    re.compile(r"\bhigh[- ]risk\s+user\b", re.I),
    re.compile(r"\brisk[_ -]?state\s*:?\s*(atRisk|confirmedCompromised)\b", re.I),
    re.compile(r"\brisk[_ -]?level[_ -]?aggregated\s*:?\s*high\b", re.I),
    re.compile(r"\bseverity\s*:?\s*(High|Critical)\b"),
    re.compile(r"\battempted\s+atypical\s+travel\b", re.I),
    re.compile(r"\bsuccessful\s+atypical\s+travel\b", re.I),
    re.compile(r"\bimpossible\s+travel\b", re.I),
    re.compile(r"\bmalicious\s+ip\s+address\b", re.I),
    # Additional Entra IdentityProtection markers
    re.compile(r"\bconfirmedCompromised\b", re.I),
    re.compile(r"\bIdentityProtection\b.*?\batRisk\b", re.I | re.S),
]

# Credential-access + MFA-bypass markers from raw log content. Reduces
# reliance on behavioral_indicators alone. Includes Unix credential
# targets (/etc/shadow, /etc/passwd, ~/.ssh/id_rsa) alongside Windows.
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
    # Linux credential targets
    re.compile(r"(?:cat|less|more|head|tail|dd\s+if=)\s+/etc/shadow\b", re.I),
    re.compile(r"(?:cat|less|more|head|tail|dd\s+if=)\s+/etc/passwd\b", re.I),
    re.compile(r"/etc/shadow\b.*\b(?:copied|exfiltrated|accessed)", re.I | re.S),
    re.compile(r"(?:cat|scp|curl|wget)\s+.*?~?/\.ssh/id_[a-z0-9_]+\b", re.I),
    re.compile(r"\.ssh/id_rsa\b.*(?:exfiltrated|leaked|read|copied)", re.I | re.S),
    # macOS credential targets — Keychain, TCC.db (holds sensitive perms)
    re.compile(r"\blogin\.keychain(-db)?\b.*(?:accessed|copied|read|dumped)", re.I | re.S),
    re.compile(r"\bsecurity\s+dump-keychain\b", re.I),
    re.compile(r"\bsecurity\s+find-generic-password\b.*-w\b", re.I),
    re.compile(r"\bTCC\.db\b.*(?:modified|inserted\s+into|updated)", re.I | re.S),
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
    # BAV2ROPC user agent — legacy Basic Auth via Resource Owner
    # Password Credentials. Almost every credential-stuffing tool
    # uses this UA. Real users don't. Very high-signal.
    re.compile(r"\bBAV2ROPC\b"),
    re.compile(r"\buserAgent[\"'\s]*[:=][\"'\s]*BAV2ROPC\b", re.I),
    # Multiple Entra IdentityProtection Unfamiliar-* risk reasons
    # in one event = high-confidence risky sign-in. One Unfamiliar
    # flag is common (new phone, new IP), 3+ in a single alert
    # is almost always malicious.
    re.compile(r"(?:Unfamiliar(?:ASN|Browser|Device|IP|Location|EASId|TenantIPsubnet|Features)[\"',\s]*){3,}", re.I),
    re.compile(r"riskReasons.*?Unfamiliar.*?Unfamiliar.*?Unfamiliar", re.I | re.S),
    # MITRE T1078 (Valid Accounts) references — the specific technique
    # subclasses attackers use for cloud identity compromise
    re.compile(r"\bT1078(?:\.\d{3})?\b"),
    re.compile(r"\bmitreTechniques[\"'\s]*[:=][\"'\s]*[\"']?T1078", re.I),
]

# Windows AV detection patterns — Defender detecting HackTool / PUA
# variants and Defender action failures. These are TIER 2 corroborating
# signals: the detection itself is a real signal, and a failed
# remediation means the artefact is still on disk.
_DEFENDER_DETECTION_TIER2_PATTERNS = [
    # HackTool / PUA / PUABundler / Trojan named detections
    ("Defender HackTool detection",
     re.compile(r"\bName\s*:\s*HackTool\s*:", re.I)),
    ("Defender PUA / PUABundler detection",
     re.compile(r"\bName\s*:\s*PUA(?:Bundler)?\s*:", re.I)),
    ("Defender Trojan detection",
     re.compile(r"\bName\s*:\s*Trojan\s*:", re.I)),
    ("Defender Backdoor detection",
     re.compile(r"\bName\s*:\s*Backdoor\s*:", re.I)),
    ("Defender Ransom detection",
     re.compile(r"\bName\s*:\s*Ransom\s*:", re.I)),
    ("Defender Behavior detection",
     re.compile(r"\bName\s*:\s*Behavior\s*:", re.I)),
    # Any HackTool: / PUA: string in the log (not necessarily prefixed by Name:)
    ("HackTool / PUA family name in log",
     re.compile(r"\b(?:HackTool|PUA|PUABundler|Backdoor|Ransom|Trojan|Exploit)\s*:\s*(?:Script|Win\d\d|MSIL|VBS|JS|HTML|Linux|OSX|MacOS)/", re.I)),
    # Defender action failed — file still on disk
    ("Defender action failed — Error Code present",
     re.compile(r"\bAction\s*:\s*Quarantine\b.*?\bError\s+Code\s*:\s*0x[0-9a-f]+", re.I | re.S)),
    ("Defender ActionSuccess: false",
     re.compile(r"\bActionSuccess\s*:\s*false\b", re.I)),
    ("Defender error 0x800700df (file too large to quarantine)",
     re.compile(r"\b0x800700df\b", re.I)),
    # High-severity Defender detection
    ("Defender Severity: High detection",
     re.compile(r"\bSeverity\s*:\s*High\b.*?\b(?:HackTool|PUA|Trojan|Backdoor|Ransom)\s*:", re.I | re.S)),
    ("Defender Severity: Severe detection",
     re.compile(r"\bSeverity\s*:\s*Severe\b", re.I)),
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

# ──────────────────────────────────────────────────────────────────────
# WINDOWS AD / KERBEROS ATTACK PATTERNS — TIER 1
# ──────────────────────────────────────────────────────────────────────
_WIN_AD_TIER1_PATTERNS = [
    # Kerberos attacks
    ("Kerberoasting attempt",
     re.compile(r"\bkerberoast(?:ing)?\s+(?:attempt|attack|detected)", re.I)),
    ("Kerberoasting — RC4-HMAC downgrade + Event 4769",
     re.compile(r"(?:event\s+id\s*:?\s*4769.*?RC4[- ]HMAC|RC4[- ]HMAC.*?event\s+id\s*:?\s*4769)", re.I | re.S)),
    ("AS-REP roasting",
     re.compile(r"\bAS[-_ ]REP\s+roast(?:ing)?\b", re.I)),
    ("AS-REP roasting — DONT_REQ_PREAUTH targeting",
     re.compile(r"\bDONT_REQ_PREAUTH\b.*?(?:target|attempt|multiple)", re.I | re.S)),
    ("Golden Ticket usage",
     re.compile(r"\bgolden\s+ticket\b.*?(?:used|usage|suspected|detected)", re.I | re.S)),
    ("Golden Ticket — unusual TGT lifetime",
     re.compile(r"\bTGT\s+lifetime\s*:?\s*\d+\s*year", re.I)),
    ("Silver Ticket usage",
     re.compile(r"\bsilver\s+ticket\b.*?(?:used|usage|suspected|detected)", re.I | re.S)),
    ("DCSync from non-DC",
     re.compile(r"\bDCSync\s+.*?(?:non[-_ ]DC|workstation|not\s+a\s+domain\s+controller)", re.I | re.S)),
    ("DCSync — Directory Replication permissions abuse",
     re.compile(r"\bDirectory\s+Replication\s+permissions\b.*?(?:granted|abuse)", re.I | re.S)),
    # CVE exploitation
    ("Zerologon exploitation (CVE-2020-1472)",
     re.compile(r"\bzerologon\b|\bCVE-2020-1472\b", re.I)),
    ("Zerologon — Netlogon NULL session flood",
     re.compile(r"\bnetlogon\b.*?NULL\s+session.*?(?:flood|bombardment|attempts?)", re.I | re.S)),
    ("PrintNightmare exploitation (CVE-2021-34527)",
     re.compile(r"\bprintnightmare\b|\bCVE-2021-34527\b", re.I)),
    ("PrintNightmare — RpcAddPrinterDriver from non-admin",
     re.compile(r"\bRpcAddPrinterDriver\b.*?(?:remote\s+non-admin|non-privileged|unusual)", re.I | re.S)),
    ("Follina MSDT exploitation (CVE-2022-30190)",
     re.compile(r"\bfollina\b|\bms-msdt\b.*?(?:id=PCWDiagnostic|invoke|exploit)", re.I | re.S)),
    ("Log4Shell JNDI injection (CVE-2021-44228)",
     re.compile(r"\$\{jndi\s*:\s*(?:ldap|rmi|dns|nis|nds|corba|iiop)\s*:", re.I)),
    ("ProxyShell / ProxyLogon exploitation",
     re.compile(r"\bproxy(?:shell|logon)\b.*?(?:exploitation|attempt|detected)", re.I | re.S)),
    # Security tooling disabled — high-signal ATT&CK T1562
    ("Windows Defender AV disabled",
     re.compile(r"Set-MpPreference\s+.*?-Disable(?:RealtimeMonitoring|BehaviorMonitoring|IntrusionPreventionSystem|IOAVProtection|ScriptScanning)\s+\$?true", re.I)),
    ("Defender exclusion added",
     re.compile(r"Add-MpPreference\s+.*?-Exclusion(?:Path|Extension|Process)\b", re.I)),
    ("Sysmon service stopped",
     re.compile(r"(?:net\s+stop|Stop-Service|sc\s+stop)\s+.*?sysmon(?:64|drv)?\b", re.I)),
    ("Sysmon driver unloaded",
     re.compile(r"\bfltmc\s+unload\s+sysmon\b|sysmon\s+.*?-u\s+force", re.I)),
    ("EDR service tampered",
     re.compile(r"(?:net\s+stop|Stop-Service|sc\s+stop)\s+.*?(?:CrowdStrike|CSFalcon|SentinelOne|SentinelAgent|MsSense|WinDefend|MpsSvc)\b", re.I)),
    ("BitLocker encryption disabled",
     re.compile(r"\bmanage-bde\s+.*?-(?:protectors\s+-disable|off)\b", re.I)),
    ("BitLocker suspended via PowerShell",
     re.compile(r"\bSuspend-BitLocker\b", re.I)),
    # AD identity
    ("Group Policy weakened",
     re.compile(r"Group\s+Policy.*?(?:password\s+policy\s+weakened|min\s+length\s+.*?->\s*\d)", re.I | re.S)),
    # Persistence
    ("WMI event subscription persistence",
     re.compile(r"(?:EventFilter\s*:.*?EventConsumer\s*:|CommandLineEventConsumer.*?FilterToConsumerBinding)", re.I | re.S)),
    ("WMI persistence — __InstanceModificationEvent watcher",
     re.compile(r"__InstanceModificationEvent\s+.*?WITHIN\s+\d+", re.I | re.S)),
    ("schtasks persistence — onlogon / onstart with high privilege",
     re.compile(r"\bschtasks(?:\.exe)?\s+/create\s+.*?/sc\s+(?:onlogon|onstart|onidle)", re.I | re.S)),
    ("Registry Run key persistence with suspicious value",
     re.compile(r"HK(?:LM|CU)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.*?(?:AppData|Public|Temp|ProgramData)\\.*?\.(?:exe|dll|ps1|vbs|bat)", re.I | re.S)),
]

# Cloud attacks TIER 1 (additional — beyond critical cloud already in _CRITICAL_CLOUD_TIER1)
_CLOUD_ATTACK_TIER1_EXTRA = [
    # Mass secret access
    ("AWS mass GetSecretValue calls",
     re.compile(r"mass\s+GetSecretValue\s+calls|GetSecretValue\s+.*?(?:47|100|1000)\s+.*?in\s+\d+\s+min", re.I | re.S)),
    ("Secrets accessed baseline exceeded",
     re.compile(r"Secrets\s+accessed\s*:\s*\d{2,}\s+in\s+\d+\s+min", re.I)),
    # Conditional Access disabled
    ("Azure Conditional Access policy disabled",
     re.compile(r"Conditional\s+Access\s+policy\s+disabled", re.I)),
    ("MFA policy removed for admins",
     re.compile(r"Require\s+MFA\s+for\s+admins.*?(?:disabled|removed)", re.I | re.S)),
    # GCP IAM
    ("GCP high-privilege IAM role granted to external",
     re.compile(r"GCP\s+IAM.*?roles?/(?:iam\.securityAdmin|owner|editor|iam\.roleAdmin)\b.*?(?:external|@evil|@attacker)", re.I | re.S)),
    ("GCP roles/Owner or roles/Editor granted externally",
     re.compile(r"\broles/(?:owner|editor|iam\.securityAdmin|iam\.roleAdmin)\s+granted\b.*?(?:external|no\s+approval|no\s+ticket)", re.I | re.S)),
    # O365 forwarding rule to external — high-signal BEC persistence
    ("O365 inbox forwarding rule to external",
     re.compile(r"O365\s+.*?forwarding\s+rule\s+created.*?forward\s+to\s*:\s*.*?@(?!contoso\.com|company\.com)", re.I | re.S)),
    ("Inbox rule — delete on forward",
     re.compile(r"Delete\s+on\s+forward\s*:\s*true", re.I)),
]

# ──────────────────────────────────────────────────────────────────────
# LINUX ATTACK PATTERNS
# ──────────────────────────────────────────────────────────────────────
# TIER 1 — verdict-determining. Reverse shells, container escape,
# kernel rootkit indicators, log-tampering. These are unambiguously
# malicious on any Linux host.
_LINUX_TIER1_PATTERNS = [
    # Reverse shells — bash/nc/python/perl/ruby/php/socat variants
    ("reverse shell (bash /dev/tcp)",
     re.compile(r"\bbash\s+-i\s*>\s*&\s*/dev/tcp/", re.I)),
    ("reverse shell (bash /dev/tcp) — alt form",
     re.compile(r"/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d{1,5}", re.I)),
    ("reverse shell (nc -e)",
     re.compile(r"\bnc(?:at)?\s+-e\s+(?:/bin/(?:sh|bash|dash)|cmd\.exe)", re.I)),
    ("reverse shell (nc mkfifo)",
     re.compile(r"\bmkfifo\s+.*?nc(?:at)?\s+.*?\d{1,3}(?:\.\d{1,3}){3}", re.I | re.S)),
    ("reverse shell (python socket)",
     re.compile(r"python\d?\s+-c\s+['\"].*?socket\.socket\(.*?\.connect\(", re.I | re.S)),
    ("reverse shell (perl socket)",
     re.compile(r"perl\s+-e\s+['\"].*?socket\(S,PF_INET", re.I | re.S)),
    ("reverse shell (socat)",
     re.compile(r"\bsocat\s+.*?tcp[-:]connect:", re.I)),
    ("reverse shell (php)",
     re.compile(r"php\s+-r\s+['\"].*?fsockopen\(", re.I | re.S)),

    # Container escape indicators
    ("container escape — /proc/1/root mount",
     re.compile(r"mount\s+.*?/proc/1/root", re.I)),
    ("container escape — docker.sock mounted",
     re.compile(r"/var/run/docker\.sock(?:\s+mounted|.*mounted\s+into)", re.I)),
    ("container escape — privileged container",
     re.compile(r"privileged\s*:\s*true\b|--privileged\b", re.I)),
    ("container escape — hostPath / hostNetwork",
     re.compile(r"\bhostPath\s*:|hostNetwork\s*:\s*true\b|hostPID\s*:\s*true\b", re.I)),
    ("container escape — cgroups notify_on_release",
     re.compile(r"notify_on_release.*release_agent", re.I | re.S)),

    # Kernel rootkit / module load
    ("kernel module load (insmod / rootkit)",
     re.compile(r"\binsmod\s+.*?\.ko\b", re.I)),
    ("kernel module load with suspicious path",
     re.compile(r"\bmodprobe\s+.*?/tmp/|/dev/shm/", re.I)),
    ("/dev/kmem or /dev/mem write",
     re.compile(r"write\s+to\s+/dev/(?:kmem|mem)\b", re.I)),

    # LD_PRELOAD injection
    ("LD_PRELOAD injection",
     re.compile(r"\bLD_PRELOAD\s*=\s*(?:['\"]?/tmp/|/dev/shm/|['\"]?[^\s]+\.so)", re.I)),
    ("LD_LIBRARY_PATH hijack to /tmp",
     re.compile(r"\bLD_LIBRARY_PATH\s*=\s*[^\s]*/tmp/", re.I)),

    # Log tampering
    ("audit log tampered",
     re.compile(r"(?:>\s*|truncate.*?)/var/log/(?:audit/)?audit\.log", re.I)),
    ("bash history cleared / redirected",
     re.compile(r"(?:>\s*~?/\.bash_history|unset\s+HISTFILE|history\s+-c\s*&&\s*)", re.I)),

    # Passwd/shadow direct modification
    ("passwd/shadow direct write",
     re.compile(r"(?:echo\s+.*?>>|>\s*)/etc/(?:passwd|shadow|sudoers)\b", re.I)),

    # Cryptominer named
    ("cryptominer (xmrig / cpuminer / t-rex / phoenixminer)",
     re.compile(r"\b(?:xmrig|cpuminer|t-rex|phoenixminer|nsfminer|nbminer|nanominer)\b", re.I)),
    ("monero pool connection",
     re.compile(r"\b(?:supportxmr|nanopool|minergate|monerohash|pool\.hashvault)\.com\b", re.I)),

    # SUID escalation
    ("SUID bit added to unusual binary",
     re.compile(r"\bchmod\s+(?:[+]?4[0-7]{3}|u[+]s)\s+/(?:tmp|home|var/tmp|dev/shm)/", re.I)),

    # authorized_keys / SSH persistence
    ("SSH authorized_keys modified — new key added",
     re.compile(r"authorized_keys\b.*?(?:new\s+ssh\s+key|added\s+by|key\s+added)", re.I | re.S)),

    # PAM backdoor
    ("PAM backdoor — pam_permit.so added",
     re.compile(r"/etc/pam\.d/\S+\b.*?(?:pam_permit\.so|auth\s+sufficient\s+pam_permit)", re.I | re.S)),

    # /etc/ld.so.preload write — universal LD_PRELOAD alternative
    ("/etc/ld.so.preload modified",
     re.compile(r"/etc/ld\.so\.preload\b.*?(?:modified|added|written|new\s+entry)", re.I | re.S)),

    # sudoers backdoor
    ("sudoers backdoor — NOPASSWD via web-app or non-admin",
     re.compile(r"/etc/sudoers\b.*?(?:modified|written|edited).*?NOPASSWD", re.I | re.S)),
    ("sudoers echo append backdoor",
     re.compile(r"echo\s+['\"][^'\"]*NOPASSWD[^'\"]*['\"]\s*>>\s*/etc/sudoers", re.I)),

    # .bashrc / .profile backdoor
    ("bashrc / profile backdoor with curl payload",
     re.compile(r"~?/\.(?:bashrc|profile|bash_profile|zshrc)\b.*?(?:appended|modification|new\s+line).*?(?:curl|wget|nc\s+-e)", re.I | re.S)),

    # syslog / journal tampering
    ("systemd journal cleared",
     re.compile(r"journalctl\s+--vacuum-(?:time|size|files)\s*[=\s]\s*\S+", re.I)),
    ("rsyslog forward to external IP",
     re.compile(r"(?:rsyslog\.conf|/etc/syslog).*?\*\.\*\s+@@?\d{1,3}(?:\.\d{1,3}){3}", re.I | re.S)),

    # Meterpreter / staging
    ("Meterpreter stage-0 shellcode signature",
     re.compile(r"meterpreter\s+(?:stage[-_ ]0|session|payload|signature)", re.I)),
    ("Metasploit reverse handler",
     re.compile(r"metasploit\s+.*?(?:handler|payload|reverse)", re.I | re.S)),

    # SSH key harvest
    ("SSH keyscan harvest across hosts",
     re.compile(r"ssh-keyscan\s+.*?(?:for\s+\S+\s+in|>>\s+/tmp/|>>\s+/dev/shm)", re.I | re.S)),

    # GTFOBins-style SUID escalation
    ("GTFOBins find -exec /bin/sh",
     re.compile(r"\bfind\s+\S+\s+.*?-exec\s+(?:/bin/)?(?:sh|bash)\s+-p", re.I)),
    ("GTFOBins vim / nano / less shell escape",
     re.compile(r"(?:vim|nano|less|more)\s+.*?:!(?:/bin/)?(?:sh|bash)", re.I)),

    # Docker privileged variants
    ("Docker run with --cap-add=ALL",
     re.compile(r"docker\s+run\s+.*?--cap-add\s*=?\s*ALL\b", re.I)),
    ("Docker run mounting host root",
     re.compile(r"docker\s+run\s+.*?-v\s+/:/host\b", re.I)),
    ("Docker run --pid=host or --network=host",
     re.compile(r"docker\s+run\s+.*?--(?:pid|network|ipc|uts)=host\b", re.I)),

    # iptables C2 allow — as TIER 1 since it opens attacker's channel
    ("iptables allow outbound to bad IP",
     re.compile(r"iptables\s+.*?-[AI]\s+(?:OUTPUT|FORWARD).*?-d\s+\d{1,3}(?:\.\d{1,3}){3}.*?-j\s+ACCEPT", re.I)),
    ("iptables allow inbound reverse tunnel port",
     re.compile(r"iptables\s+.*?-[AI]\s+INPUT.*?-p\s+tcp\s+.*?--dport\s+(?:4444|8080|1337|31337|4448)", re.I)),

    # Modules on boot
    ("kernel module registered at boot",
     re.compile(r"/etc/modules-load\.d/\S+\.conf\b.*?(?:created|written|registered|modified|added)", re.I | re.S)),
    ("modprobe.d config with malicious module",
     re.compile(r"/etc/modprobe\.d/\S+\.conf.*?(?:install|blacklist).*?/tmp/|/dev/shm/", re.I | re.S)),
]

# TIER 2 — corroborating Linux attack signals.
_LINUX_TIER2_PATTERNS = [
    # auditd EXECVE with suspicious command
    ("auditd EXECVE curl|bash pattern",
     re.compile(r"type=EXECVE.*?(?:curl|wget)\s+[^\s]+\s*\|\s*(?:bash|sh|python|perl)", re.I)),
    ("curl piped to shell",
     re.compile(r"(?:curl|wget)\s+(?:-[a-z]+\s+)*(?:https?://)?[^\s|]+\s*\|\s*(?:bash|sh|zsh)", re.I)),

    # SELinux AVC denials against sensitive contexts
    ("SELinux AVC denied for shell exec from unusual context",
     re.compile(r"avc:\s+denied\s+\{[^}]*(?:execute|execute_no_trans)[^}]*\}.*?(?:tmp_t|user_tmp_t|var_tmp_t)", re.I | re.S)),
    ("SELinux AVC denied — passwd/shadow read",
     re.compile(r"avc:\s+denied\s+\{[^}]*read[^}]*\}.*?shadow_t", re.I | re.S)),

    # systemd persistence
    ("systemd unit ExecStart in /tmp or /dev/shm",
     re.compile(r"ExecStart\s*=\s*/(?:tmp|dev/shm|home/[^/]+/\.[^/]+)/", re.I)),
    ("systemd service enabled from user tmp dir",
     re.compile(r"systemctl\s+enable\s+.*?/(?:tmp|dev/shm)/", re.I)),

    # cron persistence
    ("cron persistence in /etc/cron paths",
     re.compile(r"(?:echo\s+.*?>|>\s*|writing\s+to)/etc/cron\.(?:d|daily|hourly|weekly|monthly)/", re.I)),
    ("crontab entry with suspicious payload",
     re.compile(r"crontab.*?(?:curl|wget|base64\s+-d|\|\s*bash)", re.I | re.S)),

    # SSH tunneling
    ("SSH reverse port forward established",
     re.compile(r"\bssh\s+.*?-R\s+\d+:", re.I)),
    ("SSH dynamic proxy (SOCKS)",
     re.compile(r"\bssh\s+.*?-D\s+\d+\b", re.I)),
    ("SSH known-suspicious flag combo",
     re.compile(r"\bssh\s+.*?-[a-zA-Z]*[fN]{1,2}[a-zA-Z]*\s+.*?-[a-zA-Z]*[LR]\s+", re.I)),

    # sudo abuse
    ("sudo NOPASSWD granted to unusual user",
     re.compile(r"\bNOPASSWD\s*:\s*ALL\b", re.I)),
    ("sudo su to root from service account",
     re.compile(r"sudo\s+.*?(?:USER=root|TARGET=root).*?COMMAND=/bin/(?:sh|bash)", re.I | re.S)),

    # Docker / Kubernetes
    ("Docker socket exposed to container",
     re.compile(r"-v\s+/var/run/docker\.sock:/var/run/docker\.sock", re.I)),
    ("K8s pod created in kube-system by non-controller",
     re.compile(r"kube-system.*?created.*?(?:serviceaccount|user)\s*:", re.I | re.S)),
    ("K8s exec into pod with sh/bash",
     re.compile(r"kubectl\s+exec\s+.*?--\s+(?:/bin/)?(?:sh|bash)\b", re.I)),

    # fail2ban / brute-force
    ("fail2ban banned IP after N attempts (large N)",
     re.compile(r"fail2ban.*?[Bb]an\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I)),
    ("sshd many failed passwords",
     re.compile(r"sshd.*?Failed\s+password\s+for.*?\d{2,}\s+time", re.I | re.S)),

    # Package manager unusual
    ("apt/yum install from suspicious URL",
     re.compile(r"(?:apt-get|yum|dnf|pacman)\s+install\s+.*?(?:https?://[^\s]+\.(?:tk|top|icu|xyz)|/tmp/)", re.I)),

    # Firewall modification
    ("iptables flush all rules",
     re.compile(r"iptables\s+(?:-F|--flush)(?:\s+.*)?\s*(?:$|#|&&)", re.I | re.M)),
    ("iptables allow C2 outbound",
     re.compile(r"iptables\s+.*?-A\s+OUTPUT.*?-d\s+\d{1,3}(?:\.\d{1,3}){3}.*?-j\s+ACCEPT", re.I)),

    # Bash history exfil
    ("bash history exfil",
     re.compile(r"\bcat\s+.*?~?/\.bash_history\b.*?(?:curl|wget|nc)", re.I | re.S)),

    # New user creation
    ("useradd with -o -u 0 (uid 0 backdoor)",
     re.compile(r"useradd\s+.*?-u\s+0\b|adduser\s+.*?-uid\s+0\b", re.I)),
]

# ──────────────────────────────────────────────────────────────────────
# macOS ATTACK PATTERNS
# ──────────────────────────────────────────────────────────────────────
# TIER 1 — LaunchDaemon persistence, TCC.db modification, quarantine
# bypass, KEXT loading of unsigned code.
_MACOS_TIER1_PATTERNS = [
    # LaunchDaemon / LaunchAgent persistence
    ("LaunchDaemon dropped in /Library/LaunchDaemons",
     re.compile(r"/Library/LaunchDaemons/[a-z0-9_.\-]+\.plist\b.*?(?:created|written|dropped|installed)", re.I | re.S)),
    ("LaunchAgent dropped in ~/Library/LaunchAgents",
     re.compile(r"(?:~|/Users/[^/]+)/Library/LaunchAgents/[a-z0-9_.\-]+\.plist\b.*?(?:created|written|dropped)", re.I | re.S)),
    ("launchctl load of unusual plist",
     re.compile(r"launchctl\s+load\s+.*?(?:/tmp/|/var/tmp/|/private/tmp/)", re.I)),

    # TCC.db bypass
    ("TCC.db direct modification (privacy bypass)",
     re.compile(r"/Library/Application Support/com\.apple\.TCC/TCC\.db\b.*(?:INSERT|UPDATE|modified|written)", re.I | re.S)),
    ("sqlite3 write to TCC.db",
     re.compile(r"sqlite3\s+.*?TCC\.db\s+.*?(?:INSERT|UPDATE|REPLACE)", re.I | re.S)),

    # Quarantine attribute stripped
    ("Gatekeeper bypass — quarantine xattr removed",
     re.compile(r"xattr\s+-d\s+com\.apple\.quarantine\b", re.I)),
    ("Gatekeeper disabled",
     re.compile(r"\bspctl\s+--master-disable\b", re.I)),

    # Unsigned KEXT load
    ("KEXT load without valid signature",
     re.compile(r"kextload\s+.*?(?:/tmp/|/Users/[^/]+/Downloads/)", re.I)),
    ("kext-dev-mode / SIP disable",
     re.compile(r"csrutil\s+(?:disable|clear)\b|kext-dev-mode\s*=\s*1", re.I)),

    # osascript with suspicious payload
    ("osascript do shell script with base64",
     re.compile(r"osascript\s+-e\s+['\"].*?do\s+shell\s+script.*?base64", re.I | re.S)),
    ("osascript do shell script with curl/wget/nc",
     re.compile(r"osascript\s+-e\s+['\"].*?do\s+shell\s+script.*?(?:curl|wget|nc\s+-e)", re.I | re.S)),

    # macOS reverse shell
    ("macOS reverse shell (bash /dev/tcp)",
     re.compile(r"\bbash\s+-i\s*>\s*&\s*/dev/tcp/", re.I)),  # also caught in Linux

    # DYLD_INSERT_LIBRARIES — macOS equivalent of LD_PRELOAD
    ("DYLD_INSERT_LIBRARIES injection",
     re.compile(r"\bDYLD_INSERT_LIBRARIES\s*=\s*(?:['\"]?/tmp/|/var/tmp/|/Users/[^/]+/(?:Downloads|Library/LaunchAgents)/|['\"]?[^\s]+\.dylib)", re.I)),
    ("DYLD_INSERT_LIBRARIES targeting system binary",
     re.compile(r"DYLD_INSERT_LIBRARIES\s*=.*?/(?:Applications|System)/.*?\.app/Contents/MacOS/", re.I)),

    # FileVault / firmware / SIP bypasses
    ("FileVault disabled",
     re.compile(r"\bfdesetup\s+disable\b", re.I)),
    ("Firmware password disabled",
     re.compile(r"\bfirmwarepasswd\s+-disable-firmware-pw\b", re.I)),

    # Persistence — existing LaunchDaemon plist replaced
    ("Existing LaunchDaemon plist ProgramArguments replaced",
     re.compile(r"/Library/LaunchDaemons/[a-z0-9_.\-]+\.plist\b.*?(?:ProgramArguments\s+changed|replaced|overwritten).*?/tmp/", re.I | re.S)),
    ("periodic script backdoor",
     re.compile(r"/etc/periodic/(?:daily|weekly|monthly)/[^/]+\b.*?(?:modified|written).*?(?:curl|wget|osascript|bash)", re.I | re.S)),
    ("Login items plist persistence",
     re.compile(r"~?/?Library/Preferences/com\.apple\.loginitems\.plist\b.*?(?:new\s+entry|added|written)", re.I | re.S)),

    # sudoers modification on macOS (also caught by Linux but explicit)
    ("macOS sudoers modification",
     re.compile(r"(?:echo\s+.*?NOPASSWD.*?>>|>>\s*)/etc/sudoers\b", re.I)),

    # Endpoint Security event exec from Downloads/Applications with no signature
    ("ES event exec from Downloads with no signature",
     re.compile(r"ES_EVENT_TYPE_NOTIFY_EXEC.*?/Downloads/.*?[Ss]igned\s*:\s*no", re.I | re.S)),
    ("ES event exec from tmp with unusual parent",
     re.compile(r"ES_EVENT_TYPE_NOTIFY_EXEC.*?/(?:tmp|private/tmp)/.*?(?:parent|from)\s*:?\s*sh\b", re.I | re.S)),

    # Authorization DB write to system.privilege.admin
    ("Authorization DB: system.privilege.admin modified",
     re.compile(r"authorizationdb\s+write\b.*?system\.privilege\.admin", re.I | re.S)),
]

# TIER 2 — corroborating macOS signals.
_MACOS_TIER2_PATTERNS = [
    # Persistence variants
    ("login hook installed",
     re.compile(r"defaults\s+write\s+com\.apple\.loginwindow\s+LoginHook", re.I)),
    ("logout hook installed",
     re.compile(r"defaults\s+write\s+com\.apple\.loginwindow\s+LogoutHook", re.I)),
    ("Cron persistence on macOS",
     re.compile(r"crontab\s+.*?(?:curl|wget|osascript|bash)", re.I | re.S)),

    # Authorization changes
    ("Authorization plist modification (rights removed)",
     re.compile(r"/etc/authorization\b.*?(?:modified|written)", re.I | re.S)),
    ("security authorizationdb modification",
     re.compile(r"security\s+authorizationdb\s+write\b", re.I)),

    # Detection notifications
    ("XProtect / MRT match logged",
     re.compile(r"\b(?:XProtect|MRT|MRTAgent)\b.*?(?:detected|blocked|found|remediated)", re.I | re.S)),
    ("Gatekeeper blocked signed cert revoked",
     re.compile(r"Gatekeeper.*?(?:signature\s+invalid|developer\s+ID\s+revoked)", re.I | re.S)),

    # Endpoint Security Framework events
    ("ES event: ES_EVENT_TYPE_NOTIFY_EXEC unusual",
     re.compile(r"ES_EVENT_TYPE_NOTIFY_EXEC.*?(?:/tmp/|/private/tmp/|/Users/[^/]+/Downloads/)", re.I)),

    # Application bundle in unusual location
    ("app bundle created in /tmp",
     re.compile(r"/(?:tmp|private/tmp)/[a-z0-9_.\-]+\.app\b", re.I)),

    # Sandbox escape / entitlement abuse
    ("codesign check bypass",
     re.compile(r"codesign\s+.*?--force.*?--sign\s+-\s+", re.I)),

    # Suspicious osascript execution
    ("osascript spawned by unusual parent",
     re.compile(r"parent\s*:\s*(?:Preview|Safari|Terminal|iTerm|Mail).*?osascript", re.I | re.S)),

    # Common macOS malware families
    ("named macOS malware family",
     re.compile(r"\b(?:XLoader|Silver\s*Sparrow|Shlayer|OSAMiner|CDDS|Bundlore|XcodeSpy|iWebUpdate|CookieMiner|CrescentCore)\b", re.I)),
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
    # NOTE: bare "Microsoft Defender" / "Windows Defender Antivirus"
    # removed as broad downweight patterns — the log source being
    # Defender doesn't mean the alert is benign. Defender frequently
    # LOGS threat detections. The specific benign markers
    # (Threat Status: Remediated, ActionSuccess: true, Defender has
    # removed) below stay in the list — those are true benign signals.
    re.compile(r"\bWindows\s+Update\b", re.I),
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
    # Common RMM tools — LOLBAS/vendor process names + install paths.
    # These are legitimate remote-management platforms that trigger
    # Defender behavior detections (OpenProcess, remote script exec)
    # in the course of normal operation. False positives when
    # observed inside their own install directory.
    re.compile(r"\\CentraStage\\CagService\.exe", re.I),  # Datto RMM (was CentraStage)
    re.compile(r"\bCentraStage\b", re.I),
    re.compile(r"\bCagService\.exe\b", re.I),
    re.compile(r"\bConnectWise\s+(?:Automate|Control|ScreenConnect)\b", re.I),
    re.compile(r"\\LabTech\\", re.I),  # ConnectWise Automate old name
    re.compile(r"\bLTS(?:vcMon|ervice)\.exe\b", re.I),
    re.compile(r"\bScreenConnect(?:\.exe|\.WindowsClient\.exe|\.WindowsBackstageShell\.exe)?\b", re.I),
    re.compile(r"\bNinja(?:One|RMM)(?:Agent(?:Patcher)?)?\b", re.I),
    re.compile(r"\bNinjaRMMAgent\.exe\b", re.I),
    re.compile(r"\bN-?able\b", re.I),
    re.compile(r"\bN-?central\b", re.I),
    re.compile(r"\bWindows_Agent\.exe\b", re.I),   # N-able generic
    re.compile(r"\bKaseya\s+VSA\b", re.I),
    re.compile(r"\\Kaseya\\", re.I),
    re.compile(r"\bAgentMon\.exe\b", re.I),
    re.compile(r"\bKaVSMB\.exe\b", re.I),
    re.compile(r"\bAteraAgent\.exe\b", re.I),
    re.compile(r"\\ATERA Networks\\", re.I),
    re.compile(r"\bPCMonitor(?:Srv|Manager)?\.exe\b", re.I),   # Pulseway
    re.compile(r"\bPulseway\b", re.I),
    re.compile(r"\bITSMAgent\b", re.I),   # ITarian / Comodo One
    re.compile(r"\bComodo\s+One\b", re.I),
    re.compile(r"\bSolarWinds\s+(?:RMM|MSP\s+Anywhere|N-central|Take\s+Control)\b", re.I),
    re.compile(r"\bImmyAgent\b|\bImmyBot\b", re.I),
    re.compile(r"\bSyncroAgent\.exe\b|\bSyncroMSP\b", re.I),
    re.compile(r"\bLevel\.io\b|\blevel-service\b", re.I),
    re.compile(r"\bAction1\s+(?:Corporation|Agent)\b", re.I),
    re.compile(r"\bAeroAdmin\.exe\b|\bAeroAdmin\b", re.I),
    re.compile(r"\bTeamViewer(?:_Service)?\.exe\b", re.I),
    re.compile(r"\bAnyDesk\.exe\b", re.I),
    re.compile(r"\bLogMeIn\b", re.I),
    re.compile(r"\bGoToAssist\b", re.I),
    re.compile(r"\bBomgar\b|\bBeyondTrust\s+Remote\s+Support\b", re.I),
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
    # Security vendor signing certs
    re.compile(r"o=threatlocker\s+inc\b", re.I),
    re.compile(r"cn=windows\s+core,\s+o=threatlocker", re.I),
    re.compile(r"cn=crowdstrike\s+holdings", re.I),
    re.compile(r"o=sentinelone\s+inc\b", re.I),
    re.compile(r"o=carbon\s+black\b", re.I),
    re.compile(r"o=vmware,?\s+inc\b", re.I),
    re.compile(r"o=cisco\s+systems", re.I),
    re.compile(r"o=palo\s+alto\s+networks", re.I),
    # Breach and Attack Simulation (BAS) platforms — vendor tools that
    # legitimately drop and execute simulated malware on customer
    # endpoints to test detection efficacy. Defender catching the
    # simulated payload is the TEST SUCCEEDING, not a real threat.
    re.compile(r"\bPicus\s+(?:Security|Simulator|Simulation\s+Agent)\b", re.I),
    re.compile(r"\bAttackIQ\b", re.I),
    re.compile(r"\bSafeBreach\b", re.I),
    re.compile(r"\bCymulate\b", re.I),
    re.compile(r"\bXM\s+Cyber\b", re.I),
    re.compile(r"\bRandori\s+(?:Attack|Recon)\b", re.I),
    re.compile(r"\bMandiant\s+Security\s+Validation\b", re.I),
    re.compile(r"\bVerodin\b", re.I),
    re.compile(r"\bPentera\b", re.I),
    re.compile(r"\bAtomicRedTeam\b|\batomic-red-team\b", re.I),
    # Simulation path markers — combined with a BAS vendor these
    # strongly signal authorized testing.
    re.compile(r"\\Picus\s+Security\\", re.I),
    re.compile(r"\\Simulations?\\Simulation_\d+", re.I),
    re.compile(r"\\BAS\s+Agent\\|/BAS/Agent/", re.I),
    re.compile(r"\\Attack\s+Simulation\\", re.I),
    # ThreatLocker built-in policy — vetted by the vendor's trust team
    re.compile(r"\bPolicy Name\s*:.*\(Built-In\)", re.I),
    re.compile(r"\(Built-In\)\s*$", re.I | re.M),
    # Defender routine remediation — malware detection with confirmed
    # removal is a resolved event, not an active compromise. BUT only
    # when the action ACTUALLY succeeded — a "Quarantine" line with an
    # Error Code means the file is still on disk and this is NOT
    # benign. The downweight list is filtered by the "action failed"
    # TIER 2 check below so a failed remediation doesn't slip through.
    re.compile(r"\bThreat\s+Status\s*:\s*Remediated\b", re.I),
    re.compile(r"\bActionSuccess\s*:\s*true\b", re.I),
    re.compile(r"\bDefender\s+has\s+removed\b", re.I),
    # Successful Defender remediation event (1117 shape) — Action:
    # Quarantine + Error Code: 0x00000000 + "The operation completed
    # successfully". This is Defender confirming it removed the file.
    re.compile(r"\bError\s+Code\s*:\s*0x0+\b.*?\boperation\s+completed\s+successfully\b", re.I | re.S),
    re.compile(r"\bAction\s*:\s*Quarantine\b.*?\boperation\s+completed\s+successfully\b", re.I | re.S),
    # File in RECYCLE.BIN — the artefact is already deleted by the user
    # or a prior cleanup pass, so a Defender scan finding it there is
    # low-signal noise (routine trash scanning). Only fires as
    # downweight; doesn't override a real active-threat marker.
    re.compile(r"\$RECYCLE\.BIN\\S-1-5-21-\d+-\d+-\d+-\d+\\", re.I),
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
    # BAS simulation detection: when the raw log contains a BAS vendor
    # + simulation path (Picus, AttackIQ, SafeBreach, Cymulate, XM
    # Cyber, Randori, etc.), any malware family detected IS the
    # simulation target. Defender catching it is a test-success signal,
    # not a real incident. Skip the TIER 1 malware-family attribution
    # in this context — the LLM investigation will still note the
    # detection, and the BAS pattern already fires as a downweight.
    _bas_markers = [
        r"\bPicus\s+(?:Security|Simulator|Simulation\s+Agent)\b",
        r"\bAttackIQ\b", r"\bSafeBreach\b", r"\bCymulate\b",
        r"\bXM\s+Cyber\b", r"\bRandori\s+(?:Attack|Recon)\b",
        r"\bMandiant\s+Security\s+Validation\b", r"\bVerodin\b",
        r"\bPentera\b", r"\bAtomicRedTeam\b|\batomic-red-team\b",
        r"\\Simulations?\\Simulation_\d+",
        r"\\BAS\s+Agent\\|/BAS/Agent/",
        r"\\Attack\s+Simulation\\",
    ]
    _is_bas_sim = any(re.search(p, log_text, re.I) for p in _bas_markers)
    if fam and not _is_bas_sim:
        # Only fire TIER 1 for real malware families (LockBit, Emotet,
        # TrickBot, etc.). Microsoft's PUA / HackTool / Adware / Tool /
        # Bundler prefixes are unwanted-software categorizations, not
        # traditional malware families — those cases are already caught
        # at TIER 2 by the Defender detection patterns.
        _pua_prefixes = ("pua:", "puabundler:", "hacktool:", "tool:",
                          "adware:", "bundler:", "misleading:", "riskware:")
        _fam_lower = fam.lower()
        if not any(_fam_lower.startswith(p) for p in _pua_prefixes):
            _push(tier_1, "named malware family attributed",
                  f"family={fam}")
        else:
            # Skip the TIER 2 PUA-family-attributed signal if the same
            # detection is going to fire via the `Name : <prefix>:`
            # Defender pattern — otherwise a single PUA event fires
            # both signals and over-triages via the 2-TIER-2 rule.
            _has_name_prefix_in_log = bool(re.search(
                r"\bName\s*:\s*(?:HackTool|PUA(?:Bundler)?|Trojan|Backdoor|Ransom|Behavior|Adware|Riskware)\s*:",
                log_text, re.I,
            ))
            if not _has_name_prefix_in_log:
                _push(tier_2, "PUA / HackTool family attributed",
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

    # Windows AD / Kerberos / CVE exploitation / security-tooling
    # tampering — TIER 1 verdict-determining Windows attacks.
    for name, rx in _WIN_AD_TIER1_PATTERNS:
        m = rx.search(log_text)
        if m:
            _push(tier_1, f"Windows: {name}",
                  f"matched '{m.group(0)[:80]}'")
            break

    # Impacket smbexec / atexec / wmiexec signature — the ADMIN$ share
    # output redirect with `__<epoch>.<frac>` file naming is unmistakable.
    # Zero legit Windows admin activity uses this pattern; it's Impacket's
    # method of capturing command output for remote execution modules.
    _impacket_patterns = [
        # cmd.exe /Q /c <cmd> 1> \\<ip>\ADMIN$\__<epoch>.<frac> 2>&1
        (r"cmd(?:\.exe)?\s+/Q\s+/c\s+.*?1>\s*\\\\[^\\]+\\ADMIN\$\\__\d+\.\d+", "Impacket smbexec/atexec/wmiexec pattern"),
        (r"\\\\[^\\]+\\ADMIN\$\\__\d+\.\d+", "Impacket ADMIN$ output-capture file"),
        # Impacket-generated service naming (BTOBTO / atexec)
        (r"\bImpacket\b.*(?:atexec|smbexec|wmiexec|psexec\.py)", "Impacket toolkit reference"),
    ]
    for pat, name in _impacket_patterns:
        if re.search(pat, log_text, re.I):
            _push(tier_1, name, f"Impacket signature in raw log")
            break

    # Extra cloud attack patterns beyond the critical set.
    for name, rx in _CLOUD_ATTACK_TIER1_EXTRA:
        m = rx.search(log_text)
        if m:
            _push(tier_1, f"Cloud: {name}",
                  f"matched '{m.group(0)[:80]}'")
            break

    # Linux TIER 1 — reverse shell, container escape, kernel rootkit,
    # LD_PRELOAD, log tampering, passwd/shadow write, cryptominer.
    for name, rx in _LINUX_TIER1_PATTERNS:
        m = rx.search(log_text)
        if m:
            _push(tier_1, f"Linux: {name}",
                  f"matched '{m.group(0)[:80]}'")
            break

    # `curl | bash` / `wget | sh` — download-and-execute of unverified
    # remote code. Textbook malicious pattern regardless of platform.
    # Was TIER 2; promoted to TIER 1 because MONITOR verdict from AI
    # was under-triaging what is unambiguously an execution primitive.
    if re.search(r"(?:curl|wget)\s+(?:-[a-z]+\s+)*(?:https?://)?[^\s|]+\s*\|\s*(?:bash|sh|zsh|python)",
                 log_text, re.I):
        _push(tier_1, "download-and-execute (curl|bash pattern)",
              "unverified remote code piped to shell")

    # macOS TIER 1 — LaunchDaemon/Agent persistence, TCC.db bypass,
    # Gatekeeper bypass, unsigned KEXT load, osascript exec.
    for name, rx in _MACOS_TIER1_PATTERNS:
        m = rx.search(log_text)
        if m:
            _push(tier_1, f"macOS: {name}",
                  f"matched '{m.group(0)[:80]}'")
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

    # Linux TIER 2 — auditd EXECVE, SELinux AVC, systemd/cron
    # persistence, SSH tunneling, sudo abuse, Docker socket exposure,
    # K8s privileged pod, fail2ban, package manager, iptables mods,
    # bash history exfil, useradd uid=0.
    for name, rx in _LINUX_TIER2_PATTERNS:
        m = rx.search(log_text)
        if m:
            _push(tier_2, f"Linux: {name}",
                  f"matched '{m.group(0)[:80]}'")
            break

    # macOS TIER 2 — login/logout hooks, cron, authorization plist,
    # XProtect/MRT, Endpoint Security, macOS malware families.
    for name, rx in _MACOS_TIER2_PATTERNS:
        m = rx.search(log_text)
        if m:
            _push(tier_2, f"macOS: {name}",
                  f"matched '{m.group(0)[:80]}'")
            break

    # Defender successful remediation — Error Code: 0x00000000 with
    # "operation completed successfully" text means Defender caught
    # AND removed the threat. The severity/family info in the log
    # represents Defender's PRE-remediation assessment; after
    # successful quarantine, the file is neutralized. Skip the whole
    # Defender-detection TIER 2 block so a resolved event doesn't
    # force ESCALATE via the 2-TIER-2 rule.
    _defender_success = bool(re.search(
        r"\bError\s+Code\s*:\s*0x0+\b.*?\boperation\s+completed\s+successfully\b",
        log_text, re.I | re.S
    ) or re.search(r"\bAction\s*Status\s*:\s*No\s+additional\s+actions\s+required\b.*?\bError\s+Code\s*:\s*0x0+\b",
                   log_text, re.I | re.S))

    # Vendor + behavior context — computed early so both the family
    # detection block AND the severity block can consult it. Defender
    # Behavior:Win32/... detections are notoriously FP-prone on
    # legitimate management tools (RMM agents, EDRs, backup software).
    _has_known_good_vendor = any(rx.search(log_text) for rx in _KNOWN_GOOD_VENDOR_PATTERNS)
    _is_behavior_only = bool(re.search(r"\bName\s*:\s*Behavior\s*:", log_text, re.I))
    _behavior_fp_context = _has_known_good_vendor and _is_behavior_only

    # Defender AV detection — HackTool / PUA / Trojan / failed
    # remediation. The patterns split into three semantic groups; we
    # fire at most ONE signal per group to prevent double-counting on
    # a single detection event (which was over-triaging low-severity
    # PUAs). Skipped entirely on successful remediation events.
    #
    # Group A — the family detection (Name: prefix + generic form
    #           are two ways to detect the same thing)
    # Group B — action / remediation outcome
    # Group C — severity marker
    if not _defender_success:
        _det_family_pats = [
            ("Defender HackTool detection",       r"\bName\s*:\s*HackTool\s*:", ),
            ("Defender PUA / PUABundler detection", r"\bName\s*:\s*PUA(?:Bundler)?\s*:", ),
            ("Defender Trojan detection",         r"\bName\s*:\s*Trojan\s*:", ),
            ("Defender Backdoor detection",       r"\bName\s*:\s*Backdoor\s*:", ),
            ("Defender Ransom detection",         r"\bName\s*:\s*Ransom\s*:", ),
            ("Defender Behavior detection",       r"\bName\s*:\s*Behavior\s*:", ),
            ("Defender Adware detection",         r"\bName\s*:\s*Adware\s*:", ),
            ("Defender Riskware detection",       r"\bName\s*:\s*Riskware\s*:", ),
            ("Defender Exploit detection",        r"\bName\s*:\s*Exploit\s*:", ),
            ("Defender Worm detection",           r"\bName\s*:\s*Worm\s*:", ),
            ("Defender Spyware detection",        r"\bName\s*:\s*Spyware\s*:", ),
            ("Defender VirTool detection",        r"\bName\s*:\s*VirTool\s*:", ),
            ("Defender Constructor detection",    r"\bName\s*:\s*Constructor\s*:", ),
            ("Defender DoS detection",            r"\bName\s*:\s*DoS\s*:", ),
            ("Defender Dropper detection",        r"\bName\s*:\s*(?:Dropper|TrojanDropper)\s*:", ),
            ("Defender Downloader detection",     r"\bName\s*:\s*(?:Downloader|TrojanDownloader)\s*:", ),
            ("HackTool / PUA family name in log", r"\b(?:HackTool|PUA|PUABundler|Backdoor|Ransom|Trojan|Exploit|Adware|Riskware|Worm|Spyware|Behavior|VirTool|Constructor|DoS|Dropper|Downloader|TrojanDropper|TrojanDownloader)\s*:\s*(?:Script|Win\d\d|MSIL|VBS|JS|HTML|Linux|OSX|MacOS)/", ),
        ]
        # Defender's heuristic BEHAVIOR detections (Behavior:Win32/...)
        # are notoriously FP-prone on legitimate management tools —
        # RMM agents, EDRs, backup software all trigger them via
        # legit OpenProcess / ReadProcessMemory calls. When the log
        # ALSO carries a known-good vendor marker (CentraStage, Datto,
        # ConnectWise, NinjaOne, Kaseya, Atera, ThreatLocker,
        # CrowdStrike, SentinelOne, etc.), suppress the Behavior
        # family + severity signals. Real malware behavior detections
        # without vendor context still fire normally.
        if _behavior_fp_context:
            # Skip both the family and severity signals for this event.
            # Vendor downweight + LLM investigation handles verdict.
            _det_family_pats = []
        for name, pat in _det_family_pats:
            m = re.search(pat, log_text, re.I)
            if m:
                _push(tier_2, name, f"matched '{m.group(0)[:80]}'")
                break   # only ONE family-detection signal fires

    _det_action_pats = [
        ("Defender action failed — Error Code present",
         r"\bAction\s*:\s*Quarantine\b.*?\bError\s+Code\s*:\s*0x[0-9a-f]+"),
        ("Defender ActionSuccess: false",
         r"\bActionSuccess\s*:\s*false\b"),
        ("Defender error 0x800700df (file too large to quarantine)",
         r"\b0x800700df\b"),
    ]
    # Only fire action-failure signals when the error code is NON-zero.
    # Error Code 0x00000000 = success — the file WAS quarantined and
    # the log's "Action Status: No additional actions required" is
    # accurate. This suppresses false ESCALATE on Defender remediated
    # events (event 1117).
    _has_success_code = bool(re.search(r"\bError\s+Code\s*:\s*0x0+\b|\bthe\s+operation\s+completed\s+successfully\b",
                                       log_text, re.I))
    if not _has_success_code:
        for name, pat in _det_action_pats:
            m = re.search(pat, log_text, re.I | re.S)
            if m:
                _push(tier_2, name, f"matched '{m.group(0)[:80]}'")
                break   # only ONE action-outcome signal fires

    if not _defender_success and not _behavior_fp_context:
        _det_severity_pats = [
            ("Defender Severity: Severe detection",
             r"\bSeverity\s*:\s*Severe\b"),
            ("Defender Severity: High detection",
             r"\bSeverity\s*:\s*High\b.*?\b(?:HackTool|PUA|PUABundler|Trojan|Backdoor|Ransom|Adware|Riskware|Worm|Spyware|Exploit|Behavior)\s*:"),
        ]
        for name, pat in _det_severity_pats:
            m = re.search(pat, log_text, re.I | re.S)
            if m:
                _push(tier_2, name, f"matched '{m.group(0)[:80]}'")
                break   # only ONE severity signal fires

    otx_ge_5 = False
    for _t, ioc, p in _iter_ioc_enrichments(state):
        otx = p.get("otx") or {}
        if isinstance(otx, dict) and (otx.get("pulseCount") or otx.get("pulse_count") or 0) >= 5:
            _push(tier_2, "AlienVault OTX ≥5 community pulses on IOC",
                  f"IOC={ioc}")
            otx_ge_5 = True
            break

    # LOLBAS binary-name hit alone is TIER 3 context, NOT abuse — reg.exe /
    # rundll32 / mshta ARE frequently used legitimately by admin tools and
    # signed vendor agents. The actual abuse signature (mshta javascript:,
    # regsvr32 /i:http, rundll32 javascript:, certutil -urlcache, etc.) is
    # handled by _LOLBAS_ABUSE_PATTERNS above with proper TIER 2 semantics.
    if (cross.get("lolbas") or []):
        _push(tier_3, "LOLBAS binary invoked (context only)",
              f"{len(cross['lolbas'])} LOLBins present in raw text")
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
        # Linux attack markers
        r"\bbash\s+-i\s*>\s*&\s*/dev/tcp/",
        r"\bnc(?:at)?\s+-e\s+/bin/(?:sh|bash)",
        r"\bLD_PRELOAD\s*=\s*(?:/tmp/|/dev/shm/)",
        r"\binsmod\s+.*?\.ko",
        r"/var/run/docker\.sock",
        r"\bprivileged\s*:\s*true",
        r"\b(?:xmrig|cpuminer)\b",
        r"\bcurl\s+[^\s|]+\s*\|\s*bash\b",
        r"\bavc:\s+denied",
        # macOS attack markers
        r"/Library/LaunchDaemons/[a-z0-9_.\-]+\.plist",
        r"\bTCC\.db\b.*(?:INSERT|UPDATE)",
        r"\bxattr\s+-d\s+com\.apple\.quarantine",
        r"\bcsrutil\s+disable",
        r"\bosascript\s+.*?do\s+shell\s+script",
        r"\bDYLD_INSERT_LIBRARIES\s*=",
        r"\bfdesetup\s+disable",
        r"/etc/periodic/.*(?:modified|written)",
        # Windows AD attacks
        r"\bkerberoast",
        r"\bAS[-_ ]REP\s+roast",
        r"\bgolden\s+ticket",
        r"\bDCSync\b",
        r"\bzerologon\b|\bCVE-2020-1472\b",
        r"\bprintnightmare\b|\bCVE-2021-34527\b",
        r"\bfollina\b|\bms-msdt\b",
        r"\$\{jndi\s*:",
        r"Set-MpPreference\s+.*?-Disable",
        r"(?:net\s+stop|Stop-Service)\s+.*?sysmon",
        r"\bmanage-bde\s+.*?-disable",
        r"__InstanceModificationEvent",
        # Linux additions
        r"authorized_keys\b.*?(?:new\s+ssh\s+key|added)",
        r"pam_permit\.so",
        r"/etc/ld\.so\.preload",
        r"NOPASSWD.*>>\s*/etc/sudoers",
        r"~?/\.(?:bashrc|profile|zshrc).*?curl",
        r"\bjournalctl\s+--vacuum",
        r"rsyslog\.conf.*?\*\.\*\s+@@?\d",
        r"\bmeterpreter\b",
        r"\bmetasploit\b",
        r"\bfind\s+\S+.*?-exec\s+.*?(?:sh|bash)\s+-p",
        r"docker\s+run\s+.*?--cap-add\s*=?\s*ALL",
        r"docker\s+run\s+.*?-v\s+/:/host",
        r"docker\s+run\s+.*?--(?:pid|network|ipc|uts)=host",
        r"iptables\s+.*?-[AI]\s+(?:OUTPUT|FORWARD).*?-j\s+ACCEPT",
        # Cloud additions
        r"GetSecretValue\s+.*?in\s+\d+\s+min",
        r"Conditional\s+Access\s+policy\s+disabled",
        r"roles?/(?:owner|editor|iam\.securityAdmin|iam\.roleAdmin)\s+granted",
        r"O365.*?forwarding\s+rule.*?forward",
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
