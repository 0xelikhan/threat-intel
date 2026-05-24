"""
Behavioral / TTP extractor — spec §1.

Pre-enrichment regex + pattern matching against raw log input. Surfaces
behavioral indicators that won't show up in IOC-based enrichment (PowerShell
encoded commands, LOLBin abuse, persistence mechanisms, lateral-movement
patterns, credential-access tradecraft, C2 communication tells) and maps each
to the most specific MITRE ATT&CK technique it represents.

Returns one structured dict per category with:
  - name:         human label for the pattern
  - match:        the snippet that matched (truncated)
  - mitre:        Txxxx[.yyy] technique id
  - mitre_name:   technique name resolved from enterprise-attack.json when present
  - severity:     LOW | MEDIUM | HIGH | CRITICAL
  - explanation:  plain-English 1-sentence why-it's-suspicious

Wired into triage.py via extract_behavioral_indicators(raw, decoded_b64).
"""

from __future__ import annotations
import re
import base64
from functools import lru_cache
from typing import List, Dict, Optional

# ─── MITRE technique name lookup ────────────────────────────────────────────────
@lru_cache(maxsize=1)
def _mitre_name_index() -> Dict[str, str]:
    try:
        from intel.mitre_data import get_all_techniques
        return {t["id"]: t["name"] for t in get_all_techniques() or []}
    except Exception:
        return {}


def _mitre_name(tid: str) -> Optional[str]:
    return _mitre_name_index().get(tid)


# ─── Pattern table ──────────────────────────────────────────────────────────────
# Each entry: (regex, category, name, mitre, severity, explanation)
# Categories: powershell, lolbin, persistence, lateral, credentials, c2
_PATTERNS = [
    # ── PowerShell ─────────────────────────────────────────────────────────────
    (re.compile(r"-(?:enc|encoded|encodedcommand)\s+[a-zA-Z0-9+/=]{16,}", re.IGNORECASE),
     "powershell", "PowerShell EncodedCommand", "T1059.001", "HIGH",
     "Base64-encoded PowerShell payload — common technique to obfuscate malicious commands and evade simple string-based detection."),
    (re.compile(r"-(?:ep|executionpolicy)\s+bypass", re.IGNORECASE),
     "powershell", "PowerShell -ExecutionPolicy Bypass", "T1059.001", "MEDIUM",
     "Bypasses PowerShell's execution policy to allow unsigned scripts to run; benign admin tools rarely need this."),
    (re.compile(r"-windowstyle\s+hidden", re.IGNORECASE),
     "powershell", "PowerShell -WindowStyle Hidden", "T1564.003", "MEDIUM",
     "Hides the PowerShell window from the user — strong indicator of stealth execution."),
    (re.compile(r"-noninteractive", re.IGNORECASE),
     "powershell", "PowerShell -NonInteractive", "T1059.001", "LOW",
     "Suppresses interactive prompts; often combined with other obfuscation flags in automated attacks."),
    (re.compile(r"(?:iex|invoke-expression)\s*\(", re.IGNORECASE),
     "powershell", "PowerShell IEX download cradle", "T1059.001", "HIGH",
     "Dynamically evaluates a string as code — classic download-and-execute cradle."),
    (re.compile(r"downloadstring\s*\(", re.IGNORECASE),
     "powershell", "WebClient.DownloadString", "T1105", "HIGH",
     "Fetches remote content over HTTP and returns it as a string — typically chained with IEX to execute."),
    (re.compile(r"downloadfile\s*\(", re.IGNORECASE),
     "powershell", "WebClient.DownloadFile", "T1105", "HIGH",
     "Downloads a file to disk — used for staging second-stage payloads."),
    (re.compile(r"new-object\s+(?:net\.)?webclient", re.IGNORECASE),
     "powershell", "New-Object Net.WebClient", "T1105", "MEDIUM",
     "Constructs a WebClient — typically the first step of a download cradle."),
    (re.compile(r"\[ref\]\.assembly\.gettype\(.{0,80}amsi", re.IGNORECASE),
     "powershell", "AMSI bypass via reflection", "T1562.001", "CRITICAL",
     "Reflectively patches the Anti-Malware Scan Interface to silence detection — strong attacker signal."),
    (re.compile(r"amsiscanbuffer", re.IGNORECASE),
     "powershell", "AMSI bypass — AmsiScanBuffer patch", "T1562.001", "CRITICAL",
     "Targets the AmsiScanBuffer function to bypass AV inspection of in-memory PowerShell."),
    (re.compile(r"\[reflection\.assembly\]::load\(", re.IGNORECASE),
     "powershell", "Reflective Assembly Load", "T1620", "HIGH",
     "Loads a .NET assembly directly from memory — bypasses disk-based EDR scanning."),

    # ── Windows LOLBin abuse ───────────────────────────────────────────────────
    (re.compile(r"certutil\s+(?:-urlcache|-decode|-decodehex|-f|-split)", re.IGNORECASE),
     "lolbin", "certutil download / decode", "T1140", "HIGH",
     "certutil.exe abused to download remote files or decode base64 payloads — not normal admin use."),
    (re.compile(r"bitsadmin\s+/transfer", re.IGNORECASE),
     "lolbin", "bitsadmin /transfer", "T1197", "HIGH",
     "BITS service abuse to silently download payloads; persists across reboots."),
    (re.compile(r"mshta(?:\.exe)?\s+(?:https?://|vbscript:|javascript:)", re.IGNORECASE),
     "lolbin", "mshta executing remote content", "T1218.005", "CRITICAL",
     "mshta.exe running scripts directly from URLs or inline — signature LOLBin technique."),
    (re.compile(r"regsvr32\s+(?:/s\s+)?(?:/n\s+)?(?:/u\s+)?/i:\s*[\w:/\\.]+\s+scrobj\.dll", re.IGNORECASE),
     "lolbin", "regsvr32 scrobj.dll squiblydoo", "T1218.010", "CRITICAL",
     "'Squiblydoo' technique — regsvr32 executing remote scriptlets via scrobj.dll to bypass app whitelisting."),
    (re.compile(r"rundll32\s+(?!.*\\(?:system32|syswow64))[\w:/\\.]+\s*,\s*\w+", re.IGNORECASE),
     "lolbin", "rundll32 executing non-system DLL", "T1218.011", "HIGH",
     "rundll32 invoking a DLL outside system directories — common malware loader pattern."),
    (re.compile(r"(?:wscript|cscript)\s+(?:https?://|//\S+)", re.IGNORECASE),
     "lolbin", "wscript/cscript executing remote file", "T1059.005", "HIGH",
     "Windows Script Host executing remote VBS/JS — bypasses many EDRs that focus on PowerShell."),
    (re.compile(r"schtasks\s+/create", re.IGNORECASE),
     "lolbin", "schtasks /create — task scheduler", "T1053.005", "MEDIUM",
     "Scheduled task creation is a common persistence vector — verify the binary it launches."),
    (re.compile(r"wmic\s+process\s+call\s+create", re.IGNORECASE),
     "lolbin", "wmic process call create", "T1047", "HIGH",
     "WMI process creation often used for fileless lateral movement and persistence."),
    (re.compile(r"msbuild(?:\.exe)?\s+[\w\\:/.]+\.csproj", re.IGNORECASE),
     "lolbin", "MSBuild executing inline tasks", "T1127.001", "HIGH",
     "MSBuild compiling C# inline at runtime to bypass application whitelisting."),
    (re.compile(r"installutil(?:\.exe)?\s+/logfile=\s+/logtoconsole=false\s+/u", re.IGNORECASE),
     "lolbin", "InstallUtil uninstall flag abuse", "T1218.004", "HIGH",
     "InstallUtil abused to execute uninstall code path that hosts arbitrary .NET."),

    # ── Persistence ────────────────────────────────────────────────────────────
    (re.compile(r"hkcu\\\\?software\\\\?microsoft\\\\?windows\\\\?currentversion\\\\?run", re.IGNORECASE),
     "persistence", "HKCU Run key", "T1547.001", "HIGH",
     "Registry Run key launches the value at every logon — most common Windows persistence."),
    (re.compile(r"hklm\\\\?software\\\\?microsoft\\\\?windows\\\\?currentversion\\\\?run", re.IGNORECASE),
     "persistence", "HKLM Run key", "T1547.001", "HIGH",
     "HKLM Run key runs at every logon for any user; requires admin to write."),
    (re.compile(r"appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup", re.IGNORECASE),
     "persistence", "Startup folder drop", "T1547.001", "MEDIUM",
     "Files dropped here execute at user logon — classic persistence vector."),
    (re.compile(r"sc(?:\.exe)?\s+(?:create|config)\s+\S+\s+binpath=", re.IGNORECASE),
     "persistence", "sc.exe create/modify service", "T1543.003", "HIGH",
     "New Windows service installation — persists across reboots and may run as SYSTEM."),
    (re.compile(r"__eventfilter|__filtertoconsumerbinding|activescripteventconsumer|commandlineeventconsumer", re.IGNORECASE),
     "persistence", "WMI event subscription", "T1546.003", "CRITICAL",
     "WMI event subscription survives reboot and runs payloads on Windows events — favorite of APTs."),
    (re.compile(r"<schedulertask[^>]*>", re.IGNORECASE),
     "persistence", "Scheduled-task XML payload", "T1053.005", "MEDIUM",
     "Inline scheduled-task XML body — verify the action and trigger."),

    # ── Lateral movement ───────────────────────────────────────────────────────
    (re.compile(r"net\s+use\s+\\\\\\\\\S+\s+\S+\s+/user:", re.IGNORECASE),
     "lateral", "net use with credential", "T1021.002", "HIGH",
     "Mounting a remote SMB share with credentials — used for lateral movement."),
    (re.compile(r"psexec(?:\.exe)?\s+(?:\\\\\\\\)?\S+", re.IGNORECASE),
     "lateral", "PsExec remote execution", "T1569.002", "HIGH",
     "PsExec is widely abused for lateral movement — even legitimate use should be reviewed."),
    (re.compile(r"wmic\s+/node:\S+", re.IGNORECASE),
     "lateral", "WMIC /node remote execution", "T1047", "HIGH",
     "WMIC against a remote node — fileless lateral movement technique."),
    (re.compile(r"invoke-wmimethod\s+-computername\s+\S+", re.IGNORECASE),
     "lateral", "Invoke-WmiMethod remote", "T1047", "HIGH",
     "PowerShell WMI remote execution — favored for living-off-the-land lateral movement."),
    (re.compile(r"net\s+view\s+\\\\\\\\?\S*", re.IGNORECASE),
     "lateral", "net view SMB enumeration", "T1135", "MEDIUM",
     "Enumerating SMB shares — usually a discovery step preceding lateral movement."),

    # ── Credential access ──────────────────────────────────────────────────────
    (re.compile(r"sekurlsa::(?:logonpasswords|wdigest|tickets|kerberos)", re.IGNORECASE),
     "credentials", "Mimikatz sekurlsa::*", "T1003.001", "CRITICAL",
     "Mimikatz command extracting cleartext credentials from LSASS."),
    (re.compile(r"lsadump::(?:sam|secrets|lsa|dcsync)", re.IGNORECASE),
     "credentials", "Mimikatz lsadump::*", "T1003.002", "CRITICAL",
     "Mimikatz dumping SAM/LSA secrets — credential-access end state."),
    (re.compile(r"comsvcs\.dll.*minidump", re.IGNORECASE),
     "credentials", "comsvcs.dll MiniDump (LSASS)", "T1003.001", "CRITICAL",
     "Using comsvcs.dll to dump LSASS memory — fileless credential theft."),
    (re.compile(r"ntdsutil.*ifm", re.IGNORECASE),
     "credentials", "ntdsutil ifm — NTDS.dit copy", "T1003.003", "CRITICAL",
     "Creating an Install From Media set extracts the AD database — domain-wide credential theft."),
    (re.compile(r"reg\s+save\s+(?:hklm\\)?sam\s+\S+", re.IGNORECASE),
     "credentials", "reg save SAM hive", "T1003.002", "CRITICAL",
     "Exporting the SAM registry hive to file — offline cracking target."),
    (re.compile(r"dcsync\b|getncchanges|drsuapi", re.IGNORECASE),
     "credentials", "DCSync replication request", "T1003.006", "CRITICAL",
     "DCSync abuses domain replication to extract password hashes from a DC — requires Domain Admin or equivalent."),

    # ── C2 communication patterns ──────────────────────────────────────────────
    (re.compile(r"\b(?:dyndns|no-ip|duckdns|hopto|zapto|ddns)\.(?:org|net|com)\b", re.IGNORECASE),
     "c2", "Dynamic DNS host", "T1568.002", "HIGH",
     "Dynamic DNS provider — frequently used for C2 because IPs can rotate while the hostname is stable."),
    (re.compile(r"(?:[a-zA-Z0-9_-]{30,}\.){2,}[a-z]{2,10}", re.IGNORECASE),
     "c2", "Long subdomain (DNS exfil)", "T1071.004", "HIGH",
     "Unusually long subdomain labels suggest DNS-based data exfiltration or beaconing."),
    (re.compile(r"user-agent:\s*python-requests|user-agent:\s*curl|user-agent:\s*go-http-client", re.IGNORECASE),
     "c2", "Scripted User-Agent", "T1071.001", "MEDIUM",
     "Automated tooling User-Agent — rarely seen from end-user workstations."),
    (re.compile(r"\bbeacon(?:ing)?\b.*interval\s*[:=]?\s*\d+", re.IGNORECASE),
     "c2", "Beacon interval reference", "T1071.001", "HIGH",
     "Beacon interval terminology hints at Cobalt Strike or similar C2 framework."),
    (re.compile(r"port\s*[:=]?\s*(?:4444|8080|1080|8888|9001|9050)", re.IGNORECASE),
     "c2", "Known C2 / proxy port", "T1571", "MEDIUM",
     "Ports 4444/8080/1080/8888/9001/9050 are common defaults for C2 frameworks and proxies."),
]


# ─── Decoded-payload secondary scan ─────────────────────────────────────────────
_BASE64_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{40,}={0,2})\b")


def _decode_b64_candidates(text: str, max_decodes: int = 5) -> List[str]:
    """Try to base64-decode any long base64-ish string from the input — UTF-16LE
    common for PowerShell -EncodedCommand."""
    out = []
    for m in _BASE64_RE.findall(text)[:max_decodes]:
        for enc in ("utf-16le", "utf-8"):
            try:
                pad = "=" * (-len(m) % 4)
                decoded = base64.b64decode(m + pad).decode(enc, errors="ignore").strip()
                if len(decoded) > 4 and any(c.isprintable() for c in decoded):
                    out.append(decoded)
                    break
            except Exception:
                continue
    return out


# ─── public API ────────────────────────────────────────────────────────────────
def extract_behavioral_indicators(raw: str) -> Dict:
    """Spec §1 entry point. Returns categorized behavioral indicators with MITRE."""
    if not raw:
        return {"categories": {}, "total": 0, "decoded_payloads": [], "techniques": []}

    text_full = raw
    decoded = _decode_b64_candidates(raw)
    # Run patterns against decoded payloads too so EncodedCommand bodies get tagged
    haystacks = [("raw", text_full)] + [("decoded", d) for d in decoded]

    by_category: Dict[str, List[Dict]] = {}
    seen = set()
    for source, hay in haystacks:
        for pattern, category, name, mitre, severity, explanation in _PATTERNS:
            for m in pattern.finditer(hay):
                snippet = m.group(0)
                key = (category, name, snippet[:80].lower())
                if key in seen:
                    continue
                seen.add(key)
                by_category.setdefault(category, []).append({
                    "name":        name,
                    "match":       snippet[:200],
                    "source":      source,
                    "mitre":       mitre,
                    "mitre_name":  _mitre_name(mitre),
                    "severity":    severity,
                    "explanation": explanation,
                })

    techniques = sorted({h["mitre"] for hits in by_category.values() for h in hits})
    total = sum(len(v) for v in by_category.values())
    return {
        "categories":       by_category,
        "total":            total,
        "decoded_payloads": decoded[:5],
        "techniques":       techniques,
        "techniques_with_names": [
            {"id": t, "name": _mitre_name(t)} for t in techniques
        ],
    }
