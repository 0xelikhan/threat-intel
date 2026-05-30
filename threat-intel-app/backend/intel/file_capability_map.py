"""
Behavioral / MITRE ATT&CK mapping for static file findings — spec §3 of the
all-in-one scanner plan.

Takes a result dict produced by file_analyzer.analyze_file() and synthesizes:
  - capability_tags: short labels like 'Process Injection', 'Persistence',
    'Keylogging', 'Network C2', 'Anti-Debug', 'Crypto', 'Packed'
  - mitre_techniques: list of {id, name, tactic, evidence, explanation,
    attack_url} — each backed by a specific piece of evidence
  - plain_english_summary: 2-3 sentence narrative for a junior analyst
  - verdict: heuristic verdict before TI correlation
"""

from __future__ import annotations
from functools import lru_cache
from typing import Dict, List


@lru_cache(maxsize=1)
def _mitre_index() -> Dict[str, str]:
    """{technique_id: name} from enterprise-attack.json — uses the existing helper."""
    try:
        from intel.mitre_data import get_all_techniques
        return {t["id"]: t["name"] for t in get_all_techniques() or []}
    except Exception:
        return {}


def _t_name(tid: str) -> str:
    return _mitre_index().get(tid, tid)


def _attack_url(tid: str) -> str:
    return f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"


# Mapping table: (predicate fn, technique_id, capability_label, tactic, explanation)
# Each predicate takes the analyze_file result dict.
def _pe_imports_have(result: Dict, *funcs: str) -> bool:
    pe = (result.get("format_specific") or {}).get("pe") or {}
    flat = {fn for v in (pe.get("imports") or {}).values() for fn in v}
    return all(f in flat for f in funcs)


def _pe_any_import(result: Dict, *funcs: str) -> bool:
    pe = (result.get("format_specific") or {}).get("pe") or {}
    flat = {fn for v in (pe.get("imports") or {}).values() for fn in v}
    return any(f in flat for f in funcs)


def _has_sus_string(result: Dict, name: str) -> bool:
    for s in (result.get("suspicious_strings") or []):
        if s.get("pattern") == name:
            return True
    return False


def _has_office_pattern(result: Dict, name: str) -> bool:
    fs = (result.get("format_specific") or {}).get("office") or {}
    for s in (fs.get("suspicious_patterns") or []):
        if s.get("pattern") == name:
            return True
    return False


def _pe_has_section_flag(result: Dict, flag: str) -> bool:
    pe = (result.get("format_specific") or {}).get("pe") or {}
    for s in (pe.get("sections") or []):
        if flag in (s.get("flags") or []):
            return True
    return False


# (capability_label, technique_id, tactic, explanation, predicate)
_RULES = [
    # ── Process injection ────────────────────────────────────────────────────
    ("Process Injection", "T1055", "Defense Evasion",
     "Allocates memory in another process and writes/executes code there — classic process injection.",
     lambda r: _pe_imports_have(r, "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread") or
               _pe_imports_have(r, "NtUnmapViewOfSection", "WriteProcessMemory")),
    # ── PowerShell encoded execution ─────────────────────────────────────────
    ("Encoded PowerShell", "T1059.001", "Execution",
     "Contains base64-encoded PowerShell — typical command obfuscation.",
     lambda r: _has_sus_string(r, "powershell_encoded_cmd") or _has_sus_string(r, "base64_powershell") or
               _has_office_pattern(r, "PowerShell")),
    # ── WMI ──────────────────────────────────────────────────────────────────
    ("WMI", "T1047", "Execution",
     "Calls WMI APIs — commonly abused for fileless lateral movement.",
     lambda r: _pe_any_import(r, "CoCreateInstance") and "WMI" in str((r.get("strings") or {}).get("ascii_sample", []))),
    # ── Registry persistence ─────────────────────────────────────────────────
    ("Registry Persistence", "T1547.001", "Persistence",
     "References registry Run keys — startup persistence on Windows.",
     lambda r: _has_sus_string(r, "registry_run_key")),
    # ── Scheduled task ───────────────────────────────────────────────────────
    ("Scheduled Task", "T1053.005", "Persistence",
     "Creates scheduled tasks — durable persistence vector.",
     lambda r: _has_sus_string(r, "scheduled_task")),
    # ── Keylogging ───────────────────────────────────────────────────────────
    ("Keylogging", "T1056.001", "Collection",
     "Uses keyboard-state APIs — likely keylogger.",
     lambda r: _pe_any_import(r, "GetAsyncKeyState", "GetKeyState", "SetWindowsHookExA", "SetWindowsHookExW")),
    # ── Network download ─────────────────────────────────────────────────────
    ("Network Download", "T1105", "Command and Control",
     "Calls download APIs — retrieves second-stage payloads from the network.",
     lambda r: _pe_any_import(r, "URLDownloadToFile", "URLDownloadToFileA", "URLDownloadToFileW",
                                  "InternetOpenUrl", "InternetOpenUrlA", "InternetOpenUrlW") or
               _has_sus_string(r, "download_cradle")),
    # ── Anti-debug ───────────────────────────────────────────────────────────
    ("Anti-Debug", "T1497", "Defense Evasion",
     "Contains debugger / sandbox detection APIs — may behave differently when analyzed.",
     lambda r: _pe_any_import(r, "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                                  "NtQueryInformationProcess", "OutputDebugStringA",
                                  "OutputDebugStringW")),
    # ── Packed ───────────────────────────────────────────────────────────────
    ("Packed / Obfuscated", "T1027", "Defense Evasion",
     "Sections have high entropy — file is likely packed or encrypted to evade static AV.",
     lambda r: (r.get("entropy") or {}).get("flag") in ("high_entropy_packed",) or
               _pe_has_section_flag(r, "high_entropy")),
    # ── DLL search-order ─────────────────────────────────────────────────────
    ("DLL Search-Order Hijack", "T1574.001", "Persistence / Defense Evasion",
     "Imports DLLs by name without explicit path — vulnerable to or used in search-order hijacking.",
     lambda r: bool((r.get("format_specific") or {}).get("pe", {}).get("imports"))),
    # ── Credential dumping ───────────────────────────────────────────────────
    ("Credential Dumping", "T1003", "Credential Access",
     "Contains mimikatz-style commands or LSASS access patterns.",
     lambda r: _has_sus_string(r, "credential_dump")),
    # ── Lateral movement ─────────────────────────────────────────────────────
    ("Lateral Movement", "T1021.002", "Lateral Movement",
     "PsExec / admin share references — possible lateral movement tool.",
     lambda r: _has_sus_string(r, "lateral_psexec") or
               _pe_any_import(r, "NetShareEnum", "WNetOpenEnum")),
    # ── Crypto (ransomware) ──────────────────────────────────────────────────
    ("Crypto / Ransomware", "T1486", "Impact",
     "Combines file enumeration with encryption APIs — possible ransomware behavior.",
     lambda r: _pe_any_import(r, "CryptEncrypt", "BCryptEncrypt") and
               _pe_any_import(r, "FindFirstFileA", "FindFirstFileW", "FindFirstFile")),
    # ── AMSI bypass ──────────────────────────────────────────────────────────
    ("AMSI Bypass", "T1562.001", "Defense Evasion",
     "Attempts to disable AMSI — silences PowerShell AV inspection.",
     lambda r: _has_sus_string(r, "amsi_bypass")),
    # ── Office auto-exec macro ──────────────────────────────────────────────
    ("Office Auto-Exec Macro", "T1204.002", "Execution",
     "Document macro runs automatically on open — classic phishing weaponization.",
     lambda r: bool((r.get("format_specific") or {}).get("office", {}).get("auto_exec"))),
    # ── Shell from macro ─────────────────────────────────────────────────────
    ("Macro → Shell", "T1059.005", "Execution",
     "Macro invokes Shell() / CreateObject(WScript.Shell) — out-of-band command execution.",
     lambda r: _has_office_pattern(r, "Shell") or _has_office_pattern(r, "WScript.Shell")),
    # ── PDF JavaScript ───────────────────────────────────────────────────────
    ("PDF JavaScript", "T1059.007", "Execution",
     "PDF contains JavaScript — used to exploit PDF reader vulnerabilities.",
     lambda r: bool((r.get("format_specific") or {}).get("pdf", {}).get("javascript"))),
    # ── PDF launch action ────────────────────────────────────────────────────
    ("PDF Launch Action", "T1204.002", "Execution",
     "PDF contains a /Launch action — can execute commands on open.",
     lambda r: bool((r.get("format_specific") or {}).get("pdf", {}).get("launch_actions"))),
]


def build_capability_assessment(result: Dict) -> Dict:
    techniques: List[Dict] = []
    tags: List[str] = []
    for label, tid, tactic, expl, pred in _RULES:
        try:
            if pred(result):
                tags.append(label)
                techniques.append({
                    "id":          tid,
                    "name":        _t_name(tid),
                    "tactic":      tactic,
                    "label":       label,
                    "explanation": expl,
                    "attack_url":  _attack_url(tid),
                })
        except Exception:
            continue

    # Plain-English summary
    summary = _build_summary(tags, result)

    # Heuristic verdict from capability count
    verdict = "UNKNOWN"
    if len(techniques) >= 5:
        verdict = "MALICIOUS"
    elif len(techniques) >= 2:
        verdict = "SUSPICIOUS"
    elif techniques:
        verdict = "LOW"

    return {
        "tags":                 sorted(set(tags)),
        "mitre_techniques":     techniques,
        "technique_count":      len(techniques),
        "plain_english_summary": summary,
        "verdict":              verdict,
    }


def _build_summary(tags: List[str], result: Dict) -> str:
    if not tags:
        return ("No high-confidence malicious capabilities detected from static analysis "
                "alone. Verify against threat intel and consider dynamic analysis if context warrants.")

    category = (result.get("type") or {}).get("category", "file")
    bits = []
    if "Process Injection" in tags:
        bits.append("inject code into other running processes")
    if "Encoded PowerShell" in tags:
        bits.append("execute base64-encoded PowerShell commands")
    if "WMI" in tags:
        bits.append("execute commands via WMI")
    if "Keylogging" in tags:
        bits.append("capture keystrokes")
    if "Network Download" in tags:
        bits.append("download additional payloads from the internet")
    if "Registry Persistence" in tags or "Scheduled Task" in tags:
        bits.append("establish persistence so it runs again at startup")
    if "Crypto / Ransomware" in tags:
        bits.append("encrypt files on disk (ransomware behavior)")
    if "Credential Dumping" in tags:
        bits.append("dump credentials from memory")
    if "Lateral Movement" in tags:
        bits.append("move laterally to other hosts on the network")
    if "Macro → Shell" in tags or "Office Auto-Exec Macro" in tags:
        bits.append("execute commands on document open")
    if "PDF JavaScript" in tags or "PDF Launch Action" in tags:
        bits.append("run code or external commands when the PDF is opened")

    capabilities = ", ".join(bits) if bits else "perform suspicious actions"

    anti_analysis = ""
    if "Anti-Debug" in tags or "Packed / Obfuscated" in tags or "AMSI Bypass" in tags:
        anti_analysis = (" It contains anti-analysis techniques (anti-debug checks, "
                         "packing, or AMSI bypass) that may cause it to behave differently "
                         "inside a sandbox or while a debugger is attached.")

    family_hint = ""
    if "Crypto / Ransomware" in tags:
        family_hint = " The combination of file enumeration + encryption APIs is the classic ransomware fingerprint."
    elif "Network Download" in tags and "Process Injection" in tags:
        family_hint = " The combination of network download + process injection is the classic loader / RAT fingerprint."

    return (f"This {category} appears capable of being able to {capabilities}.{anti_analysis}{family_hint}")
