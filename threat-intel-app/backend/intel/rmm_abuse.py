"""
Remote-Management & Monitoring (RMM) tools known to be abused by
ransomware affiliates and other threat actors.

These tools are LEGITIMATE software. Their presence doesn't mean compromise —
it means the SOC should verify whether the install was authorized.

Source: CISA AA23-025A (LockBit), CISA AA24-038A (BlackCat), Mandiant M-Trends,
SentinelLabs blogs, public CTI reports.
"""
import re

# (binary/process name, vendor, threat groups using it, description)
RMM_CATALOG = [
    # ─── Most commonly abused in 2024-2025 ─────────────────────────────────
    ("ScreenConnect.ClientSetup.exe", "ConnectWise ScreenConnect (Control)",
     ["LockBit", "Black Basta", "ALPHV/BlackCat", "Akira", "Lazarus"],
     "Heavily abused for initial access & persistence; February 2024 CVE-2024-1709 mass-exploited."),
    ("ScreenConnect.WindowsClient.exe", "ConnectWise ScreenConnect",
     ["LockBit", "Black Basta", "ALPHV"], "Active session/agent."),

    ("anydesk.exe", "AnyDesk",
     ["LockBit", "Akira", "Phobos", "Cuba", "Black Basta"],
     "Most-abused commercial RMM. Often dropped to user temp dirs and run portably."),

    ("teamviewer.exe", "TeamViewer",
     ["LockBit", "Black Basta", "BlackCat"], "Long-running RMM-abuse target."),
    ("teamviewer_service.exe", "TeamViewer service",
     ["LockBit", "Black Basta"], "TeamViewer Windows service."),

    ("atera.exe", "Atera Agent",
     ["BlackCat", "Akira", "Lazarus"], "Atera RMM — abused for persistence and remote tasking."),
    ("ateraagent.exe", "Atera Agent",
     ["BlackCat", "Akira"], "Atera RMM service."),

    ("splashtop.exe", "Splashtop",
     ["LockBit", "Akira"], "Splashtop remote desktop."),
    ("srservice.exe", "Splashtop Streamer",
     ["LockBit"], "Splashtop streamer service."),

    ("rustdesk.exe", "RustDesk",
     ["Akira", "Royal", "BlackBasta"], "Open-source RMM; rising abuse 2024-2025."),

    ("client32.exe", "NetSupport Manager",
     ["FIN7", "SocGholish operators"], "NetSupport RAT — SocGholish/Konni final-payload."),
    ("client32u.exe", "NetSupport Manager",
     ["FIN7", "SocGholish"], "NetSupport RAT variant."),
    ("presentationhost.exe", "NetSupport Manager",
     ["SocGholish"], "NetSupport process variant."),

    ("action1.exe", "Action1 RMM",
     ["BlackCat", "Monti"], "Action1 free RMM — abused for endpoint enumeration."),

    ("logmein.exe", "LogMeIn",
     ["BlackBasta", "Conti"], "Legacy LogMeIn RMM."),
    ("lmiguardiansvc.exe", "LogMeIn Guardian",
     ["BlackBasta"], "LogMeIn Guardian service."),

    ("zohoassist.exe", "Zoho Assist",
     ["Akira", "Karakurt"], "Zoho Assist remote support tool."),

    ("supremo.exe", "Supremo Remote Desktop",
     ["LockBit", "Akira"], "Supremo remote desktop tool."),

    ("ammyy.exe", "Ammyy Admin",
     ["Lazarus", "TA505", "FIN8"], "Long-abused commodity RMM."),
    ("aa_v3.exe", "Ammyy Admin",
     ["TA505"], "Ammyy Admin version 3."),

    ("rsupport.exe", "RemoteSupport",
     ["LockBit"], "Korean RMM tool occasionally seen in incidents."),

    ("dwagent.exe", "DWService",
     ["Akira", "RansomHub"], "Open-source RMM; growing abuse."),
    ("dwservice.exe", "DWService",
     ["Akira"], "DWService daemon."),

    ("kabuto.exe", "Kabuto", ["NoEscape", "Akira"],
     "Less common but observed in ransomware affiliate ops."),

    # Microsoft built-ins that get abused for remote admin
    ("quickassist.exe", "Microsoft Quick Assist",
     ["Storm-1811", "Black Basta"],
     "Built-in. Storm-1811 used Quick Assist for help-desk impersonation phishing."),
    ("psexec.exe", "Sysinternals PsExec",
     ["LockBit", "Conti", "Hive", "REvil"], "Lateral-movement workhorse; near-universal in ransomware kill chains."),
    ("psexec64.exe", "Sysinternals PsExec",
     ["LockBit", "Conti"], "PsExec 64-bit."),
]

# Build a fast lookup dict — keys lowercased; both with .exe and without.
_LOOKUP: dict[str, dict] = {}
for binary, vendor, groups, desc in RMM_CATALOG:
    entry = {"binary": binary, "vendor": vendor, "groups": groups[:5], "description": desc}
    n = binary.lower()
    _LOOKUP[n] = entry
    if n.endswith(".exe"):
        _LOOKUP[n[:-4]] = entry

# Compile name regex — match .exe binaries in process strings or paths
_BIN_RE = re.compile(r"\b([A-Za-z0-9_\-\.]{2,80}\.(?:exe|dll|sys|bat|ps1|cmd|vbs|js|hta|lnk|msi|scr))\b",
                     re.IGNORECASE)


def lookup(name: str) -> dict | None:
    if not name:
        return None
    n = name.lower().strip()
    # Strip directory prefix
    n = n.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    return _LOOKUP.get(n) or _LOOKUP.get(n[:-4] if n.endswith(".exe") else n)


def extract_and_check(text: str) -> list[dict]:
    """Scan text for executable references that appear in the RMM catalog."""
    seen, hits = set(), []
    for m in _BIN_RE.finditer(text or ""):
        n = m.group(1).lower()
        bare = n.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        if bare in seen:
            continue
        seen.add(bare)
        entry = lookup(bare)
        if entry:
            hits.append({**entry, "match_value": bare})
    return hits


# ─── Suspicious filesystem paths (where attackers commonly drop tooling) ──────────
SUSPICIOUS_PATHS = [
    (r"C:\\Windows\\Temp\\",            "Windows Temp — common drop location"),
    (r"C:\\Windows\\SystemTemp\\",       "Windows SystemTemp — uncommon, attackers use it to evade Temp monitoring"),
    (r"C:\\Users\\Public\\",             "Public user profile — favored by attackers (writable, world-readable)"),
    (r"C:\\ProgramData\\(?!Microsoft)",  "ProgramData root — outside vendor dirs"),
    (r"\\AppData\\Local\\Temp\\",        "User Temp"),
    (r"\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\", "Office templates path — fileless persistence"),
    (r"\\Music\\|\\Pictures\\|\\Videos\\","Media folder for an executable — almost never legitimate"),
    (r"C:\\Intel\\(?!.*Intel)",          "Fake 'Intel' directory often used by malware to look benign"),
    (r"C:\\PerfLogs\\",                  "PerfLogs — Windows event-tracing dir, abused for staging"),
    (r"C:\\Recovery\\",                  "Recovery partition mount — unusual location for executables"),
]


def check_suspicious_paths(text: str) -> list[dict]:
    hits = []
    for pattern, label in SUSPICIOUS_PATHS:
        if re.search(pattern, text or "", re.IGNORECASE):
            hits.append({"pattern": pattern, "label": label})
    return hits


def stats() -> dict:
    return {"rmm_tool_count": len(RMM_CATALOG)}
