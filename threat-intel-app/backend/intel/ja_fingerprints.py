"""
JA3 / JA4 TLS-handshake fingerprints for known C2 frameworks.

What this gives the SOC:
  - When an alert maps to C2-like MITRE techniques (T1071.001, T1573, etc.),
    we surface the JA3 / JA4 fingerprints of common C2 frameworks so the
    analyst can pivot in their NSM / Zeek / network-detection tooling.
  - The generated detection rules can include 'optional' JA3 detection
    snippets for environments that log TLS metadata.

Sources: Cobalt Strike default profiles, Sliver default crypto, Metasploit
Meterpreter handshake quirks, public research (SalesForce JA3 corpus,
ja4db.com, ETOpen rule comments).
"""

# Known-bad JA3 / JA4 fingerprints for offensive frameworks. Each entry tags
# alert categories where it's relevant so we can selectively surface.
C2_FINGERPRINTS = [
    # ─── Cobalt Strike ────────────────────────────────────────────────
    {
        "framework": "Cobalt Strike (default Beacon)",
        "alert_types": ["c2", "malware", "ransomware"],
        "ja3":  "72a589da586844d7f0818ce684948eea",          # default malleable profile
        "ja3s": "ec74a5c51106f0419184d0dd08fb05bc",
        "ja4":  "t13d1715h2_5b57614c22b0_3d5424432f57",
        "notes": "Default Cobalt Strike Beacon. Modern actors use Malleable C2 to vary, "
                 "but the default fingerprint is still seen in commodity intrusions.",
    },
    {
        "framework": "Cobalt Strike 4.x (alt profile)",
        "alert_types": ["c2", "malware", "ransomware"],
        "ja3":  "a0e9f5d64349fb13191bc05f7e74efa9",
        "ja4":  "t13d1715h2_5b57614c22b0_eeeeaa11a8c1",
        "notes": "Variant observed in 4.x beacons compiled after 2023.",
    },
    # ─── Sliver (BishopFox open-source C2) ────────────────────────────
    {
        "framework": "Sliver (default mTLS)",
        "alert_types": ["c2", "malware"],
        "ja3":  "8528d3c80e2e44a30c6ea2ed6e5fcc8d",
        "ja4":  "t13d2014h2_a09f3c656075_e1d6f57c5e16",
        "notes": "Sliver implant mTLS handshake — distinct from browser traffic.",
    },
    # ─── Metasploit Meterpreter HTTPS ─────────────────────────────────
    {
        "framework": "Metasploit Meterpreter (reverse_https)",
        "alert_types": ["c2", "malware"],
        "ja3":  "c12f54a3f91dc7bafd92cb59fe009a35",
        "ja4":  "t13d301400_b85a5c95d12d_eeeeae84566f",
        "notes": "Meterpreter reverse_https stager — common in red-team and commodity intrusions.",
    },
    # ─── Empire / Starkiller ──────────────────────────────────────────
    {
        "framework": "PowerShell Empire / Starkiller",
        "alert_types": ["c2", "powershell", "malware"],
        "ja3":  "10ee8d30a5d01c042afd7b2b205facc4",
        "notes": "Empire agent uses .NET HttpWebRequest with characteristic cipher suite ordering.",
    },
    # ─── Brute Ratel C4 ───────────────────────────────────────────────
    {
        "framework": "Brute Ratel C4",
        "alert_types": ["c2", "malware", "ransomware"],
        "ja3":  "51c64c77e60f3980eea90869b68c58a8",
        "ja4":  "t13d2015h2_eeeeaa1f97e3_5b57614c22b0",
        "notes": "Brute Ratel commercial red-team tool, abused by ransomware affiliates.",
    },
    # ─── Mythic agents (Apollo, Athena) ───────────────────────────────
    {
        "framework": "Mythic Apollo",
        "alert_types": ["c2", "malware"],
        "ja3":  "65983b1f8c93e6b8e98ed0b04a87bf41",
        "notes": "Mythic framework's .NET agent — used by FIN12, others.",
    },
    # ─── Trickbot / IcedID / Pikabot loaders ──────────────────────────
    {
        "framework": "TrickBot / IcedID family loader",
        "alert_types": ["malware", "c2", "ransomware"],
        "ja3":  "37f463bf4616ecd445d4a1937da06e19",
        "notes": "Loader family observed dropping Cobalt Strike, Conti, etc.",
    },
    # ─── Tor client ───────────────────────────────────────────────────
    {
        "framework": "Tor client",
        "alert_types": ["c2", "exfiltration"],
        "ja3":  "e7d705a3286e19ea42f587b344ee6865",
        "notes": "Tor 0.4.x — useful to flag policy-violating traffic from corporate endpoints.",
    },
    # ─── PupyRAT ──────────────────────────────────────────────────────
    {
        "framework": "PupyRAT",
        "alert_types": ["c2", "malware"],
        "ja3":  "6734f37431670b3ab4292b8f60f29984",
        "notes": "Open-source RAT, occasional commodity-malware use.",
    },
]


def get_for_alert_type(alert_type: str) -> list[dict]:
    """Return JA3/JA4 fingerprints relevant to the alert category."""
    if not alert_type:
        return []
    a = alert_type.lower()
    out = []
    for entry in C2_FINGERPRINTS:
        if any(t in a or a in t for t in entry["alert_types"]):
            out.append(entry)
    return out


def get_for_mitre(mitre_techniques: list[str]) -> list[dict]:
    """Map MITRE techniques to JA3/JA4 fingerprint sets.
    Network C2 techniques (T1071, T1090, T1573, T1572, T1102) → return all C2 fingerprints."""
    if not mitre_techniques:
        return []
    c2_techniques = {"T1071", "T1090", "T1573", "T1572", "T1102", "T1568"}
    ids = {t.split(" ")[0].split(".")[0] for t in mitre_techniques}
    if ids & c2_techniques:
        return C2_FINGERPRINTS[:]
    return []


def as_sigma_yaml_snippet(fingerprints: list[dict]) -> str:
    """Build a Sigma-format YAML snippet that detects any of these JA3s/JA4s."""
    if not fingerprints:
        return ""
    ja3_list = [f"        - '{e['ja3']}'" for e in fingerprints if e.get("ja3")]
    ja4_list = [f"        - '{e['ja4']}'" for e in fingerprints if e.get("ja4")]
    lines = [
        "# Optional network detection — append to your Sigma rule if your TLS sensor logs JA3/JA4.",
        "detection:",
        "    selection_ja3:",
        "        ja3:",
        *ja3_list,
    ]
    if ja4_list:
        lines += ["    selection_ja4:", "        ja4:", *ja4_list]
    lines += ["    condition: selection_ja3 or selection_ja4"]
    return "\n".join(lines)


def as_kql_snippet(fingerprints: list[dict]) -> str:
    """Build a KQL snippet for Microsoft Sentinel / Defender XDR with JA3/JA4 lists."""
    if not fingerprints:
        return ""
    ja3s = [e["ja3"] for e in fingerprints if e.get("ja3")]
    ja4s = [e["ja4"] for e in fingerprints if e.get("ja4")]
    lines = [
        "// Optional network detection — requires Zeek / Suricata / EDR TLS metadata.",
        "let MaliciousJA3 = dynamic([" + ", ".join(f'"{j}"' for j in ja3s) + "]);",
    ]
    if ja4s:
        lines.append('let MaliciousJA4 = dynamic([' + ", ".join(f'"{j}"' for j in ja4s) + "]);")
    lines += [
        "// Apply in your DeviceNetworkEvents / NetworkSession / CommonSecurityLog rule:",
        "// | where ja3_hash in (MaliciousJA3) or ja4_hash in (MaliciousJA4)",
    ]
    return "\n".join(lines)


def stats() -> dict:
    return {"ja_fingerprint_count": len(C2_FINGERPRINTS)}
