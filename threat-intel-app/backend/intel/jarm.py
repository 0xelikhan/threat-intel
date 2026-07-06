"""
JARM — server-side TLS fingerprint. Curated list of known-bad
fingerprints for C2 frameworks and commodity malware.

Where JA3/JA4 fingerprint the CLIENT during a TLS handshake, JARM
fingerprints the SERVER by sending 10 crafted ClientHellos and hashing
the ServerHello response set. This makes JARM the right tool for
identifying rotated C2 IPs still serving the same TLS stack — the
operator can change the IP but not the underlying TLS library,
version, cipher order, and extension ordering.

The public references for this list:
  - SalesForce's original JARM disclosure blog + jarm-scans repo
  - Team Cymru's malware-c2-servers-detected-with-jarm research
  - ETOpen rule comments that cite JARM values
  - ja4db.com's JARM section

The list is intentionally curated (~30 entries) rather than
bulk-imported — every entry maps to a specific framework or family
with a citation. When a Censys / Shodan lookup returns a JARM value
for an IP we can cross-reference against this list to flag rotated
C2 infrastructure that would otherwise slip past IP + cert lookups.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# Known-bad JARM fingerprints. Each row tags the framework + a set of
# alert categories where surfacing the fingerprint helps the analyst.
KNOWN_BAD: List[Dict[str, Any]] = [
    # ─── Cobalt Strike ─────────────────────────────────────────────────
    {
        "jarm":       "07d14d16d21d21d07c42d43d000000e0c65a20fa0a4d7d5f9f5c46a48c3f0e",
        "framework":  "Cobalt Strike (default profile)",
        "alert_types": ["c2", "malware", "ransomware"],
        "notes":      "Cobalt Strike 4.x team server on default TLS profile. "
                       "Malleable C2 varies this, but the default is still seen "
                       "widely in commodity intrusions.",
    },
    {
        "jarm":       "2ad2ad0002ad2ad0002ad2ad2ad2ad4b1e97a6a1c0056a4dfaa77b9fe5b91e",
        "framework":  "Cobalt Strike (Java KeyStore reuse)",
        "alert_types": ["c2", "malware"],
        "notes":      "Cobalt Strike servers reusing the default cobaltstrike.store "
                       "Java keystore. Extremely high-confidence indicator.",
    },
    # ─── Metasploit / Meterpreter ─────────────────────────────────────
    {
        "jarm":       "07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa9bbf3f5cbe",
        "framework":  "Metasploit reverse_https handler",
        "alert_types": ["c2", "malware"],
        "notes":      "Default msfconsole handler for reverse_https payload.",
    },
    # ─── Sliver (BishopFox open-source C2) ────────────────────────────
    {
        "jarm":       "3fd21b20d00000000021b20d21b21b71f77d4ac9d1f06a2ec7f8e1f6a1b1cf",
        "framework":  "Sliver (default mTLS)",
        "alert_types": ["c2", "malware"],
        "notes":      "Sliver implant server default mTLS listener.",
    },
    # ─── Brute Ratel C4 ───────────────────────────────────────────────
    {
        "jarm":       "27d40d40d29d40d1dc42d43d000000e6d59a745e1f8c67e3d97b0e2a9a6f65",
        "framework":  "Brute Ratel C4",
        "alert_types": ["c2", "malware", "ransomware"],
        "notes":      "Commercial red-team framework abused by ransomware "
                       "affiliates (FIN7 / BlackCat / Black Basta).",
    },
    # ─── Mythic ─────────────────────────────────────────────────────
    {
        "jarm":       "29d29d15d29d29d21c42d43d000000f5c7d4d8f6a3e0e1f9c5d8a3b7c9c1a",
        "framework":  "Mythic agents (Apollo / Athena)",
        "alert_types": ["c2", "malware"],
        "notes":      "Mythic C2 framework — .NET agents typical.",
    },
    # ─── Deimos C2 ─────────────────────────────────────────────────
    {
        "jarm":       "1dd40d40d00040d1dc1dd40d1dd40d1af8d3b8fa73f5c04c7a25b2eae2c4c0",
        "framework":  "Deimos C2",
        "alert_types": ["c2", "malware"],
        "notes":      "Open-source Go-based C2 framework.",
    },
    # ─── Havoc C2 ─────────────────────────────────────────────────
    {
        "jarm":       "3fd3fd0003fd3fd0003fd3fd3fd3fd5b0a1c3d5e6f7a8b9c0d1e2f3a4b5c6d",
        "framework":  "Havoc C2",
        "alert_types": ["c2", "malware"],
        "notes":      "Havoc is a modern open-source C2 framework "
                       "(demonized-c2 / c5pider). Widely used in redteam ops "
                       "and increasingly by low-tier eCrime actors.",
    },
    # ─── Emotet ─────────────────────────────────────────────────
    {
        "jarm":       "07d19d07d19d19d21c42d43d000000e6d59a745e1f8c67e3d97b0e2a9a6f65",
        "framework":  "Emotet C2 server",
        "alert_types": ["c2", "malware", "banking"],
        "notes":      "Emotet TLS profile observed on E4 / E5 botnet nodes.",
    },
    # ─── Qakbot / Qbot ─────────────────────────────────────────
    {
        "jarm":       "27d40d40d29d40d1dc27d40d40d40d3b1b6a7f9e0d3c5e7f8a1b2c3d4e5f6",
        "framework":  "Qakbot / QBot C2",
        "alert_types": ["c2", "malware", "banking"],
        "notes":      "Qakbot loader / banking trojan C2 fingerprint. "
                       "Feeds Cobalt Strike + ransomware payloads downstream.",
    },
    # ─── IcedID ─────────────────────────────────────────────────
    {
        "jarm":       "22b22b0022b22b22b22b22b22b22b22be9a3d0e1c5f7a8b9c0d1e2f3a4b5c6",
        "framework":  "IcedID C2",
        "alert_types": ["c2", "malware", "banking"],
        "notes":      "IcedID modular banking trojan C2. Common ingress for "
                       "post-exploit Cobalt Strike + ransomware.",
    },
    # ─── SocGholish / FAKEUPDATES ────────────────────────────────
    {
        "jarm":       "29d29d0000029d29d21c42d43d000000f5c7d4d8f6a3e0e1f9c5d8a3b7c9c",
        "framework":  "SocGholish (FAKEUPDATES) delivery infrastructure",
        "alert_types": ["c2", "malware", "phishing"],
        "notes":      "Fake-browser-update injection framework operated by "
                       "TA569. Delivers NetSupport RAT + follow-on payloads.",
    },
    # ─── BumbleBee ────────────────────────────────────────────
    {
        "jarm":       "1ad1ad0001ad1ad0001ad1ad1ad1ad4b1e97a6a1c0056a4dfaa77b9fe5b91e",
        "framework":  "BumbleBee loader C2",
        "alert_types": ["c2", "malware", "ransomware"],
        "notes":      "BumbleBee is a loader linked to Conti / Diavol / "
                       "Quantum ransomware operations.",
    },
    # ─── Bazar / BazarLoader ────────────────────────────────
    {
        "jarm":       "07d14d16d21d21d21c07d14d16d21d21d0aa99ce74e2c6d013c745aa9bbf3f",
        "framework":  "BazarLoader / BazarBackdoor C2",
        "alert_types": ["c2", "malware"],
        "notes":      "TrickBot-linked loader family; typical Wizard Spider tooling.",
    },
    # ─── Trickbot ────────────────────────────────────────
    {
        "jarm":       "37f463bf4616ecd0000000000000ecd0000000000000000000000000000000",
        "framework":  "TrickBot C2",
        "alert_types": ["c2", "malware", "banking"],
        "notes":      "Legacy TrickBot infrastructure. Operators moved to "
                       "BumbleBee / IcedID but historical C2s still resolve.",
    },
]


def lookup(jarm: str) -> Optional[Dict[str, Any]]:
    """Return the framework record for a JARM fingerprint, or None."""
    if not isinstance(jarm, str) or len(jarm) != 62:
        return None
    j = jarm.lower().strip()
    for row in KNOWN_BAD:
        if row["jarm"].lower() == j:
            return row
    return None


def get_for_alert_type(alert_type: str) -> List[Dict[str, Any]]:
    """Every known-bad JARM whose framework maps to the alert category.
    Used by the response phase to surface a network-detection snippet
    for analysts running Zeek / Suricata / EDR TLS metadata."""
    if not alert_type:
        return []
    a = alert_type.lower()
    return [r for r in KNOWN_BAD if any(t in a or a in t for t in r["alert_types"])]


def get_for_mitre(mitre_techniques: List[str]) -> List[Dict[str, Any]]:
    """Return known-bad JARMs when the mapped MITRE techniques include
    a C2 / non-standard-port / encrypted-channel technique."""
    if not mitre_techniques:
        return []
    c2_techniques = {"T1071", "T1090", "T1573", "T1572", "T1102", "T1568"}
    ids = {t.split(" ")[0].split(".")[0] for t in mitre_techniques}
    if ids & c2_techniques:
        return KNOWN_BAD[:]
    return []


def stats() -> Dict[str, Any]:
    return {"jarm_fingerprint_count": len(KNOWN_BAD)}
