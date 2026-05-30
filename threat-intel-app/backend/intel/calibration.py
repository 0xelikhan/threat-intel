"""
Shared AI calibration — single source of truth for the "innocent until
proven guilty" principles applied across every AI call site.

Background: the investigation agent's bias (calling Dell SupportAssist
maintenance "suspicious") was the canonical failure. The same bias risks
appearing anywhere we ask an LLM to grade an alert / file / email — so
this module centralises the calibration so file_ai_analyst,
file_ai_summary, email_composer, response, and investigation all reuse
the same wording.

Public surface:
    CALIBRATION_PRINCIPLES (str)        — paste into any system prompt
    VERDICT_LEVEL_GUIDE     (str)       — the 5-tier severity ladder
    EVIDENCE_STANDARD       (str)       — the "what HIGH requires" rule
    benign_only_basis(basis) -> bool    — safety-net classifier
    downshift_if_benign_only(result)    — in-place threat_level lowering
    build_known_good_block(state) -> str — formatted KG block for prompts

The textual blocks are designed to be concatenated into a system prompt
verbatim. Each starts with a divider line so multiple blocks render
cleanly in sequence.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List


_log = logging.getLogger("recon.calibration")


# ─── prompt blocks ────────────────────────────────────────────────────────────
CALIBRATION_PRINCIPLES = """
──────────────────────────────────────────────────────────────────────────────────
CALIBRATION PRINCIPLES (apply STRICTLY)
──────────────────────────────────────────────────────────────────────────────────
You are a senior analyst at a tier-1 MDR. You have seen thousands of alerts.
You know the vast majority are false positives or low-risk events. Your job is
to ACCURATELY assess true risk — not to find threats that are not there.

Reason like a detective who requires evidence before drawing conclusions.

1. CONTEXT MATTERS MORE THAN PATTERNS
   • reg.exe exporting registry keys is NOT inherently suspicious.
   • PowerShell running as SYSTEM is NOT inherently suspicious.
   • Files written to ProgramData subdirectories are NOT inherently suspicious.
   • Processes running from System32 are NOT inherently suspicious.

2. KNOWN-GOOD SOFTWARE BEHAVIOUR
   Before flagging anything as suspicious, consider whether it matches known
   vendor-tool behaviour — Dell SupportAssist, HP Support Assistant, Microsoft
   Defender, Windows Update, SCCM, Intune, CrowdStrike, Carbon Black,
   SentinelOne, Splunk forwarders, Veeam. If a process / path / parent / cmd
   pattern matches known vendor software, classify as LIKELY LEGITIMATE and
   say so explicitly.

3. THE EVIDENCE STANDARD
   Only escalate severity above INFORMATIONAL when you have CONCRETE evidence
   of malicious intent — not just the theoretical possibility of misuse.
   HIGH or CRITICAL requires at least ONE of:
     • a hash flagged by multiple independent reputation sources
     • a command line matching known malware / attacker-tool patterns
     • a network connection to known-malicious infrastructure
     • lateral-movement indicators
     • credential-access patterns (LSASS dump, SAM hive copy, DCSync)
     • explicit evidence of unauthorized access
   Suspicious-LOOKING behaviour ALONE — without one of these — is
   INFORMATIONAL or LOW.

4. BE EXPLICIT ABOUT WHAT YOU DO AND DO NOT KNOW
   If the data shows no malicious indicators, say so plainly: "the hash is
   clean across every source checked," "no malicious indicators found." Do
   NOT hedge with "while indicators do not directly confirm malicious
   activity, the context suggests potential misuse" — that is misleading when
   the evidence points toward benign activity.

5. THE VERDICT MUST MATCH THE EVIDENCE
   Most alerts from well-tuned EDR tools on enterprise endpoints should be
   INFORMATIONAL or LOW. If you reach for HIGH or CRITICAL, confirm at least
   one Principle-3 evidence category actually applies.
""".strip()


VERDICT_LEVEL_GUIDE = """
──────────────────────────────────────────────────────────────────────────────────
SEVERITY LADDER
──────────────────────────────────────────────────────────────────────────────────
 • CRITICAL      — Confirmed active attack with evidence of compromise
                   (named malware executing, active C2 callout, confirmed
                    credential theft, in-progress ransomware).
 • HIGH          — Strong indicators of malicious activity with MULTIPLE
                   corroborating signals (named malware hash + suspicious
                   network indicator + matching MITRE technique).
 • MEDIUM        — Genuinely suspicious activity warranting investigation
                   but with a plausible legitimate explanation.
 • LOW           — Unusual activity worth noting but likely legitimate.
 • INFORMATIONAL — Normal or expected activity with no meaningful risk
                   indicators (most known-vendor maintenance, scheduled
                   tasks, routine updates).
""".strip()


EVIDENCE_STANDARD = """
──────────────────────────────────────────────────────────────────────────────────
EVIDENCE STANDARD FOR HIGH / CRITICAL
──────────────────────────────────────────────────────────────────────────────────
Do not assign HIGH or CRITICAL on speculation. Require at least ONE of:
  • known-bad hash (VT >= 5 independent detections, MalwareBazaar named family)
  • command-line matching known malware (Mimikatz, Cobalt Strike, Sliver, BRC4)
  • network call to known-malicious infrastructure (AbuseIPDB >= 80 + recent
    activity + local blocklist hit, or domain on a high-confidence phishing feed)
  • lateral-movement indicators (cross-host credential reuse, PsExec against
    multiple hosts in a short window)
  • credential-access patterns (LSASS dump, SAM copy, DCSync, NTDS.dit)
  • confirmed unauthorized access (impossible-travel + risky sign-in + no MFA,
    attacker-known IP from a credential-stuffing campaign)
""".strip()


# ─── safety-net classifier ────────────────────────────────────────────────────
_BENIGN_MARKERS = (
    "known-good", "known good", "clean across", "is clean",
    "no malicious", "legitimate", "expected", "vendor pattern",
    "vendor directory", "service account", "matches dell",
    "matches microsoft", "matches crowdstrike", "matches sccm",
    "matches intune", "matches sentinel", "matches carbon black",
    "matches splunk", "matches veeam", "matches hp", "matches lenovo",
    "scheduled maintenance", "vendor maintenance",
)

_MALICIOUS_MARKERS = (
    "flagged by", "vt detect", "malware family", "cobalt strike",
    "mimikatz", "lsass", "ransomware", "dcsync", "credential",
    "lateral", "c2 callout", "command-and-control", "exfiltrat",
    "kev ", "malicious infrastructure", "phishing kit", "byovd",
    "loldrivers hit", "active exploitation", "named threat actor",
    "encoded payload decoded to", "powershell empire", "brute ratel",
)


def benign_only_basis(basis: List[Any]) -> bool:
    """True when every evidence point in `basis` matches a benign marker
    and none matches a malicious marker. Used to decide whether the
    safety-net should downshift a HIGH/CRITICAL verdict."""
    if not basis:
        return False
    text = " ".join(str(b).lower() for b in basis)
    has_benign    = any(m in text for m in _BENIGN_MARKERS)
    has_malicious = any(m in text for m in _MALICIOUS_MARKERS)
    return has_benign and not has_malicious


def downshift_if_benign_only(
    result: Dict[str, Any],
    *,
    level_key: str = "threat_level",
    basis_key: str = "assessment_basis",
    verdict_key: str = "verdict_classification",
    label: str = "RECON calibration",
) -> Dict[str, Any]:
    """In-place safety-net. If `result[level_key]` is HIGH or CRITICAL AND
    `result[basis_key]` lists only benign indicators (no malicious markers),
    lower the level to LOW and append an audit note. Verdict classifier
    is corrected too when present. Returns the same dict for chaining."""
    try:
        level = (result.get(level_key) or "").upper()
        basis = result.get(basis_key) or []
        if level in ("HIGH", "CRITICAL") and benign_only_basis(basis):
            _log.info(
                "calibration override (%s): %s -> LOW", label, level
            )
            result[level_key] = "LOW"
            result[basis_key] = list(basis) + [
                f"[{label}] threat_level lowered — assessment_basis "
                "contained only benign indicators and no concrete "
                "malicious evidence."
            ]
            if result.get(verdict_key) in ("MALICIOUS", "LIKELY_MALICIOUS"):
                result[verdict_key] = "LIKELY_BENIGN"
    except Exception:  # never let the safety-net itself break the response
        pass
    return result


# ─── known-good block builder ─────────────────────────────────────────────────
def build_known_good_block(state: Dict[str, Any]) -> str:
    """Return a formatted KNOWN_GOOD_MATCHES block ready to paste into a
    system prompt. Returns a 'no matches' line when nothing matches —
    keeps the prompt template stable so the AI always sees a marker."""
    try:
        from intel.known_good import extract_context_from_state, match
        ctx = extract_context_from_state(state)
        hits = match(ctx)
    except Exception:
        return "(known-good library unavailable)"
    if not hits:
        return "(no known-good software patterns matched)"
    lines = []
    for h in hits[:8]:
        lines.append(f"  • {h['vendor']} {h['product']} ({h['category']})")
        lines.append(f"      WHY THIS IS NORMAL: {h['rationale']}")
        for field, pat in h["matched_fields"][:3]:
            lines.append(f"      matched on {field}: /{pat}/")
    return "\n".join(lines)


def build_known_good_block_from_fields(
    *,
    process: str = "",
    parent_process: str = "",
    path: str = "",
    command_line: str = "",
    destination_path: str = "",
    user_context: str = "",
) -> str:
    """Variant for callers that already have parsed fields (file analyzer,
    email composer) and don't want to round-trip through state extraction."""
    try:
        from intel.known_good import match
        ctx = {
            "process": process, "parent_process": parent_process,
            "path": path, "command_line": command_line,
            "destination_path": destination_path, "user_context": user_context,
        }
        hits = match(ctx)
    except Exception:
        return "(known-good library unavailable)"
    if not hits:
        return "(no known-good software patterns matched)"
    lines = []
    for h in hits[:8]:
        lines.append(f"  • {h['vendor']} {h['product']} ({h['category']})")
        lines.append(f"      WHY THIS IS NORMAL: {h['rationale']}")
    return "\n".join(lines)
