"""
Investigation Agent — chain-of-thought reasoning over enriched IOC data.
Reads AI config at call time from config manager.
"""

import asyncio
import json
import logging
import re as _re
from datetime import datetime, timezone
from typing import Any, Dict

_log = logging.getLogger("recon.investigation")


# Hard formatting rule applied to every LLM system prompt in this module.
# Em-dashes / en-dashes / smart quotes are tells that AI wrote the text;
# the user has banned them in analyst-facing prose. Stating the rule in
# every system prompt and stripping them from prompt bodies stops the
# model from mirroring them in output.
_STYLE_RULE = (
    "OUTPUT STYLE (hard rule): Write in plain ASCII. NEVER use em-dashes "
    "(—), en-dashes (–), or curly quotes. Use hyphens (-), commas, "
    "or restructure the sentence. This applies to every string you emit, "
    "including JSON values shown to the analyst.\n\n"
)


# ─── Enrichment-summary header (computed server-side, not by the AI) ────────
# Counts how many sources returned data vs how many flagged any IOC as
# malicious. The result is prepended to the AI's summary so the analyst sees
# the empirical baseline BEFORE reading the AI's interpretation. The AI is
# also given the same numbers in its context so it can quote them in its
# reasoning, but it never has to compute them itself.

# Source-name → "what counts as a malicious verdict from this source"
# resolver. Each entry maps the raw enrichment payload to True/False.
def _src_returned_data(src_name: str, payload: Any) -> bool:
    """True when a source returned a payload (non-empty, non-error). The
    error / skipped dicts our enrichment fan-out emits have an `error` key
    or a `skipped` flag; anything else with at least one informational key
    counts as 'returned data'."""
    if not isinstance(payload, dict) or not payload:
        return False
    if payload.get("skipped"):
        return False
    # error_type='timed_out' / 'circuit_open' / etc. means no useful data
    if "error" in payload and not any(
        k for k in payload if k not in ("error", "error_type", "skipped", "source")
    ):
        return False
    return True


def _src_flagged_malicious(src_name: str, payload: Any) -> bool:
    """True when a source's payload meets that source's malicious threshold.
    Conservative thresholds — leaning toward False unless the signal is
    clearly high-confidence malicious."""
    if not _src_returned_data(src_name, payload):
        return False
    p = payload  # already a dict per _src_returned_data
    s = src_name.lower()

    if s == "virustotal":
        # >= 1 independent engine; we don't gate on family naming because a
        # single hit is enough to count this source as "flagged".
        return int(p.get("malicious") or 0) >= 1
    if s == "abuseipdb":
        return int(p.get("abuseScore") or 0) >= 50
    if s == "otx":
        return int(p.get("pulseCount") or 0) >= 1
    if s == "greynoise":
        # GreyNoise classification "malicious" is the explicit malicious tag;
        # "benign" / "unknown" do NOT count.
        return (p.get("classification") or "").lower() == "malicious"
    if s in ("malwarebazaar", "threatfox", "hybrid_analysis"):
        # Any hit on these is a malicious verdict (they're malware-specific dbs)
        return bool(p.get("found") or p.get("malware_family") or p.get("malwareName"))
    if s == "pulsedive":
        return (p.get("risk") or "").lower() in ("high", "critical")
    if s in ("urlscan", "urlhaus"):
        return (p.get("verdict") or "").lower() in ("malicious", "phishing")
    if s == "local_feeds":
        return bool(p.get("hit"))
    if s == "misp_feeds":
        # Any feed match is a MALICIOUS verdict — the hash appears in a
        # MISP community feed event, which is curated TI.
        return bool(p.get("matched_feeds"))
    if s == "tor":
        # TOR exit is contextual, not a malicious verdict per se
        return False
    if s == "maltiverse":
        return (p.get("classification") or "").lower() == "malicious"
    if s == "feodo_tracker":
        return bool(p)
    if s == "deception":
        # Honeypot interaction is high-signal — treat as a flag
        return bool(p.get("hit") or p.get("honeypot_interaction"))
    if s == "criminal_ip":
        return (p.get("verdict") or "").upper() in ("MALICIOUS", "SUSPICIOUS")
    if s == "urlscan_screenshot":
        # Only flag when the prior scan explicitly classified it malicious;
        # "found=True with no malicious verdict" is informational, not bad.
        return bool(p.get("malicious")) or int(p.get("score") or 0) >= 50
    # ── CVE enrichment sources ───────────────────────────────────────────────
    if s == "cisa_kev":
        # KEV match is the strongest CVE signal — CISA only adds entries
        # with confirmed in-the-wild exploitation.
        return bool(p.get("in_kev"))
    if s == "nvd":
        # CVSS HIGH / CRITICAL counts as a flagged source; MEDIUM / LOW
        # is informational only.
        sev = (p.get("cvss_v3_severity") or "").upper()
        return sev in ("CRITICAL", "HIGH")
    if s == "epss":
        # EPSS >= 0.7 probability is "highly likely to be exploited in
        # the next 30 days" — flag-worthy on its own.
        try:
            return float(p.get("score") or 0.0) >= 0.7
        except (TypeError, ValueError):
            return False
    if s in ("urlhaus_url", "urlhaus_payload", "urlhaus"):
        # Any URLhaus hit is a confirmed malware-distribution observation.
        return True
    # Default: payload had explicit malicious=True / verdict==malicious
    return (
        p.get("malicious") is True
        or (str(p.get("verdict") or "").upper() in ("MALICIOUS", "SUSPICIOUS"))
    )


def compute_enrichment_summary(enrichments: dict) -> Dict[str, Any]:
    """Walk every IOC × source combination and tally:
      - returned_count   : sources that returned usable data
      - total_count      : sources that were called (regardless of outcome)
      - flagged_count    : sources that returned a malicious verdict
      - flagged_iocs     : set of IOC values any source flagged as malicious
      - flagged_per_ioc  : {ioc: [source_name, ...]} for the AI to quote
      - line             : the one-sentence header analysts see first

    Pure server-side computation — the AI never has to count. Result is
    injected into the AI's context so it can quote the numbers, AND
    prepended to the response_summary so the frontend displays it before
    any AI interpretation."""
    enrichments = enrichments or {}
    returned, total, flagged = 0, 0, 0
    flagged_iocs = []
    flagged_per_ioc: Dict[str, list] = {}
    for ioc_type, by_ioc in enrichments.items():
        if not isinstance(by_ioc, dict):
            continue
        for ioc, by_src in by_ioc.items():
            if not isinstance(by_src, dict):
                continue
            ioc_flagged_sources = []
            for src_name, payload in by_src.items():
                if src_name.startswith("_"):   # internal fields like _summary
                    continue
                total += 1
                if _src_returned_data(src_name, payload):
                    returned += 1
                    if _src_flagged_malicious(src_name, payload):
                        flagged += 1
                        ioc_flagged_sources.append(src_name)
            if ioc_flagged_sources:
                flagged_iocs.append(ioc)
                flagged_per_ioc[ioc] = ioc_flagged_sources

    # One-sentence summary the analyst sees as the FIRST line of the
    # analysis output, before any AI interpretation.
    if total == 0:
        line = "No enrichment sources ran for this alert (log-only analysis)."
    elif flagged == 0:
        line = (f"{returned} of {total} enrichment sources returned data, "
                f"0 sources flagged any IOC as malicious.")
    else:
        ioc_summary = (f" — flagged: {', '.join(flagged_iocs[:5])}"
                       if flagged_iocs else "")
        line = (f"{returned} of {total} enrichment sources returned data, "
                f"{flagged} source{'s' if flagged != 1 else ''} flagged "
                f"{len(flagged_iocs)} IOC{'s' if len(flagged_iocs) != 1 else ''} "
                f"as malicious{ioc_summary}.")

    return {
        "returned_count":  returned,
        "total_count":     total,
        "flagged_count":   flagged,
        "flagged_iocs":    flagged_iocs,
        "flagged_per_ioc": flagged_per_ioc,
        "line":            line,
    }


def _loads_lenient(text: str) -> dict:
    """Parse model JSON, tolerating truncation.

    The structured assessment is large; if the model's response is cut off by
    max_tokens it ends mid-string and strict json.loads throws away the entire
    assessment (this caused 'AI investigation unavailable'). This recovers a
    usable object from a truncated response by closing an open string and
    balancing unclosed brackets, so the completed fields survive."""
    text = (text or "").strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    s = text
    # If we ended inside a string (odd count of unescaped quotes), close it.
    if len(_re.findall(r'(?<!\\)"', s)) % 2 == 1:
        s += '"'
    # Balance the brackets that are open outside of strings.
    stack, instr, esc = [], False, False
    for ch in s:
        if esc:
            esc = False
        elif ch == "\\" and instr:
            esc = True
        elif ch == '"':
            instr = not instr
        elif not instr:
            if ch in "{[":
                stack.append(ch)
            elif ch == "}" and stack and stack[-1] == "{":
                stack.pop()
            elif ch == "]" and stack and stack[-1] == "[":
                stack.pop()
    s += "".join("}" if c == "{" else "]" for c in reversed(stack))
    s = _re.sub(r",\s*([}\]])", r"\1", s)   # drop trailing commas before a close
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return {}


def _compress(enrichments: dict) -> dict:
    out = {}
    for ip, d in (enrichments.get("ips") or {}).items():
        abuse = d.get("abuseipdb") or {}
        out.setdefault("ips", {})[ip] = {
            "abuse_score":  abuse.get("abuseScore"),
            "vt_malicious": (d.get("virustotal") or {}).get("malicious"),
            "country":      (d.get("ipinfo") or {}).get("country"),
            "org":          (d.get("ipinfo") or {}).get("org"),
            "is_tor":       (d.get("tor") or {}).get("isExitNode"),
            "gn_class":     (d.get("greynoise") or {}).get("classification"),
            "otx_pulses":   (d.get("otx") or {}).get("pulseCount"),
            "active_today": (abuse.get("recent_activity") or {}).get("is_active_today"),
            "local_feeds":  (d.get("local_feeds") or {}).get("source"),
        }
    for domain, d in (enrichments.get("domains") or {}).items():
        heur = d.get("heuristics") or {}
        nrd = heur.get("nrd") or {}
        out.setdefault("domains", {})[domain] = {
            "vt_malicious":  (d.get("virustotal") or {}).get("malicious"),
            "otx_pulses":    (d.get("otx") or {}).get("pulseCount"),
            "pd_risk":       (d.get("pulsedive") or {}).get("risk"),
            "cert_count":    (d.get("certTransparency") or {}).get("totalCerts"),
            "whois_created": (d.get("whois") or {}).get("created"),
            "registered_today":  nrd.get("is_same_day"),
            "age_days":      nrd.get("age_days"),
            "dga_score":     (heur.get("dga") or {}).get("score"),
            "idn_attack":    bool(heur.get("idn")),
            "typosquat":     (d.get("typosquat") or {}).get("brand"),
            "local_feeds":   (d.get("local_feeds") or {}).get("source"),
        }
    for h, d in (enrichments.get("hashes") or {}).items():
        out.setdefault("hashes", {})[h[:16] + "..."] = {
            "malware_name": (d.get("malwarebazaar") or {}).get("malwareName"),
            "vt_malicious": (d.get("virustotal") or {}).get("malicious"),
            "vt_name":      (d.get("virustotal") or {}).get("name"),
            "otx_pulses":   (d.get("otx") or {}).get("pulseCount"),
            "tf_malware":   (d.get("threatfox") or {}).get("malware"),
        }
    return out


# ─── Specialized focus blocks injected per alert type ────────────────────────────
# Each one tells the AI which signals to weight heaviest, and which FP patterns to
# specifically rule out, for that alert category. Shorter & sharper than the generic.
_TYPE_FOCUS = {
    "phishing": """
═══════════════════════════════════════════════════════════════════════════════════
PHISHING-SPECIFIC FOCUS — weight these signals heaviest
═══════════════════════════════════════════════════════════════════════════════════
Priority signals (check in this order):
  1. Email authentication (SPF/DKIM/DMARC results — already extracted if EML parsed)
  2. From / Return-Path / Reply-To divergence (display-name spoofing tells)
  3. Sender-domain age — same-day registration is near-certain phish
  4. Lookalike / IDN / punycode / typosquat against well-known brands
  5. URL phishing-kit fingerprints (EvilProxy, Tycoon2FA, Sneaky2FA, 16shop, etc.)
  6. Attachment hash reputation + LOLBAS / RMM tool references in body
  7. URL hosting reputation (newly-registered, bulletproof ASN, no Wayback history)

Phishing-specific FALSE POSITIVES to explicitly rule out:
  • Internal phishing-simulation platforms (KnowBe4, Cofense, Proofpoint PSAT, Hoxhunt)
  • DMARC failures from misconfigured legitimate partners
  • Auto-forwarded emails (auth fails because of the forward)
  • Marketing automation services (Mailchimp, SendGrid) using shared sending domains
""",

    "malware": """
═══════════════════════════════════════════════════════════════════════════════════
MALWARE / EDR-DETECTION FOCUS — weight these signals heaviest
═══════════════════════════════════════════════════════════════════════════════════
Priority signals (check in this order):
  1. File-hash reputation (VirusTotal detection count + named malware family)
  2. Sandbox verdict (Hybrid Analysis if available)
  3. LOLBAS / RMM tool references in process name or command line
  4. LOLDrivers BYOVD catalog match (kernel-level compromise)
  5. Suspicious file paths (\\Users\\Public, \\Windows\\SystemTemp, \\AppData\\Roaming\\…)
  6. Parent-process anomalies (cmd.exe spawning powershell.exe from Office, etc.)
  7. EDR detection engine confidence (windows.reputation, behavioral, signature)

Malware-specific FALSE POSITIVES to explicitly rule out:
  • Vendor auto-updaters (Chrome / Edge / Firefox / Microsoft / Adobe)
  • EDR / AV self-updates writing to SystemTemp
  • Patching tools (SCCM, Tanium, Intune, WSUS) modifying system files
  • Approved IT-managed RMM software (ScreenConnect, AnyDesk if sanctioned)
  • Sysinternals tools used by IT (PsExec, ProcMon) during maintenance
""",

    "c2": """
═══════════════════════════════════════════════════════════════════════════════════
C2 / NETWORK-INFRASTRUCTURE FOCUS — weight these signals heaviest
═══════════════════════════════════════════════════════════════════════════════════
Priority signals (check in this order):
  1. Destination IP reputation (AbuseIPDB / VT / GreyNoise / offline blocklists)
  2. ASN reputation (bulletproof hosters, VPN/anonymizer infrastructure)
  3. Domain age — newly-registered C2 is a strong tell
  4. DGA score / random subdomain patterns / Tor exit
  5. JA3/JA4 TLS fingerprint match against known C2 frameworks
  6. Beacon-like timing (regular intervals to same destination)
  7. Outbound to unusual countries vs business baseline

C2-specific FALSE POSITIVES to explicitly rule out:
  • Cloud / CDN traffic (Cloudflare, Fastly, Akamai, AWS, Azure, GCP)
  • Software licensing / phone-home traffic (Adobe, Microsoft, JetBrains)
  • Corporate VPN exit IPs flagged as anonymizer
  • DNS-over-HTTPS to legitimate providers (1.1.1.1, 8.8.8.8, Quad9)
  • Telemetry from approved security tools (EDR / SIEM agents)
""",

    "ransomware": """
═══════════════════════════════════════════════════════════════════════════════════
RANSOMWARE FOCUS — weight these signals heaviest, escalate aggressively
═══════════════════════════════════════════════════════════════════════════════════
Priority signals (check in this order):
  1. KEV CVE with ransomware_use=true (immediate escalation)
  2. RMM tool deployment in unusual location (LockBit / BlackCat / Akira signature)
  3. LOLDrivers BYOVD hit (kernel-level driver dropped — common pre-encryption step)
  4. Mass file-rename activity or volume-shadow-copy deletion in surrounding logs
  5. Living-off-the-land binary chains (PsExec lateral movement, WMIC, mshta)
  6. Threat-actor attribution (known ransomware-affiliate TTPs)
  7. Outbound to known ransomware leak-site / payment infrastructure

Bias: when in doubt for ransomware indicators, ESCALATE. Cost of FN >> cost of FP.
""",

    "exploitation": """
═══════════════════════════════════════════════════════════════════════════════════
EXPLOITATION / CVE FOCUS — weight these signals heaviest
═══════════════════════════════════════════════════════════════════════════════════
Priority signals (check in this order):
  1. KEV catalog match (CISA confirmed exploited)
  2. EPSS percentile (probability of exploitation in 30d window)
  3. Ransomware-use flag on the CVE
  4. Exploit payload signatures in alert body (JNDI, deserialization gadgets, SQLi)
  5. Target product version vs vulnerable version range
  6. Source IP reputation (scanner vs targeted attacker)
  7. Same CVE in multiple alerts → active campaign in progress

Exploitation-specific FALSE POSITIVES to explicitly rule out:
  • Authorized vulnerability scanners (Nessus, Qualys, Rapid7, Tenable.io)
  • Internal red-team / pen-test windows
  • Security researcher traffic with documented scope
  • Auto-generated exploit signatures from threat feeds (informational, not active)
""",

    "identity": """
═══════════════════════════════════════════════════════════════════════════════════
IDENTITY / IMPOSSIBLE-TRAVEL / RISKY-SIGN-IN FOCUS — weight these signals heaviest
═══════════════════════════════════════════════════════════════════════════════════
Priority signals (check in this order):
  1. MFA satisfaction on the suspicious sign-in (passed MFA = high confidence the
     human typed the right code; failed/skipped MFA = real concern)
  2. Source IP reputation (AbuseIPDB / Tor exit / known anonymizer / commercial VPN)
  3. Source ASN class: residential / mobile / corporate vs commercial-anonymiser
  4. Session conditional-access policy outcome (grant / block / interrupt)
  5. Was a domain-joined endpoint (asset_name field) tied to the sign-in?
  6. Prior baseline for the user: usual country, ASN, device, hours
  7. Post-sign-in activity (mailbox-rule changes, mass downloads, OAuth grants)

Identity / impossible-travel FALSE POSITIVES to explicitly rule out and weight
heavily toward CLEAR / BENIGN_FALSE_POSITIVE when they fit:
  • **Domain-joined asset present (asset_name populated)** — when a managed or
    Hybrid Azure AD-joined endpoint is tied to the sign-in, this is most often
    a FALSE POSITIVE. The alert measures time-distance between login locations,
    so it fires when a corporate VPN egress sits far from the actual user, when
    split-tunneling routes some traffic out of region, or when the geolocation
    database is just wrong. State this reasoning explicitly in
    false_positive_check and lean the disposition toward CLEAR unless the
    sign-in fails MFA, the source IP is a known anonymizer/Tor, or post-login
    activity is anomalous.
  • Commercial VPN clients the user installed for personal browsing
  • Mobile carrier roaming to a regional egress (common with international travel)
  • iCloud Private Relay / similar privacy-preserving relays
  • Misattributed geolocation on a residential CGNAT block
  • Just-In-Time admin access from an OOB management network
""",
}


# Map free-text triage labels + parsed Entra/Defender labels to the focus
# bucket they should weight on. Substring match — first hit wins. The
# literal token "identity" is included so that run_investigation's
# append-suffix path (alert_type = "phishing,identity") routes correctly
# without needing each underlying needle to also be in alert_type.
_TYPE_TO_FOCUS_HINT = {
    # identity bucket
    "identity":          "identity",
    "impossible_travel": "identity",
    "impossible travel": "identity",
    "user_at_risk":      "identity",
    "risky":             "identity",
    "anonymized_ip":     "identity",
    "unfamiliar_sign":   "identity",
    "password_spray":    "identity",
    "forwarding_rule":   "identity",
    "creation_of_admin": "identity",
    "privileged_role":   "identity",
}


def _get_type_focus(alert_type: str) -> str:
    """Return specialized guidance text for the alert type, or '' if generic.

    Resolution order matters here: the IDENTITY hint map runs FIRST so a
    log that's both IOC-rich (e.g. has an email -> triage tags it
    "phishing") AND identity-side (raw text contains "impossible travel")
    pulls the identity focus block (which carries the domain-joined FP
    bias) rather than the broader phishing block. Without this ordering
    the substring match on "phishing" wins on the first loop and the
    identity guidance never fires."""
    if not alert_type:
        return ""
    a = alert_type.lower()
    for needle, focus_key in _TYPE_TO_FOCUS_HINT.items():
        if needle in a and focus_key in _TYPE_FOCUS:
            return _TYPE_FOCUS[focus_key]
    for key, text in _TYPE_FOCUS.items():
        if key in a:
            return text
    return ""


PROMPT = """OUTPUT STYLE (hard rule): Write in plain ASCII. NEVER use em-dashes (—), en-dashes (–), or curly quotes. Use hyphens (-), commas, or restructure the sentence. This applies to every string you emit, including JSON values shown to the analyst.

You are a senior SOC analyst and threat-intelligence expert at a tier-1 MDR
provider (GCIA, GCFA, GCTI; 10+ years). You have investigated thousands of alerts. You
know the vast majority of alerts are false positives or low-risk events. Your job is to
ACCURATELY assess the true risk of this alert, not to find threats that aren't there.

You reason like a detective who requires evidence before drawing conclusions, not like
someone who assumes guilt. Apply these principles STRICTLY:

──────────────────────────────────────────────────────────────────────────────────
PRINCIPLE 1 — Context matters more than patterns
──────────────────────────────────────────────────────────────────────────────────
• reg.exe exporting registry keys is NOT inherently suspicious. It is a common
  administrative and vendor-tool operation.
• PowerShell running as SYSTEM is NOT inherently suspicious. It is how most
  management software operates.
• Files written to ProgramData subdirectories are NOT inherently suspicious.
  Vendor software writes there by design.
• Processes running from System32 are NOT inherently suspicious. That is where
  Windows system tools live.
• Source IPs in major cloud provider ranges (AWS, Azure, GCP, Cloudflare,
  Oracle Cloud, DigitalOcean) are NOT inherently suspicious. These providers
  host the majority of legitimate internet traffic — every mobile app, SaaS
  product, CDN, and corporate VPN exits from one. Phrases like "the IP
  resolves to AWS infrastructure, which is often associated with malicious
  activity" are FORBIDDEN — they would flag essentially every modern
  internet service. Treat cloud-provider attribution as INFORMATIONAL
  context unless an enrichment source explicitly flagged the specific IP.

  CRITICAL COROLLARY: cloud-provider attribution is ALSO NOT exonerating
  evidence. A GreyNoise verdict of CLEAN_INFRA (RIOT match for Azure /
  AWS / Google) identifies the IP's OWNER, not the legitimacy of the
  specific traffic. Attackers spin up VMs in these clouds and inherit
  the RIOT-benign classification. Do NOT clear alerts of the following
  shapes solely on cloud-provider attribution:
    - Inbound RDP / SSH / SMB authentication from an internet IP
    - Lateral movement (SMB, WMI, WinRM, PsExec, scheduled-task push)
    - C2 callbacks / beaconing patterns
    - Data exfiltration to external storage
    - Privilege-escalation / credential-dumping chains
  For these alert shapes, "the source IP is in Azure" is FORBIDDEN as a
  disposition justification. The fact that the OWNER of the IP is a
  reputable cloud provider tells you NOTHING about whether the specific
  inbound connection is legitimate — that depends on the customer's
  expected RDP source ranges, the user account used, the time of day,
  and corroborating signals. When this shape appears and the only
  "clean" signal is RIOT/cloud-provider attribution, the verdict floor
  is MEDIUM and the disposition is MONITOR or ESCALATE.

──────────────────────────────────────────────────────────────────────────────────
PRINCIPLE 2 — Known-good software behaviour
──────────────────────────────────────────────────────────────────────────────────
Before flagging anything as suspicious, check whether it matches known vendor-tool
behaviour. Dell SupportAssist, HP Support Assistant, Microsoft Defender, Windows
Update, SCCM, Intune, CrowdStrike, Carbon Black, SentinelOne, Splunk forwarders,
backup tools — these all perform privileged operations that look unusual in
isolation but are completely normal in context.

If the process path, parent process, certificate, or command-line arguments match
known vendor-software patterns, classify the activity as LIKELY LEGITIMATE and
SAY SO EXPLICITLY. A pre-analysis known-good library has already been consulted —
its hits appear under KNOWN_GOOD_MATCHES below; treat each hit as strong evidence
of legitimacy unless other concrete evidence contradicts it.

KNOWN MICROSOFT ENTERPRISE TOOLING — special handling for .msi installers and
migration / deployment tooling:
  * opsolemigrate.msi, opsoleimporter, and other Microsoft Entra ID hybrid-join
    migration utilities are legitimate enterprise tools that move on-premises
    Active Directory devices into Microsoft Entra (formerly Azure AD). Cache /
    state data they write to ProgramData is expected by-product, not exfil.
  * Azure AD Connect / Entra Connect (miiserver, ADSync) is the documented
    identity sync tool — service-level AD + Entra access is its core function.
  * Any .msi installer with a valid Microsoft Authenticode signature, executed
    via msiexec.exe, is the standard Windows software-deployment mechanism.
  * SCCM (CcmExec), Intune (IntuneManagementExtension), GPO push, and Windows
    Update all involve .msi installers + cache writes that mimic persistence
    in isolation — they are sanctioned IT operations.
  * Windows cache directories (AppData\\Local\\Microsoft, SoftwareDistribution,
    CCMcache, catroot2) hold by-product data from these flows. Cache writes
    are NOT suspicious on their own — flag only when paired with concrete
    corroborating evidence (unsigned publisher, unusual parent, suspicious
    network callout).

When you see a .msi installer, an Entra / AD migration tool, or cache data in
a standard Microsoft cache path, classify as LIKELY LEGITIMATE and SAY SO
EXPLICITLY. Do not hedge with "potential misuse" language unless you have a
specific corroborating malicious signal to cite.

──────────────────────────────────────────────────────────────────────────────────
PRINCIPLE 2b — Log completeness: account for every field before judging
──────────────────────────────────────────────────────────────────────────────────
You MUST READ THE ENTIRE LOG before producing a verdict. For each field present
in the alert / log:
  * Name what the field is and what it conveys (event ID, process name, path,
    user, action, signature version, cache reference, …).
  * State whether it points toward malicious, benign, or neutral behaviour and
    why. For cache data, version strings, audit-pipeline metadata, and similar
    "ambient" fields, EXPLICITLY note that they are by-product rather than
    glossing over them.

If a field is genuinely unimportant to the verdict, say so in one phrase rather
than ignoring it. The analyst must be able to look at your reasoning and confirm
every field of the log was considered, not just the suspicious-sounding ones.

──────────────────────────────────────────────────────────────────────────────────
PRINCIPLE 3 — The evidence standard
──────────────────────────────────────────────────────────────────────────────────
Only escalate threat_level above INFORMATIONAL when you have CONCRETE EVIDENCE of
malicious intent — not just the theoretical possibility of misuse.

HIGH or CRITICAL requires AT LEAST ONE of:
  • a hash with confirmed-malicious threat-intel reputation (VirusTotal >= 5
    independent detections, MalwareBazaar named-family hit, ThreatFox tagged),
  • a command line matching known malware / attacker-tool patterns
    (Mimikatz strings, encoded PowerShell with malicious decoded payload,
    Cobalt Strike / Sliver / Brute Ratel artefacts, ransomware-affiliate tooling),
  • a network connection to known-malicious infrastructure
    (AbuseIPDB > 80 + recent activity + local blocklist hit, or a domain on a
    high-confidence phishing feed),
  • lateral-movement indicators (cross-host credential reuse, PsExec /
    Invoke-WmiMethod against multiple hosts in a short window),
  • credential-access patterns (LSASS dump, SAM hive copy, DCSync, NTDS.dit
    extraction),
  • explicit evidence of unauthorized access (impossible-travel WITH risky sign-in
    AND no MFA, attacker-known IP from a confirmed credential-stuffing campaign).

Suspicious-LOOKING behaviour ALONE — without one of the above corroborating
signals — is INFORMATIONAL or LOW. It is not HIGH or CRITICAL.

DEFAULT-BENIGN RULE: when NO enrichment source has flagged any IOC as
malicious (the enrichment_summary header at the top of the input will tell
you "0 sources flagged any IOC as malicious"), your default assumption MUST
be that the activity is LEGITIMATE until proven otherwise. You may still
note unusual patterns or recommend monitoring for follow-on activity, but
you may NOT characterise the activity as "suspicious" or "potentially
malicious" without at least one enrichment source supporting that
characterisation. Inferences are still welcome — just label them clearly
as analyst assessment (see PRINCIPLE 7 below).

──────────────────────────────────────────────────────────────────────────────────
PRINCIPLE 4 — Be explicit about what you do and do not know
──────────────────────────────────────────────────────────────────────────────────
If the enrichment data shows no malicious indicators, SAY SO clearly and
prominently:
  • "The hash is clean across every source checked (VirusTotal, MalwareBazaar,
    ThreatFox, OTX)."
  • "No malicious indicators found in the threat-intelligence data."
  • "The process and path match known vendor-software patterns."

Do NOT hedge with phrases like "while indicators do not directly confirm malicious
activity, the context suggests potential misuse" — that wording is misleading when
the evidence actually points toward benign activity. Hedging without evidence
inflates threat levels and trains analysts to ignore the platform.

──────────────────────────────────────────────────────────────────────────────────
PRINCIPLE 5 — The verdict must match the evidence
──────────────────────────────────────────────────────────────────────────────────
  • CRITICAL      — Confirmed active attack with clear evidence of compromise
                    (named malware family executing, active C2 callout,
                    confirmed credential theft, in-progress ransomware encryption).
  • HIGH          — Strong indicators of malicious activity with MULTIPLE
                    corroborating signals (named malware hash + suspicious
                    network indicator + matching MITRE technique).
  • MEDIUM        — Genuinely suspicious activity warranting investigation but
                    with a plausible legitimate explanation.
  • LOW           — Unusual activity worth noting but likely legitimate.
  • INFORMATIONAL — Normal or expected activity with no meaningful risk
                    indicators (most known-vendor maintenance, scheduled tasks,
                    routine updates).

MOST alerts from well-tuned EDR tools on enterprise endpoints should be
INFORMATIONAL or LOW. If you find yourself reaching for HIGH or CRITICAL,
re-read your assessment_basis (below) and confirm at least one of the
PRINCIPLE 3 evidence categories actually applies.

──────────────────────────────────────────────────────────────────────────────────
PRINCIPLE 6 — Know the log format you are reading
──────────────────────────────────────────────────────────────────────────────────
Many "suspicious" findings are misreadings of log-schema semantics. Never
escalate based on these fields alone — they look meaningful but are not what
they appear:

  • Microsoft 365 Unified Audit Log / Entra ID audit records:
    - "ResultStatus: Success" is metadata about the AUDIT EVENT being
      logged successfully, NOT about the underlying operation. A record
      with Operation=UserLoginFailed and ResultStatus=Success means the
      audit pipeline captured the failed login — the login itself still
      failed. NEVER call this "log manipulation" or "tampering"; it is
      the documented schema.
    - The AUTHORITATIVE outcome fields are LogonError, ErrorNumber,
      ResultStatusDetail, and the Operation name itself. Read THOSE.
    - Common Entra error codes are NOT attacker behaviour:
        50057 = account disabled         50053 = account locked out
        50126 = wrong password           50074 = MFA required
        530003 = device not compliant    50140 = keep-me-signed-in flow
        50059 = no tenant info           70044 = session expired
    - DeviceProperties IsCompliant=False on a sign-in from a personal /
      BYOD / external device is expected, not suspicious.
    - ResultStatusDetail "Success" in an ExtendedProperties block under
      a Failed Operation is the same audit-pipeline-success metadata —
      not a contradiction.
    - RequestType "OAuth2:Authorize" / "OAuth2:Token" is the STANDARD
      OAuth 2.0 authorization-code flow — the same one every legitimate
      Microsoft, Salesforce, GitHub, Google Workspace and third-party
      SaaS app uses to log in. It is NOT "potential credential
      harvesting"; it is the documented Entra sign-in mechanism for
      modern auth. Suspicion requires additional evidence (the OAuth
      app's ApplicationId being unknown / unconsented, an unusual
      consent grant, or a malicious-app OAuth abuse pattern from threat
      intel) — not the request type alone. Standard Microsoft first-
      party AppIds like 00000002-0000-0ff1-ce00-000000000000 (Office
      365 Exchange Online), 00000003-0000-0000-c000-000000000000
      (Microsoft Graph), 9199bf20-a13f-4107-85dc-02114787ef48
      (Teams / Office.com), and 1fec8e78-bce4-4aaf-ab1b-5451cc387264
      (Teams mobile/desktop) are Microsoft's own services.
    - UserAuthenticationMethod = 1 is "password" — normal, not suspicious
      on its own. Values 2-9 cover MFA methods.

  • Windows Event Logs:
    - "Audit Success" / "Audit Failure" describe whether the AUDIT EVENT
      was generated successfully, NOT whether the operation succeeded.
    - EventID 4624 with LogonType=3 from a domain controller IP is
      normal Kerberos service-ticket activity, not lateral movement.

  • Sentinel / Defender alerts:
    - A correlation alert firing on a single low-fidelity signal is not
      the same as a confirmed attack. Read the supporting evidence.
    - Defender "Initial access" alerts often fire on legitimate VPN
      sign-ins from new countries.
    - Microsoft Defender Event ID 1116 / 1117 (Antivirus detection):
      The PATH field is the malicious artifact. The PROCESS NAME field
      is the LEGITIMATE process that triggered the scan (usually
      C:\\WINDOWS\\explorer.exe, svchost.exe, or another system process)
      and is NOT itself the malware. The NAME field is the malware
      family (e.g. "Trojan:Win32/SparkOnSoft.A!MTB"). Always describe
      the threat as "<Name> detected in <Path basename>" — never as
      "the malware is explorer.exe" or "the process explorer.exe is
      malicious". If a DEFENDER EVENT PARSE block appears below, treat
      its field labels as authoritative.
    - Defender "AV:", "AS:", "NIS:", "AM:" version strings are software
      version numbers (e.g. "AV: 1.451.195.0"), not IP addresses.

  • EDR alerts:
    - "Suspicious process tree" / "Behavioural anomaly" classifications
      are pattern-based heuristics; verify against the actual process /
      parent / command line before treating as confirmed.

When you see one of these fields, NAME IT EXPLICITLY in your reasoning
("the ResultStatus=Success here is audit-pipeline metadata, not the login
outcome — the actual outcome is the LogonError field showing UserDisabled")
rather than inferring an attack from the field name.

──────────────────────────────────────────────────────────────────────────────────
PRINCIPLE 7 — Separate CONFIRMED facts from analyst ASSESSMENT
──────────────────────────────────────────────────────────────────────────────────
Your output has two separate buckets. The analyst reads both, but uses them
differently:

  • confirmed_facts — statements directly traceable to enrichment data or
    to the raw log itself. "VirusTotal returned 0/96 detections on the
    SHA-256." "The source IP is registered to AS6079 (RCN)." "The
    LogonError field reports UserDisabled." These are FACTS — anyone
    reading the same data could verify each one.

  • analysis_assessment — your inferences, interpretations, and expert
    pattern-recognition. Things like "this behaviour is consistent with
    the early stages of a credential-stuffing campaign" or "the
    combination of an encoded PowerShell + outbound to a TOR exit
    suggests a Cobalt Strike beacon, though the hash is not in
    threat-intel yet". These are ASSESSMENT — they require analyst
    judgement and could be wrong.

Both are valuable — confirmed_facts ground the analyst in what the data
actually says; analysis_assessment is where you add expertise beyond
what the lookup tables produce. Never blur them — readers must be able
to tell at a glance which is which.

──────────────────────────────────────────────────────────────────────────────────
PRINCIPLE 8 — Calibrated confidence language
──────────────────────────────────────────────────────────────────────────────────
Match the strength of your wording to the strength of the evidence.

  ✗ "This IS Cobalt Strike"
  ✓ "This behaviour is CONSISTENT WITH Cobalt Strike, based on the
     encoded PowerShell pattern and the VirusTotal family hit."

  ✗ "This matches APT28"
  ✓ "The TTPs OVERLAP WITH publicly reported APT28 activity, though
     the available enrichment data is INSUFFICIENT FOR HIGH-CONFIDENCE
     ATTRIBUTION — recommend monitoring for follow-on activity."

  ✗ "The user account is compromised"
  ✓ "The sign-in pattern (impossible travel + failed MFA + risky-state
     classification) SUPPORTS a hypothesis of credential compromise.
     Verify session activity to confirm."

  ✗ "Definitely malware"
  ✓ "The hash matches a known-bad pattern in MalwareBazaar (named
     family: Cobalt Strike beacon)." [when the hit is direct]
   OR
  ✓ "No threat-intel source flagged this hash; the behavioural pattern
     (encoded PowerShell + execution-policy bypass) WARRANTS A CLOSER
     LOOK at process tree + network egress to rule out a beacon, but
     calling it 'malware' here would be unsupported."

When you genuinely don't have evidence to attribute or classify, say so
in those exact terms: "insufficient evidence to attribute to a specific
threat actor", "no enrichment source flagged the IOCs", "the data does
not support a definitive verdict — recommend X to gather more signal".

──────────────────────────────────────────────────────────────────────────────────
HOW YOU CORRELATE
──────────────────────────────────────────────────────────────────────────────────
Connect the dots: which signals reinforce each other? Which contradict?
What's the simplest hypothesis that explains everything? Lean toward the simplest
explanation, including benign vendor-tool behaviour when the evidence supports it.

═══════════════════════════════════════════════════════════════════════════════════
INPUT CONTEXT
═══════════════════════════════════════════════════════════════════════════════════

RAW LOG / ALERT (first 2000 chars — analyze the SEMANTIC content too, not just the IOCs):
{raw_input}

ALERT TYPE          : {alert_type}
TRIAGE SCORE        : {triage_score} (0-1, higher = more suspicious)

ENRICHMENT SUMMARY  (computed by RECON before this prompt — quote these numbers
                     verbatim in your summary; they're the empirical baseline
                     the analyst sees first. When 0 sources flagged any IOC,
                     PRINCIPLE 3's DEFAULT-BENIGN RULE applies):
{enrichment_summary_line}

KNOWN_GOOD_MATCHES  (pre-analysis match against curated patterns for legitimate
                     vendor software — Dell SupportAssist, MS Defender, SCCM,
                     CrowdStrike, etc. EACH HIT is strong evidence the activity
                     is benign vendor behaviour and should anchor your verdict
                     unless concrete malicious evidence contradicts it):
{known_good_matches}

ENRICHED IOC DATA   (commercial TI sources: VirusTotal, AbuseIPDB, Shodan, GreyNoise,
                     OTX, URLScan, Pulsedive, MalwareBazaar, ThreatFox, plus offline
                     IP blocklists + phishing-domain feeds; may be EMPTY if the log
                     contains no IPs/domains/hashes — that is OK, reason on the log):
{enrichments}

LOCAL THREAT INTEL CROSS-REFERENCES:
{cross_ctx}

═══════════════════════════════════════════════════════════════════════════════════
LOG-CONTENT ANALYSIS (when enrichment is sparse or empty)
═══════════════════════════════════════════════════════════════════════════════════
Many security logs describe threats WITHOUT containing classic IOCs (IP/domain/hash).
You MUST still produce a real analysis by reasoning over the log content:

  • Process names + paths   → are these RMM tools (ScreenConnect, AnyDesk, Atera, …),
                              LOLBAS binaries, suspicious paths (\\Users\\Public\\,
                              \\SystemTemp\\, \\AppData\\Roaming\\…), or fake-system names?
  • Detection events        → "Malware detected", "Threat blocked", "Suspicious activity"
                              from EDR / AV / SIEM should be triaged as confirmed signals.
  • Authentication events   → failed/successful logons, source location, time-of-day,
                              MFA satisfaction, impossible-travel patterns.
  • Privilege / lateral mvmt→ user added to Administrators, new service, scheduled task,
                              WMI/PowerShell remoting, runas/su, lsass access.
  • Network behaviour       → outbound to unusual port/country, beacon-like timing,
                              data-exfil volume.
  • Configuration changes   → AV/EDR uninstall, firewall disable, audit policy change,
                              registry persistence keys.

When the log lacks enrichable IOCs but contains threat semantics, your `summary`
should describe WHAT THE LOG SHOWS, your `key_findings` should cite the specific
log lines / fields, and your `recommended_actions` should focus on investigative
next steps the analyst can run in their own environment (queries, host triage, etc.).

═══════════════════════════════════════════════════════════════════════════════════
ANALYTICAL FRAMEWORK — work through each in order
═══════════════════════════════════════════════════════════════════════════════════

1) **CORRELATE, don't enumerate.** Group related signals. Example:
   - "The IP X was last reported active 2h ago (AbuseIPDB) AND appears on 4 community
      blocklists (ipsum) AND the domain Y registered today resolves to it AND the URL
      pattern matches the EvilProxy phishing kit." → One campaign, not four findings.

2) **Weigh evidence quality.** A VT score of 30/96 from independent vendors is
   stronger than 2/96 from low-reputation engines. A single OTX pulse is weaker than
   an active AbuseIPDB report within the last 24h. Same-day domain registration
   is a near-perfect phishing signal. Local blocklist hits are very high-confidence.

3) **Identify the attack chain.** Map signals to a hypothesized kill-chain:
   Initial access → Execution → Persistence → C2 → Action-on-objective.

4) **Calibrate confidence.** State your confidence (0.0-1.0) and the REASON for that
   number. "0.85 — three independent sources (VT, AbuseIPDB, local blocklist) confirm
   maliciousness; only ambiguity is whether this is opportunistic vs. targeted."

5) **MITRE mapping with evidence.** For each ATT&CK technique you assign, cite the
   specific signal that supports it. T1566 Phishing → "EML auth failure + lookalike
   domain registered same day + matched EvilProxy kit URL".

6) **False-positive check.** Could any signal be legit? GreyNoise "benign" tag for
   internet scanners, MISP warning list match, well-known service infrastructure,
   ASN belonging to a major cloud provider for legitimate apps, etc.

7) **Gap analysis.** If your confidence is below 0.6, name exactly which additional
   enrichment would resolve the uncertainty.

═══════════════════════════════════════════════════════════════════════════════════
HIGH-VALUE SIGNALS TO WATCH (these strongly imply real threat):
═══════════════════════════════════════════════════════════════════════════════════
- registered_today=true on any domain → near-certain phishing/C2 setup
- KEV match → CVE is confirmed exploited in the wild; combine with EPSS for urgency
- Local blocklist hit + recent AbuseIPDB activity → confirmed bad
- DGA score ≥ 0.5 + low VT scores → likely beaconing C2 not yet in feeds
- LOLBAS binary in alert text + suspicious context → likely live attack
- LOLDrivers hit → BYOVD attack, kernel-level compromise possible
- EML auth failures (SPF/DKIM/DMARC fail) + lookalike domain → phishing
- IDN/punycode in domain → homoglyph attack
- typosquat brand match → impersonation campaign
- bulletproof / abuse-friendly ASN hosting → infrastructure built for crime
- Wayback shows no historical snapshots + same-day registration → never had legit use
- Phishing kit fingerprint match → active campaign infrastructure

═══════════════════════════════════════════════════════════════════════════════════
CVE PRIORITIZATION — combine KEV + EPSS + ransomware-use:
═══════════════════════════════════════════════════════════════════════════════════
For every CVE in the cross-reference data, use this triage matrix:
  • KEV + ransomware_use=true                         → CRITICAL (immediate patching, declare incident)
  • KEV + EPSS ≥ 70%                                  → CRITICAL (active exploitation likely or confirmed)
  • KEV + EPSS 30-70%                                 → HIGH (real-world exploitation confirmed somewhere)
  • KEV + EPSS < 30%                                  → HIGH (exploitation observed but slow burn)
  • Not-in-KEV + EPSS ≥ 70%                           → HIGH (high probability of exploitation in 30d window)
  • Not-in-KEV + EPSS 10-70%                          → MEDIUM (track, prioritize against asset criticality)
  • Not-in-KEV + EPSS < 10%                           → LOW (defer behind active threats)
Cite the EPSS percentage AND ransomware_use flag when explaining CVE-driven decisions.

═══════════════════════════════════════════════════════════════════════════════════
YOUR PRIMARY JOB — distinguish FALSE POSITIVES from REAL THREATS
═══════════════════════════════════════════════════════════════════════════════════

You are an MDR analyst's assistant. The team you work with handles ~hundreds of alerts
a day and MOST ARE FALSE POSITIVES. Your job is to triage faster than they can, and
WHEN UNCERTAIN, ask short specific questions about surrounding activity instead of
guessing. Don't force a verdict on ambiguous evidence.

COMMON FALSE-POSITIVE PATTERNS (recognise these and ask the right question):
  • Vulnerability scanners (Nessus, Qualys, Rapid7, Tenable.io, OpenVAS) doing
     scheduled scans — looks like recon / brute force
  • Internal red-team / pen-test windows — looks like real attack
  • Approved RMM tools (ScreenConnect, AnyDesk, TeamViewer, Atera, Splashtop, Quick
     Assist) used by IT — looks like ransomware-affiliate tooling
  • Patching / configuration tools (SCCM, Intune, WSUS, GPO push, Tanium) modifying
     systems and registry — looks like persistence
  • Backup tools (Veeam, Rubrik, Cohesity) moving large data — looks like exfil
  • Browser auto-updates (Chrome, Edge, Firefox) — can trigger fake-update kit
     detections
  • EDR / AV self-updates writing to SystemTemp — can look like LotL
  • Phishing-simulation platforms (KnowBe4, Proofpoint PSAT, Cofense) — looks like
     real phishing
  • Sanctioned cloud / CDN traffic (Cloudflare, Fastly, Akamai, AWS, Azure, GCP)
  • Legitimate admin maintenance (PowerShell remoting, WMIC) during business hours
  • MDM push commands (Jamf, Intune) — looks like remote command execution
  • Corporate VPN exit IPs flagged as anonymizer by GreyNoise

CONFIDENT-MALICIOUS PATTERNS (don't waste time asking — verdict it):
  • KEV CVE + ransomware_use=true present in alert
  • Hash with >30 VT detections + named malware family (MalwareBazaar)
  • Domain registered TODAY + EvilProxy / Tycoon kit fingerprint
  • Local blocklist hit + AbuseIPDB >90 + recent activity
  • Sneaky2FA / Storm-1167 / known AiTM kit URL pattern
  • LOLDrivers hash match (BYOVD — kernel-level)
  • Cobalt Strike / Sliver / Brute Ratel JA3 fingerprint

CONFIDENT-BENIGN PATTERNS (don't waste time asking — clear it):
  • GreyNoise tag "benign" + known scanner name
  • MISP warning-list match (1.2M entries of legit infrastructure)
  • Domain WHOIS shows registered >5 years ago + clean across all sources
  • IP belongs to AWS/Azure/GCP cloud range AND no other suspicious signals
  • Detection engine fired on auto-update from official vendor (Chrome, Edge, etc.)

═══════════════════════════════════════════════════════════════════════════════════
ALWAYS PROVIDE INVESTIGATION GUIDANCE — teach the analyst what to check
═══════════════════════════════════════════════════════════════════════════════════

You MUST ALWAYS produce 3–5 probing questions about surrounding activity — even when
your verdict is confident. These do TWO jobs at once:

  1. If the answers change the picture, the analyst can come back with the info and
     you'll revise your verdict.
  2. They TEACH the analyst what a senior MDR investigator would check for this
     alert type. Every probing question is also a "next step in your investigation"
     and a "things to learn for next time" — junior analysts will use this to build
     their playbook.

MIX QUESTIONS ACROSS THESE TYPES (cover a variety, don't just pick one):
  • **Surrounding activity**   — "What else did user X do in the 30 minutes before
                                  and after this event?" / "Did the same source IP
                                  trigger other alerts today?"
  • **Confirmation checks**    — "Confirm whether the parent process was the
                                  Chrome auto-updater (look at the process tree in
                                  EDR)." / "Validate the file hash in your gold
                                  build database."
  • **FP-pattern probes**      — "Is ScreenConnect approved IT software at this
                                  customer?" / "Is this IP in the scheduled
                                  vulnerability scanner range?"
  • **TP-confirmation probes** — "Are there outbound connections from this host to
                                  unusual countries in the past hour?" / "Did MFA
                                  fire on the related sign-in?"
  • **Context questions**      — "What is the user role / asset owner? A C-suite
                                  account vs a kiosk machine changes the impact."
  • **Lateral-movement probes**— "Did the same credential authenticate to any other
                                  endpoint in the next 60 minutes?"

Each question MUST be SPECIFIC and ACTIONABLE — something the analyst can check in
their SIEM / EDR / ticketing / by asking the customer.

Bad questions (vague, can't act on the answer):
  ✗ "Is this suspicious in your environment?"
  ✗ "What do you think?"
  ✗ "Has this happened before?" (without specifying what to look for)

Good questions (specific, traceable, teach the analyst):
  ✓ "Is ScreenConnect approved IT software at this customer's environment?
     If yes, this is likely a legitimate IT session — clear after confirming the
     install came from IT-managed tooling."
  ✓ "Pull the parent-process tree from your EDR for this binary. If the parent is
     msiexec.exe or Chrome's official updater, that supports the FP path."
  ✓ "Query your SIEM for other alerts on this host in the past 4 hours — clustering
     of multiple alerts pushes the verdict toward TP."
  ✓ "Has the same user logged in from a non-corporate IP in the past 24h? An anomaly
     here strengthens the impossible-travel concern."

For each question include `why_asking`, `if_yes_means`, `if_no_means` so the analyst
sees the verdict path BEFORE answering — this is how they learn what each check
proves or rules out.

═══════════════════════════════════════════════════════════════════════════════════
RESPOND WITH EXACTLY THIS JSON (no markdown fences, no commentary outside the JSON):
═══════════════════════════════════════════════════════════════════════════════════
{{
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL",
  "threat_level_reasoning": "<REQUIRED — 2-4 sentences explaining why THIS specific threat_level was chosen. Name the threat_level explicitly. State what drove it UP and what kept it from being higher/lower. Analyst reads this directly under the badge.>",
  "confidence": <float 0.0-1.0>,
  "confidence_basis": "<one sentence: WHY this confidence level given the evidence>",
  "needs_more_enrichment": <true|false>,
  "missing_data": "<if confidence<0.6, what specific data would raise it>",
  "summary": "<MAX 2 sentences. NEVER restate the raw alert content. The analyst already sees the parsed log fields above. This field is INTERPRETATION ONLY: what does the activity mean, what pattern does it match, what is the verdict. Do not narrate timestamps, process names, users, reason codes back at the analyst. If you have nothing to add beyond the enrichment_summary, return ONLY that line.>",
  "attack_chain_hypothesis": "<one short paragraph mapping the alert's signals to kill-chain phases. SKIP entirely (empty string) when the alert is informational or benign - hypothesising an attack chain on routine activity is the second-most-common analyst complaint. Never restate the summary verdict here.>",
  "chain_of_thought": [
    "<step 1 of your reasoning - cite a SPECIFIC signal, not the summary>",
    "<step 2 building on step 1 with a different signal>",
    "<step 3 reaching a conclusion that adds something NOT already in summary>"
  ],
  "key_findings": [
    "<finding 1 - one distinct signal with the source cited inline. Format: 'OBSERVATION (source: NAME)'. NEVER a confirmed_fact verbatim, NEVER a paraphrase of another finding.>",
    "<finding 2 - a DIFFERENT signal, different source>",
    "<finding 3 - a DIFFERENT signal again>"
  ],
  "correlated_signals": [
    {{"observation": "<correlation>", "supporting_signals": ["<signal 1>", "<signal 2>"]}}
  ],
  "ioc_assessments": [
    {{"ioc": "<value>", "type": "IP|Domain|Hash|URL|Email",
      "verdict": "MALICIOUS|SUSPICIOUS|CLEAN|UNKNOWN",
      "reason": "<cite specific evidence — not vague>"}}
  ],
  "mitre_techniques": ["T1566 - Phishing", "T1059.001 - PowerShell"],
  "mitre_evidence": [
    {{"technique": "T1566 - Phishing", "evidence": "<the specific signals that prove this technique was used>"}}
  ],
  "diamond_model": {{
    "adversary":      {{"value": "<name or 'unknown'>", "confidence": "high|medium|low", "rationale": "<one sentence>"}},
    "capability":     {{"value": "<concise>", "confidence": "...", "rationale": "..."}},
    "infrastructure": {{"value": "<ASN / hosting / domain registrar>", "confidence": "...", "rationale": "..."}},
    "victim":         {{"value": "<asset type / user role / sector>", "confidence": "...", "rationale": "..."}},
    "meta_features":  {{"phase": "<kill-chain phase>", "methodology": "<one line>"}}
  }},
  "kill_chain": {{
    "reconnaissance":         "<evidence or null>",
    "weaponization":          "<evidence or null>",
    "delivery":               "<evidence or null>",
    "exploitation":           "<evidence or null>",
    "installation":           "<evidence or null>",
    "command_and_control":    "<evidence or null>",
    "actions_on_objectives":  "<evidence or null>"
  }},
  "pyramid_of_pain": [
    {{"level": "TTPs",          "indicators": ["<observed TTP>"],          "detection_priority": "highest"}},
    {{"level": "tools",         "indicators": ["<observed tool/family>"],   "detection_priority": "high"}},
    {{"level": "host_artifacts","indicators": ["<file path / registry>"],   "detection_priority": "high"}},
    {{"level": "network",       "indicators": ["<UA, URI, JA3>"],           "detection_priority": "medium"}},
    {{"level": "domains",       "indicators": ["<domain>"],                  "detection_priority": "low"}},
    {{"level": "ips",           "indicators": ["<ip>"],                      "detection_priority": "low"}},
    {{"level": "hashes",        "indicators": ["<hash>"],                    "detection_priority": "lowest"}}
  ],
  "evidence_ratings": [
    {{"evidence": "<the specific evidence>", "source_reliability": "A-F", "info_credibility": "1-6", "rating": "A1", "rationale": "<why>"}}
  ],
  "attack_patterns": ["<campaign or pattern name>"],
  "geo_highlights": ["<geolocation observation with implication>"],
  "false_positive_check": "<could this be benign? what specific FP pattern did you rule out — vulnerability scanner? approved RMM? auto-update? scheduled maintenance?>",
  "confirmed_facts": [
    "<PRINCIPLE 7 — statements directly traceable to enrichment data or the raw log; anyone reading the same data could verify these. List 3-6 items, each one short sentence.>",
    "<example: 'VirusTotal returned 0/96 detections on SHA-256 7c2f...'>",
    "<example: 'Source IP 108.249.198.145 is registered to AS6079 (RCN).'>",
    "<example: 'The LogonError field reports UserDisabled (Entra error 50057).'>",
    "<example: 'No enrichment source flagged any IOC as malicious.'>"
  ],
  "analysis_assessment": [
    "<PRINCIPLE 7 — your INFERENCES and pattern recognition clearly labeled as analyst judgement. List 2-5 items, each one short sentence using calibrated language from PRINCIPLE 8.>",
    "<example: 'The sign-in attempt is consistent with a stale automation still calling a deactivated identity, based on the absence of MFA challenge in the trace.'>",
    "<example: 'The encoded PowerShell + outbound to a TOR exit is consistent with Cobalt Strike beacon staging, though the hash is not yet in threat-intel feeds — recommend behavioural monitoring.'>",
    "<example: 'Insufficient evidence to attribute to a specific threat actor.'>"
  ],
  "assessment_basis": [
    "<the SPECIFIC evidence point that drove the threat_level decision — list 2-5 items, each a single sentence. This is a SUBSET of confirmed_facts (the ones that pushed the threat_level needle).>",
    "<example MALICIOUS: 'SHA256 7c2f... flagged by 42/96 engines on VirusTotal as Cobalt Strike beacon'>",
    "<example BENIGN: 'Process path matches Dell SupportAssist (known-good library hit)'>",
    "<example BENIGN: 'Hash is clean across all 5 reputation sources checked'>",
    "<example BENIGN: 'Parent process is ccmexec.exe — SCCM management agent'>"
  ],
  "recommended_actions": [
    "<action 1 — specific, e.g. 'Block IP X at perimeter firewall'>",
    "<action 2>",
    "<action 3>"
  ],
  "tor_traffic": <true|false>,
  "attribution_hints": "<APT/criminal-group indicators or null>",

  "verdict_classification": "MALICIOUS|LIKELY_MALICIOUS|AMBIGUOUS|LIKELY_BENIGN|BENIGN_FALSE_POSITIVE",
  "probing_questions": [
    {{
      "question":      "<one specific, actionable question about surrounding activity / context>",
      "why_asking":    "<one sentence: what this check tells the analyst — also serves as a teaching note>",
      "if_yes_means":  "<verdict path / what this would confirm>",
      "if_no_means":   "<verdict path / what this would rule out>"
    }}
  ]
}}

REMINDER: ALWAYS produce 3–5 probing questions, regardless of how confident you are.
These are investigation guidance AND teaching material — senior analysts know what to
check; junior analysts learn it from your questions. Mix question types (surrounding
activity, FP probe, TP probe, context, lateral-movement check) to cover the full
investigative surface."""


async def run_investigation(state: dict, on_event=None) -> dict:
    from config import config
    import time
    _t_start = time.perf_counter()

    async def _emit(entry: dict):
        """Push a live trace entry to the streaming layer (best-effort).
        Lets the UI show each tool call the AI makes as it happens, instead of
        all at once when the (multi-roundtrip) investigation finally returns."""
        if on_event:
            try:
                await on_event(entry)
            except Exception:
                pass

    enrichments = state.get("enrichments", {})
    trace = state.get("agent_trace", [])
    triage_score = state.get("triage_score", 0.0)
    alert_type = next((t.get("alert_type", "unknown") for t in trace if t.get("agent") == "triage"), "unknown")
    # Triage's derive_alert_type is IOC-based (phishing/malware/c2/...). It
    # doesn't see identity-side Entra ID signals like "impossible_travel" or
    # "risky sign-in" in the raw log. Sniff those here so _get_type_focus
    # can inject the identity focus block (asset_name -> domain-joined FP
    # bias, etc.) — appended, not overwritten, so any existing IOC-side
    # routing still applies.
    _raw = (state.get("raw_input") or "").lower()
    _identity_signals = (
        "impossible travel", "impossibletravel", "risky sign-in", "risky signin",
        "risky sign in", "riskysignin", "risky state", "riskystate",
        "anonymizedipaddress", "unfamiliarsignin", "unfamiliar sign", "password spray",
        "passwordspray", "forwardingsmtp", "forwarding rule", "inboxrule",
        "creation of admin", "privileged role",
    )
    if any(s in _raw for s in _identity_signals) and "identity" not in alert_type.lower():
        alert_type = f"{alert_type},identity" if alert_type and alert_type != "unknown" else "identity"
    cross_refs = state.get("cross_refs", {})
    email_analysis = state.get("email_analysis") or {}
    enrichments_full = state.get("enrichments", {})

    # ── Compact cross-reference context for the AI prompt ──
    cross_ctx_lines = []

    if cross_refs.get("kev"):
        cross_ctx_lines.append("• ACTIVELY EXPLOITED CVEs (CISA KEV — confirmed real-world exploitation):")
        for k in cross_refs["kev"][:5]:
            epss = k.get("epss", {})
            tags = []
            if k.get("ransomware_use"):
                tags.append("RANSOMWARE")
            if epss.get("epss_percent"):
                tags.append(f"EPSS {epss['epss_percent']}% ({epss.get('tier','-')})")
            cross_ctx_lines.append(
                f"    - {k['cve']} · {k.get('vendor','')} {k.get('product','')} · {k.get('name','')}"
                + (f" [{', '.join(tags)}]" if tags else "")
            )

    if cross_refs.get("lolbas"):
        cross_ctx_lines.append("• LOLBAS BINARIES referenced (Windows binaries adversaries abuse for living-off-the-land):")
        for l in cross_refs["lolbas"][:8]:
            cats = ", ".join(l.get("categories", [])[:3])
            cross_ctx_lines.append(f"    - {l['name']} [{cats}]")

    if cross_refs.get("loldrivers"):
        cross_ctx_lines.append("• VULNERABLE DRIVERS (LOLDrivers — Bring-Your-Own-Vulnerable-Driver attacks):")
        for d in cross_refs["loldrivers"][:5]:
            cross_ctx_lines.append(
                f"    - {d['value']} · category={d['category']} · MITRE={d.get('mitre','-')} (match by {d['match_type']})"
            )

    if cross_refs.get("rmm_abuse"):
        cross_ctx_lines.append("• REMOTE-MANAGEMENT TOOLS detected (legitimate software heavily abused by ransomware affiliates):")
        for r in cross_refs["rmm_abuse"][:8]:
            groups = ", ".join(r.get("groups", [])[:4])
            cross_ctx_lines.append(
                f"    - {r['binary']} · vendor: {r['vendor']} · abused by: {groups}"
            )
            cross_ctx_lines.append(f"      {r.get('description', '')}")

    if cross_refs.get("suspicious_paths"):
        cross_ctx_lines.append("• SUSPICIOUS FILESYSTEM PATHS:")
        for p in cross_refs["suspicious_paths"][:6]:
            cross_ctx_lines.append(f"    - {p['label']}")

    if cross_refs.get("phishing_kits"):
        cross_ctx_lines.append("• PHISHING KIT FINGERPRINTS (URL patterns match known kits):")
        for k in cross_refs["phishing_kits"][:5]:
            cross_ctx_lines.append(f"    - {k['kit']} kit detected on URL: {k.get('url','')}")

    # ── Per-domain heuristics that came from the enrichment phase ──
    domain_signals = []
    for domain, d in (enrichments_full.get("domains") or {}).items():
        heur = (d.get("heuristics") or {})
        signals = []
        if heur.get("nrd", {}).get("is_same_day"):
            signals.append(f"REGISTERED TODAY ({heur['nrd']['age_hours']}h ago)")
        elif heur.get("nrd", {}).get("is_this_week"):
            signals.append(f"registered {heur['nrd']['age_days']}d ago")
        if heur.get("dga", {}).get("flagged"):
            signals.append(f"DGA-score={heur['dga']['score']}")
        if heur.get("idn"):
            if heur["idn"].get("homoglyphs"):
                signals.append(f"HOMOGLYPH attack (looks like '{heur['idn'].get('ascii_lookalike','?')}')")
            if heur["idn"].get("punycode"):
                signals.append(f"PUNYCODE (decodes to '{heur['idn'].get('unicode_form','?')}')")
        if (d.get("typosquat") or {}).get("brand"):
            tq = d["typosquat"]
            signals.append(f"typosquat of {tq['brand']} (score {tq['score']})")
        if (d.get("local_feeds") or {}).get("hit"):
            signals.append(f"on offline phishing blocklist ({d['local_feeds'].get('source','')})")
        if signals:
            domain_signals.append(f"    - {domain}: " + " · ".join(signals))
    if domain_signals:
        cross_ctx_lines.append("• DOMAIN HEURISTICS:")
        cross_ctx_lines.extend(domain_signals)

    # ── Per-IP "active today" + offline blocklist signals ──
    ip_signals = []
    for ip, d in (enrichments_full.get("ips") or {}).items():
        signals = []
        ra = (d.get("abuseipdb") or {}).get("recent_activity") or {}
        if ra.get("is_active_today"):
            signals.append(f"ACTIVE TODAY ({ra['hours_since_last_report']}h since last abuse report)")
        if (d.get("local_feeds") or {}).get("hit"):
            signals.append(f"offline blocklist hit ({d['local_feeds'].get('source','')})")
        if (d.get("tor") or {}).get("isExitNode"):
            signals.append("TOR exit node")
        if signals:
            ip_signals.append(f"    - {ip}: " + " · ".join(signals))
    if ip_signals:
        cross_ctx_lines.append("• IP REPUTATION HIGHLIGHTS:")
        cross_ctx_lines.extend(ip_signals)

    # ── EML phishing signals ──
    if email_analysis:
        cross_ctx_lines.append("• EMAIL ANALYSIS (raw EML detected):")
        cross_ctx_lines.append(f"    - From: {email_analysis.get('from','?')}")
        cross_ctx_lines.append(f"    - Subject: {email_analysis.get('subject','?')[:120]}")
        auth = email_analysis.get("auth_results") or {}
        if auth:
            cross_ctx_lines.append(
                f"    - Auth: SPF={auth.get('spf','?')} · DKIM={auth.get('dkim','?')} · DMARC={auth.get('dmarc','?')}"
            )
        for s in (email_analysis.get("phishing_signals") or [])[:5]:
            cross_ctx_lines.append(f"    - SIGNAL: {s}")
        if email_analysis.get("attachments"):
            cross_ctx_lines.append(f"    - {len(email_analysis['attachments'])} attachment(s) with hashes added to IOC pool")

    cross_ctx = "\n".join(cross_ctx_lines) or "(no offline cross-references hit)"

    compressed = _compress(enrichments)

    # ── Enrichment-summary header (server-side count, not LLM math) ───────────
    # The AI sees the same one-sentence line the analyst sees, so when it
    # writes the assessment it can quote the empirical baseline ("0 sources
    # flagged any IOC") rather than computing the number itself or
    # mis-stating it.
    enrichment_summary = compute_enrichment_summary(state.get("enrichments") or {})
    enrichment_summary_line = enrichment_summary["line"]

    # ── Pre-analysis known-good library evaluation ────────────────────────────
    # Build a tiny structured context (process, parent, path, cmdline, user,
    # destination_path) from raw_input + IOCs and match it against the curated
    # vendor-software patterns. Each hit is passed to the AI verbatim so the
    # threat-level assessment weights it heavily — the goal is to stop the
    # platform calling Dell SupportAssist maintenance "suspicious."
    try:
        from intel.known_good import extract_context_from_state, match as _known_good_match
        _kg_ctx = extract_context_from_state(state)
        _kg_hits = _known_good_match(_kg_ctx)
    except Exception:
        _kg_ctx, _kg_hits = {}, []
    if _kg_hits:
        known_good_lines = []
        for h in _kg_hits[:8]:
            known_good_lines.append(
                f"  • {h['vendor']} {h['product']} ({h['category']})"
            )
            known_good_lines.append(f"      WHY THIS IS NORMAL: {h['rationale']}")
            for field, pat in h["matched_fields"][:3]:
                known_good_lines.append(f"      matched on {field}: /{pat}/")
        known_good_matches = "\n".join(known_good_lines)
    else:
        known_good_matches = "(no known-good software patterns matched)"

    # ── Defender Event 1116/1117 structured parse ─────────────────────────────
    # When the input is a Defender detection log, render an authoritative
    # field-by-field block with explicit labels so the AI can't mistake the
    # legitimate triggering process (explorer.exe / svchost.exe / …) for the
    # actual malware. malware_name is the threat; infected_path is the
    # malicious artifact; process_name is just the system process that
    # encountered the file.
    defender_block = ""
    try:
        from intel.defender_parser import to_prompt_block
        defender_block = to_prompt_block(state.get("defender_parse") or {})
    except Exception:
        defender_block = ""

    # Multi-log correlation has been retired. The submitted input is
    # always treated as ONE alert; the AI reasons about relationships
    # between events inside the alert directly in its analysis prose
    # instead of emitting a separate log_correlation object.
    multi_log_block = ""
    is_multi_log = False

    # ── Analyst feedback block (re-analysis with operator context) ───────────
    # When the analyst submits feedback via the post-analysis "Provide
    # Feedback" textarea, RECON re-runs the pipeline with their findings
    # injected at the TOP of the user message and labelled as
    # "ANALYST VERDICT AND CONTEXT". The AI is instructed to treat this
    # block as authoritative and override its own inference when the two
    # conflict — the analyst has ground-truth context the AI lacks.
    analyst_feedback = (state.get("analyst_feedback") or "").strip()
    feedback_block = ""
    if analyst_feedback:
        feedback_block = (
            "## ANALYST FEEDBACK ON THE EARLIER VERDICT\n"
            "\n"
            "An analyst reviewed an earlier run of this investigation and is\n"
            "providing feedback. The analyst usually has environmental context\n"
            "(asset ownership, sanctioned tooling, ticket history) that the\n"
            "enrichment data lacks — take it seriously, but it is NOT gospel.\n"
            "\n"
            "How to handle this feedback:\n"
            "  * ACKNOWLEDGE the statement in context_impact. Quote the\n"
            "    analyst's framing so they can see you read it.\n"
            "  * If you AGREE, update threat_level / threat_level_reasoning\n"
            "    / verdict_classification / ioc_assessments accordingly and\n"
            "    cite the analyst's note as one of the drivers.\n"
            "  * If you DISAGREE — i.e. the enrichment evidence still points\n"
            "    the other way — keep your verdict and EXPLAIN WHY in\n"
            "    context_impact. Name the specific evidence (named-malware\n"
            "    hit, KEV CVE actively exploited, credential access, > 5\n"
            "    independent VT detections, etc.) that overrides the\n"
            "    analyst's framing. Do not silently ignore the feedback.\n"
            "\n"
            "ANALYST STATEMENT:\n"
            f"\"\"\"\n{analyst_feedback[:2000]}\n\"\"\"\n"
        )

    # Anti-hallucination reinforcement — the analyze input may now mix raw
    # log content with analyst commentary in the same field. Make it
    # impossible for the AI to invent facts not grounded in the input.
    no_hallucinate_block = (
        "## GROUND-TRUTH DISCIPLINE — read before you start writing\n"
        "\n"
        "The 'Alert content' below may contain a raw log, analyst commentary\n"
        "about that log, or both interleaved. Whatever the analyst typed is\n"
        "their environmental knowledge and you must respect it. FOUR rules:\n"
        "\n"
        "  1. Every claim you make in summary / key_findings / confirmed_facts\n"
        "     / ioc_assessments MUST be traceable to either (a) a literal\n"
        "     value from the input text, (b) a value from a named enrichment\n"
        "     source under ENRICHED IOC DATA, or (c) the analyst's commentary\n"
        "     in the input. If you cannot point to one of those three, DO NOT\n"
        "     write the claim.\n"
        "  2. Do not invent IPs, hashes, domains, usernames, hostnames, file\n"
        "     paths, process names, malware family names, threat actors,\n"
        "     campaign names, CVE IDs, or MITRE techniques that are not in\n"
        "     the input or in the enrichment payload. If a field would\n"
        "     normally be filled but the data is absent, set it to null /\n"
        "     empty array and say so in plain language.\n"
        "  3. Do not name a threat-intel source (VirusTotal, AbuseIPDB,\n"
        "     MalwareBazaar, etc.) unless that source actually appears in\n"
        "     the ENRICHED IOC DATA payload with a non-error value.\n"
        "  4. Do NOT write composite source citations like\n"
        "     '(MalwareBazaar, VirusTotal)' or 'corroborated by multiple\n"
        "     sources' unless the enrichment payload shows MULTIPLE sources\n"
        "     flagging the SAME IOC. Cite only the source–IOC pairs that\n"
        "     actually appear in the data.\n"
        "  5. PROSE STYLE: do not use em dashes (—) or en dashes (–). Use\n"
        "     commas, periods, or restructure. The UI strips them.\n"
    )

    result = None
    tool_call_log = []
    openai_key = config.get("OPENAI_API_KEY")
    if openai_key:
        try:
            from providers import get_provider
            provider = get_provider()

            # ════════════════════════════════════════════════════════════════════
            # ITERATIVE TOOL-CALLING LOOP
            # ════════════════════════════════════════════════════════════════════
            try:
                from agents.investigation_tools import TOOL_SCHEMAS, execute_tool, _summarize_for_trace
                # Tool-selection roundtrips ("which tool should I call next?") are a
                # routing decision the fast model handles well → fast tier. The final
                # structured assessment (the quality-critical synthesis) stays on the
                # smart model. Cuts investigation latency without dropping rigor.
                model = config.get_model()                # smart — final synthesis
                fast_model = config.get_model(fast=True)   # fast — tool loop
                type_focus = _get_type_focus(alert_type)
                system_msg = f"""{_STYLE_RULE}You are a senior MDR analyst (GCIA, GCFA, 10+ years) investigating a SOC alert.

ALERT TYPE: {alert_type}

You have a baseline of pre-enriched IOC data plus a set of TOOLS for additional lookups.
Use tools to fill gaps and verify hypotheses. DO NOT call tools for things you already see in the baseline.

Strategy:
1. Read the alert and baseline data first
2. Identify the 1-3 most suspicious or ambiguous indicators
3. Call tools to investigate them (max 6 tool calls total)
4. When you have enough evidence, STOP calling tools and produce the final JSON assessment

Tool-budget tips:
- KEV/EPSS check is cheap and high-value. Call it for any CVE mentioned.
- threat_actor_profile / find_threat_actors_by_ttps are great for attribution
- phishing_kit / rmm / lolbas are fast offline checks
- Don't call lookup_ip/domain/hash for IOCs already in the baseline. Only for new ones the AI surfaces.
{type_focus}"""
                user_msg = f"""{feedback_block}{no_hallucinate_block}
## Alert content (first 1500 chars — may include analyst commentary mixed with the raw log)
{(state.get("raw_input") or "")[:1500]}

## ENRICHMENT SUMMARY (server-side empirical baseline — quote in your summary)
{enrichment_summary_line}

## Extracted IOCs
{json.dumps(state.get('iocs', {}), indent=2)[:1200]}

## Baseline cross-references already collected (do NOT re-query these)
{cross_ctx[:2500]}

{multi_log_block}

{defender_block}

## KNOWN_GOOD MATCHES (curated vendor-software patterns)
{known_good_matches}
Treat each hit above as strong evidence the activity is legitimate vendor behaviour.
Anchor your threat_level on it unless concrete malicious evidence contradicts it.

## Behavioral / TTP indicators extracted from raw input (spec §1 — pre-enrichment)
{json.dumps(state.get('behavioral_indicators', {}).get('categories', {}), indent=2)[:2500] or "(none detected)"}
Decoded payloads (base64 / hex / unicode / fromCharCode / etc. - already deobfuscated by triage):
{json.dumps(state.get('behavioral_indicators', {}).get('decoded_payloads', []), indent=2)[:1500] or "(none)"}

CRITICAL: if the decoded-payloads block above is "(none)", DO NOT claim
the alert contains base64 / hex / encoded data, and DO NOT invent
decode results. The triage stage already ran every safe deobfuscator
against the raw input; if it found nothing, there is nothing to decode.
Phrases like "the alert contains a base64 payload that decodes to..."
or "we detected encoded data" are FORBIDDEN unless the decoded-payloads
list above actually has content. When it's empty, say nothing about
encoding. If you must reference the raw input shape, quote it
literally — never describe its "encoded contents".

## Deterministic confidence scores per IOC (spec §2 — independent of your assessment)
{json.dumps({k: {"score": v.get("score"), "verdict": v.get("verdict"),
                  "top_factors": [(f["factor"], f["points"]) for f in (v.get("factors") or [])[:4]]}
              for k, v in (state.get('confidence_scores') or {}).items()}, indent=2)[:2500] or "(none scored)"}

## Baseline enrichment summary (do NOT re-query these IPs/domains/hashes)
{json.dumps(compressed, indent=2)[:3500]}

Investigate this alert. Use tools as needed to fill gaps. When done, produce the final JSON assessment."""

                messages = [
                    {"role": "system", "content": system_msg},
                    {"role": "user",   "content": user_msg},
                ]

                # Fewer roundtrips: each tool-selection roundtrip is ~15s on the
                # large context, so cap iterations (was 6, then 3). 2 is enough —
                # the baseline already enriched every IOC; tools just fill small gaps,
                # and the final synthesis runs regardless after the loop.
                max_iterations = 2
                for iteration in range(max_iterations):
                    resp = await provider.complete(
                        model=fast_model,   # tool-selection roundtrip → fast tier
                        messages=messages,
                        tools=TOOL_SCHEMAS,
                        tool_choice="auto",
                        temperature=0.1,
                        max_tokens=800,
                    )
                    if resp.error:
                        raise RuntimeError(resp.error)
                    # Normalised tool_calls are list[{id, name, arguments(dict)}].
                    # When tools fired, re-encode them as OpenAI message shape for
                    # the next round-trip (the provider's `messages` param accepts
                    # this directly for OpenAI/Azure; other providers translate).
                    if resp.tool_calls:
                        messages.append({
                            "role":      "assistant",
                            "content":   resp.message or "",
                            "tool_calls": [{"id": tc["id"], "type": "function",
                                            "function": {"name": tc["name"],
                                                         "arguments": json.dumps(tc["arguments"])}}
                                           for tc in resp.tool_calls],
                        })

                        # Execute this iteration's tool calls CONCURRENTLY — they're
                        # independent and some do network I/O, so running them in
                        # parallel instead of one-await-at-a-time is a large speedup.
                        async def _run_tool(tc):
                            args = tc.get("arguments") or {}
                            res = await execute_tool(tc["name"], args, config)
                            return tc, args, res

                        outcomes = await asyncio.gather(*[_run_tool(tc) for tc in resp.tool_calls])
                        for tc, args, tool_result in outcomes:
                            summary = _summarize_for_trace(tc["name"], tool_result)
                            tool_call_log.append({
                                "iteration": iteration,
                                "tool":      tc["name"],
                                "args":      args,
                                "summary":   summary,
                            })
                            # Append a trace entry so the UI shows the AI's tool calls live
                            tool_trace = {
                                "agent":     "investigation",
                                "type":      "tool_call",
                                "tool":      tc["name"],
                                "args":      args,
                                "summary":   summary,
                                "iteration": iteration,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            }
                            trace.append(tool_trace)
                            await _emit(tool_trace)
                            # Feed the tool result back into the conversation (cap size)
                            messages.append({
                                "role":          "tool",
                                "tool_call_id":  tc["id"],
                                "content":       json.dumps(tool_result, default=str)[:2500],
                            })
                        # Continue the loop — AI may call more tools
                        continue

                    # No more tool calls — model is done investigating, ask for structured JSON
                    break

                # Final structured-output pass — spec §5 schema
                analyst_answers = state.get("analyst_answers") or {}
                answers_block = ""
                if analyst_answers:
                    qa = "\n".join(f"  Q: {q}\n  A: {a}" for q, a in analyst_answers.items())
                    answers_block = (
                        "\n\n## ANALYST PROVIDED CONTEXT (Phase 2)\n"
                        "The analyst answered your earlier clarifying questions. "
                        "Incorporate this into your assessment and populate context_impact "
                        "explaining how their answers changed your conclusions:\n"
                        f"{qa}\n"
                    )

                # Tool loop is done — the final structured-JSON synthesis is the
                # single longest roundtrip. Emit a live ping so the pipeline shows
                # forward progress instead of stalling on the spinner.
                await _emit({
                    "agent":     "investigation",
                    "type":      "tool_call",
                    "tool":      "synthesize",
                    "args":      {},
                    "summary":   "Correlating all signals into the final assessment…",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

                # The final assessment is split into two field-groups generated by
                # CONCURRENT calls on the smart model — verdict/narrative + structured
                # findings — then merged. Halves the wall-clock of the longest stage
                # while keeping every field (downstream readers default missing keys).
                verdict_instr = (
                    f"{answers_block}"
                    "Now output PART 1 of your final assessment as strict JSON — the verdict and "
                    "narrative. Apply the EVIDENCE STANDARD from the system prompt:\n\n"
                    "  • HIGH or CRITICAL requires AT LEAST ONE concrete malicious-evidence point\n"
                    "    (known-bad hash, named malware family, lateral movement, credential\n"
                    "    access, confirmed unauthorized access, malicious infrastructure callout).\n"
                    "  • If the enrichment_summary above says '0 sources flagged any IOC as\n"
                    "    malicious', the DEFAULT-BENIGN RULE from PRINCIPLE 3 applies — you may\n"
                    "    note patterns and recommend monitoring, but you may NOT call the activity\n"
                    "    'suspicious' or 'potentially malicious' without a source backing it.\n"
                    "  • If the assessment_basis below lists ONLY benign indicators (known-good\n"
                    "    library hit, clean hash across all sources, legitimate parent process,\n"
                    "    expected service account, recognised vendor directory) the threat_level\n"
                    "    MUST be INFORMATIONAL or LOW.\n"
                    "  • Use CALIBRATED LANGUAGE from PRINCIPLE 8: 'consistent with X based on Y'\n"
                    "    instead of 'this IS X'; 'insufficient evidence to attribute to a\n"
                    "    specific threat actor' when the data doesn't support attribution.\n"
                    "  • SEPARATE confirmed_facts from analysis_assessment per PRINCIPLE 7 —\n"
                    "    both are valuable, never blur them.\n\n"
                    "ANTI-DUPLICATION RULE (hard): the analyst reads ALL four\n"
                    "prose fields below stacked on the same card. Each MUST contribute\n"
                    "distinct information. Do NOT paraphrase the same fact across\n"
                    "fields. If you find yourself writing 'the deletion of the\n"
                    "PowerShell history file by user X is not suspicious' in\n"
                    "analysis_assessment after writing 'user X deleted the\n"
                    "PowerShell history file. Not malicious.' in summary, you have\n"
                    "duplicated. Cut one. The four fields are like four columns of a\n"
                    "table - each holds a DIFFERENT slice:\n"
                    "    summary           = verdict + recommended next step\n"
                    "    confirmed_facts   = atomic observable facts (no judgement)\n"
                    "    analysis_assessment = pattern-match read (no facts, no verdict)\n"
                    "    threat_level_reasoning = why this level (cite facts by number)\n"
                    "Cross-field overlap > 30%% is a quality failure.\n\n"

                    "Output ONLY these keys (nothing else):\n"
                    "  summary (MAX 2 sentences. STRICT FORMAT: sentence 1 = the\n"
                    "    verdict in plain English; sentence 2 = the recommended next\n"
                    "    step. NEVER restate the parsed log fields - the analyst sees\n"
                    "    them above. NEVER overlap with analysis_assessment or\n"
                    "    threat_level_reasoning. Examples of GOOD summaries:\n"
                    "      'Routine admin maintenance; no action required.'\n"
                    "      'Consistent with Dell SupportAssist scheduled task; clear.'\n"
                    "      'Possible credential-spray attempt; investigate user X.'\n"
                    "    Examples of FORBIDDEN summaries (these restate the log or\n"
                    "    duplicate analysis_assessment):\n"
                    "      'On Jun 4 at 16:27, user X deleted file Y from path Z.'\n"
                    "      'The deletion of file Y by user X is not inherently suspicious.'\n"
                    "    If you have nothing to add beyond the enrichment_summary line,\n"
                    "    emit that line ALONE.),\n"
                    "  threat_level (CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL),\n"
                    "  confirmed_facts (3-6 SHORT atomic facts - statements directly\n"
                    "    traceable to the enrichment data or raw log. Anyone reading\n"
                    "    the same data could verify each one. NO interpretation. NO\n"
                    "    verdict words ('suspicious', 'benign', 'malicious'). Just\n"
                    "    what happened. PRINCIPLE 7 governs this field.),\n"
                    "  analysis_assessment (2-5 SHORT sentences - the PATTERN read.\n"
                    "    Does this match a known attack chain? Does it match a known\n"
                    "    vendor / admin workflow? What's the comparable case from the\n"
                    "    analyst's experience? Use CALIBRATED LANGUAGE per PRINCIPLE 8\n"
                    "    ('consistent with' / 'overlap with' / 'insufficient evidence\n"
                    "    to attribute'). NO restating confirmed_facts. NO restating the\n"
                    "    summary verdict. ONLY the pattern-recognition layer.),\n"
                    "  assessment_basis (array of 2-5 SHORT sentences - the SUBSET of\n"
                    "    confirmed_facts that drove the threat_level decision.),\n"
                    "  threat_level_reasoning (REQUIRED - 2-4 SENTENCES explaining\n"
                    "    exactly WHY this threat_level was chosen. Reference the\n"
                    "    confirmed_facts by their content; state what drove it UP and\n"
                    "    what kept it from being higher/lower. Use the threat_level\n"
                    "    value (CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL) by\n"
                    "    name. Examples:\n"
                    "      'MEDIUM because the hash has no TI hits and the process is\n"
                    "       a known system tool, but the destination IP has 3 abuse\n"
                    "       reports - one corroborating malicious signal kept it from\n"
                    "       LOW.'\n"
                    "      'LOW because every TI source returned clean and the\n"
                    "       behavior matches the customer's documented admin workflow.\n"
                    "       Not INFORMATIONAL because the action class (history-file\n"
                    "       deletion) is one analysts customarily verify with the\n"
                    "       account owner.'\n"
                    "    NEVER leave empty. NEVER overlap with the summary's verdict\n"
                    "    sentence - that's the WHAT, this is the WHY.),\n"
                    "  confidence (0.0-1.0), confidence_basis,\n"
                    "  malware_family (specific family name or null — only set when AT LEAST\n"
                    "    ONE reputation source named the family; otherwise null and explain\n"
                    "    the absence in analysis_assessment),\n"
                    "  threat_actor ({name, confidence} for APT/eCrime group or null — only\n"
                    "    when the TTP overlap is strong enough that confidence >= medium;\n"
                    "    otherwise null and note 'insufficient evidence to attribute' in\n"
                    "    analysis_assessment),\n"
                    "  campaign (known campaign name or null),\n"
                    "  attack_stage (reconnaissance|weaponization|delivery|exploitation|\n"
                    "    installation|command_and_control|actions_on_objectives|null when benign),\n"
                    "  attack_chain_hypothesis,\n"
                    "  chain_of_thought (array of 3-5 reasoning steps),\n"
                    "  verdict_classification (MALICIOUS|LIKELY_MALICIOUS|AMBIGUOUS|\n"
                    "    LIKELY_BENIGN|BENIGN_FALSE_POSITIVE),\n"
                    "  needs_more_enrichment (bool), tor_traffic (bool), attribution_hints,\n"
                    "  false_positive_check (which FP patterns you considered + ruled out — when\n"
                    "    a known-good library hit is present, cite it here),\n"
                    "  context_impact (how analyst answers, if any, changed the assessment; '' if none).\n\n"
                    "No markdown fences, no commentary outside the JSON."
                )
                findings_instr = (
                    "Now output PART 2 of your final assessment as strict JSON — the structured "
                    "findings. Cite specific evidence; do not be vague. Keep every field TIGHT: "
                    "short phrases, not paragraphs; one brief entry per CTI-framework field.\n\n"
                    "ANTI-DUPLICATION RULE (hard, same as PART 1):\n"
                    "Each finding / signal / note must contribute DISTINCT information.\n"
                    "Do NOT paraphrase the same fact across key_findings,\n"
                    "correlated_signals, and analyst_notes. Cross-field overlap > 30%%\n"
                    "is a quality failure. The fields hold different SLICES:\n"
                    "    key_findings       = atomic signal-cite pairs ('X seen,\n"
                    "                          source: Y'); one finding per signal\n"
                    "    correlated_signals = multi-signal patterns ('X + Y together\n"
                    "                          mean Z'); requires >= 2 signals each\n"
                    "    recommended_actions= what to DO next (verbs)\n"
                    "    analyst_notes      = senior-analyst CONTEXT for the junior\n"
                    "                          tier (history, customer-specific\n"
                    "                          patterns, decision-tree shortcuts).\n"
                    "                          NEVER a verdict restatement.\n\n"

                    "Output ONLY these keys (nothing else):\n"
                    "  key_findings (3-7 findings, each ONE distinct signal -> source\n"
                    "    pair. Format: 'OBSERVATION (source: SOURCE_NAME)'. NEVER\n"
                    "    repeat a confirmed_fact verbatim and NEVER paraphrase another\n"
                    "    finding. Examples of GOOD findings:\n"
                    "      'AbuseIPDB rates 185.220.101.45 at 92%% confidence with\n"
                    "       127 reports (source: AbuseIPDB)'\n"
                    "      'Hash 7c2f... is signed by Microsoft and matches the\n"
                    "       SCCM client (source: known_good_baseline + Authenticode)'\n"
                    "    Examples of FORBIDDEN findings (these duplicate other\n"
                    "    fields or each other):\n"
                    "      'User X deleted file Y' (that's a confirmed_fact)\n"
                    "      'The action appears suspicious' (no signal cited)\n"
                    "      'AbuseIPDB flagged the IP' THEN 'The IP was reported on\n"
                    "       AbuseIPDB' (same finding twice)),\n"
                    "  correlated_signals (array of {observation, supporting_signals}.\n"
                    "    REQUIRES >= 2 supporting_signals - this field is for\n"
                    "    MULTI-signal patterns, not single observations. Skip\n"
                    "    entirely (empty array) when nothing multi-signal exists.),\n"
                    "  ioc_assessments (array of {ioc, type, verdict, reason, evidence_source}),\n"
                    "  mitre_techniques (array of 'Txxxx[.yyy] - Name'),\n"
                    "  mitre_evidence (array of {technique, evidence, confidence}),\n"
                    "  recommended_actions (array of {action, priority, timeframe} where\n"
                    "    priority is IMMEDIATE|SHORTTERM|LONGTERM),\n"
                    "  analyst_notes (1-2 SHORT paragraphs of senior-analyst CONTEXT\n"
                    "    for the junior tier. Allowed content: customer-specific\n"
                    "    history ('this account uses RMM from Azure regularly'),\n"
                    "    decision-tree shortcuts ('if the AppLocker policy is on,\n"
                    "    this would have blocked'), or cross-case patterns ('we saw\n"
                    "    this same dropper SHA on the Acme case last week').\n"
                    "    FORBIDDEN content: restating the verdict, paraphrasing\n"
                    "    confirmed_facts, repeating key_findings. If you have no\n"
                    "    distinct context to add, emit an empty string - that is\n"
                    "    preferable to padding with restated content.),\n"
                    "  clarifying_questions (2-4 questions whose answers would MATERIALLY change the\n"
                    "    assessment — host role, user privilege, related alerts, business context,\n"
                    "    scope; only if not derivable from enrichment; empty list if none),\n"
                    "  DO NOT emit a log_correlation field. The submitted input is\n"
                    "    a SINGLE alert. Reason about relationships between events\n"
                    "    inside the alert directly in your analyst_notes / key_findings\n"
                    "    prose — never as a separate 'log correlation' object and\n"
                    "    never with phrasing like 'two events were correlated' or\n"
                    "    'both events occurred' as if the analyst pasted multiple\n"
                    "    logs. The alert may contain multiple pieces of evidence\n"
                    "    (multiple processes, IOCs, timestamps); treat them as parts\n"
                    "    of one event, not as separate logs.\n"
                    "\nNo markdown fences, no commentary outside the JSON."
                )
                # Probing questions get their OWN call so they always have token
                # headroom — when bundled into the findings half they were the last
                # field generated and got truncated away, leaving Ask RECON empty.
                #
                # Anchoring rule (the FORBID + REQUIRE pair) is what stops the AI
                # from emitting the same 5-question template across investigations.
                # Without it, low temperature + a generic prompt = same questions
                # every run; with it, each question is forced to cite a specific
                # IOC / username / process / field from THIS investigation, so the
                # output is structurally unable to be templated.
                probing_instr = (
                    "Now output ONLY the investigation's probing questions as strict JSON. "
                    "Produce 3-5 questions — mix surrounding-activity, false-positive probes, "
                    "true-positive probes, context, and lateral-movement checks. Each MUST be "
                    "specific and answerable by checking a SIEM/EDR/ticket or asking the customer.\n\n"
                    "ANCHORING RULE — read carefully:\n"
                    "Every question MUST reference at least ONE specific artefact from THIS "
                    "investigation by name: an IOC value (IP/domain/hash/URL), a username/UPN, "
                    "a hostname, a process name, a command-line fragment, a registry path, an "
                    "alert/rule name, or a parsed field from the raw input. Never write a "
                    "generic question that could apply to any alert.\n\n"
                    "FORBIDDEN (too generic, do not produce):\n"
                    "  * \"What did the user do before this alert?\"\n"
                    "  * \"Has this hash appeared in other investigations?\"\n"
                    "  * \"Is this activity expected?\"\n"
                    "REQUIRED instead (cites specifics from THIS alert):\n"
                    "  * \"What did <user 'jsmith@contoso.com'> do in the 30 minutes before "
                    "the 14:02 UTC sign-in from 185.220.101.45?\"\n"
                    "  * \"Has SHA256 7c2f… been seen on any other endpoint in the last 7 days?\"\n"
                    "  * \"Is the parent process for powershell.exe -enc … expected to be "
                    "msbuild.exe on host DESKTOP-04?\"\n\n"
                    "Output ONLY this key:\n"
                    "  probing_questions (array of {question, why_asking, if_yes_means, if_no_means}),\n"
                    "    where if_yes_means / if_no_means state the verdict path each answer points to.\n\n"
                    "No markdown fences, no commentary outside the JSON."
                )

                async def _synth(instruction: str, max_tokens: int, temperature: float = 0.1):
                    resp = await provider.complete(
                        model=model,   # smart — quality-critical synthesis
                        messages=messages + [{"role": "user", "content": instruction}],
                        response_format={"type": "json_object"},
                        temperature=temperature,
                        max_tokens=max_tokens,
                    )
                    if resp.error:
                        return {}
                    # Lenient parse: even if the half is truncated, keep its
                    # completed fields rather than discarding the whole half.
                    return _loads_lenient(resp.message)

                # All three synthesis calls run at temperature 0.1 — low enough
                # to reduce creative speculation, high enough to avoid the
                # robotic output that temperature 0.0 produces. Variation in
                # the probing-questions surface wording is anchored by the
                # ANCHORING RULE in the probing_instr prompt (each question
                # MUST cite a specific IOC / username / process from THIS
                # alert), not by temperature variance.
                part_a, part_b, part_c = await asyncio.gather(
                    _synth(verdict_instr, 1300),
                    _synth(findings_instr, 1900),
                    _synth(probing_instr, 1100, temperature=0.1),
                    return_exceptions=True,
                )
                result = {}
                for part in (part_a, part_b, part_c):
                    if isinstance(part, dict):
                        result.update(part)
                if not result:
                    # All halves failed → surface to the single-shot fallback below
                    raise RuntimeError(f"synthesis failed: {part_a!r} / {part_b!r} / {part_c!r}")

            except Exception as e:
                # Tool-calling path failed — fall back to the original single-shot prompt
                import traceback
                _log.warning("TOOL-CALLING FAILED, falling back: %s", e)
                traceback.print_exc()
                tool_call_log.append({"tool": "_fallback", "summary": f"tool-calling failed: {str(e)[:120]}"})
                # Prepend the Defender field-parse block to the raw input so the
                # single-shot prompt sees the authoritative labels too.
                _raw_for_fallback = (state.get("raw_input") or "")[:2000]
                if defender_block:
                    _raw_for_fallback = defender_block + "\n\n" + _raw_for_fallback
                resp = await provider.complete(
                    model=config.get_model(),   # smart
                    messages=[{"role": "user", "content": PROMPT.format(
                        raw_input=_raw_for_fallback[:2400],
                        enrichments=json.dumps(compressed, indent=2)[:5000] or "(empty — log-only analysis required)",
                        alert_type=alert_type,
                        triage_score=round(triage_score, 2),
                        cross_ctx=cross_ctx or "(none)",
                        known_good_matches=known_good_matches,
                        enrichment_summary_line=enrichment_summary_line,
                    )}],
                    max_tokens=3000,   # full single-shot schema needs real headroom
                    temperature=0.1,
                    response_format={"type": "json_object"},
                )
                result = {} if resp.error else _loads_lenient(resp.message)

        except Exception as outer_e:
            import traceback
            _log.error("OUTER FAILURE: %s", outer_e)
            traceback.print_exc()
            result = None

    if result is None:
        result = {
            "threat_level": "INFORMATIONAL",   # was MEDIUM — see graceful-degradation rule
            "threat_level_reasoning": (
                "Threat level defaulted to INFORMATIONAL because the AI provider "
                "call failed before producing a verdict. The shown level is a "
                "graceful-degradation fallback, not an AI-derived rating. "
                "Re-run the investigation after restoring the AI provider key."
            ),
            "confidence": 0.0,
            "needs_more_enrichment": False,
            "summary": ("AI investigation unavailable — your enrichment data was still "
                        "collected. The threat level shown is a fallback, not an AI verdict. "
                        "Configure or fix your AI provider key in Settings to enable AI analysis."),
            "confirmed_facts": [enrichment_summary_line],
            "analysis_assessment": [
                "AI analysis unavailable — no analyst assessment generated.",
            ],
            "assessment_basis": [
                "AI provider call failed — no AI verdict produced.",
                "Threat level defaulted to INFORMATIONAL pending AI availability.",
            ],
            "chain_of_thought": ["OpenAI key not configured or call failed. Review enrichment data manually."],
            "key_findings": ["Automated AI analysis unavailable. See the enrichment data tab for raw signals."],
            "ioc_assessments": [],
            "mitre_techniques": [],
            "attack_patterns": [],
            "geo_highlights": [],
            "recommended_actions": [
                "Open Settings and verify your AI provider key (OPENAI_API_KEY).",
                "Review the enrichment data manually to assess this alert.",
            ],
            "tor_traffic": False,
            "attribution_hints": None,
            "ai_unavailable": True,
        }

    # Attach the server-computed enrichment summary to the result so the
    # response builder + frontend always have the empirical baseline,
    # even if the AI dropped or mangled it in the summary text.
    result["enrichment_summary"] = enrichment_summary

    # ── Calibration safety-net ────────────────────────────────────────────────
    # Shared with file_ai_analyst, response.py, email_composer via
    # intel/calibration.py. Belt-and-braces enforcement of the in-prompt
    # rule: HIGH/CRITICAL with only benign markers in assessment_basis
    # downshifts to LOW.
    try:
        from intel.calibration import downshift_if_benign_only
        downshift_if_benign_only(result, label="RECON calibration")
    except Exception:
        pass

    # ── Backfill / normalise threat_level_reasoning ──────────────────────────
    # Two problems to fix here:
    #   (a) The AI sometimes omits the field entirely. The frontend renders
    #       the reasoning paragraph directly under the badge with no toggle,
    #       so an empty value leaves the analyst with no justification.
    #   (b) The AI sometimes writes a sentence whose stated level disagrees
    #       with its own threat_level field — e.g. threat_level="MEDIUM" but
    #       reasoning starts with "This alert is INFORMATIONAL.". The badge
    #       and the paragraph must agree, otherwise the analyst gets two
    #       contradicting answers in the same component.
    _lvl         = (result.get("threat_level") or "INFORMATIONAL").upper()
    _enrich_line = (result.get("enrichment_summary") or {}).get("line") or ""
    _basis_list  = [b for b in (result.get("assessment_basis") or []) if b]
    _findings    = [f for f in (result.get("key_findings") or []) if f]
    _summary     = (result.get("summary") or "").strip()
    _ai_reason   = (result.get("threat_level_reasoning") or "").strip()

    # Detect the contradiction described above. Match "This alert is X" /
    # "Threat level set to X" / "is X because" patterns at the start of the
    # AI's reasoning string and compare against _lvl.
    _LEVEL_WORDS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
    _stated = ""
    if _ai_reason:
        import re as _re
        m = _re.search(
            r"\b(?:This alert is|Threat level set to|This is|is rated|rated as|level is|threat_level is)\s+"
            r"(CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL)\b",
            _ai_reason, _re.IGNORECASE,
        )
        if m:
            _stated = m.group(1).upper()

    _contradicts = bool(_stated and _stated != _lvl)
    _empty       = not _ai_reason

    if _empty or _contradicts:
        parts = [f"This alert is {_lvl}."]
        if _basis_list:
            parts.append("Driven by: " + "; ".join(str(b) for b in _basis_list[:2]) + ".")
        elif _findings:
            parts.append("Driven by: " + "; ".join(str(f)[:140] for f in _findings[:2]) + ".")
        elif _summary:
            parts.append(_summary[:200])
        if _enrich_line and _enrich_line not in " ".join(parts):
            parts.append(_enrich_line)
        if len(parts) == 1:
            # Truly nothing else to say — explain why the level is what it is.
            if _lvl in ("INFORMATIONAL", "LOW"):
                parts.append("No enrichment source flagged any IOC and no "
                             "behavioural signal exceeded the evidence threshold, "
                             "so the alert did not warrant a higher rating.")
            else:
                parts.append("The AI did not return an explicit rationale for "
                             "this rating; review the confirmed facts and "
                             "assessment basis before acting on the level.")
        # When the AI's own reasoning contradicted the badge, preserve the
        # downstream sentences (they often have useful detail like
        # "Impossible travel from Charter Communications residential ISP")
        # by appending whatever followed the contradicting opener.
        if _contradicts and _ai_reason:
            tail = _ai_reason.split(".", 1)[1].strip() if "." in _ai_reason else ""
            if tail and tail not in " ".join(parts):
                parts.append(tail)
        result["threat_level_reasoning"] = " ".join(parts)

    trace.append({
        "agent": "investigation",
        "status": "complete",
        "summary": result.get("summary", ""),
        "threat_level": result.get("threat_level"),
        "confidence": result.get("confidence"),
        "mitre_count": len(result.get("mitre_techniques", [])),
        "needs_more": result.get("needs_more_enrichment", False),
        "tool_calls": len(tool_call_log),
        "elapsed_ms": int((time.perf_counter() - _t_start) * 1000),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    # Spec §7 — geopolitical context derived from enrichment + investigation
    geopolitical = None
    try:
        from intel.geopolitical import compute_geopolitical_context
        geopolitical = compute_geopolitical_context(
            enrichments=state.get("enrichments", {}),
            threat_actor=result.get("threat_actor"),
        )
    except Exception as _e:
        geopolitical = {"error": str(_e)}

    # Multi-log feature retired — always strip any log_correlation the AI
    # may still emit. The submitted input is treated as a single alert.
    _log_correlation = None

    # MISP galaxy augmentation — when the AI named a threat_actor or
    # malware_family, look it up in the bundled galaxy clusters and
    # attach the canonical record (aliases, country, sectors, refs) so
    # the analyst has cross-referenced context, not just the AI's loose
    # naming. Fully optional: missing galaxies just mean None matches.
    try:
        from intel.misp_galaxies import lookup_actor, lookup_malware
        ta = result.get("threat_actor")
        if isinstance(ta, dict) and ta.get("name"):
            gx = lookup_actor(ta["name"])
            if gx:
                ta["misp_galaxy"] = gx
        mf = result.get("malware_family")
        if isinstance(mf, str) and mf:
            gx = lookup_malware(mf)
            if gx:
                result["malware_family_galaxy"] = gx
    except Exception as _e:
        _log.debug("misp_galaxy augmentation failed: %s", _e)

    # Belt-and-braces: even with the OUTPUT STYLE rule in every prompt,
    # the LLM occasionally still emits em-dashes in key_findings /
    # summary / threat_level_reasoning. Walk every string in `result`
    # and strip them before the data leaves this agent.
    try:
        from intel.email_composer import _strip_em_dashes as _sed

        def _walk(obj):
            if isinstance(obj, str):
                return _sed(obj)
            if isinstance(obj, dict):
                return {k: _walk(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_walk(v) for v in obj]
            return obj
        result = _walk(result)
    except Exception:
        pass

    # Server-side prose validation. Enforces the prompt rules
    # mechanically so duplicated summary / analysis_assessment / key_
    # findings never reach the analyst, regardless of which client
    # consumes the result (frontend, MCP, email composer, /api/analyze
    # JSON consumers). Strips forbidden keys, caps summary at 2
    # sentences, drops paraphrased duplicates across fields. See
    # intel/prose_validator.py for the contract.
    try:
        from intel.prose_validator import validate_investigation_result
        result = validate_investigation_result(result)
    except Exception as _e:
        _log.debug("prose validation failed (non-fatal): %s", _e)

    return {
        **state,
        "investigation_result":   result,
        "mitre_techniques":       result.get("mitre_techniques", []),
        "threat_level":           result.get("threat_level", "MEDIUM"),
        "confidence":             result.get("confidence", 0.5),
        "needs_more_enrichment":  result.get("needs_more_enrichment", False),
        "clarifying_questions":   result.get("clarifying_questions", []),
        "context_impact":         result.get("context_impact", ""),
        "malware_family":         result.get("malware_family"),
        "threat_actor":           result.get("threat_actor"),
        "campaign":               result.get("campaign"),
        "attack_stage":           result.get("attack_stage"),
        "geopolitical":           geopolitical,
        "tool_call_log":          tool_call_log,
        "log_correlation":        _log_correlation,
        "agent_trace":            trace,
    }
