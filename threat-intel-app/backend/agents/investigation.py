"""
Investigation Agent — chain-of-thought reasoning over enriched IOC data.
Reads AI config at call time from config manager.
"""

import asyncio
import json
import re as _re
from datetime import datetime, timezone


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
            "shodan_ports": (d.get("shodan") or {}).get("ports"),
            "shodan_vulns": (d.get("shodan") or {}).get("vulns"),
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
  2. Sandbox verdict (Hybrid Analysis / ANY.RUN if available)
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


PROMPT = """You are a senior threat intelligence analyst (GCIA, GCFA, GCTI; 10+ years SOC + MDR
experience). You are the investigation step in an autonomous SOC pipeline. Your job is to
CORRELATE every signal below into a coherent threat narrative — not to describe each one
in isolation. Connect the dots: which signals reinforce each other? Which contradict?
What's the simplest hypothesis that explains everything?

═══════════════════════════════════════════════════════════════════════════════════
INPUT CONTEXT
═══════════════════════════════════════════════════════════════════════════════════

RAW LOG / ALERT (first 2000 chars — analyze the SEMANTIC content too, not just the IOCs):
{raw_input}

ALERT TYPE          : {alert_type}
TRIAGE SCORE        : {triage_score} (0-1, higher = more suspicious)

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
  "confidence": <float 0.0-1.0>,
  "confidence_basis": "<one sentence: WHY this confidence level given the evidence>",
  "needs_more_enrichment": <true|false>,
  "missing_data": "<if confidence<0.6, what specific data would raise it>",
  "summary": "<2-3 sentence executive summary that synthesizes the correlated picture, NOT a list>",
  "attack_chain_hypothesis": "<one-paragraph narrative: how this attack likely unfolds, mapping signals to phases>",
  "chain_of_thought": [
    "<step 1 of your reasoning, citing specific evidence>",
    "<step 2 building on step 1>",
    "<step 3 reaching a conclusion>"
  ],
  "key_findings": [
    "<finding 1 — must cite specific evidence (e.g. 'AbuseIPDB 92% + ipsum blocklist + same-day domain')>",
    "<finding 2>",
    "<finding 3>"
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
                system_msg = f"""You are a senior MDR analyst (GCIA, GCFA, 10+ years) investigating a SOC alert.

ALERT TYPE: {alert_type}

You have a baseline of pre-enriched IOC data plus a set of TOOLS for additional lookups.
Use tools to fill gaps and verify hypotheses — DO NOT call tools for things you already see in the baseline.

Strategy:
1. Read the alert and baseline data first
2. Identify the 1-3 most suspicious or ambiguous indicators
3. Call tools to investigate them (max 6 tool calls total)
4. When you have enough evidence, STOP calling tools and produce the final JSON assessment

Tool-budget tips:
- KEV/EPSS check is cheap and high-value — call it for any CVE mentioned
- threat_actor_profile / find_threat_actors_by_ttps are great for attribution
- phishing_kit / rmm / lolbas are fast offline checks
- Don't call lookup_ip/domain/hash for IOCs already in the baseline — only for new ones the AI surfaces
{type_focus}"""
                user_msg = f"""## Alert content (first 1500 chars)
{(state.get("raw_input") or "")[:1500]}

## Extracted IOCs
{json.dumps(state.get('iocs', {}), indent=2)[:1200]}

## Baseline cross-references already collected (do NOT re-query these)
{cross_ctx[:2500]}

## Behavioral / TTP indicators extracted from raw input (spec §1 — pre-enrichment)
{json.dumps(state.get('behavioral_indicators', {}).get('categories', {}), indent=2)[:2500] or "(none detected)"}
Decoded base64 payloads from PowerShell/etc:
{json.dumps(state.get('behavioral_indicators', {}).get('decoded_payloads', []), indent=2)[:1500] or "(none)"}

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
                    "narrative. Be definitive — if the evidence points to a specific malware family, "
                    "threat actor, or campaign, name it. Do not hedge unnecessarily.\n\n"
                    "Output ONLY these keys (nothing else):\n"
                    "  summary (2-3 sentence executive summary for a customer-facing report),\n"
                    "  threat_level (CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL),\n"
                    "  confidence (0.0-1.0), confidence_basis,\n"
                    "  malware_family (specific family name or null — e.g. 'Cobalt Strike', 'Emotet'),\n"
                    "  threat_actor ({name, confidence} for APT/eCrime group or null),\n"
                    "  campaign (known campaign name or null),\n"
                    "  attack_stage (reconnaissance|weaponization|delivery|exploitation|\n"
                    "    installation|command_and_control|actions_on_objectives),\n"
                    "  attack_chain_hypothesis,\n"
                    "  chain_of_thought (array of 3-5 reasoning steps),\n"
                    "  verdict_classification (MALICIOUS|LIKELY_MALICIOUS|AMBIGUOUS|\n"
                    "    LIKELY_BENIGN|BENIGN_FALSE_POSITIVE),\n"
                    "  needs_more_enrichment (bool), tor_traffic (bool), attribution_hints,\n"
                    "  false_positive_check (which FP patterns you considered + ruled out),\n"
                    "  context_impact (how analyst answers, if any, changed the assessment; '' if none).\n\n"
                    "No markdown fences, no commentary outside the JSON."
                )
                findings_instr = (
                    "Now output PART 2 of your final assessment as strict JSON — the structured "
                    "findings. Cite specific evidence; do not be vague. Keep every field TIGHT: "
                    "short phrases, not paragraphs; one brief entry per CTI-framework field.\n\n"
                    "Output ONLY these keys (nothing else):\n"
                    "  key_findings (3-7 findings; each cites the supporting enrichment source),\n"
                    "  correlated_signals (array of {observation, supporting_signals}),\n"
                    "  ioc_assessments (array of {ioc, type, verdict, reason, evidence_source}),\n"
                    "  mitre_techniques (array of 'Txxxx[.yyy] - Name'),\n"
                    "  mitre_evidence (array of {technique, evidence, confidence}),\n"
                    "  recommended_actions (array of {action, priority, timeframe} where\n"
                    "    priority is IMMEDIATE|SHORTTERM|LONGTERM),\n"
                    "  analyst_notes (1-2 paragraphs of senior-analyst context for junior tier),\n"
                    "  clarifying_questions (2-4 questions whose answers would MATERIALLY change the\n"
                    "    assessment — host role, user privilege, related alerts, business context,\n"
                    "    scope; only if not derivable from enrichment; empty list if none).\n\n"
                    "No markdown fences, no commentary outside the JSON."
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

                # Generous per-half budgets so the full schema isn't truncated —
                # the findings half (lists + CTI frameworks) is the heavy one.
                # Both run concurrently, so wall-time ≈ the findings call, still
                # faster than one complete ~3500-token single call.
                #
                # Probing questions get a higher temperature (0.55 vs 0.1) so
                # surface wording varies between runs — combined with the
                # evidence-anchoring rule in the prompt, this stops "second
                # analysis hits the same probe template" by making each call
                # structurally and stylistically unique.
                part_a, part_b, part_c = await asyncio.gather(
                    _synth(verdict_instr, 1300),
                    _synth(findings_instr, 1900),
                    _synth(probing_instr, 1100, temperature=0.55),
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
                print(f"[investigation] TOOL-CALLING FAILED, falling back: {e}")
                traceback.print_exc()
                tool_call_log.append({"tool": "_fallback", "summary": f"tool-calling failed: {str(e)[:120]}"})
                resp = await provider.complete(
                    model=config.get_model(),   # smart
                    messages=[{"role": "user", "content": PROMPT.format(
                        raw_input=(state.get("raw_input") or "")[:2000],
                        enrichments=json.dumps(compressed, indent=2)[:5000] or "(empty — log-only analysis required)",
                        alert_type=alert_type,
                        triage_score=round(triage_score, 2),
                        cross_ctx=cross_ctx or "(none)",
                    )}],
                    max_tokens=3000,   # full single-shot schema needs real headroom
                    temperature=0.1,
                    response_format={"type": "json_object"},
                )
                result = {} if resp.error else _loads_lenient(resp.message)

        except Exception as outer_e:
            import traceback
            print(f"[investigation] OUTER FAILURE: {outer_e}")
            traceback.print_exc()
            result = None

    if result is None:
        result = {
            "threat_level": "MEDIUM",
            "confidence": 0.4,
            "needs_more_enrichment": False,
            "summary": "AI investigation unavailable — enrichment data collected. Manual review required.",
            "chain_of_thought": ["OpenAI key not configured or call failed. Review enrichment data manually."],
            "key_findings": ["Automated AI analysis unavailable. See enrichment data tab."],
            "ioc_assessments": [],
            "mitre_techniques": [],
            "attack_patterns": [],
            "geo_highlights": [],
            "recommended_actions": ["Review enrichment data manually.", "Configure OpenAI API key for AI analysis."],
            "tor_traffic": False,
            "attribution_hints": None,
        }

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
        "agent_trace":            trace,
    }
