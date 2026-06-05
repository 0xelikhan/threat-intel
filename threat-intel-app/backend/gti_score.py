"""
GTI Threat Score Engine
Replicates Google Threat Intelligence scoring logic from the GTI documentation.

Score: 0–100 numeric representation of likely impact if detected in an environment.
Driven by: Verdict (likelihood of malicious) × Severity (potential impact) + contributing factors.

Verdict values:  MALICIOUS | SUSPICIOUS | UNDETECTED | BENIGN | UNKNOWN
Severity values: HIGH | MEDIUM | LOW | NONE

Score bands (matching GTI logic):
  MALICIOUS  + HIGH   → 85–100
  MALICIOUS  + MEDIUM → 65–84
  MALICIOUS  + LOW    → 45–64
  SUSPICIOUS + HIGH   → 55–74
  SUSPICIOUS + MEDIUM → 35–54
  SUSPICIOUS + LOW    → 15–34
  UNDETECTED          → 5–14
  BENIGN / UNKNOWN    → 0–4
"""

from dataclasses import dataclass
from typing import Optional


# ─── SCORE RESULT ─────────────────────────────────────────────────────────────────
@dataclass
class GTIScore:
    score: int                          # 0–100
    verdict: str                        # MALICIOUS | SUSPICIOUS | UNDETECTED | BENIGN | UNKNOWN
    severity: str                       # HIGH | MEDIUM | LOW | NONE
    contributing_factors: list[str]     # human-readable reasons
    ioc_type: str                       # file | domain | ip | url
    label: str                          # e.g. "CRITICAL", "HIGH RISK", "SUSPICIOUS", "CLEAN"
    color: str                          # hex color for UI

    def to_dict(self) -> dict:
        return {
            "score":               self.score,
            "verdict":             self.verdict,
            "severity":            self.severity,
            "contributing_factors": self.contributing_factors,
            "ioc_type":            self.ioc_type,
            "label":               self.label,
            "color":               self.color,
        }


def _label_and_color(score: int, verdict: str) -> tuple[str, str]:
    if verdict == "BENIGN":
        return "CLEAN", "#34A853"
    if score >= 85:
        return "CRITICAL", "#EA4335"
    if score >= 65:
        return "HIGH RISK", "#FF6B35"
    if score >= 45:
        return "ELEVATED", "#FBBC04"
    if score >= 25:
        return "SUSPICIOUS", "#FFA726"
    if score >= 10:
        return "LOW RISK", "#4ECDC4"
    return "CLEAN", "#34A853"


def _clamp(val: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, val))


# ─── FILE SCORING ─────────────────────────────────────────────────────────────────
def score_file(enrichment: dict) -> GTIScore:
    """
    Score a file hash.
    Sources: VirusTotal, MalwareBazaar, ThreatFox, OTX.

    GTI file logic:
    - MALICIOUS if detected by trusted sources (Mandiant via VT, MB, ThreatFox)
    - BENIGN if explicitly classified as legitimate
    - Severity based on malware category (ransomware/RAT = HIGH, adware/PUA = LOW)
    """
    vt  = enrichment.get("virustotal")  or {}
    mb  = enrichment.get("malwarebazaar") or {}
    tf  = enrichment.get("threatfox")   or {}
    otx = enrichment.get("otx")         or {}

    factors = []
    verdict  = "UNKNOWN"
    severity = "NONE"
    base     = 0

    vt_mal  = vt.get("malicious") or 0
    vt_sus  = vt.get("suspicious") or 0
    vt_name = vt.get("name") or ""
    mb_fam  = mb.get("malwareName") or ""
    tf_mal  = tf.get("malware") or ""
    otx_cnt = otx.get("pulseCount") or 0

    # ── Verdict ───────────────────────────────────────────────────────────────────
    if mb_fam or tf_mal:
        verdict = "MALICIOUS"
        factors.append(f"Confirmed malware: {mb_fam or tf_mal}")
    elif vt_mal >= 5:
        verdict = "MALICIOUS"
        factors.append(f"VT: {vt_mal} engines flagged as malicious")
    elif vt_mal >= 2 or vt_sus >= 3:
        verdict = "SUSPICIOUS"
        factors.append(f"VT: {vt_mal} malicious, {vt_sus} suspicious engines")
    elif vt_mal == 0 and vt_sus == 0 and not mb_fam and not tf_mal:
        verdict = "UNDETECTED"
        factors.append("No detections across VT, MalwareBazaar, or ThreatFox")

    # ── Severity ──────────────────────────────────────────────────────────────────
    HIGH_KEYWORDS = [
        "ransomware", "ransom", "locker", "cryptolocker", "wiper",
        "cobalt strike", "beacon", "metasploit", "meterpreter",
        "backdoor", "trojan", "rat ", "remote access", "apt",
        "infostealer", "stealer", "keylogger", "rootkit", "bootkit",
        "lazarus", "conti", "lockbit", "blackcat", "cl0p",
    ]
    MED_KEYWORDS = [
        "exploit", "hack tool", "hacktool", "downloader", "dropper",
        "loader", "miner", "botnet", "banker", "financial", "spyware",
        "credential", "mimikatz", "psexec", "cobaltstrike",
    ]
    LOW_KEYWORDS = [
        "adware", "pua", "pup", "unwanted", "spam",
        "fake antivirus", "riskware", "grayware",
    ]

    combined = (mb_fam + " " + tf_mal + " " + vt_name).lower()

    if verdict in ("MALICIOUS", "SUSPICIOUS"):
        if any(k in combined for k in HIGH_KEYWORDS) or vt_mal >= 20:
            severity = "HIGH"
            matched = [k for k in HIGH_KEYWORDS if k in combined]
            if matched:
                factors.append(f"High-severity category: {matched[0]}")
        elif any(k in combined for k in MED_KEYWORDS) or 5 <= vt_mal < 20:
            severity = "MEDIUM"
            matched = [k for k in MED_KEYWORDS if k in combined]
            if matched:
                factors.append(f"Medium-severity category: {matched[0]}")
        elif any(k in combined for k in LOW_KEYWORDS):
            severity = "LOW"
            factors.append("Low-severity category: adware/PUA/riskware")
        else:
            severity = "MEDIUM" if verdict == "MALICIOUS" else "LOW"

    # ── Base score from verdict + severity ────────────────────────────────────────
    SCORE_MAP = {
        ("MALICIOUS",  "HIGH"):   90,
        ("MALICIOUS",  "MEDIUM"): 72,
        ("MALICIOUS",  "LOW"):    52,
        ("SUSPICIOUS", "HIGH"):   62,
        ("SUSPICIOUS", "MEDIUM"): 42,
        ("SUSPICIOUS", "LOW"):    25,
        ("UNDETECTED", "NONE"):    8,
        ("BENIGN",     "NONE"):    0,
        ("UNKNOWN",    "NONE"):    2,
    }
    base = SCORE_MAP.get((verdict, severity), SCORE_MAP.get((verdict, "NONE"), 2))

    # ── Modifiers ─────────────────────────────────────────────────────────────────
    modifier = 0
    if vt_mal >= 50:
        modifier += 8; factors.append(f"Very high VT detection count: {vt_mal}/72")
    elif vt_mal >= 30:
        modifier += 5
    if otx_cnt >= 10:
        modifier += 4; factors.append(f"High OTX pulse count: {otx_cnt} community pulses")
    elif otx_cnt >= 3:
        modifier += 2

    score = _clamp(base + modifier, 0, 100)
    label, color = _label_and_color(score, verdict)
    return GTIScore(score=score, verdict=verdict, severity=severity,
                    contributing_factors=factors, ioc_type="file", label=label, color=color)


# ─── IP ADDRESS SCORING ───────────────────────────────────────────────────────────
def score_ip(enrichment: dict) -> GTIScore:
    """
    Score an IP address.
    GTI IP logic mirrors Domain coverage — verdict based on Mandiant analytics
    (approximated via AbuseIPDB + VT + GreyNoise) and Google SafeBrowsing signals.
    """
    abuse = enrichment.get("abuseipdb")  or {}
    vt    = enrichment.get("virustotal") or {}
    gn    = enrichment.get("greynoise")  or {}
    otx   = enrichment.get("otx")        or {}
    tor   = enrichment.get("tor")        or {}

    factors  = []
    verdict  = "UNKNOWN"
    severity = "NONE"

    abuse_score = abuse.get("abuseScore") or 0
    vt_mal      = vt.get("malicious")    or 0
    vt_rep      = vt.get("reputation")   or 0
    gn_class    = gn.get("classification") or ""
    gn_noise    = gn.get("noise") or False
    is_tor      = tor.get("isExitNode") or False
    otx_cnt     = otx.get("pulseCount") or 0

    # ── Verdict ───────────────────────────────────────────────────────────────────
    if abuse_score >= 75 or vt_mal >= 5 or vt_rep < -50:
        verdict = "MALICIOUS"
        if abuse_score >= 75:
            factors.append(f"AbuseIPDB score: {abuse_score}% — highly abusive")
        if vt_mal >= 5:
            factors.append(f"VT: {vt_mal} engines flagged as malicious")
    elif abuse_score >= 25 or vt_mal >= 2 or gn_class == "malicious":
        verdict = "SUSPICIOUS"
        if abuse_score >= 25:
            factors.append(f"AbuseIPDB score: {abuse_score}% — suspicious activity")
        if gn_class == "malicious":
            factors.append("GreyNoise: classified as malicious")
    elif gn_noise or (abuse_score < 5 and vt_mal == 0):
        verdict = "UNDETECTED"
        if gn_noise:
            factors.append("GreyNoise: mass internet scanner — low targeted threat")
    else:
        verdict = "UNDETECTED"

    # ── Severity ──────────────────────────────────────────────────────────────────
    if verdict in ("MALICIOUS", "SUSPICIOUS"):
        if is_tor or (abuse_score >= 90 and otx_cnt >= 5):
            severity = "HIGH"
            if is_tor:
                factors.append("Confirmed Tor exit node — anonymized threat actor traffic")
        elif (abuse_score >= 50) or otx_cnt >= 5:
            severity = "MEDIUM"
        else:
            severity = "LOW"

    # ── Base score ────────────────────────────────────────────────────────────────
    SCORE_MAP = {
        ("MALICIOUS",  "HIGH"):   88,
        ("MALICIOUS",  "MEDIUM"): 70,
        ("MALICIOUS",  "LOW"):    50,
        ("SUSPICIOUS", "HIGH"):   58,
        ("SUSPICIOUS", "MEDIUM"): 38,
        ("SUSPICIOUS", "LOW"):    22,
        ("UNDETECTED", "NONE"):    6,
        ("BENIGN",     "NONE"):    0,
    }
    base = SCORE_MAP.get((verdict, severity), 5)

    # ── Modifiers ─────────────────────────────────────────────────────────────────
    modifier = 0
    if is_tor:
        modifier += 6; 
    if otx_cnt >= 10:
        modifier += 5; factors.append(f"OTX: {otx_cnt} threat community pulses")
    elif otx_cnt >= 3:
        modifier += 2
    if abuse_score == 100:
        modifier += 5; factors.append("AbuseIPDB: maximum abuse confidence score")

    score = _clamp(base + modifier, 0, 100)
    label, color = _label_and_color(score, verdict)
    return GTIScore(score=score, verdict=verdict, severity=severity,
                    contributing_factors=factors, ioc_type="ip", label=label, color=color)


# ─── DOMAIN SCORING ───────────────────────────────────────────────────────────────
def score_domain(enrichment: dict) -> GTIScore:
    """
    Score a domain.
    GTI Domain logic:
    - BENIGN if top 10K popularity or explicitly excluded by Mandiant
    - MALICIOUS if rated highly malicious by Mandiant analytics or Google SafeBrowsing
    - SUSPICIOUS if above threshold but below conclusive malicious
    """
    vt       = enrichment.get("virustotal")       or {}
    urlscan  = enrichment.get("urlscan")          or {}
    otx      = enrichment.get("otx")              or {}
    whois    = enrichment.get("whois")            or {}
    pd       = enrichment.get("pulsedive")        or {}
    crt      = enrichment.get("certTransparency") or {}

    factors  = []
    verdict  = "UNKNOWN"
    severity = "NONE"

    vt_mal   = vt.get("malicious")   or 0
    vt_sus   = vt.get("suspicious")  or 0
    vt_rep   = vt.get("reputation")  or 0
    vt_cats  = vt.get("categories")  or {}
    us_mal   = urlscan.get("malicious") or False
    otx_cnt  = otx.get("pulseCount") or 0
    pd_risk  = (pd.get("risk") or "").lower()
    pd_threats = pd.get("threats") or []

    # Category analysis
    cat_vals = list(vt_cats.values()) if isinstance(vt_cats, dict) else []
    cat_str  = " ".join(cat_vals).lower()

    HIGH_CATS = ["malware", "ransomware", "phishing", "c2", "command and control", "botnet", "exploit"]
    MED_CATS  = ["spam", "spyware", "adware", "suspicious", "hacking", "newly registered"]

    # ── Verdict ───────────────────────────────────────────────────────────────────
    if vt_mal >= 5 or (us_mal and vt_mal >= 2) or vt_rep < -50:
        verdict = "MALICIOUS"
        factors.append(f"VT: {vt_mal} engines flagged as malicious")
        if us_mal:
            factors.append("URLScan: independently confirmed malicious")
    elif vt_mal >= 2 or vt_sus >= 3 or us_mal or pd_risk in ("high", "critical") or otx_cnt >= 5:
        verdict = "SUSPICIOUS"
        if vt_mal >= 2:
            factors.append(f"VT: {vt_mal} malicious detections")
        if otx_cnt >= 5:
            factors.append(f"OTX: {otx_cnt} threat pulses — community flagged")
        if pd_risk in ("high", "critical"):
            factors.append(f"Pulsedive risk: {pd_risk}")
    elif vt_mal == 0 and vt_sus == 0 and not us_mal:
        verdict = "UNDETECTED"

    # ── Severity ──────────────────────────────────────────────────────────────────
    if verdict in ("MALICIOUS", "SUSPICIOUS"):
        if any(k in cat_str for k in HIGH_CATS) or len(pd_threats) >= 2:
            severity = "HIGH"
            matched = [k for k in HIGH_CATS if k in cat_str]
            if matched:
                factors.append(f"High-risk category: {matched[0]}")
        elif any(k in cat_str for k in MED_CATS) or otx_cnt >= 3:
            severity = "MEDIUM"
        else:
            severity = "LOW" if verdict == "SUSPICIOUS" else "MEDIUM"

    # ── WHOIS age modifier: newly registered domains are higher risk ───────────────
    newly_registered = False
    if whois.get("created"):
        try:
            from datetime import datetime, timezone
            created_str = whois["created"]
            # Handle various date formats
            for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ"]:
                try:
                    created = datetime.strptime(created_str[:19], fmt).replace(tzinfo=timezone.utc)
                    age_days = (datetime.now(timezone.utc) - created).days
                    if age_days < 90:
                        newly_registered = True
                        factors.append(f"Domain created {age_days} days ago — newly registered, elevated risk")
                    break
                except ValueError:
                    continue
        except Exception:
            pass

    # ── Base score ────────────────────────────────────────────────────────────────
    SCORE_MAP = {
        ("MALICIOUS",  "HIGH"):   88,
        ("MALICIOUS",  "MEDIUM"): 70,
        ("MALICIOUS",  "LOW"):    50,
        ("SUSPICIOUS", "HIGH"):   55,
        ("SUSPICIOUS", "MEDIUM"): 38,
        ("SUSPICIOUS", "LOW"):    20,
        ("UNDETECTED", "NONE"):    5,
        ("BENIGN",     "NONE"):    0,
    }
    base = SCORE_MAP.get((verdict, severity), 4)

    modifier = 0
    if newly_registered and verdict != "BENIGN":
        modifier += 8
    if otx_cnt >= 10:
        modifier += 5; factors.append(f"OTX: {otx_cnt} pulses")
    elif otx_cnt >= 3:
        modifier += 2
    if crt.get("totalCerts", 0) > 100 and verdict == "MALICIOUS":
        modifier += 3; factors.append("High cert count on malicious domain — infra scale indicator")

    score = _clamp(base + modifier, 0, 100)
    label, color = _label_and_color(score, verdict)
    return GTIScore(score=score, verdict=verdict, severity=severity,
                    contributing_factors=factors, ioc_type="domain", label=label, color=color)


# ─── URL SCORING ──────────────────────────────────────────────────────────────────
def score_url(enrichment: dict) -> GTIScore:
    """
    Score a URL.
    GTI URL logic similar to Domain, tailored for URL-specific properties.
    """
    vt      = enrichment.get("virustotal") or {}
    urlhaus = enrichment.get("urlhaus")    or {}
    pt      = enrichment.get("phishtank")  or {}

    factors  = []
    verdict  = "UNKNOWN"
    severity = "NONE"

    vt_mal   = vt.get("malicious")   or 0
    vt_sus   = vt.get("suspicious")  or 0
    uh_qs    = urlhaus.get("queryStatus") or ""
    uh_threat= urlhaus.get("threat") or ""
    is_phish = pt.get("isPhishing")  or False
    in_pt    = pt.get("inDatabase")  or False

    # ── Verdict ───────────────────────────────────────────────────────────────────
    if vt_mal >= 5 or (is_phish and in_pt):
        verdict = "MALICIOUS"
        if vt_mal >= 5:
            factors.append(f"VT: {vt_mal} engines flagged URL as malicious")
        if is_phish:
            factors.append("PhishTank: confirmed phishing URL")
    elif uh_qs == "is_malware" or vt_mal >= 2 or vt_sus >= 3:
        verdict = "MALICIOUS" if uh_qs == "is_malware" else "SUSPICIOUS"
        if uh_qs == "is_malware":
            factors.append(f"URLHaus: active malware distribution — {uh_threat or 'unknown family'}")
        elif vt_mal >= 2:
            factors.append(f"VT: {vt_mal} malicious, {vt_sus} suspicious")
    elif in_pt and not is_phish:
        verdict = "SUSPICIOUS"
        factors.append("PhishTank: in database but not confirmed")
    elif vt_mal == 0 and vt_sus == 0:
        verdict = "UNDETECTED"

    # ── Severity ──────────────────────────────────────────────────────────────────
    if verdict in ("MALICIOUS", "SUSPICIOUS"):
        PHISH_KEYWORDS  = ["phish", "credential", "login", "banking", "financial", "steal"]
        MALWARE_KEYWORDS= ["malware", "ransomware", "exploit", "dropper", "loader"]

        combined = (uh_threat + " " + (vt.get("categories") or "")).lower()

        if any(k in combined for k in MALWARE_KEYWORDS) or uh_qs == "is_malware":
            severity = "HIGH"
            factors.append("Active malware distribution URL")
        elif is_phish or any(k in combined for k in PHISH_KEYWORDS):
            severity = "HIGH"
            factors.append("Phishing / credential harvesting URL")
        elif verdict == "MALICIOUS":
            severity = "MEDIUM"
        else:
            severity = "LOW"

    SCORE_MAP = {
        ("MALICIOUS",  "HIGH"):   90,
        ("MALICIOUS",  "MEDIUM"): 72,
        ("MALICIOUS",  "LOW"):    50,
        ("SUSPICIOUS", "HIGH"):   58,
        ("SUSPICIOUS", "MEDIUM"): 38,
        ("SUSPICIOUS", "LOW"):    20,
        ("UNDETECTED", "NONE"):    5,
        ("BENIGN",     "NONE"):    0,
    }
    base = SCORE_MAP.get((verdict, severity), 4)
    score = _clamp(base, 0, 100)
    label, color = _label_and_color(score, verdict)
    return GTIScore(score=score, verdict=verdict, severity=severity,
                    contributing_factors=factors, ioc_type="url", label=label, color=color)


# ─── PUBLIC INTERFACE ─────────────────────────────────────────────────────────────
def score_cve(data: dict, label: str = "cve") -> GTIScore:
    """Score a CVE based on NVD severity + EPSS probability + CISA KEV
    actively-exploited status. KEV match is the highest-confidence signal
    (CISA only adds CVEs with confirmed in-the-wild exploitation)."""
    factors = []
    score = 0
    verdict = "UNKNOWN"

    kev = data.get("cisa_kev") or {}
    if kev and not kev.get("error") and kev.get("in_kev"):
        score += 60
        verdict = "MALICIOUS"
        factors.append(f"CISA KEV: actively exploited (added {kev.get('date_added')})")
        if kev.get("ransomware_use"):
            score += 10
            factors.append("CISA KEV: known ransomware-campaign use")

    nvd = data.get("nvd") or {}
    if nvd and not nvd.get("error") and nvd.get("found"):
        sev = (nvd.get("cvss_v3_severity") or "").upper()
        sc = nvd.get("cvss_v3_score") or 0
        if sev == "CRITICAL":
            score += 25
            if verdict == "UNKNOWN":
                verdict = "MALICIOUS"
            factors.append(f"NVD: CVSS {sc} CRITICAL")
        elif sev == "HIGH":
            score += 15
            if verdict == "UNKNOWN":
                verdict = "SUSPICIOUS"
            factors.append(f"NVD: CVSS {sc} HIGH")
        elif sev == "MEDIUM":
            score += 5
            factors.append(f"NVD: CVSS {sc} MEDIUM")
        elif sev == "LOW":
            factors.append(f"NVD: CVSS {sc} LOW")

    ep = data.get("epss") or {}
    if ep and not ep.get("error") and ep.get("found"):
        prob = float(ep.get("score") or 0.0)
        if prob >= 0.7:
            score += 15
            if verdict == "UNKNOWN":
                verdict = "SUSPICIOUS"
            factors.append(f"EPSS: {round(prob * 100, 1)}% exploit probability")
        elif prob >= 0.1:
            score += 5
            factors.append(f"EPSS: {round(prob * 100, 1)}% exploit probability")

    if not factors:
        factors.append("No CVE intelligence data available.")
        verdict = "UNKNOWN"

    score = min(score, 100)
    severity = "HIGH" if score >= 70 else "MEDIUM" if score >= 40 \
               else "LOW" if score >= 20 else "NONE"
    tier_label, color = _label_and_color(score, verdict)
    return GTIScore(
        score=score, verdict=verdict, severity=severity,
        contributing_factors=factors,
        ioc_type="cve", label=label, color=color,
    )


def compute_gti_scores(enrichments: dict) -> dict:
    """
    Compute GTI scores for all IOC types in an enrichment result.
    Returns a dict keyed by IOC value with GTIScore dicts.
    """
    scores = {}

    for ip, data in (enrichments.get("ips") or {}).items():
        if isinstance(data, dict):
            scores[ip] = score_ip(data).to_dict()

    for domain, data in (enrichments.get("domains") or {}).items():
        if isinstance(data, dict):
            scores[domain] = score_domain(data).to_dict()

    for hash_val, data in (enrichments.get("hashes") or {}).items():
        if isinstance(data, dict):
            scores[hash_val] = score_file(data).to_dict()

    for url, data in (enrichments.get("urls") or {}).items():
        if isinstance(data, dict):
            scores[url] = score_url(data).to_dict()

    for cve, data in (enrichments.get("cves") or {}).items():
        if isinstance(data, dict):
            scores[cve] = score_cve(data, label=cve).to_dict()

    return scores


def get_highest_score(gti_scores: dict) -> Optional[dict]:
    """Return the highest-scoring IOC across all types."""
    if not gti_scores:
        return None
    return max(gti_scores.values(), key=lambda x: x.get("score", 0))
