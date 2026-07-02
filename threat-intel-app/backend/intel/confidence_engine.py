"""
Transparent confidence-scoring engine — spec §2.

Deterministic per-IOC score computed from the enrichment payload + behavioral
indicators + feed cache. Independent of the AI assessment so analysts can see
exactly why a score was assigned.

Score buckets (cap at 100):
  Reputation        VT>50%=30, AbuseIPDB>75=20, ThreatFox=25,
                    Feodo/SSLBL=30
  Context           GreyNoise mal=20 / benign=-20, suspicious ports
                    (4444/8080/1080/etc.)=10, bulletproof ASN=15
  Behavioral        PowerShell encoded=20, malware family=25,
                    C2 framework=30, persistence mechanism=15
  Feed              TAXII match=20, FreshRSS article=10
  Infrastructure    NRD <30d=15, dynamic DNS=10, self-signed cert=10
  Deception         DShield/ET/HoneyPot=25, StopForumSpam=10

Verdict bands: 0-20 CLEAN, 21-44 LOW, 45-64 MEDIUM, 65-84 HIGH, 85-100 CRITICAL

Each IOC gets a full breakdown showing every contributing factor with its
point value and the evidence that triggered it.
"""

from __future__ import annotations
from typing import Dict, List, Optional

# Bulletproof / abuse-hosting ASN keywords (substring match against ISP/org strings)
_BULLETPROOF_ASNS = {
    "alexhost", "fastmedia", "ddos-guard", "stark industries", "zservers",
    "petersburg internet network", "selectel", "g-core labs",
    "abelohost", "shock hosting", "frantech", "buyvm", "njal.la",
}

_C2_FRAMEWORKS = {
    "cobaltstrike", "cobalt strike", "metasploit", "sliver", "havoc",
    "brute ratel", "mythic", "covenant", "empire", "merlin",
}

_DDNS_TLDS = {
    "dyndns.org", "no-ip.com", "no-ip.org", "duckdns.org", "hopto.org",
    "zapto.org", "ddns.net", "ddns.org",
}


def _band(score: int) -> str:
    if score >= 85: return "CRITICAL"
    if score >= 65: return "HIGH"
    if score >= 45: return "MEDIUM"
    if score >= 21: return "LOW"
    return "CLEAN"


def _factor(name: str, points: int, evidence: str, category: str) -> Dict:
    return {"factor": name, "points": points, "evidence": evidence, "category": category}


# ─── per-IOC scorers ───────────────────────────────────────────────────────────
def score_ip(ioc: str, enrichment: Dict, behavioral: Optional[Dict] = None,
             feed_hit: Optional[Dict] = None) -> Dict:
    factors: List[Dict] = []

    # ── Reputation ─────────────────────────────────────────────────────────────
    vt = enrichment.get("virustotal") or {}
    mal, harmless = vt.get("malicious") or 0, vt.get("harmless") or 0
    total_engines = mal + harmless + (vt.get("suspicious") or 0)
    if total_engines:
        ratio = mal / max(total_engines, 1)
        if ratio > 0.5:
            factors.append(_factor("VirusTotal detection ratio >50%", 30,
                                   f"{mal}/{total_engines} engines malicious", "reputation"))

    abuse = enrichment.get("abuseipdb") or {}
    if (abuse.get("abuseScore") or 0) > 75:
        factors.append(_factor("AbuseIPDB confidence >75", 20,
                               f"score={abuse.get('abuseScore')} reports={abuse.get('totalReports')}",
                               "reputation"))

    if (enrichment.get("threatfox") or {}).get("verdict") == "MALICIOUS":
        factors.append(_factor("ThreatFox match", 25,
                               f"family={enrichment['threatfox'].get('malware_family')}",
                               "reputation"))

    if (enrichment.get("feodo_tracker") or {}).get("verdict") == "MALICIOUS":
        factors.append(_factor("Feodo Tracker match", 30, "Botnet C2 blocklist hit", "reputation"))

    # ── Context ────────────────────────────────────────────────────────────────
    gn = enrichment.get("greynoise") or {}
    gn_class = (gn.get("classification") or "").lower()
    if gn_class == "malicious":
        factors.append(_factor("GreyNoise classification: malicious", 20,
                               f"actor={gn.get('actor') or gn.get('name')}",
                               "context"))
    elif gn_class == "benign":
        factors.append(_factor("GreyNoise classification: benign", -20,
                               f"actor={gn.get('actor') or gn.get('name')}",
                               "context"))

    isp_org = " ".join([(abuse.get("isp") or ""),
                        (enrichment.get("ipinfo") or {}).get("org") or ""]).lower()
    bp_hits = [k for k in _BULLETPROOF_ASNS if k in isp_org]
    if bp_hits:
        factors.append(_factor("Bulletproof/abuse hosting ASN", 15,
                               f"matched: {bp_hits[0]}", "context"))

    # ── Behavioral (applies globally — same factors used for any IP in a case)
    if behavioral:
        cats = (behavioral.get("categories") or {})
        if any(h.get("name", "").startswith("PowerShell EncodedCommand")
               for h in (cats.get("powershell") or [])):
            factors.append(_factor("PowerShell EncodedCommand in input", 20,
                                   "Base64-encoded PowerShell detected upstream", "behavioral"))
        for fam in _C2_FRAMEWORKS:
            if any(fam in (h.get("match") or "").lower() for hits in cats.values() for h in hits):
                factors.append(_factor("C2 framework identified", 30,
                                       f"matched: {fam}", "behavioral"))
                break
        if cats.get("persistence"):
            factors.append(_factor("Persistence mechanism detected", 15,
                                   f"{len(cats['persistence'])} pattern(s)", "behavioral"))
        # Malware family from any source — VT file, MalwareBazaar, ThreatFox
        family = (vt.get("malware_family") or
                  (enrichment.get("malwarebazaar") or {}).get("malware_family") or
                  (enrichment.get("threatfox") or {}).get("malware_family"))
        if family:
            factors.append(_factor("Known malware family identified", 25,
                                   f"family={family}", "behavioral"))

    # ── Feed (TAXII + FreshRSS unified cache hit) ──────────────────────────────
    if feed_hit:
        src = feed_hit.get("source") or ""
        if "FreshRSS" in src:
            factors.append(_factor("FreshRSS article mention", 10,
                                   f"source={src} article='{(feed_hit.get('from_article') or '')[:60]}'",
                                   "feed"))
        else:
            factors.append(_factor("TAXII feed match", 20,
                                   f"source={src}", "feed"))

    # ── Deception (honeypot / abuse-list hits — see spec §5) ───────────────────
    dec = enrichment.get("deception") or {}
    if (dec.get("dshield") or {}).get("flagged"):
        factors.append(_factor("DShield / SANS ISC flagged", 25,
                               (dec["dshield"].get("summary") or "")[:120], "deception"))
    if (dec.get("emerging_threats") or {}).get("flagged"):
        factors.append(_factor("Emerging Threats compromised IPs list", 25,
                               "IP appears on ET compromised-ips blocklist", "deception"))
    if (dec.get("project_honeypot") or {}).get("flagged"):
        factors.append(_factor("Project Honeypot HTTP:BL", 25,
                               (dec["project_honeypot"].get("classification") or ""), "deception"))
    if (dec.get("stopforumspam") or {}).get("flagged"):
        factors.append(_factor("StopForumSpam abuse history", 10,
                               (dec["stopforumspam"].get("summary") or ""), "deception"))

    return _finalize(ioc, "ip", factors)


def score_domain(ioc: str, enrichment: Dict, behavioral: Optional[Dict] = None,
                 feed_hit: Optional[Dict] = None) -> Dict:
    factors: List[Dict] = []

    vt = enrichment.get("virustotal") or {}
    mal, harmless = vt.get("malicious") or 0, vt.get("harmless") or 0
    total = mal + harmless + (vt.get("suspicious") or 0)
    if total and mal / max(total, 1) > 0.5:
        factors.append(_factor("VirusTotal detection ratio >50%", 30,
                               f"{mal}/{total} engines malicious", "reputation"))

    if (enrichment.get("threatfox") or {}).get("verdict") == "MALICIOUS":
        factors.append(_factor("ThreatFox match", 25,
                               f"family={enrichment['threatfox'].get('malware_family')}",
                               "reputation"))

    pd = enrichment.get("pulsedive") or {}
    if (pd.get("verdict") == "MALICIOUS"):
        factors.append(_factor("Pulsedive risk: critical/high", 20,
                               f"risk={pd.get('risk')}", "reputation"))

    # ── Infrastructure ────────────────────────────────────────────────────────
    heur = enrichment.get("heuristics") or {}
    nrd = heur.get("nrd") or {}
    if nrd.get("is_same_day") or (nrd.get("age_days") or 999) < 30:
        factors.append(_factor("Newly registered domain (<30d)", 15,
                               f"age_days={nrd.get('age_days')}", "infrastructure"))

    if any(ioc.endswith(tld) for tld in _DDNS_TLDS):
        factors.append(_factor("Dynamic DNS provider", 10,
                               f"matched: {next(t for t in _DDNS_TLDS if ioc.endswith(t))}",
                               "infrastructure"))

    cert = enrichment.get("ssl_cert") or {}
    issuer = (cert.get("issuer") or "").lower()
    if "let's encrypt" in issuer or "lets encrypt" in issuer or "self" in issuer:
        factors.append(_factor("Free or self-signed certificate", 10,
                               f"issuer={cert.get('issuer')}", "infrastructure"))

    # Reuse behavioral + feed wiring (same as score_ip)
    if behavioral:
        cats = (behavioral.get("categories") or {})
        family = (vt.get("malware_family") or
                  (enrichment.get("malwarebazaar") or {}).get("malware_family") or
                  (enrichment.get("threatfox") or {}).get("malware_family"))
        if family:
            factors.append(_factor("Known malware family identified", 25,
                                   f"family={family}", "behavioral"))
        for fam in _C2_FRAMEWORKS:
            if any(fam in (h.get("match") or "").lower() for hits in cats.values() for h in hits):
                factors.append(_factor("C2 framework identified", 30,
                                       f"matched: {fam}", "behavioral"))
                break

    if feed_hit:
        src = feed_hit.get("source") or ""
        if "FreshRSS" in src:
            factors.append(_factor("FreshRSS article mention", 10, f"source={src}", "feed"))
        else:
            factors.append(_factor("TAXII feed match", 20, f"source={src}", "feed"))

    return _finalize(ioc, "domain", factors)


def score_hash(ioc: str, enrichment: Dict, behavioral: Optional[Dict] = None,
               feed_hit: Optional[Dict] = None) -> Dict:
    factors: List[Dict] = []

    vt = enrichment.get("virustotal") or {}
    mal = vt.get("malicious") or 0
    if mal > 5:
        factors.append(_factor("VirusTotal detection count >5", 30,
                               f"{mal} engines flagged it", "reputation"))
    elif mal >= 1:
        factors.append(_factor("VirusTotal detection (low)", 15,
                               f"{mal} engines flagged it", "reputation"))

    if (enrichment.get("malwarebazaar") or {}).get("verdict") == "MALICIOUS":
        factors.append(_factor("MalwareBazaar match", 30,
                               f"family={(enrichment['malwarebazaar'] or {}).get('malware_family')}",
                               "reputation"))

    if (enrichment.get("threatfox") or {}).get("verdict") == "MALICIOUS":
        factors.append(_factor("ThreatFox match", 25,
                               f"family={(enrichment['threatfox'] or {}).get('malware_family')}",
                               "reputation"))

    ha = enrichment.get("hybrid_analysis") or {}
    if ha.get("verdict") == "MALICIOUS":
        factors.append(_factor("Hybrid Analysis sandbox: malicious", 25,
                               f"score={ha.get('threat_score')} family={ha.get('malware_family')}",
                               "reputation"))

    hl = enrichment.get("circl_hashlookup") or {}
    if hl.get("verdict") == "CLEAN":
        factors.append(_factor("CIRCL hashlookup known-good", -25,
                               f"{hl.get('ProductName') or hl.get('FileName')}",
                               "context"))

    family = (vt.get("malware_family") or
              (enrichment.get("malwarebazaar") or {}).get("malware_family") or
              (enrichment.get("threatfox") or {}).get("malware_family"))
    if family:
        factors.append(_factor("Known malware family identified", 25,
                               f"family={family}", "behavioral"))

    if feed_hit:
        src = feed_hit.get("source") or ""
        if "FreshRSS" in src:
            factors.append(_factor("FreshRSS article mention", 10, f"source={src}", "feed"))
        else:
            factors.append(_factor("TAXII feed match", 20, f"source={src}", "feed"))

    return _finalize(ioc, "hash", factors)


# ─── helpers ───────────────────────────────────────────────────────────────────
def _finalize(ioc: str, ioc_type: str, factors: List[Dict]) -> Dict:
    raw = sum(f["points"] for f in factors)
    score = max(0, min(100, raw))
    return {
        "ioc":      ioc,
        "type":     ioc_type,
        "score":    score,
        "verdict":  _band(score),
        "factors":  sorted(factors, key=lambda f: -f["points"]),
        "raw_sum":  raw,
    }


def score_all(enrichments: Dict, behavioral: Optional[Dict] = None,
              feed_cache_lookup=None) -> Dict[str, Dict]:
    """Score every IOC in the enrichments payload. feed_cache_lookup is an
    optional callable(value) -> dict|None — wires in the unified TAXII+FreshRSS
    cache lookup so feed hits become a scoring factor."""
    out: Dict[str, Dict] = {}
    scorers = {
        "ips":     score_ip,
        "domains": score_domain,
        "hashes":  score_hash,
    }
    for cat, scorer in scorers.items():
        items = enrichments.get(cat) or {}
        for ioc, payload in items.items():
            feed_hit = feed_cache_lookup(ioc) if feed_cache_lookup else None
            out[ioc] = scorer(ioc, payload or {}, behavioral=behavioral, feed_hit=feed_hit)
    return out
