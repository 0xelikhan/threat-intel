"""
Triage Agent — reads API config at call time, not import time.
This allows keys entered in the Settings UI to take effect immediately.
"""

import re
import json
from datetime import datetime, timezone


BENIGN_IPS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "208.67.222.222", "169.254.169.254", "100.100.100.200",
}
PRIVATE_RANGES = [
    r"^10\.", r"^192\.168\.", r"^172\.(1[6-9]|2\d|3[01])\.",
    r"^127\.", r"^::1$", r"^fe80:",
]
BENIGN_DOMAINS = {
    "microsoft.com", "windows.com", "windowsupdate.com", "office.com",
    "office365.com", "live.com", "azure.com", "amazonaws.com",
    "google.com", "googleapis.com", "gstatic.com", "apple.com",
    "icloud.com", "cloudflare.com", "fastly.net", "akamai.net",
}


def _is_private_ip(ip: str) -> bool:
    return any(re.match(p, ip) for p in PRIVATE_RANGES)


def _valid_octets(ip: str) -> bool:
    try:
        return all(0 <= int(p) <= 255 for p in ip.split("."))
    except ValueError:
        return False


_EXE_RE  = re.compile(
    r"\b([A-Za-z0-9_\-\.]{2,80}\.(?:exe|dll|sys|bat|ps1|cmd|vbs|js|hta|lnk|msi|scr|jar|jse|wsf))\b",
    re.IGNORECASE,
)
_PATH_RE = re.compile(
    r"\b(?:[a-zA-Z]:\\|\\\\)[^\s\"'<>|*?\r\n]+|/(?:home|var|tmp|etc|usr|opt|root)/[^\s\"'<>|*?\r\n]+",
)


def extract_iocs(text: str) -> dict:
    """Extract IOCs using iocextract (handles defanged forms like 8[.]8[.]8[.]8,
    hxxp://, bracketed dots, etc.) with a regex fallback if the library is missing."""
    iocs = {"ips": set(), "domains": set(), "urls": set(), "hashes": set(),
            "emails": set(), "files": set(), "paths": set()}

    # Try the library route first — refangs defanged IOCs automatically
    try:
        import iocextract

        for ip in iocextract.extract_ips(text, refang=True):
            ip = ip.strip()
            if ip in BENIGN_IPS or _is_private_ip(ip) or not _valid_octets(ip):
                continue
            iocs["ips"].add(ip)

        for url in iocextract.extract_urls(text, refang=True):
            iocs["urls"].add(url.rstrip(".,;)\"'"))

        for h in iocextract.extract_hashes(text):
            iocs["hashes"].add(h.lower())

        for e in iocextract.extract_emails(text, refang=True):
            iocs["emails"].add(e.lower())

    except ImportError:
        # Fallback regex path — keeps the app running if iocextract isn't installed
        norm = (text
            .replace("[.]", ".").replace("(dot)", ".")
            .replace("[://]", "://").replace("hxxp", "http"))
        for url in re.findall(r"https?://[^\s\"'<>\]\),]+", norm):
            iocs["urls"].add(url.rstrip(".,;)"))
        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", norm):
            if ip in BENIGN_IPS or _is_private_ip(ip) or not _valid_octets(ip):
                continue
            iocs["ips"].add(ip)
        for pat in [r"\b[a-fA-F0-9]{64}\b", r"\b[a-fA-F0-9]{40}\b", r"\b[a-fA-F0-9]{32}\b"]:
            for h in re.findall(pat, norm):
                iocs["hashes"].add(h.lower())
        for e in re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", norm):
            iocs["emails"].add(e.lower())

    # Domain extraction (TLD-bounded so we don't grab arbitrary words)
    norm = (text.replace("[.]", ".").replace("(dot)", ".")
            .replace("[://]", "://").replace("hxxp", "http"))
    stripped = re.sub(r"https?://[^\s\"'<>\]\),]+", "", norm)
    domain_re = re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)"
        r"+(?:com|net|org|io|gov|edu|mil|co|uk|ru|cn|de|xyz|top|online|"
        r"site|app|dev|cloud|tech|store|live|icu|pw|cc|me|tv|ws|mobi)\b",
        re.IGNORECASE,
    )
    for d in domain_re.findall(stripped):
        d = d.lower()
        if not any(d == b or d.endswith("." + b) for b in BENIGN_DOMAINS):
            iocs["domains"].add(d)

    # Filename / executable extraction — common in EDR / OS log lines
    for m in _EXE_RE.finditer(text or ""):
        name = m.group(1)
        # Filter out the obvious noise (windows.exe is not an IOC by itself etc.)
        bare = name.lower().rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        if bare in {"windows.exe", "system.exe", "system32.exe", "logonui.exe", "winlogon.exe"}:
            continue
        iocs["files"].add(name)

    # Filesystem path extraction
    for m in _PATH_RE.finditer(text or ""):
        p = m.group(0).rstrip(".,;)\"'")
        if len(p) >= 8:
            iocs["paths"].add(p)

    return {k: list(v) for k, v in iocs.items()}


def score_iocs(iocs: dict) -> float:
    score = 0.0
    score += min(len(iocs.get("ips", [])) * 0.15, 0.45)
    score += min(len(iocs.get("hashes", [])) * 0.25, 0.50)
    score += min(len(iocs.get("domains", [])) * 0.10, 0.30)
    score += min(len(iocs.get("urls", [])) * 0.10, 0.20)
    score += min(len(iocs.get("emails", [])) * 0.05, 0.10)
    score += min(len(iocs.get("files", [])) * 0.08, 0.24)
    return min(score, 1.0)


def derive_alert_type(iocs: dict, cross_refs: dict) -> str:
    """Infer alert type from heuristic signals — no AI call needed."""
    if cross_refs.get("phishing_kits"):
        return "phishing"
    if cross_refs.get("kev"):
        if any(k.get("ransomware_use") for k in cross_refs["kev"]):
            return "ransomware"
        return "exploitation"
    if cross_refs.get("rmm_abuse"):
        return "ransomware"
    if cross_refs.get("loldrivers"):
        return "malware"
    if cross_refs.get("lolbas"):
        return "malware"
    if iocs.get("hashes") or iocs.get("files"):
        return "malware"
    if iocs.get("emails"):
        return "phishing"
    if iocs.get("urls"):
        return "phishing"
    if iocs.get("ips"):
        return "c2"
    return "unknown"


def _is_high_confidence(heuristic_score: float, cross_refs: dict, iocs: dict) -> bool:
    """Return True when heuristic + offline-intel signals are strong enough that
    the AI triage call adds nothing — skip it to save 2-5 seconds per run.

    The AI investigation step (later, slower, more thorough) does the real reasoning.
    Triage is just a routing decision: should we proceed and what alert type?
    Be aggressive about skipping — false negatives just mean we route to investigation
    anyway, which still produces a real analysis.
    """
    # ANY offline intel hit → skip AI. These signals are already authoritative.
    if any(cross_refs.get(k) for k in
           ("kev", "rmm_abuse", "loldrivers", "lolbas", "phishing_kits", "suspicious_paths")):
        return True
    # Heuristic score alone of 0.4+ is enough — IOC counts already tell us this is real.
    if heuristic_score >= 0.4:
        return True
    return False


TRIAGE_PROMPT = """You are a SOC triage analyst. Quickly assess this security alert.

CHARACTER: Senior SOC analyst, 10+ years experience.
CONTEXT: First agent in an automated pipeline. Your decision controls whether resources are spent.
CONSTRAINTS: Output ONLY valid JSON. When in doubt, proceed.
COMMAND: Score this alert and classify it.

RAW INPUT (first 800 chars):
{log_snippet}

EXTRACTED IOCs:
{ioc_summary}

Respond with exactly this JSON:
{{
  "triage_score": <float 0.0-1.0>,
  "should_proceed": <true|false>,
  "reasoning": "<one sentence>",
  "alert_type": "<phishing|malware|c2|recon|bruteforce|exfiltration|ransomware|unknown>",
  "urgency": "<immediate|high|medium|low>",
  "false_positive_indicators": [],
  "priority_iocs": []
}}"""


async def run_triage(state: dict) -> dict:
    from config import config
    from openai import AsyncAzureOpenAI, AsyncOpenAI
    import time
    _t_start = time.perf_counter()

    raw = state["raw_input"]

    # EML detection — if the input is a raw email, run dedicated phishing analysis
    # and append the extracted URLs/IPs/hashes to the IOC list before triage continues.
    email_analysis = None
    try:
        from intel.eml_analysis import looks_like_eml, analyze as analyze_eml
        if looks_like_eml(raw):
            email_analysis = analyze_eml(raw)
    except Exception:
        email_analysis = None

    iocs = extract_iocs(raw)
    if email_analysis:
        for url in email_analysis.get("urls", []):
            if url not in iocs.get("urls", []):
                iocs.setdefault("urls", []).append(url)
        for ip in email_analysis.get("sender_ips", []):
            if ip not in iocs.get("ips", []) and not _is_private_ip(ip):
                iocs.setdefault("ips", []).append(ip)
        for att in email_analysis.get("attachments", []):
            for hkey in ("sha256", "sha1", "md5"):
                h = att.get(hkey)
                if h and h not in iocs.get("hashes", []):
                    iocs.setdefault("hashes", []).append(h)
                    break

    try:
        from intel.warninglist_filter import filter_iocs
        iocs, _ = filter_iocs(iocs)
    except Exception:
        pass

    # Cross-reference local threat intel: KEV exploited CVEs + LOLBAS binaries
    cross_refs: dict = {}
    try:
        from intel.kev import extract_and_check as kev_check
        kev_hits = kev_check(raw)
        if kev_hits:
            # Enrich each KEV entry with EPSS exploit-prediction score
            try:
                from intel.epss import enrich_kev_entries
                enrich_kev_entries(kev_hits)
            except Exception:
                pass
            cross_refs["kev"] = kev_hits
    except Exception:
        pass
    try:
        from intel.loldrivers import extract_and_check as drv_check
        drv_hits = drv_check(raw, iocs.get("hashes", []))
        if drv_hits:
            cross_refs["loldrivers"] = drv_hits
    except Exception:
        pass
    try:
        from intel.lolbas import extract_and_check as lolbas_check
        lolbas_hits = lolbas_check(raw)
        if lolbas_hits:
            cross_refs["lolbas"] = lolbas_hits
    except Exception:
        pass
    try:
        from intel.rmm_abuse import extract_and_check as rmm_check, check_suspicious_paths
        rmm_hits = rmm_check(raw)
        if rmm_hits:
            cross_refs["rmm_abuse"] = rmm_hits
        path_hits = check_suspicious_paths(raw)
        if path_hits:
            cross_refs["suspicious_paths"] = path_hits
    except Exception:
        pass
    try:
        from intel.phishing_kit import scan_urls
        urls_for_kit = iocs.get("urls", [])
        # also pull URLs from email if EML was parsed
        if email_analysis:
            urls_for_kit = urls_for_kit + email_analysis.get("urls", [])
        kit_hits = scan_urls(urls_for_kit)
        if kit_hits:
            cross_refs["phishing_kits"] = kit_hits
    except Exception:
        pass

    heuristic_score = score_iocs(iocs)
    # KEV hits boost score significantly — actively exploited CVE = real threat
    if cross_refs.get("kev"):
        heuristic_score = min(1.0, heuristic_score + 0.3)
    total_iocs = sum(len(v) for v in iocs.values())
    trace = state.get("agent_trace", [])
    ts = datetime.now(timezone.utc).isoformat()

    # Even with zero traditional IOCs, proceed — many EDR / OS / audit logs describe
    # threats through process names, paths, behaviors. Let the AI investigation reason
    # over the raw log content rather than dropping the alert.
    if total_iocs == 0:
        # Bootstrap a minimal heuristic score from cross-refs so we don't fall below
        # the proceed threshold simply for lacking IPs/hashes/domains.
        if any(cross_refs.get(k) for k in ("kev", "lolbas", "rmm_abuse",
                                            "suspicious_paths", "phishing_kits")):
            heuristic_score = max(heuristic_score, 0.45)
        else:
            heuristic_score = max(heuristic_score, 0.30)

    ioc_summary = json.dumps({k: v[:5] for k, v in iocs.items() if v}, indent=2) or "(no traditional IOCs — proceed with log-content analysis)"

    # Fast-path: if cross-refs + heuristics already give us a confident verdict,
    # skip the AI triage call entirely. The AI investigation step still does the
    # deep reasoning later — triage is just a routing decision.
    ai_result = None
    skipped_for_speed = False
    if _is_high_confidence(heuristic_score, cross_refs, iocs):
        skipped_for_speed = True
        ai_result = {
            "triage_score":   heuristic_score,
            "should_proceed": True,
            "reasoning":      f"Fast-path: strong heuristic signals (score {heuristic_score:.2f}) — AI triage skipped.",
            "alert_type":     derive_alert_type(iocs, cross_refs),
            "urgency":        "high" if heuristic_score >= 0.6 else "medium",
            "false_positive_indicators": [],
            "priority_iocs":  [],
        }

    openai_key = config.get("OPENAI_API_KEY")
    if ai_result is None and openai_key:
        try:
            base_url = config.get("OPENAI_BASE_URL", "")
            if "openai.azure.com" in base_url:
                client = AsyncAzureOpenAI(
                    api_key=openai_key,
                    azure_endpoint=base_url.rstrip("/"),
                    api_version="2024-02-01",
                )
            else:
                client = AsyncOpenAI(
                    api_key=openai_key,
                    base_url=base_url or "https://api.openai.com/v1",
                )
            resp = await client.chat.completions.create(
                model=config.get("AI_MODEL", "gpt-4o-mini"),
                messages=[{"role": "user", "content": TRIAGE_PROMPT.format(
                    log_snippet=raw[:600], ioc_summary=ioc_summary,
                )}],
                max_tokens=220,
                temperature=0.0,
                response_format={"type": "json_object"},
            )
            ai_result = json.loads(resp.choices[0].message.content)
        except Exception as e:
            ai_result = None

    if ai_result is None:
        ai_result = {
            "triage_score": heuristic_score,
            "should_proceed": heuristic_score > 0.15,
            "reasoning": "Heuristic score (AI unavailable or key not configured).",
            "alert_type": "unknown",
            "urgency": "medium",
            "false_positive_indicators": [],
            "priority_iocs": [],
        }

    final_score = (ai_result.get("triage_score", heuristic_score) + heuristic_score) / 2

    elapsed_ms = int((time.perf_counter() - _t_start) * 1000)
    trace.append({
        "agent": "triage",
        "status": "complete",
        "summary": ai_result.get("reasoning", ""),
        "score": round(final_score, 2),
        "alert_type": ai_result.get("alert_type", "unknown"),
        "urgency": ai_result.get("urgency", "medium"),
        "ioc_count": total_iocs,
        "elapsed_ms": elapsed_ms,
        "ai_skipped": skipped_for_speed,
        "timestamp": ts,
    })

    return {
        **state,
        "iocs": iocs,
        "triage_score": final_score,
        "should_proceed": ai_result.get("should_proceed", True) and final_score > 0.15,
        "triage_reasoning": ai_result.get("reasoning", ""),
        "cross_refs": cross_refs,
        "email_analysis": email_analysis,
        "agent_trace": trace,
    }
