"""
Triage Agent — reads API config at call time, not import time.
This allows keys entered in the Settings UI to take effect immediately.
"""

import ipaddress
import re
import json
from datetime import datetime, timezone


BENIGN_IPS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "208.67.222.222", "169.254.169.254", "100.100.100.200",
    # IPv6 equivalents of the well-known public resolvers
    "2001:4860:4860::8888", "2001:4860:4860::8844",
    "2606:4700:4700::1111", "2606:4700:4700::1001",
}
BENIGN_DOMAINS = {
    "microsoft.com", "windows.com", "windowsupdate.com", "office.com",
    "office365.com", "live.com", "azure.com", "amazonaws.com",
    "google.com", "googleapis.com", "gstatic.com", "apple.com",
    "icloud.com", "cloudflare.com", "fastly.net", "akamai.net",
}

# Loose IPv6 candidate matcher — handles full notation, leading ::, trailing ::,
# and embedded :: compression. Every candidate is validated through
# ipaddress.ip_address() so false-positive substrings (hex strings, MAC
# addresses, etc.) are rejected at the validation step.
#
# Alternation ORDER matters: re.findall takes the first match it commits to
# at each position. The "trailing ::" branch is moved LAST so a fully-formed
# "2606:4700:4700::1111" tries to match as a full-with-suffix form FIRST
# before the engine falls back to the trailing-:: prefix-only match.
_IPV6_CANDIDATE_RE = re.compile(
    r"\b(?:"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"          # full 8-group form
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"      # compressed with 1-group suffix
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})"
    r"|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}"     # leading :: with suffix
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"                       # trailing :: (NO suffix — LAST)
    r"|::"                                                  # bare ::
    r")\b"
)


def _is_private_ip(ip: str) -> bool:
    """True for loopback / private / link-local / multicast / reserved
    addresses in BOTH IPv4 and IPv6 — uses the stdlib `ipaddress`
    module so we don't have to re-implement RFC1918 / RFC4193 / etc."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def _valid_ip(ip: str) -> bool:
    """Accept any well-formed IPv4 or IPv6 address. Replaces the old
    IPv4-only _valid_octets which rejected every IPv6 input on the
    `int(part) ValueError` branch — that bug caused impossible-travel
    alerts (which carry IPv6 source IPs) to skip enrichment entirely."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _valid_ipv4_octets(ip: str) -> bool:
    """Explicit IPv4 octet validation: every octet must be 0-255. Belt-and-
    braces gate on top of ipaddress.ip_address() — Microsoft Defender logs
    emit Security Intelligence Version strings like "AV: 1.451.195.0" that
    look IPv4-shaped but have octets > 255. They are not IPs and must never
    reach the IOC list."""
    if not ip or ":" in ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if int(part) > 255:
            return False
    return True


# Backwards-compatible alias — `_valid_octets` was the old name and may be
# imported by tests. The new behaviour accepts IPv6 too.
_valid_octets = _valid_ip


# Microsoft Defender Event ID 1116/1117 emits Security Intelligence and
# Engine version strings in the form "AV: 1.451.195.0", "AS: 1.451.195.0",
# "NIS: 1.451.195.0", "AM: 1.1.24090.11". Their second octet routinely
# exceeds 255, so they are NOT IP addresses — they are software version
# numbers. iocextract still matches them as dotted-quad candidates, so we
# scrub them out of the raw text before IOC extraction runs.
_DEFENDER_VERSION_RE = re.compile(
    r"\b(?:AV|AS|NIS|AM|AntiSpyware|AntiVirus|Engine|"
    r"Security\s+Intelligence|Anti(?:malware|spyware|virus))\s+"
    r"(?:Version|Signature\s+Version)?\s*:\s*"
    r"\d{1,5}(?:\.\d{1,5}){2,3}",
    re.IGNORECASE,
)
# Standalone "AV: 1.451.195.0" form (no "Version" word) — common in Defender XML.
_DEFENDER_AV_KV_RE = re.compile(
    r"\b(?:AV|AS|NIS|AM)\s*:\s*\d{1,5}(?:\.\d{1,5}){2,3}\b",
)

# Version-numbered directories inside a file path look like
#   c:\users\X\appdata\local\app-name\6.35.0.35\service\app.exe
#   /opt/foo/1.2.3.4/bin/foo
#   "C:/Program Files/Vendor/2.10.4.7/lib/X"
# iocextract matches `6.35.0.35` as a dotted-quad even though all octets
# are < 256, but in this context it's a version directory, not a host
# address. Strip every 4-part numeric segment that is bracketed on both
# sides by a path separator. We deliberately don't strip segments at the
# end of a token (no trailing /) — `connect to 6.35.0.35` is still a
# legitimate IP candidate and should reach extraction.
_PATH_VERSION_RE = re.compile(
    r"(?<=[\\\\/])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?=[\\\\/])"
)


def strip_defender_version_strings(text: str) -> str:
    """Remove Microsoft Defender Security Intelligence / Engine version
    strings AND in-path version directories (like \\6.35.0.35\\service\\)
    from the input so they never reach IOC extraction. Replaces each
    match with a single space so token boundaries upstream of the match
    still hold."""
    if not text:
        return text
    text = _DEFENDER_VERSION_RE.sub(" ", text)
    text = _DEFENDER_AV_KV_RE.sub(" ", text)
    text = _PATH_VERSION_RE.sub(" ", text)
    return text


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
            "emails": set(), "files": set(), "paths": set(), "cves": set()}

    # Scrub Microsoft Defender version strings (AV/AS/NIS/AM: 1.451.195.0)
    # BEFORE iocextract sees them. Their second octet routinely exceeds 255
    # so they are software versions, not IP addresses, but iocextract's
    # regex would still pick them up before validation runs.
    text = strip_defender_version_strings(text or "")

    # Try the library route first — refangs defanged IOCs automatically.
    # iocextract's extract_ips() covers both v4 and v6.
    try:
        import iocextract

        for ip in iocextract.extract_ips(text, refang=True):
            ip = ip.strip()
            if ip in BENIGN_IPS or _is_private_ip(ip) or not _valid_ip(ip):
                continue
            # Explicit IPv4 octet gate — discard any v4-shaped string with
            # an octet > 255 (Defender version numbers slip past iocextract
            # but get caught here).
            if "." in ip and ":" not in ip and not _valid_ipv4_octets(ip):
                continue
            iocs["ips"].add(ip)

        for url in iocextract.extract_urls(text, refang=True):
            # Skip documentation / KB URLs inside alert message bodies —
            # Defender, Sentinel, EDR vendors embed links like
            # https://go.microsoft.com/fwlink/?linkid=37020 inside their
            # message field as the "more info" target. These are not
            # IOCs and shouldn't reach enrichment / GTI scoring.
            u_lower = url.lower()
            if any(s in u_lower for s in (
                "go.microsoft.com/", "learn.microsoft.com/",
                "docs.microsoft.com/", "support.microsoft.com/",
                "aka.ms/", "technet.microsoft.com/",
                "google.com/search?", "support.google.com/",
                "developer.mozilla.org/",
            )):
                continue
            iocs["urls"].add(url.rstrip(".,;)\"'"))

        for h in iocextract.extract_hashes(text):
            iocs["hashes"].add(h.lower())

        for e in iocextract.extract_emails(text, refang=True):
            iocs["emails"].add(e.lower())

    except ImportError:
        # Fallback regex path — keeps the app running if iocextract isn't installed.
        norm = (text
            .replace("[.]", ".").replace("(dot)", ".")
            .replace("[://]", "://").replace("hxxp", "http"))
        for url in re.findall(r"https?://[^\s\"'<>\]\),]+", norm):
            u_lower = url.lower()
            if any(s in u_lower for s in (
                "go.microsoft.com/", "learn.microsoft.com/",
                "docs.microsoft.com/", "support.microsoft.com/",
                "aka.ms/", "technet.microsoft.com/",
                "google.com/search?", "support.google.com/",
            )):
                continue
            iocs["urls"].add(url.rstrip(".,;)"))
        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", norm):
            if ip in BENIGN_IPS or _is_private_ip(ip) or not _valid_ip(ip):
                continue
            if not _valid_ipv4_octets(ip):
                continue
            iocs["ips"].add(ip)
        for pat in [r"\b[a-fA-F0-9]{64}\b", r"\b[a-fA-F0-9]{40}\b", r"\b[a-fA-F0-9]{32}\b"]:
            for h in re.findall(pat, norm):
                iocs["hashes"].add(h.lower())
        for e in re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", norm):
            iocs["emails"].add(e.lower())

    # IPv6 sweep — runs regardless of which path above ran. iocextract picks
    # up most IPv6 forms but the regex catch-all here makes the impossible-
    # travel case (where v6 addresses sit in `FirstLoginIp : <addr>` lines)
    # bulletproof. Every candidate is validated through ipaddress.ip_address()
    # so hex strings, MAC addresses, and other v6-shaped noise get rejected.
    for cand in _IPV6_CANDIDATE_RE.findall(text or ""):
        try:
            normalised = str(ipaddress.ip_address(cand))
        except ValueError:
            continue
        if normalised in BENIGN_IPS or _is_private_ip(normalised):
            continue
        iocs["ips"].add(normalised)

    # IPv6 substring dedup — the trailing-:: branch of the regex (plus the
    # equivalent in iocextract) sometimes matches both "2606:4700::" and the
    # longer "2606:4700::1111" from the same source. They're both technically
    # valid IPv6, but the shorter is just a regex prefix of the longer.
    # Whichever raw substring is contained in another is dropped.
    v6_in_set = [s for s in iocs["ips"] if ":" in s]
    if len(v6_in_set) > 1:
        # Reconstruct the raw textual forms we'd compare against — using the
        # source text, not the canonicalised forms (those have already been
        # normalised away from each other).
        for shorter in list(v6_in_set):
            for longer in v6_in_set:
                if shorter == longer:
                    continue
                # A raw "2606:4700::" appears INSIDE "2606:4700::1111" in the
                # source text. Drop the shorter when it's a textual prefix
                # substring of another match and they normalise to different
                # addresses.
                if shorter in longer and shorter != longer:
                    iocs["ips"].discard(shorter)
                    break

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

    # CVE IDs — extracted from raw text via a strict regex, deduped,
    # year-validated. Drives the CVE-enrichment pipeline (NVD + EPSS +
    # live CISA KEV check). Lives in its own bucket alongside ips/domains
    # so it routes through the same parallel fan-out + per-source
    # streaming.
    try:
        from intel.cve_enrichment import extract_cves as _xcves
        for cve in _xcves(text):
            iocs["cves"].add(cve)
    except Exception:
        pass

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

    # Microsoft Defender Event 1116/1117 detection — structured parse so
    # downstream stages (investigation prompt, response summary, email
    # composer) treat the Path field as the infected artifact and the
    # Process Name field as the legitimate triggering process, not as the
    # malware itself.
    defender_parse = None
    try:
        from intel.defender_parser import parse_defender_event
        defender_parse = parse_defender_event(raw)
    except Exception:
        defender_parse = None

    # Multi-log detection has been retired — the AI was producing
    # "log correlation" output for single alerts containing multiple
    # pieces of evidence (Robocopy + Code Integrity modification in one
    # Defender alert, etc.) which read as if the user had pasted two
    # logs. The AI's main analysis paragraph already reasons about
    # relationships between events inside the alert; the dedicated
    # log_correlation field added more noise than signal. Always set
    # log_count=1 so downstream stages treat the input as one alert.
    multi_log = {"log_count": 1, "is_multi": False,
                  "segments": [raw], "anchors": []}

    # AI log translation (spec §4) — runs before IOC extraction and behavioral
    # analysis so they operate on structured fields rather than just raw text.
    # Fails open: if no API key or the call errors out, translation is None and
    # downstream stages fall back to raw input.
    log_translation = None
    try:
        from intel.log_translator import translate_log, fields_as_text
        from config import config as _cfg
        log_translation = await translate_log(raw, _cfg)
        if log_translation:
            extracted = fields_as_text(log_translation)
            if extracted:
                # Append normalized fields to the text we feed downstream — this
                # ensures behavior_extractor + extract_iocs see both raw + parsed
                raw = raw + "\n\n# AI-extracted fields\n" + extracted
    except Exception:
        log_translation = None

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

    # MISP warninglist false-positive filter (spec §4).
    # Both `iocs` (filtered) and `suppressed_iocs` (removed-with-reason) flow
    # downstream so the analyst sees what was filtered and why.
    suppressed_iocs: dict = {}
    try:
        from intel.warninglist_filter import filter_iocs
        filtered, suppressed_iocs = filter_iocs(iocs)
        iocs = filtered
    except Exception:
        pass

    # Behavioral / TTP extraction on the raw input (spec §1 — pre-enrichment).
    # Scans for PowerShell encoded cradles, LOLBin abuse, persistence, lateral
    # movement, credential access, and C2 patterns; maps each to MITRE.
    behavioral_indicators: dict = {}
    try:
        from intel.behavior_extractor import extract_behavioral_indicators
        behavioral_indicators = extract_behavioral_indicators(raw)
    except Exception as e:
        behavioral_indicators = {"error": str(e), "categories": {}, "total": 0}

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
            from providers import get_provider
            provider = get_provider()
            resp = await provider.complete(
                # Triage is a fast routing decision (the real reasoning is the
                # investigation step) → fast model tier.
                model=config.get_model(fast=True),
                messages=[{"role": "user", "content": TRIAGE_PROMPT.format(
                    log_snippet=raw[:600], ioc_summary=ioc_summary,
                )}],
                max_tokens=220,
                temperature=0.0,
                response_format={"type": "json_object"},   # OpenAI-only; safely ignored elsewhere
            )
            if resp.error:
                ai_result = None
            else:
                ai_result = json.loads(resp.message)
        except Exception:
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
        "suppressed_iocs":       suppressed_iocs,        # MISP warninglist removals (spec §4)
        "behavioral_indicators": behavioral_indicators,  # TTP / pattern extraction (spec §1)
        "log_translation":       log_translation,        # AI log format detection (spec §4)
        "defender_parse":        defender_parse,         # Defender 1116/1117 structured parse
        "multi_log":             multi_log,              # Multi-log split + anchors
        "log_count":             (multi_log or {}).get("log_count", 1),
        "triage_score":          final_score,
        "should_proceed":        ai_result.get("should_proceed", True) and final_score > 0.15,
        "triage_reasoning":      ai_result.get("reasoning", ""),
        "cross_refs":            cross_refs,
        "email_analysis":        email_analysis,
        "agent_trace":           trace,
    }
