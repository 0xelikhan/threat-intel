"""
Triage Agent — reads API config at call time, not import time.
This allows keys entered in the Settings UI to take effect immediately.
"""

import ipaddress
import logging
import re
import json
from datetime import datetime, timezone

_log = logging.getLogger("recon.triage")


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


# Reject `http(s)://<dotted-quad>...` URLs whose host has any octet > 255.
# iocextract's refang of "1[.]453[.]161[.]0" produces "http://1.453.161.0"
# — a syntactically-shaped URL whose host isn't a valid IP. Without this
# gate the fabricated URL reaches enrichment, where VT/AbuseIPDB return
# `bad request` and the bogus IOC pollutes the analyst report.
_URL_DOTTED_QUAD_HOST_RE = re.compile(
    r"^https?://(\d{1,5}(?:\.\d{1,5}){3})(?:[:/?#]|$)",
    re.IGNORECASE,
)


def _url_host_is_invalid_quad(url: str) -> bool:
    m = _URL_DOTTED_QUAD_HOST_RE.match(url or "")
    if not m:
        return False
    return not _valid_ipv4_octets(m.group(1))


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

# X.509 Object Identifiers (OIDs) — dot-separated numbers, 5+ components,
# often prefixed with "oid." in Windows EDR certificate fields:
#   oid.1.3.6.1.4.1.311.60.2.1.1=road town
#   oid.2.5.4.15=private organization
#   1.3.6.1.4.1.311.21.10
# iocextract's IP matcher is greedy on the leading 4 components ("1.3.6.1"
# from "1.3.6.1.4.1.311.60.2.1.1"), so OID strings get extracted as IPv4
# and shipped to VirusTotal / OTX. Strip the entire OID run before the
# IP regex ever sees it. The 5-component minimum keeps legitimate v4
# addresses (always exactly 4 parts) untouched.
_OID_RE = re.compile(
    r"\b(?:oid\.)?\d{1,5}(?:\.\d{1,5}){4,}\b",
    re.IGNORECASE,
)
# Short OIDs that LOOK like IPs (4 components) but live in certificate
# context — the "oid." prefix gives them away. Catches "oid.2.5.4.15"
# and similar.
_OID_PREFIXED_SHORT_RE = re.compile(
    r"\boid\.\d{1,5}(?:\.\d{1,5}){2,}\b",
    re.IGNORECASE,
)
# X.509 directory attribute OIDs (the 2.5.4.X branch — CN, OU, O, L, S, C,
# serialNumber, businessCategory, etc.). These appear as bare "2.5.4.15"
# in the trailing part of certificate subject strings even when the
# parser stripped the "oid." prefix. They are never real IPs in EDR
# logs, and the 2.5.4.0/24 IP range is unrouted ARIN-reserved space
# regardless, so stripping is safe.
_X509_DIR_ATTR_OID_RE = re.compile(r"\b2\.5\.4\.\d{1,3}\b")

# User-Agent / browser / software version strings:
#   Chrome/148.0.0.0
#   Mozilla/5.0
#   AppleWebKit/537.36
#   Firefox/121.0.2
#   Edg/119.0.2151.97
#   Safari/605.1.15
#   curl/7.88.1, python-requests/2.31.0, Go-http-client/1.1, etc.
# iocextract happily extracts "148.0.0.0" from "Chrome/148.0.0.0" because
# all octets are 0-255 and the regex doesn't care that the number is
# attached to a software-name slash. Strip the whole "Word/Version"
# token before IP extraction sees it. The Word part allows alnum and
# common separators (-, _, .) that show up in product names.
_SOFTWARE_VERSION_RE = re.compile(
    r"\b[A-Za-z][A-Za-z0-9_\-]*\/\d{1,5}(?:\.\d{1,5}){1,}\b"
)

# Labeled IP fields with an obviously-not-an-IP value. A user's SIEM
# auto-populates "Source IP: <first dotted-quad we found>", which for
# Defender 1116 events ends up being the AV/AS/NIS Security Intelligence
# Version (1.453.161.0 — octet > 255). The value lands in:
#   * the raw alert body the LLM reads, where the model dutifully repeats
#     "the source IP for this event is 1.453.161.0"
#   * iocextract's URL extractor, which refangs 1[.]453[.]161[.]0 to
#     http://1.453.161.0 and ships it as a URL IOC
# We blank only the *value* (not the label) so the alert structure remains
# grep-able for any downstream parser, but the LLM and IOC extractors no
# longer see a dotted-quad to latch onto. Catches the common label
# variants emitted by Defender, Sentinel, Splunk, QRadar, and Carbon Black.
_LABELED_IP_FIELD_RE = re.compile(
    r"""(?ix)
    \b
    (?:
       source\s*ip(?:\s*address)?
      |src(?:[-_]?ip)?
      |client[-_]?ip(?:\s*address)?
      |remote[-_]?ip(?:\s*address)?
      |destination[-_]?ip(?:\s*address)?
      |dest[-_]?ip
      |dst[-_]?ip
      |peer[-_]?ip
      |actor[-_]?ip(?:\s*address)?
      |sourceip\w*
      |ipaddr(?:ess)?
    )
    \s* [:=] \s*
    (\d{1,5}(?:\.\d{1,5}){3})
    \b
    """,
)


def _scrub_invalid_labeled_ip(match: "re.Match[str]") -> str:
    """Replace the value of a labeled IP field with the literal string
    `<invalid>` ONLY when the value isn't a valid IPv4 (any octet > 255).
    Leaves real source IPs untouched so impossible-travel and brute-force
    alerts still surface their attacker IPs."""
    full = match.group(0)
    ip   = match.group(1)
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() and int(p) <= 255 for p in parts):
        return full
    # Cut off the dotted-quad at the end and replace with a sentinel that
    # is obviously not extractable (no dots → no IP regex match, no URL
    # construction by iocextract).
    return full[: -len(ip)] + "<invalid>"


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
    text = _OID_PREFIXED_SHORT_RE.sub(" ", text)
    text = _OID_RE.sub(" ", text)
    text = _X509_DIR_ATTR_OID_RE.sub(" ", text)
    text = _SOFTWARE_VERSION_RE.sub(" ", text)
    text = _LABELED_IP_FIELD_RE.sub(_scrub_invalid_labeled_ip, text)
    return text


def _refang(text: str) -> str:
    """Canonicalise the common analyst-/vendor-defang forms in one pass.

    Anything that survives this also reaches the regex extractors and the
    LLM prompts in canonical dotted form, so downstream patterns don't
    need to know about [.] / (dot) / hxxp variants.
    """
    if not text:
        return text
    return (text
        .replace("[.]", ".").replace("(.)", ".").replace("(dot)", ".")
        .replace("[://]", "://")
        .replace("hxxp://", "http://").replace("hxxps://", "https://"))


def clean_for_analysis(text: str) -> str:
    """Refang + strip noise. The combined pipeline IOC extraction and
    every triage LLM prompt should run on, so vendor noise (Defender
    Security Intelligence Version strings, SIEM `Source IP:` fields
    populated with an invalid quad like 1.453.161.0) never reaches:

      * the IOC regex / iocextract fallback, where it would surface as a
        fake `http://1.453.161.0` URL,
      * the triage / investigation / response LLM prompts, where the
        model would dutifully parrot "the source IP for this event is
        1.453.161.0" into the analyst-facing narrative.

    Order matters: refang FIRST so the strip regexes see canonical dots.
    The legacy `strip_defender_version_strings` is still exported for
    the email composer and any external caller that needs the strip-
    only behaviour.
    """
    return strip_defender_version_strings(_refang(text or ""))


_EXE_RE  = re.compile(
    r"\b([A-Za-z0-9_\-\.]{2,80}\.(?:exe|dll|sys|bat|ps1|cmd|vbs|js|hta|lnk|msi|scr|jar|jse|wsf))\b",
    re.IGNORECASE,
)
_PATH_RE = re.compile(
    r"\b(?:[a-zA-Z]:\\|\\\\)[^\s\"'<>|*?\r\n]+|/(?:home|var|tmp|etc|usr|opt|root)/[^\s\"'<>|*?\r\n]+",
)
# Pure-regex IOC extractors used by extract_iocs after pre-refanging.
# Replace the slow iocextract library calls on large inputs.
_RAW_URL_RE   = re.compile(r"https?://[^\s\"'<>\]\),]+", re.IGNORECASE)
_RAW_IPV4_RE  = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RAW_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_HASH_RES     = (
    re.compile(r"\b[a-fA-F0-9]{64}\b"),
    re.compile(r"\b[a-fA-F0-9]{40}\b"),
    re.compile(r"\b[a-fA-F0-9]{32}\b"),
)

# Domain extractor — TLD-bounded so we don't grab arbitrary tokens.
# Hoisted to module scope from inside extract_iocs() so we don't pay
# the compile cost on every triage call.
_URL_STRIP_RE = re.compile(r"https?://[^\s\"'<>\]\),]+")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)"
    r"+(?:com|net|org|io|gov|edu|mil|co|uk|ru|cn|de|xyz|top|online|"
    r"site|app|dev|cloud|tech|store|live|icu|pw|cc|me|tv|ws|mobi)\b",
    re.IGNORECASE,
)


def extract_iocs(text: str) -> dict:
    """Extract IOCs with pre-refanging + pure C-level regex.

    Used to delegate to the `iocextract` library, which handles defanged
    forms beautifully (8[.]8[.]8[.]8, hxxp://, bracketed dots) but scales
    catastrophically: ~1.2 s on 50 KB, ~350 s on 1 MB. AnalyzeRequest
    accepts up to 1 MB pastes, so a single large alert could lock the
    triage stage for minutes. The pure-regex path below runs in ~10 ms
    on the same 300 KB input the library spent 13 s on.

    The defang pre-pass handles every common form we see in security
    logs (Microsoft / Mandiant / vendor copy-paste). When the input is
    small AND iocextract is installed, we still use it for one extra
    pass to pick up forms our regex misses (rare; mostly edge IPv6).
    """
    iocs = {"ips": set(), "domains": set(), "urls": set(), "hashes": set(),
            "emails": set(), "files": set(), "paths": set(), "cves": set()}

    # Refang + scrub in one step. Order is load-bearing: refang runs
    # FIRST so the strip patterns (AV/AS/NIS Defender versions, "Source
    # IP: <invalid quad>" labeled fields) see canonical dotted form.
    # Defanged Defender version strings previously slipped through every
    # pattern because they all assumed literal dots.
    norm = clean_for_analysis(text or "")

    for url in _RAW_URL_RE.findall(norm):
        u_lower = url.lower()
        if any(s in u_lower for s in (
            "go.microsoft.com/", "learn.microsoft.com/",
            "docs.microsoft.com/", "support.microsoft.com/",
            "aka.ms/", "technet.microsoft.com/",
            "google.com/search?", "support.google.com/",
            "developer.mozilla.org/",
        )):
            continue
        if _url_host_is_invalid_quad(url):
            continue
        iocs["urls"].add(url.rstrip(".,;)\"'"))
    for ip in _RAW_IPV4_RE.findall(norm):
        if ip in BENIGN_IPS or _is_private_ip(ip) or not _valid_ip(ip):
            continue
        if not _valid_ipv4_octets(ip):
            continue
        iocs["ips"].add(ip)
    for pat in _HASH_RES:
        for h in pat.findall(norm):
            iocs["hashes"].add(h.lower())
    for e in _RAW_EMAIL_RE.findall(norm):
        iocs["emails"].add(e.lower())

    # Tiny inputs (≤ 10 KB) get an extra iocextract pass for the rare
    # edge forms the regex misses. The library's quadratic behaviour
    # only bites on large inputs — below the cap it adds ~10 ms for
    # better coverage. ImportError still falls through cleanly.
    if len(norm) <= 10_000:
        try:
            import iocextract
            for ip in iocextract.extract_ips(norm, refang=True):
                ip = ip.strip()
                if ip in BENIGN_IPS or _is_private_ip(ip) or not _valid_ip(ip):
                    continue
                if "." in ip and ":" not in ip and not _valid_ipv4_octets(ip):
                    continue
                iocs["ips"].add(ip)
            for url in iocextract.extract_urls(norm, refang=True):
                u_lower = url.lower()
                if any(s in u_lower for s in (
                    "go.microsoft.com/", "learn.microsoft.com/",
                    "docs.microsoft.com/", "support.microsoft.com/",
                    "aka.ms/", "technet.microsoft.com/",
                    "google.com/search?", "support.google.com/",
                    "developer.mozilla.org/",
                )):
                    continue
                if _url_host_is_invalid_quad(url):
                    # iocextract refangs defanged "1[.]453[.]161[.]0"
                    # into "http://1.453.161.0" — drop these so SIEM
                    # mis-labelled version strings don't get shipped as
                    # URL IOCs to enrichment.
                    continue
                iocs["urls"].add(url.rstrip(".,;)\"'"))
            for h in iocextract.extract_hashes(norm):
                iocs["hashes"].add(h.lower())
            for e in iocextract.extract_emails(norm, refang=True):
                iocs["emails"].add(e.lower())
        except ImportError:
            pass

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
    stripped = _URL_STRIP_RE.sub("", norm)
    for d in _DOMAIN_RE.findall(stripped):
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
        # Defensive: tolerate KEV entries that aren't dicts (a future
        # KEV-feed schema change shouldn't crash the triage fast-path).
        kev_list = cross_refs.get("kev") or []
        if isinstance(kev_list, list) and any(
                isinstance(k, dict) and k.get("ransomware_use") for k in kev_list):
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


TRIAGE_PROMPT = """OUTPUT STYLE (hard rule): Write in plain ASCII. NEVER use em-dashes (—), en-dashes (–), or curly quotes. Use hyphens (-), commas, or restructure the sentence. This applies to every string you emit, including JSON values.

You are a SOC triage analyst. Quickly assess this security alert.

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


async def run_triage(state: dict, defer_ai: bool = False) -> dict:
    """Full triage stage: heuristic IOC extraction + MISP warninglist +
    behavioural TTP mapping + cross_refs + AI classifier.

    defer_ai=True short-circuits BEFORE the AI classifier LLM call and
    returns state with a `_pending_ai_triage` marker set. The caller is
    then expected to run `finalize_triage_ai(state)` (typically in
    parallel with the enrichment stage) to fill in alert_type / urgency /
    reasoning / final_score. Used by the SSE pipeline in main.py to
    overlap the AI classifier's ~2-3s LLM call with the enrichment
    stage's HTTP fan-out.
    """
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

    # Stash a scrubbed-for-LLM copy on state. EML / Defender / multi-log
    # parsers ran above on the ORIGINAL raw because they need to see
    # `Security intelligence Version: AV: 1.453.161.0` etc. as-is for
    # field extraction. From this point on, every LLM call (log
    # translation, triage routing, deep investigation, response summary)
    # reads `raw_input_clean` instead so the model never sees the SIEM-
    # mislabelled "Source IP: 1.453.161.0" line that it would otherwise
    # parrot back as "the source IP for this event is …".
    state["raw_input_clean"] = clean_for_analysis(raw)

    # AI log translation (spec §4) — runs before IOC extraction and behavioral
    # analysis so they operate on structured fields rather than just raw text.
    # Fails open: if no API key or the call errors out, translation is None and
    # downstream stages fall back to raw input.
    log_translation = None
    try:
        from intel.log_translator import translate_log, fields_as_text
        from config import config as _cfg
        # Use the scrubbed snippet so the translator LLM also doesn't see
        # the mislabelled "Source IP: <invalid quad>".
        log_translation = await translate_log(state["raw_input_clean"], _cfg)
        if log_translation:
            extracted = fields_as_text(log_translation)
            if extracted:
                # Append normalized fields to the text we feed downstream — this
                # ensures behavior_extractor + extract_iocs see both raw + parsed
                raw = raw + "\n\n# AI-extracted fields\n" + extracted
                # And keep raw_input_clean in sync so downstream LLM stages
                # also see the translator's structured fields.
                state["raw_input_clean"] = state["raw_input_clean"] + "\n\n# AI-extracted fields\n" + extracted
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
    #
    # This gate is load-bearing: when it fails, every benign IOC (public DNS
    # resolvers, microsoft.com / google.com / cloudflare endpoints, MISP-
    # warninglisted CIDRs) goes to the paid TI fan-out — burning quota and
    # latency on indicators the platform already knows are CLEAN. Log loudly
    # so a wedged filter shows up in operator logs instead of just looking
    # like an unexplained quota spike.
    suppressed_iocs: dict = {}
    try:
        from intel.warninglist_filter import filter_iocs
        filtered, suppressed_iocs = filter_iocs(iocs)
        iocs = filtered
    except Exception as _e:
        _log.warning("MISP warninglist filter failed; benign IOCs will reach "
                     "enrichment fan-out unfiltered: %s", _e)

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

    # Benign fast-path: signed-vendor + tenant-permit + zero positive
    # cross-refs is a strong signal this is a policy-audit event, not a
    # threat. Skip the AI classifier (saves ~4-5s of TTFT). The downstream
    # investigation stage's benign short-circuit picks the alert up next
    # and the response fast-path finishes it — total pipeline drops to
    # triage + enrichment + a few ms of synthesis.
    if ai_result is None:
        _t2_start = time.perf_counter()
        try:
            from intel.signal_priority import (
                _KNOWN_GOOD_VENDOR_PATTERNS as _KG,
                _TENANT_PERMIT_PATTERNS as _TP,
            )
            _raw_lc = raw  # regexes are case-insensitive
            _kg_hit = any(rx.search(_raw_lc) for rx in _KG)
            _tp_hits = sum(1 for rx in _TP if rx.search(_raw_lc))
            _no_pos_cross = not any(
                cross_refs.get(k) for k in
                ("kev", "lolbas", "loldrivers", "rmm_abuse",
                 "suspicious_paths", "phishing_kits")
            )
            if _kg_hit and _tp_hits >= 2 and _no_pos_cross and heuristic_score < 0.35:
                skipped_for_speed = True
                ai_result = {
                    "triage_score":   max(heuristic_score, 0.05),
                    "should_proceed": True,   # investigation short-circuits it
                    "reasoning":      (
                        f"Benign fast-path: signed-vendor + tenant-permit "
                        f"markers ({_tp_hits}) with zero positive cross-refs — "
                        f"AI triage skipped."
                    ),
                    "alert_type":     "benign_permit",
                    "urgency":        "low",
                    "false_positive_indicators": [
                        "known-good vendor pattern",
                        "tenant policy permit",
                    ],
                    "priority_iocs":  [],
                }
        except Exception as _e:
            # If signal_priority patterns aren't importable, fall through
            # to the AI path — don't fail the whole triage stage.
            pass

    # Defer-AI short-circuit: return early with heuristic-derived state
    # + everything needed to finalize the AI classifier later. Caller
    # (main.py's _stream) will kick off finalize_triage_ai concurrently
    # with enrichment.
    if defer_ai and ai_result is None:
        trace.append({
            "agent": "triage",
            "status": "pending_ai",
            "summary": "Heuristic triage complete; AI classifier deferred (running in parallel with enrichment).",
            "score": round(heuristic_score, 2),
            "alert_type": derive_alert_type(iocs, cross_refs),
            "urgency": "medium",
            "ioc_count": total_iocs,
            "elapsed_ms": int((time.perf_counter() - _t_start) * 1000),
            "ai_skipped": False,
            "timestamp": ts,
        })
        return {
            **state,
            "iocs": iocs,
            "suppressed_iocs":       suppressed_iocs,
            "behavioral_indicators": behavioral_indicators,
            "log_translation":       log_translation,
            "defender_parse":        defender_parse,
            "multi_log":             multi_log,
            "log_count":             (multi_log or {}).get("log_count", 1),
            "triage_score":          heuristic_score,
            # should_proceed conservatively True — the enrichment stage
            # gates itself on IOCs anyway; the final AI-merged score
            # will make the real drop decision after finalize.
            "should_proceed":        heuristic_score > 0.10,
            "triage_reasoning":      "heuristic complete; AI pending",
            "cross_refs":            cross_refs,
            "email_analysis":        email_analysis,
            "agent_trace":           trace,
            "_pending_ai_triage":    {
                "heuristic_score":  heuristic_score,
                "ioc_summary":      ioc_summary,
                "iocs":             iocs,
                "cross_refs":       cross_refs,
                "scrubbed_snippet": (state.get("raw_input_clean") or raw)[:600],
            },
        }

    # Use the provider-abstraction-aware check so triage runs the AI
    # path on Anthropic / Ollama deployments too; the old direct
    # OPENAI_API_KEY check skipped AI triage entirely on non-OpenAI
    # deployments and silently fell through to the heuristic-only result.
    from providers import provider_configured
    if ai_result is None and provider_configured(config):
        try:
            from providers import get_provider
            provider = get_provider()
            # Use the scrubbed snippet — Defender version strings + SIEM-
            # mislabelled "Source IP: 1.453.161.0" are wiped on state by
            # `raw_input_clean`. Without this the model parrots the invalid
            # quad back into the analyst narrative as "the source IP for
            # this event is …" (bug reported 2026-06-19 against a
            # PUABundler:FileZilla Defender alert).
            scrubbed_snippet = (state.get("raw_input_clean") or raw)[:600]
            resp = await provider.complete(
                # Triage is a fast routing decision (the real reasoning is the
                # investigation step) → fast model tier.
                model=config.get_model(fast=True),
                messages=[{"role": "user", "content": TRIAGE_PROMPT.format(
                    log_snippet=scrubbed_snippet, ioc_summary=ioc_summary,
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

    # AI sometimes returns triage_score as a string ("0.8") or even a
    # word ("high") instead of a number — coerce defensively rather than
    # crashing the whole triage pipeline with a TypeError.
    try:
        _ai_score = float(ai_result.get("triage_score", heuristic_score))
    except (TypeError, ValueError):
        _ai_score = heuristic_score
    final_score = (_ai_score + heuristic_score) / 2

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


async def finalize_triage_ai(state: dict) -> dict:
    """Runs the AI classifier LLM call that `run_triage(..., defer_ai=True)`
    skipped, merges the result back into state, and updates the trace
    entry.

    Designed to run concurrently with `run_enrichment` — the AI call
    doesn't touch enrichments and enrichment doesn't touch the fields
    finalize_triage_ai writes to, so the two overlap safely. Caller
    awaits both before starting investigation.

    When state has no `_pending_ai_triage` marker (defer wasn't used),
    the function is a no-op and returns state unchanged.
    """
    pending = state.get("_pending_ai_triage")
    if not pending:
        return state
    from config import config
    heuristic_score = pending.get("heuristic_score", 0.0)
    iocs = pending.get("iocs", {})
    cross_refs = pending.get("cross_refs", {})
    scrubbed = pending.get("scrubbed_snippet", "")
    ioc_summary = pending.get("ioc_summary", "")

    ai_result = None
    try:
        from providers import provider_configured, get_provider
        if provider_configured(config):
            provider = get_provider()
            resp = await provider.complete(
                model=config.get_model(fast=True),
                messages=[{"role": "user", "content": TRIAGE_PROMPT.format(
                    log_snippet=scrubbed, ioc_summary=ioc_summary,
                )}],
                max_tokens=220,
                temperature=0.0,
                response_format={"type": "json_object"},
            )
            if not resp.error:
                ai_result = json.loads(resp.message)
    except Exception:
        ai_result = None

    if ai_result is None:
        ai_result = {
            "triage_score":   heuristic_score,
            "should_proceed": heuristic_score > 0.15,
            "reasoning":      "Heuristic score (AI unavailable or key not configured).",
            "alert_type":     derive_alert_type(iocs, cross_refs),
            "urgency":        "medium",
            "false_positive_indicators": [],
            "priority_iocs":  [],
        }

    try:
        _ai_score = float(ai_result.get("triage_score", heuristic_score))
    except (TypeError, ValueError):
        _ai_score = heuristic_score
    final_score = (_ai_score + heuristic_score) / 2

    # Update the pending trace entry in place with the final AI-merged
    # score + AI-supplied alert_type / reasoning / urgency.
    trace = list(state.get("agent_trace", []))
    for i, t in enumerate(trace):
        if t.get("agent") == "triage" and t.get("status") == "pending_ai":
            trace[i] = {
                **t,
                "status":      "complete",
                "summary":     ai_result.get("reasoning", ""),
                "score":       round(final_score, 2),
                "alert_type":  ai_result.get("alert_type", "unknown"),
                "urgency":     ai_result.get("urgency", "medium"),
            }
            break

    new_state = dict(state)
    new_state.pop("_pending_ai_triage", None)
    new_state.update({
        "triage_score":     final_score,
        "should_proceed":   ai_result.get("should_proceed", True) and final_score > 0.15,
        "triage_reasoning": ai_result.get("reasoning", ""),
        "agent_trace":      trace,
    })
    return new_state
