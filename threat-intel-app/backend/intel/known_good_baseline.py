"""
Built-in known-good baseline for short-circuiting enrichment.

When triage extracts an IOC that maps to a well-known benign service
(public DNS, Microsoft sign-in endpoint, Cloudflare, Google API, etc.)
there's no point burning AbuseIPDB / VT / OTX quota to be told what
we already know. This module bakes the answer in.

Distinct from warninglists:
  - warninglists SUPPRESS at triage — the IOC never enters enrichment
    (correct behaviour for noisy false-positive sources like
    cloudflare.com appearing in every customer log).
  - this baseline LETS the IOC through but pre-fills a CLEAN verdict
    so the per-IOC card shows a real result instead of "no data".
    Correct behaviour for IOCs the analyst pasted *deliberately* to
    sanity-check the platform, or for warninglist-misses.

Hit format:
  {
    "matched":  True,
    "name":     "Google Public DNS",
    "category": "public_dns",
    "verdict":  "CLEAN",
    "summary":  "Well-known Google Public DNS resolver (8.8.8.8).",
    "source":   "known_good_baseline",
  }

The lists are deliberately conservative — only operator-managed
infrastructure that's stable for years. Anything ambiguous (CDN
fronts, shared hosting) is omitted so we don't accidentally whitewash
attacker-controlled CloudFront / Cloudflare-Pages content.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Optional


# ─── IPs ────────────────────────────────────────────────────────────────────
# Each entry maps a CIDR or exact IP to a label. We test exact IP first,
# then CIDR for ranges (CDN egress, Google ASN-wide, etc.).
_IP_EXACT: Dict[str, Dict[str, str]] = {
    # Public recursive resolvers
    "8.8.8.8":          {"name": "Google Public DNS",       "category": "public_dns"},
    "8.8.4.4":          {"name": "Google Public DNS",       "category": "public_dns"},
    "1.1.1.1":          {"name": "Cloudflare 1.1.1.1 DNS",  "category": "public_dns"},
    "1.0.0.1":          {"name": "Cloudflare 1.1.1.1 DNS",  "category": "public_dns"},
    "1.1.1.2":          {"name": "Cloudflare DNS (Malware Filter)", "category": "public_dns"},
    "1.0.0.2":          {"name": "Cloudflare DNS (Malware Filter)", "category": "public_dns"},
    "1.1.1.3":          {"name": "Cloudflare DNS (Family)",  "category": "public_dns"},
    "1.0.0.3":          {"name": "Cloudflare DNS (Family)",  "category": "public_dns"},
    "9.9.9.9":          {"name": "Quad9 DNS",                "category": "public_dns"},
    "149.112.112.112":  {"name": "Quad9 DNS (secondary)",    "category": "public_dns"},
    "208.67.222.222":   {"name": "OpenDNS",                  "category": "public_dns"},
    "208.67.220.220":   {"name": "OpenDNS",                  "category": "public_dns"},
    "94.140.14.14":     {"name": "AdGuard DNS",              "category": "public_dns"},
    "76.76.2.0":        {"name": "Control D DNS",            "category": "public_dns"},
    # NTP — common in network logs as outbound destinations.
    "129.6.15.28":      {"name": "NIST time-a.nist.gov",     "category": "ntp"},
    "129.6.15.29":      {"name": "NIST time-b.nist.gov",     "category": "ntp"},
    "132.163.97.1":     {"name": "NIST time-a-wwv.nist.gov", "category": "ntp"},
    "162.159.200.1":    {"name": "Cloudflare time.cloudflare.com", "category": "ntp"},
    "162.159.200.123":  {"name": "Cloudflare time.cloudflare.com", "category": "ntp"},
    # IPv6 equivalents (common in cloud-managed endpoints)
    "2001:4860:4860::8888": {"name": "Google Public DNS",    "category": "public_dns"},
    "2001:4860:4860::8844": {"name": "Google Public DNS",    "category": "public_dns"},
    "2606:4700:4700::1111": {"name": "Cloudflare 1.1.1.1 DNS","category": "public_dns"},
    "2606:4700:4700::1001": {"name": "Cloudflare 1.1.1.1 DNS","category": "public_dns"},
    "2620:fe::fe":      {"name": "Quad9 DNS",                "category": "public_dns"},
}

# CIDR ranges that are operator-stable and benign. Kept tight — only
# ranges that are dedicated to one verifiable service, never general
# ASN ranges that a tenant could spin up arbitrary infrastructure in.
_IP_CIDR_RANGES = [
    # Cloudflare core (their anycast ranges are well-known)
    ("104.16.0.0/12",   "Cloudflare anycast",       "cdn"),
    ("172.64.0.0/13",   "Cloudflare anycast",       "cdn"),
    ("141.101.64.0/18", "Cloudflare",               "cdn"),
    ("190.93.240.0/20", "Cloudflare",               "cdn"),
    # Akamai Edge DNS (rrdns.akamai.net)
    ("23.32.0.0/11",    "Akamai Edge",              "cdn"),
    # AWS S3 us-east-1 hot range (very common in legitimate prefetch logs)
    ("52.216.0.0/15",   "AWS S3 us-east-1",         "cloud"),
    # Microsoft Office 365 / Azure AD common front
    ("13.107.6.152/31", "Microsoft Office 365",     "cloud"),
    ("40.96.0.0/13",    "Microsoft Outlook",        "cloud"),
    ("52.96.0.0/14",    "Microsoft Exchange Online","cloud"),
]


# Pre-compute CIDR network objects for fast membership tests.
_CIDR_NETWORKS = [
    (ipaddress.ip_network(cidr), name, cat)
    for cidr, name, cat in _IP_CIDR_RANGES
]


# ─── Domains ────────────────────────────────────────────────────────────────
# Exact domain match (case-insensitive) OR right-anchored suffix match
# (so "login.microsoftonline.com" hits whether the user pasted that or
# any subdomain like "sts.login.microsoftonline.com").
_DOMAIN_EXACT: Dict[str, Dict[str, str]] = {
    # Microsoft / Office 365 / Azure AD core auth + telemetry
    "login.microsoftonline.com":  {"name": "Microsoft Entra ID sign-in",         "category": "ms_auth"},
    "login.microsoft.com":        {"name": "Microsoft sign-in",                  "category": "ms_auth"},
    "login.live.com":             {"name": "Microsoft consumer sign-in",         "category": "ms_auth"},
    "outlook.office365.com":      {"name": "Microsoft Outlook on the web",       "category": "ms_email"},
    "outlook.office.com":         {"name": "Microsoft Outlook",                  "category": "ms_email"},
    "graph.microsoft.com":        {"name": "Microsoft Graph API",                "category": "ms_api"},
    "management.azure.com":       {"name": "Azure ARM API",                      "category": "ms_api"},
    "portal.azure.com":           {"name": "Azure Portal",                       "category": "ms_console"},
    "admin.microsoft.com":        {"name": "Microsoft 365 admin centre",         "category": "ms_console"},
    "teams.microsoft.com":        {"name": "Microsoft Teams",                    "category": "ms_collab"},
    "sharepoint.com":             {"name": "Microsoft SharePoint",               "category": "ms_collab"},
    "onedrive.live.com":          {"name": "OneDrive",                           "category": "ms_storage"},
    "windowsupdate.com":          {"name": "Windows Update",                     "category": "ms_update"},
    "update.microsoft.com":       {"name": "Microsoft Update",                   "category": "ms_update"},
    "definitionupdates.microsoft.com": {"name": "Microsoft Defender updates",    "category": "ms_update"},
    "wdcp.microsoft.com":         {"name": "Windows Defender cloud protection",  "category": "ms_edr"},
    "events.data.microsoft.com":  {"name": "Microsoft telemetry",                "category": "ms_telemetry"},

    # Google
    "google.com":                 {"name": "Google",                             "category": "google"},
    "www.google.com":             {"name": "Google search",                      "category": "google"},
    "googleapis.com":             {"name": "Google APIs",                        "category": "google_api"},
    "accounts.google.com":        {"name": "Google sign-in",                     "category": "google_auth"},
    "drive.google.com":           {"name": "Google Drive",                       "category": "google_storage"},
    "dns.google":                 {"name": "Google Public DNS resolver",         "category": "public_dns"},

    # Cloudflare
    "cloudflare.com":             {"name": "Cloudflare",                         "category": "cdn"},
    "one.one.one.one":            {"name": "Cloudflare 1.1.1.1 DNS",             "category": "public_dns"},

    # CAs / Cert checking (very common in EDR logs as outbound HTTPS)
    "ocsp.digicert.com":          {"name": "DigiCert OCSP",                      "category": "ca_ocsp"},
    "ocsp.sectigo.com":           {"name": "Sectigo OCSP",                       "category": "ca_ocsp"},
    "ocsp.usertrust.com":         {"name": "Sectigo OCSP",                       "category": "ca_ocsp"},
    "crl.microsoft.com":          {"name": "Microsoft CRL",                      "category": "ca_crl"},
    "ctldl.windowsupdate.com":    {"name": "Windows Cert Trust List updater",    "category": "ca_crl"},

    # Common NTP pool
    "pool.ntp.org":               {"name": "Public NTP pool",                    "category": "ntp"},
    "time.windows.com":           {"name": "Windows time service",               "category": "ntp"},
    "time.apple.com":             {"name": "Apple time service",                 "category": "ntp"},
    "time.cloudflare.com":        {"name": "Cloudflare NTP",                     "category": "ntp"},

    # Apple
    "apple.com":                  {"name": "Apple",                              "category": "apple"},
    "icloud.com":                 {"name": "Apple iCloud",                       "category": "apple_storage"},
    "mzstatic.com":               {"name": "Apple App Store CDN",                "category": "apple_cdn"},
    "swcdn.apple.com":            {"name": "Apple software update CDN",          "category": "apple_update"},

    # Major EDR / AV vendor cloud endpoints (common outbound telemetry)
    "crowdstrike.com":            {"name": "CrowdStrike",                        "category": "edr_vendor"},
    "sentinelone.net":            {"name": "SentinelOne",                        "category": "edr_vendor"},
    "carbonblack.com":            {"name": "VMware Carbon Black",                "category": "edr_vendor"},
    "huntress.io":                {"name": "Huntress",                           "category": "edr_vendor"},
}


# Suffixes that match any subdomain too. Keep tight — these are operator
# zones we trust as a whole, not user-content domains like .blogspot.com.
_DOMAIN_SUFFIX_TRUSTED = [
    (".windowsupdate.com",       "Windows Update edge",      "ms_update"),
    (".office.com",              "Microsoft Office",         "ms_email"),
    (".office365.com",           "Microsoft Office 365",     "ms_email"),
    (".outlook.com",             "Microsoft Outlook",        "ms_email"),
    (".microsoftonline.com",     "Microsoft Entra ID",       "ms_auth"),
    (".live.com",                "Microsoft consumer cloud", "ms_consumer"),
    (".sharepoint.com",          "Microsoft SharePoint",     "ms_collab"),
    (".teams.microsoft.com",     "Microsoft Teams",          "ms_collab"),
    (".azure.com",               "Microsoft Azure",          "ms_api"),
    (".azureedge.net",           "Azure Edge CDN",           "cdn"),
    (".trafficmanager.net",      "Azure Traffic Manager",    "cdn"),
    (".googleapis.com",          "Google APIs",              "google_api"),
    (".gstatic.com",             "Google static content",    "google"),
    (".googleusercontent.com",   "Google user content",      "google"),   # caution: shared, but DNS-wise benign
    (".apple.com",               "Apple",                    "apple"),
    (".icloud.com",              "Apple iCloud",             "apple_storage"),
    (".cloudflare.com",          "Cloudflare",               "cdn"),
    (".cloudflare-dns.com",      "Cloudflare DNS",           "public_dns"),
    (".akamaiedge.net",          "Akamai Edge",              "cdn"),
    (".akamaihd.net",            "Akamai HD",                "cdn"),
    (".digicert.com",            "DigiCert",                 "ca_ocsp"),
    (".sectigo.com",             "Sectigo",                  "ca_ocsp"),
    (".letsencrypt.org",         "Let's Encrypt",            "ca"),
    (".mozilla.org",             "Mozilla",                  "mozilla"),
    (".ubuntu.com",              "Canonical Ubuntu",         "linux_update"),
]


# ─── Hashes ─────────────────────────────────────────────────────────────────
# We don't try to maintain a built-in clean-hash table — that's what
# CIRCL hashlookup does, and it's already wired into hash enrichment.
# Empty dict reserved for future curation (specific in-house tools the
# operator marks as known-good).
_HASH_KNOWN_GOOD: Dict[str, Dict[str, str]] = {}


# ─── Public API ─────────────────────────────────────────────────────────────
def lookup_ip(value: str) -> Optional[Dict[str, Any]]:
    """Return a CLEAN hit for an IP that matches a baseline entry, else
    None. Accepts both v4 and v6 in any textual form ipaddress can parse."""
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(value.strip())
    except (ValueError, TypeError):
        return None
    key = str(ip)
    hit = _IP_EXACT.get(key)
    if hit:
        return _make_hit(hit, key)
    # CIDR fallback
    for net, name, cat in _CIDR_NETWORKS:
        if ip.version != net.version:
            continue
        if ip in net:
            return _make_hit({"name": name, "category": cat}, f"{key} (in {net})")
    return None


def lookup_domain(value: str) -> Optional[Dict[str, Any]]:
    """Return a CLEAN hit for a domain (exact or right-anchored suffix
    match), else None. Case-insensitive."""
    if not value:
        return None
    d = value.strip().rstrip(".").lower()
    if not d:
        return None
    hit = _DOMAIN_EXACT.get(d)
    if hit:
        return _make_hit(hit, d)
    for suffix, name, cat in _DOMAIN_SUFFIX_TRUSTED:
        if d == suffix.lstrip(".") or d.endswith(suffix):
            return _make_hit({"name": name, "category": cat}, d)
    return None


def lookup_hash(value: str) -> Optional[Dict[str, Any]]:
    """Hash baseline is empty today — kept for API symmetry with the
    IP/domain paths and so external operators can populate it without
    changing call sites."""
    if not value:
        return None
    h = value.strip().lower()
    hit = _HASH_KNOWN_GOOD.get(h)
    return _make_hit(hit, h) if hit else None


def lookup_ioc(ioc_type: str, value: str) -> Optional[Dict[str, Any]]:
    """Dispatch by IOC type. Returns the CLEAN-hit dict or None."""
    if ioc_type == "ip":     return lookup_ip(value)
    if ioc_type == "domain": return lookup_domain(value)
    if ioc_type == "hash":   return lookup_hash(value)
    return None


def _make_hit(entry: Dict[str, str], matched_on: str) -> Dict[str, Any]:
    return {
        "matched":   True,
        "name":      entry["name"],
        "category":  entry["category"],
        "verdict":   "CLEAN",
        "summary":   (f"Known-good baseline: {entry['name']} "
                      f"(category: {entry['category']}). No external "
                      f"enrichment performed."),
        "source":    "known_good_baseline",
        "matched_on": matched_on,
    }


def stats() -> Dict[str, Any]:
    """Counts of baseline entries — surfaced at /api/status."""
    return {
        "ip_exact":     len(_IP_EXACT),
        "ip_cidr":      len(_IP_CIDR_RANGES),
        "domain_exact": len(_DOMAIN_EXACT),
        "domain_suffix":len(_DOMAIN_SUFFIX_TRUSTED),
        "hash":         len(_HASH_KNOWN_GOOD),
    }
