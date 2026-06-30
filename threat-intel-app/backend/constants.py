"""
Constants — single source of truth for the string literals that appear
in multiple places.

The existing call sites still inline these strings (changing every one
would risk introducing typos and is unrelated to behaviour). This module
gives new code and tests a stable import surface so we don't keep
re-spelling the same strings.

Categories:
  * THREAT_LEVELS  — output of the investigation agent's `threat_level`.
  * VERDICTS       — output of every enrichment-source verdict.
  * SEVERITY       — Sigma rule `level` values.
  * MITRE_TACTICS  — the 14 ATT&CK Enterprise tactic names, in kill-chain
                    order. The frontend's tactic colours map directly to
                    these strings, so adding/renaming requires syncing
                    DetectionTab.jsx::TACTIC_COLORS too.
  * ENRICHMENT_SOURCES — every TI source key that may appear under
                    `enrichments[<ioc_type>][<ioc>]`. Used by the
                    confidence engine + UI source listings.
  * IOC_TYPES      — the four enrichable IOC type keys.
  * CACHE_NAMESPACES — the static-dataset cache namespaces registered at
                    startup (see intel/cache.py).
  * ERROR_CODES    — machine-readable slugs for error_envelope responses.
"""

from __future__ import annotations

from typing import Tuple


# ─── threat level / verdict / severity ────────────────────────────────────────
THREAT_LEVELS: Tuple[str, ...] = (
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN",
)

VERDICTS: Tuple[str, ...] = (
    "MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN",
)

SEVERITY: Tuple[str, ...] = (
    "critical", "high", "medium", "low", "informational",
)


# ─── MITRE ATT&CK Enterprise tactics, kill-chain order ────────────────────────
MITRE_TACTICS: Tuple[str, ...] = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)


# ─── IOC + enrichment source taxonomy ─────────────────────────────────────────
IOC_TYPES: Tuple[str, ...] = ("ips", "domains", "hashes", "urls")

ENRICHMENT_SOURCES: Tuple[str, ...] = (
    "abuseipdb", "ipinfo", "greynoise", "virustotal", "otx",
    "robtex", "hackertarget", "censys",
    "misp_feeds", "misp_galaxy",
    "feodo_tracker", "tor", "bgp_ranking", "google_safebrowsing",
    "deception", "maltiverse", "opencti", "urlscan", "pulsedive",
    "malwarebazaar", "threatfox", "hybrid_analysis",
    "deep_instinct", "cybereason", "whois", "dbl",
    "domain_intel", "feed_cache",
)


# ─── cache + ops ──────────────────────────────────────────────────────────────
CACHE_NAMESPACES: Tuple[str, ...] = (
    "mitre", "warninglists", "feodo", "sslbl", "kev",
    "lolbas", "loldrivers", "enrich",
)


# ─── machine-readable error_code values ───────────────────────────────────────
ERROR_CODES = {
    "INTERNAL_ERROR":      "internal_error",
    "VALIDATION_ERROR":    "validation_error",
    "AUTH_REQUIRED":       "auth_required",
    "AUTH_FAILED":         "auth_failed",
    "NOT_FOUND":           "not_found",
    "RATE_LIMITED":        "rate_limited",
    "UPSTREAM_TIMEOUT":    "upstream_timeout",
    "UPSTREAM_FAILED":     "upstream_failed",
    "PROVIDER_AUTH":       "provider_auth",
    "CIRCUIT_OPEN":        "circuit_open",
    "PAYLOAD_TOO_LARGE":   "payload_too_large",
    "NOT_CONFIGURED":      "not_configured",
}
