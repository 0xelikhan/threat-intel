"""
Geopolitical risk context — spec §7.

Runs post-enrichment. Groups all IPs by country, computes per-country risk
based on known state-sponsored APT activity, attributes infrastructure to
nation-state actor programs via the MITRE ATT&CK groups dataset, and flags
potential false-flag scenarios where the country of identified threat actors
doesn't match the country of the actual C2 infrastructure.
"""

from __future__ import annotations
from collections import defaultdict
from typing import Dict, List, Optional

# Hard-coded curated mapping of country → notable state-sponsored APTs.
# Used both for risk scoring and for attribution-mismatch (false-flag) detection.
# Source: MITRE ATT&CK groups, Mandiant APT catalog, public DFIR reporting.
COUNTRY_APT_INDEX: Dict[str, List[str]] = {
    "Russia":      ["Sandworm Team", "APT28", "APT29", "Turla", "Cozy Bear", "Gamaredon Group", "FIN7"],
    "China":       ["APT1", "APT10", "APT40", "APT41", "Hafnium", "Volt Typhoon", "Mustang Panda",
                    "Winnti Group", "Naikon", "Stone Panda"],
    "North Korea": ["Lazarus Group", "Kimsuky", "APT38", "BlueNoroff", "Andariel"],
    "Iran":        ["APT33", "APT34", "APT35", "Charming Kitten", "MuddyWater", "OilRig"],
    "Pakistan":    ["APT36", "Transparent Tribe"],
    "Vietnam":     ["APT32", "OceanLotus"],
    "Belarus":     ["Ghostwriter"],
    "Israel":      ["Stealth Falcon"],
    "USA":         [],  # No public attribution standard for offensive ops
}

# Country-level base risk score (0–25) — feeds the confidence engine.
COUNTRY_RISK: Dict[str, int] = {
    "Russia": 25, "China": 25, "North Korea": 25, "Iran": 25,
    "Pakistan": 15, "Vietnam": 15, "Belarus": 15, "Syria": 15,
    "Cuba": 10, "Venezuela": 10, "Myanmar": 10,
}

# ISO-2 → human country name for ipinfo replies that only give a country code
_ISO2_NAME = {
    "RU": "Russia", "CN": "China", "KP": "North Korea", "IR": "Iran",
    "PK": "Pakistan", "VN": "Vietnam", "BY": "Belarus", "IL": "Israel",
    "US": "USA", "GB": "UK", "DE": "Germany", "FR": "France",
    "BR": "Brazil", "IN": "India", "JP": "Japan", "KR": "South Korea",
}


def _country_name(code_or_name: Optional[str]) -> Optional[str]:
    if not code_or_name:
        return None
    s = str(code_or_name).strip()
    if len(s) == 2:
        return _ISO2_NAME.get(s.upper(), s.upper())
    return s


def compute_geopolitical_context(enrichments: Dict, threat_actor: Optional[Dict] = None,
                                  actor_country_hints: Optional[Dict] = None) -> Dict:
    """
    enrichments       — the per-IOC dict produced by the enrichment agent
    threat_actor      — optional {name: …, confidence: …} from investigation
    actor_country_hints — optional override {actor_name: country_str}; if not
                          supplied we derive from COUNTRY_APT_INDEX
    """
    actor_country_hints = actor_country_hints or {}

    # ── group IPs by country ─────────────────────────────────────────────────
    by_country = defaultdict(lambda: {"ips": [], "asns": set(), "isp_org": set()})
    for ip, payload in (enrichments.get("ips") or {}).items():
        ipinfo = payload.get("ipinfo") or {}
        country = _country_name(ipinfo.get("country") or
                                (payload.get("abuseipdb") or {}).get("country"))
        if not country:
            continue
        bucket = by_country[country]
        bucket["ips"].append(ip)
        if ipinfo.get("asn"):
            bucket["asns"].add(ipinfo["asn"])
        if (payload.get("abuseipdb") or {}).get("isp"):
            bucket["isp_org"].add((payload["abuseipdb"] or {})["isp"])

    # ── per-country risk rollup ──────────────────────────────────────────────
    countries = []
    high_risk_count = 0
    for country, info in by_country.items():
        risk = COUNTRY_RISK.get(country, 0)
        is_high_risk = risk >= 15
        if is_high_risk:
            high_risk_count += 1
        countries.append({
            "country":     country,
            "ip_count":    len(info["ips"]),
            "ips":         info["ips"][:8],
            "asns":        sorted(info["asns"])[:5],
            "isps":        sorted(info["isp_org"])[:5],
            "risk_score":  risk,
            "is_high_risk": is_high_risk,
            "known_apts":  COUNTRY_APT_INDEX.get(country, [])[:6],
        })
    countries.sort(key=lambda c: (-c["risk_score"], -c["ip_count"], c["country"]))

    # ── threat-actor attribution & false-flag check ──────────────────────────
    attribution = None
    false_flag = None
    actor_name = (threat_actor or {}).get("name")
    if actor_name:
        actor_country = actor_country_hints.get(actor_name) or _country_for_actor(actor_name)
        attribution = {
            "actor":      actor_name,
            "country":    actor_country,
            "confidence": (threat_actor or {}).get("confidence"),
        }
        if actor_country:
            infra_countries = {c["country"] for c in countries if c["ip_count"] > 0}
            if infra_countries and actor_country not in infra_countries:
                false_flag = {
                    "warning":            "Possible false-flag operation",
                    "actor_country":      actor_country,
                    "infrastructure_countries": sorted(infra_countries),
                    "rationale":          ("Identified threat actor's country of origin does not "
                                           "match the country of the C2 infrastructure observed in "
                                           "enrichment. Either the infrastructure was leased through "
                                           "intermediaries (common) or the attribution is wrong (rarer)."),
                }

    # ── aggregated risk score for the confidence engine ──────────────────────
    aggregate_risk = max((c["risk_score"] for c in countries), default=0)
    if high_risk_count > 1:
        aggregate_risk = min(25, aggregate_risk + 5)

    return {
        "countries":      countries,
        "country_count":  len(countries),
        "high_risk_count": high_risk_count,
        "attribution":    attribution,
        "false_flag":     false_flag,
        "aggregate_risk": aggregate_risk,
    }


def _country_for_actor(actor_name: str) -> Optional[str]:
    """Reverse-lookup the curated APT index — returns the country an actor is
    publicly attributed to, or None if unknown."""
    if not actor_name:
        return None
    needle = actor_name.lower()
    for country, actors in COUNTRY_APT_INDEX.items():
        for a in actors:
            if a.lower() == needle or a.lower() in needle or needle in a.lower():
                return country
    return None
