"""
ASN reputation — flag IPs hosted by ASNs/organizations known for bulletproof
hosting, anonymizers, or recurring abuse. Uses ISP/org text from the
existing AbuseIPDB + IPInfo enrichment we already collect; no extra API calls.
"""
import re

# Known bulletproof / abuse-friendly hosters, anonymizers, and bad-rep ASNs.
# Patterns are case-insensitive substring matches against the ISP/org string.
# Categorized so the AI can reason about them.
BAD_ASN_PATTERNS = {
    "bulletproof": [
        ("frantech",          "AS53667 FranTech Solutions — long-running BPH"),
        ("inferno solutions", "Inferno Solutions — known bulletproof"),
        ("baxet group",       "Baxet — bulletproof reseller"),
        ("blazingfast",       "AS62240 BlazingFast — high abuse"),
        ("alexhost",          "AlexHost — bulletproof"),
        ("dataideas",         "DataIdeas — bulletproof"),
        ("flokinet",          "FlokiNET — privacy host, frequent abuse"),
        ("njalla",            "Njalla — privacy registrar"),
        ("buyvm",             "BuyVM (Frantech subsidiary)"),
        ("uadomen",           "Ualinkos / UADoMen — Eastern Europe BPH"),
        ("petersburg",        "Petersburg Internet Network — BPH"),
        ("pinet",             "Pinet — BPH"),
        ("velia",             "Velia.net — recurring abuse"),
        ("ddos-guard",        "DDoS-Guard — Russian DDoS protection"),
        ("nicenic",           "NiceNIC — Chinese hoster, frequent abuse"),
        ("shinjiru",          "Shinjiru Technology — BPH"),
        ("offshore racks",    "Offshore Racks — BPH"),
    ],
    "vpn_proxy": [
        ("nordvpn",   "NordVPN exit"),
        ("expressvpn","ExpressVPN exit"),
        ("mullvad",   "Mullvad VPN"),
        ("private internet access", "PIA VPN"),
        ("surfshark", "Surfshark VPN"),
        ("protonvpn", "ProtonVPN"),
        ("ipvanish",  "IPVanish"),
        ("torguard",  "TorGuard VPN"),
        ("m247",      "M247 — heavy VPN reseller"),
        ("packethub", "PacketHub — VPN reseller"),
        ("hostwinds", "Hostwinds — frequent VPN traffic"),
        ("datacamp",  "Datacamp — VPN reseller"),
    ],
    "hosting_abuse": [
        ("vultr",        "Vultr Holdings — large surface, regular abuse"),
        ("digitalocean", "DigitalOcean — frequent C2"),
        ("linode",       "Linode (Akamai) — frequent abuse"),
        ("hetzner",      "Hetzner — frequent C2"),
        ("ovh",          "OVH — frequent C2"),
        ("contabo",      "Contabo — frequent abuse"),
        ("scaleway",     "Scaleway — frequent abuse"),
        ("colocrossing", "ColoCrossing — heavy proxy reseller"),
    ],
    "anonymizer": [
        ("tor exit",  "Tor network exit"),
        ("torservers","Tor relay operator"),
        ("relakks",   "Relakks anonymizer"),
    ],
}


def _flatten_patterns() -> list[tuple[str, str, str]]:
    """[(category, pattern, description), ...]"""
    out = []
    for cat, items in BAD_ASN_PATTERNS.items():
        for pat, desc in items:
            out.append((cat, pat, desc))
    return out


_PATTERNS = _flatten_patterns()


def check(isp: str = "", org: str = "", usage_type: str = "") -> dict | None:
    """Match the ISP/org/usage strings against the bad-ASN database.
    Returns a dict if matched, None otherwise."""
    blob = " ".join(filter(None, [isp, org, usage_type])).lower()
    if not blob:
        return None

    hits = []
    seen_cats = set()
    for cat, pat, desc in _PATTERNS:
        if pat in blob:
            if cat not in seen_cats:  # only the first hit per category
                hits.append({"category": cat, "match": pat, "description": desc})
                seen_cats.add(cat)

    # Usage-type signal (AbuseIPDB tags these)
    if "hosting" in (usage_type or "").lower() and "bulletproof" not in seen_cats:
        # neutral — many legit services use hosting providers
        pass
    if "vpn" in (usage_type or "").lower() or "proxy" in (usage_type or "").lower():
        if "vpn_proxy" not in seen_cats and "anonymizer" not in seen_cats:
            hits.append({"category": "vpn_proxy", "match": "usage_type",
                         "description": f"Tagged as {usage_type}"})

    if not hits:
        return None
    # Pull AS-number out of org/isp if present  ("AS14618 Amazon.com" → "AS14618")
    asn = None
    m = re.search(r"\bAS\s*(\d{1,7})\b", blob, re.IGNORECASE)
    if m:
        asn = f"AS{m.group(1)}"

    return {
        "asn":         asn,
        "isp":         isp,
        "org":         org,
        "categories":  list(seen_cats),
        "hits":        hits,
        "severity":    ("high"   if "bulletproof" in seen_cats
                        else "medium" if "anonymizer" in seen_cats or "vpn_proxy" in seen_cats
                        else "low"),
    }
