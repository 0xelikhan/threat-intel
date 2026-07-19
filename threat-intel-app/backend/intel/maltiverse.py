"""
Maltiverse — aggregated threat intel for IP / hostname / hash / URL.
Free tier with rate limits (no key required for basic anonymous queries).
"""
import aiohttp


BASE = "https://api.maltiverse.com"


async def lookup(ioc_type: str, value: str, api_key: str = "") -> dict | None:
    """Query Maltiverse for an indicator. ioc_type ∈ {ip, hostname, sample, url}."""
    if not (ioc_type and value):
        return None
    type_map = {"ip": "ip", "domain": "hostname", "hostname": "hostname",
                "hash": "sample", "url": "url"}
    mt_type = type_map.get(ioc_type)
    if not mt_type:
        return None

    # URL value needs encoding; everything else just appends to the path.
    if mt_type == "url":
        from urllib.parse import quote
        url = f"{BASE}/url/{quote(value, safe='')}"
    else:
        url = f"{BASE}/{mt_type}/{value}"

    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status == 404:
                    return None
                if r.status >= 400:
                    return None
                d = await r.json()
    except Exception:
        return None
    if not d:
        return None
    classification = (d.get("classification") or "").lower()
    # Historical-noise gate: Maltiverse aggregates ~40 feeds, so even
    # 8.8.8.8 accumulates a 44-entry `blacklist` array (DNS reflection
    # attacks TARGET public DNS, so those feeds list 8.8.8.8 as an
    # associated address). Same story with `tag` — Google DNS carries
    # "asyncrat, c2, backdoor" tags derived from historical reflection
    # incidents. When the AI investigation prompt reads that raw blob
    # it writes prose like "Maltiverse associates this IP with AsyncRAT"
    # even though the definitive `classification` field says whitelist.
    #
    # Only surface the noisy arrays when Maltiverse's own verdict is
    # malicious/suspicious. For whitelist / neutral IPs, callers see
    # just the classification + benign metadata (ASN, country) and
    # don't get anchored on stale reflection-attack labels.
    is_flagged = classification in ("malicious", "suspicious")
    return {
        "source":         "Maltiverse",
        "classification": classification or "neutral",
        "hit":            is_flagged,
        "blacklist":      ([b.get("description") for b in (d.get("blacklist") or [])][:5]
                             if is_flagged else []),
        "tag":            (d.get("tag", [])[:8] if is_flagged else []),
        "first_seen":     d.get("first_seen"),
        "last_seen":      d.get("last_seen"),
        "asn_name":       d.get("asn_name"),
        "country":        d.get("country_code"),
    }
