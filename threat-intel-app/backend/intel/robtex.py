"""
Robtex IP + domain passive-DNS / ASN lookup.

Source: https://www.robtex.com/api/ — Robtex's free, no-key JSON API.
Returns passive DNS, reverse DNS, ASN, AS-set membership.

Endpoints:
  IP:     GET https://freeapi.robtex.com/ipquery/<ip>
  Domain: GET https://freeapi.robtex.com/pdns/forward/<domain>

The response is one JSON document per line (NDJSON for the pdns
endpoint, single JSON for ipquery). We handle both shapes.

Robtex gives us: historical/current passive DNS answers, PTR records,
AS membership, and network ranges — all for IPs that other sources
(VT, OTX, Shodan) might not have context on.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.intel.robtex")


def _summarize_pdns(entries: List[Dict[str, Any]], label: str) -> str:
    """Build a one-liner from passive-DNS entries."""
    if not entries:
        return f"Robtex {label}: no passive DNS records."
    uniq = list({e.get("rrname") or e.get("rrdata") for e in entries if (e.get("rrname") or e.get("rrdata"))})
    return (f"Robtex {label}: {len(entries)} passive DNS record"
            f"{'s' if len(entries) != 1 else ''}"
            + (f" (e.g. {uniq[0]})" if uniq else ""))


async def lookup_ip(session, ip: str) -> Dict[str, Any]:
    """Robtex ipquery endpoint — returns passive DNS, ASN, PTR."""
    if not isinstance(ip, str) or not ip:
        return {"source": "robtex", "found": False,
                "error": "missing ip"}
    try:
        from agents.enrichment import _get
        r = await _get(
            session, f"https://freeapi.robtex.com/ipquery/{ip}",
            headers={"Accept": "application/json"},
            timeout=6,
        )
    except Exception as e:
        return {"source": "robtex", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "robtex", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error"):
        return {"source": "robtex", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}

    status = (r.get("status") or "").lower()
    if status not in ("", "ok"):
        return {"source": "robtex", "found": False,
                "summary": f"Robtex no data for {ip} ({status})."}

    as_num = r.get("as")
    as_name = r.get("asname") or r.get("asdesc")
    bgp = r.get("bgproute")
    whois = r.get("whoisdesc")
    country = r.get("country")
    # Robtex returns `pas` (an array of {o: domain, t: timestamp}) for
    # reverse passive DNS — the domains that resolved TO this IP.
    pdns_records = r.get("pas") or []
    pdns_count = len(pdns_records) if isinstance(pdns_records, list) else 0

    return {
        "source":         "robtex",
        "found":          bool(as_num or pdns_count),
        "asn":            as_num,
        "asname":         as_name,
        "bgp_route":      bgp,
        "whois_desc":     whois,
        "country":        country,
        "passive_dns":    [{"domain": e.get("o"), "time": e.get("t")}
                            for e in (pdns_records[:15]
                                       if isinstance(pdns_records, list) else [])
                            if isinstance(e, dict)],
        "details_url":    f"https://www.robtex.com/ip-lookup/{ip}",
        "verdict":        "UNKNOWN",
        "summary":        (f"Robtex: {pdns_count} passive DNS record"
                           f"{'s' if pdns_count != 1 else ''}"
                           + (f", AS{as_num} ({as_name})"
                              if as_num else "")),
    }


async def lookup_domain(session, domain: str) -> Dict[str, Any]:
    """Robtex forward passive-DNS lookup — returns domain's A/AAAA/MX history.

    Robtex's /pdns/forward/ endpoint returns NDJSON (one JSON object
    per line). The shared `_get` helper's `.json()` parser crashes on
    the second line, so we fetch raw text here and parse line-by-line.
    """
    if not isinstance(domain, str) or not domain:
        return {"source": "robtex", "found": False,
                "error": "missing domain"}
    import aiohttp, json
    url = f"https://freeapi.robtex.com/pdns/forward/{domain}"
    try:
        async with session.get(
            url, headers={"Accept": "application/x-ndjson",
                           "User-Agent": "RECON-ThreatIntel/1.0"},
            timeout=aiohttp.ClientTimeout(total=6),
        ) as resp:
            if resp.status >= 400:
                return {"source": "robtex", "found": False,
                        "error": f"HTTP {resp.status}",
                        "error_type": "unreachable"}
            text = await resp.text()
    except Exception as e:
        return {"source": "robtex", "error": str(e)[:120],
                "error_type": "unreachable"}

    entries: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict):
            entries.append(obj)

    if not entries:
        return {"source": "robtex", "found": False,
                "summary": f"Robtex has no passive DNS for {domain}."}

    return {
        "source":        "robtex",
        "found":         True,
        "pdns_count":    len(entries),
        "records":       [
            {"rrtype": e.get("rrtype"), "rrdata": e.get("rrdata"),
             "first_seen": e.get("time_first"),
             "last_seen":  e.get("time_last"),
             "count":      e.get("count")}
            for e in entries[:15]
        ],
        "details_url":   f"https://www.robtex.com/dns-lookup/{domain}",
        "verdict":       "UNKNOWN",
        "summary":       _summarize_pdns(entries, "forward"),
    }
