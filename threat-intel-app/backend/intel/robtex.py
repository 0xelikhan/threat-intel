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
    as_name = r.get("asname")
    bgp = r.get("bgproute")
    whois = r.get("whoisdesc")
    country = r.get("country")
    active_records = r.get("act") or []  # current passive DNS A records
    history_records = r.get("acth") or []  # historical passive DNS
    rev_records = r.get("pas") or []  # reverse DNS / PTR

    total_pdns = len(active_records) + len(history_records)
    verdict = "UNKNOWN"

    return {
        "source":         "robtex",
        "found":          bool(as_num or active_records or rev_records),
        "asn":            as_num,
        "asname":         as_name,
        "bgp_route":      bgp,
        "whois_desc":     whois,
        "country":        country,
        "active_pdns":    [{"domain": e.get("o"), "time": e.get("t")}
                            for e in active_records[:10]],
        "historical_pdns": [{"domain": e.get("o"), "time": e.get("t")}
                            for e in history_records[:10]],
        "reverse_dns":    [{"domain": e.get("o"), "time": e.get("t")}
                            for e in rev_records[:10]],
        "details_url":    f"https://www.robtex.com/ip-lookup/{ip}",
        "verdict":        verdict,
        "summary":        (f"Robtex: {total_pdns} passive DNS record"
                           f"{'s' if total_pdns != 1 else ''}"
                           + (f", AS{as_num} ({as_name})"
                              if as_num else "")),
    }


async def lookup_domain(session, domain: str) -> Dict[str, Any]:
    """Robtex forward passive-DNS lookup — returns domain's A/AAAA/MX history."""
    if not isinstance(domain, str) or not domain:
        return {"source": "robtex", "found": False,
                "error": "missing domain"}
    try:
        from agents.enrichment import _get
        r = await _get(
            session, f"https://freeapi.robtex.com/pdns/forward/{domain}",
            headers={"Accept": "application/x-ndjson"},
            timeout=6,
        )
    except Exception as e:
        return {"source": "robtex", "error": str(e)[:120],
                "error_type": "unreachable"}

    # Robtex pdns endpoint returns NDJSON (one object per line); _get
    # may surface it as a list or as a raw dict depending on how it's
    # parsed. Normalize to a list.
    entries: List[Dict[str, Any]] = []
    if isinstance(r, list):
        entries = [e for e in r if isinstance(e, dict)]
    elif isinstance(r, dict):
        if r.get("error"):
            return {"source": "robtex", "error": r.get("error"),
                    "error_type": r.get("error_type", "unreachable")}
        # If _get returned a single-row dict, wrap it
        entries = [r] if r.get("rrname") or r.get("rrdata") else []

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
