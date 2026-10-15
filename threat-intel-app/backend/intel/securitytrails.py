"""
SecurityTrails domain + IP attack-surface lookup.

Source: https://securitytrails.com/corp/api — current DNS, historical
WHOIS, subdomain enumeration. Free tier: 50 req/month.

  Header: apikey: <SECURITYTRAILS_KEY>

Endpoints:
  Domain details:     GET https://api.securitytrails.com/v1/domain/<domain>
  Subdomains:         GET https://api.securitytrails.com/v1/domain/<domain>/subdomains
  Historical WHOIS:   GET https://api.securitytrails.com/v1/history/<domain>/whois
  IP neighbors:       GET https://api.securitytrails.com/v1/ips/nearby/<ip>
"""

from __future__ import annotations

import logging
from typing import Any, Dict

_log = logging.getLogger("recon.intel.securitytrails")

_BASE = "https://api.securitytrails.com/v1"


async def _get_json(session, path: str, api_key: str) -> Any:
    from agents.enrichment import _get
    return await _get(
        session, f"{_BASE}/{path}",
        headers={"apikey": api_key, "Accept": "application/json"},
        timeout=10,
    )


async def lookup_domain(session, domain: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"source": "securitytrails", "found": False,
                "error": "SECURITYTRAILS_KEY not configured",
                "error_type": "missing_key"}
    if not isinstance(domain, str) or not domain:
        return {"source": "securitytrails", "found": False,
                "error": "missing domain"}
    try:
        details = await _get_json(session, f"domain/{domain}", api_key)
        subdomains = await _get_json(session, f"domain/{domain}/subdomains?children_only=false", api_key)
    except Exception as e:
        return {"source": "securitytrails", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(details, dict):
        return {"source": "securitytrails", "found": False,
                "error": "unexpected shape"}
    if details.get("error") or details.get("message") == "Not Found":
        return {"source": "securitytrails", "found": False,
                "summary": f"SecurityTrails: no record for {domain}."}

    current = details.get("current_dns") or {}
    a_records = ((current.get("a") or {}).get("values") or [])
    mx_records = ((current.get("mx") or {}).get("values") or [])
    ns_records = ((current.get("ns") or {}).get("values") or [])
    subdom_list = subdomains.get("subdomains") if isinstance(subdomains, dict) else []
    subdom_count = subdomains.get("subdomain_count") if isinstance(subdomains, dict) else None

    return {
        "source":          "securitytrails",
        "found":           True,
        "apex_domain":     details.get("apex_domain"),
        "current_a":       [r.get("ip") for r in a_records if r.get("ip")][:10],
        "current_mx":      [r.get("hostname") for r in mx_records if r.get("hostname")][:5],
        "current_ns":      [r.get("nameserver") for r in ns_records if r.get("nameserver")][:5],
        "subdomain_count": subdom_count or (len(subdom_list) if isinstance(subdom_list, list) else 0),
        "subdomains":      (subdom_list[:15] if isinstance(subdom_list, list) else []),
        "details_url":     f"https://securitytrails.com/domain/{domain}",
        "verdict":         "UNKNOWN",
        "summary":         (f"SecurityTrails: {subdom_count or len(subdom_list or [])} subdomains, "
                             f"{len(a_records)} current A record"
                             f"{'s' if len(a_records) != 1 else ''}"),
    }


async def lookup_ip(session, ip: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"source": "securitytrails", "found": False,
                "error": "SECURITYTRAILS_KEY not configured",
                "error_type": "missing_key"}
    if not isinstance(ip, str) or not ip:
        return {"source": "securitytrails", "found": False,
                "error": "missing ip"}
    try:
        r = await _get_json(session, f"ips/nearby/{ip}", api_key)
    except Exception as e:
        return {"source": "securitytrails", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict) or r.get("error"):
        return {"source": "securitytrails", "found": False,
                "summary": f"SecurityTrails: no neighbor data for {ip}."}
    blocks = r.get("blocks") or r.get("records") or []
    neighbors = []
    for b in (blocks or [])[:30]:
        if isinstance(b, dict):
            neighbors.append({"ip": b.get("ip"), "hostnames": (b.get("hostnames") or [])[:3]})
    return {
        "source":        "securitytrails",
        "found":         bool(neighbors),
        "neighbor_count": len(neighbors),
        "neighbors":     neighbors[:10],
        "details_url":   f"https://securitytrails.com/list/ip/{ip}",
        "verdict":       "UNKNOWN",
        "summary":       (f"SecurityTrails: {len(neighbors)} IP neighbors"
                          if neighbors
                          else f"SecurityTrails: no neighbor data for {ip}."),
    }
