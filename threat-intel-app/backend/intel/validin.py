"""
Validin passive DNS + historical infrastructure lookup.

Source: https://app.validin.com/ — historical DNS, host records,
registration metadata; strong for IP → associated domains / historical
A pivots. Free + paid tiers.

  Header: Authorization: Bearer <VALIDIN_KEY>

Endpoints used:
  IP → domains:        GET https://app.validin.com/api/axon/ip/dns/history/<ip>
  Domain → IPs:        GET https://app.validin.com/api/axon/domain/dns/history/<domain>
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

_log = logging.getLogger("recon.intel.validin")

_BASE = "https://app.validin.com/api/axon"


async def _get_json(session, path: str, api_key: str) -> Any:
    from agents.enrichment import _get
    return await _get(
        session, f"{_BASE}/{path}",
        headers={"Authorization": f"Bearer {api_key}",
                 "Accept": "application/json"},
        timeout=10,
    )


def _records_of(payload: Any) -> List[Dict[str, Any]]:
    """Validin returns records keyed under 'records' or inline arrays
    depending on endpoint. Normalise."""
    if isinstance(payload, list):
        return [e for e in payload if isinstance(e, dict)]
    if isinstance(payload, dict):
        for key in ("records", "data", "results", "history"):
            if isinstance(payload.get(key), list):
                return [e for e in payload[key] if isinstance(e, dict)]
    return []


async def lookup_ip(session, ip: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"source": "validin", "found": False,
                "error": "VALIDIN_KEY not configured",
                "error_type": "missing_key"}
    if not isinstance(ip, str) or not ip:
        return {"source": "validin", "found": False,
                "error": "missing ip"}
    try:
        r = await _get_json(session, f"ip/dns/history/{ip}", api_key)
    except Exception as e:
        return {"source": "validin", "error": str(e)[:120],
                "error_type": "unreachable"}
    if isinstance(r, dict) and r.get("error"):
        return {"source": "validin", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    records = _records_of(r)
    if not records:
        return {"source": "validin", "found": False,
                "summary": f"Validin: no DNS history for {ip}."}
    domains = sorted({(x.get("key") or x.get("query") or x.get("domain") or "").lower()
                      for x in records
                      if (x.get("key") or x.get("query") or x.get("domain"))})
    return {
        "source":        "validin",
        "found":         True,
        "record_count":  len(records),
        "domain_count":  len(domains),
        "domains":       [d for d in domains if d][:15],
        "details_url":   f"https://app.validin.com/axon/ip/{ip}",
        "verdict":       "UNKNOWN",
        "summary":       (f"Validin: {len(domains)} unique domain"
                          f"{'s' if len(domains) != 1 else ''} historically "
                          f"resolved to {ip}"),
    }


async def lookup_domain(session, domain: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"source": "validin", "found": False,
                "error": "VALIDIN_KEY not configured",
                "error_type": "missing_key"}
    if not isinstance(domain, str) or not domain:
        return {"source": "validin", "found": False,
                "error": "missing domain"}
    try:
        r = await _get_json(session, f"domain/dns/history/{domain}", api_key)
    except Exception as e:
        return {"source": "validin", "error": str(e)[:120],
                "error_type": "unreachable"}
    if isinstance(r, dict) and r.get("error"):
        return {"source": "validin", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    records = _records_of(r)
    if not records:
        return {"source": "validin", "found": False,
                "summary": f"Validin: no DNS history for {domain}."}
    ips = sorted({(x.get("value") or x.get("ip") or x.get("rdata") or "")
                   for x in records
                   if (x.get("value") or x.get("ip") or x.get("rdata"))})
    return {
        "source":       "validin",
        "found":        True,
        "record_count": len(records),
        "ip_count":     len(ips),
        "ips":          [i for i in ips if i][:15],
        "details_url":  f"https://app.validin.com/axon/domain/{domain}",
        "verdict":      "UNKNOWN",
        "summary":      (f"Validin: {len(ips)} unique IP"
                         f"{'s' if len(ips) != 1 else ''} historically "
                         f"resolved by {domain}"),
    }
