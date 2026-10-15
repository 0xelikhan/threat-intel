"""
Netlas IP whois / infrastructure lookup.

Source: https://netlas.io/ — IP-level whois + internet-scan data.
Free tier: 50 queries/day.

  GET https://app.netlas.io/api/whois_ip/?q=ip:<ip>
  Header: X-API-Key: <NETLAS_KEY>

Response:
  {
    "items": [
      {
        "data": {
          "cidr": "...",
          "country": "...",
          "net_name": "...",
          "net_handle": "...",
          "org_name": "...",
          "org_address": "...",
          "org_country": "...",
          "created": "...",
          "updated": "...",
          "abuse_contacts": [{"email": "...", "name": "..."}]
        }
      }
    ]
  }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

_log = logging.getLogger("recon.intel.netlas")


async def lookup_ip(session, ip: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"source": "netlas", "found": False,
                "error": "NETLAS_KEY not configured",
                "error_type": "missing_key"}
    if not isinstance(ip, str) or not ip:
        return {"source": "netlas", "found": False,
                "error": "missing ip"}
    try:
        from agents.enrichment import _get
        r = await _get(
            session, f"https://app.netlas.io/api/whois_ip/?q=ip:{ip}",
            headers={"X-API-Key": api_key, "Accept": "application/json"},
            timeout=10,
        )
    except Exception as e:
        return {"source": "netlas", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "netlas", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error"):
        return {"source": "netlas", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}

    items = r.get("items") or []
    if not items:
        return {"source": "netlas", "found": False,
                "summary": f"Netlas: no whois record for {ip}."}
    data = (items[0] or {}).get("data") or {}
    abuse = [c.get("email") for c in (data.get("abuse_contacts") or []) if c.get("email")]
    return {
        "source":          "netlas",
        "found":           True,
        "cidr":            data.get("cidr"),
        "country":         data.get("country"),
        "net_name":        data.get("net_name"),
        "net_handle":      data.get("net_handle"),
        "org_name":        data.get("org_name"),
        "org_country":     data.get("org_country"),
        "created":         data.get("created"),
        "updated":         data.get("updated"),
        "abuse_contacts":  abuse[:3],
        "details_url":     f"https://app.netlas.io/whois/ip/{ip}",
        "verdict":         "UNKNOWN",
        "summary":         (f"Netlas: {data.get('cidr') or 'unknown CIDR'}"
                            + (f" / {data.get('org_name')}"
                               if data.get("org_name") else "")),
    }
