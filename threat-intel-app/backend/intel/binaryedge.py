"""
BinaryEdge host + subdomain enumeration.

Source: https://www.binaryedge.io/ — commercial internet-scan dataset
(ports, services, SSL certs, torrents, DNS). Free trial tier.

  Header: X-Key: <BINARYEDGE_KEY>

Endpoints used:
  IP recent:        GET https://api.binaryedge.io/v2/query/ip/<ip>
  Subdomains:       GET https://api.binaryedge.io/v2/query/domains/subdomain/<domain>

Response (IP):
  {
    "query": "...", "total": N,
    "events": [{"port": N, "service": "...", "ip": "...", ...}]
  }
Response (subdomains):
  {
    "query": "...", "total": N, "page": N,
    "events": ["sub1.domain", "sub2.domain", ...]
  }
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

_log = logging.getLogger("recon.intel.binaryedge")

_BASE = "https://api.binaryedge.io/v2/query"


async def _get_json(session, path: str, api_key: str) -> Any:
    from agents.enrichment import _get
    return await _get(
        session, f"{_BASE}/{path}",
        headers={"X-Key": api_key, "Accept": "application/json"},
        timeout=10,
    )


async def lookup_ip(session, ip: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"source": "binaryedge", "found": False,
                "error": "BINARYEDGE_KEY not configured",
                "error_type": "missing_key"}
    if not isinstance(ip, str) or not ip:
        return {"source": "binaryedge", "found": False,
                "error": "missing ip"}
    try:
        r = await _get_json(session, f"ip/{ip}", api_key)
    except Exception as e:
        return {"source": "binaryedge", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "binaryedge", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error"):
        return {"source": "binaryedge", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}

    events: List[Dict[str, Any]] = r.get("events") or []
    if not events:
        return {"source": "binaryedge", "found": False,
                "summary": f"BinaryEdge: no scan data for {ip}."}

    ports = sorted({e.get("port") for e in events if e.get("port")})
    services = sorted({
        ((e.get("results") or [{}])[0].get("origin") or {}).get("type")
        or e.get("service") or ""
        for e in events
    })
    return {
        "source":        "binaryedge",
        "found":         True,
        "total_events":  r.get("total") or len(events),
        "ports":         list(ports)[:30],
        "services":      [s for s in services if s][:10],
        "sample_ports":  [{"port": e.get("port"),
                            "service": e.get("service"),
                            "last_updated": e.get("origin", {}).get("ts")}
                           for e in events[:5]],
        "details_url":   f"https://app.binaryedge.io/services/query?query=ip:{ip}",
        "verdict":       "UNKNOWN",
        "summary":       (f"BinaryEdge: {len(ports)} unique port"
                          f"{'s' if len(ports) != 1 else ''} across "
                          f"{len(events)} scan event"
                          f"{'s' if len(events) != 1 else ''}"),
    }


async def lookup_domain(session, domain: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"source": "binaryedge", "found": False,
                "error": "BINARYEDGE_KEY not configured",
                "error_type": "missing_key"}
    if not isinstance(domain, str) or not domain:
        return {"source": "binaryedge", "found": False,
                "error": "missing domain"}
    try:
        r = await _get_json(session, f"domains/subdomain/{domain}", api_key)
    except Exception as e:
        return {"source": "binaryedge", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "binaryedge", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error"):
        return {"source": "binaryedge", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}

    events = r.get("events") or []
    if not events:
        return {"source": "binaryedge", "found": False,
                "summary": f"BinaryEdge: no subdomains for {domain}."}
    return {
        "source":        "binaryedge",
        "found":         True,
        "subdomain_count": r.get("total") or len(events),
        "subdomains":    [e for e in events if isinstance(e, str)][:15],
        "details_url":   f"https://app.binaryedge.io/services/query?query=domain:{domain}",
        "verdict":       "UNKNOWN",
        "summary":       (f"BinaryEdge: {r.get('total') or len(events)} "
                          f"subdomain{'s' if (r.get('total') or len(events)) != 1 else ''} "
                          f"found."),
    }
