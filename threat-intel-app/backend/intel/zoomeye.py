"""
ZoomEye host search.

Source: https://www.zoomeye.org/ — Chinese internet-scan engine
alternative to Shodan with broad fingerprint coverage. Requires
API key.

  GET https://api.zoomeye.org/host/search?query=ip:<ip>&page=1
  GET https://api.zoomeye.org/host/search?query=hostname:<domain>&page=1
  Header: API-KEY: <ZOOMEYE_KEY>

Response:
  {
    "total": N,
    "matches": [
      {"ip": "...", "portinfo": {"port": N, "service": "...", ...},
       "geoinfo": {"country": {...}}, "timestamp": "..."},
      ...
    ]
  }
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

_log = logging.getLogger("recon.intel.zoomeye")

_BASE = "https://api.zoomeye.org"


async def _search(session, query: str, api_key: str) -> Any:
    from agents.enrichment import _get
    return await _get(
        session, f"{_BASE}/host/search?query={query}&page=1",
        headers={"API-KEY": api_key, "Accept": "application/json"},
        timeout=10,
    )


def _build(matches: List[Dict[str, Any]], total: int, label: str) -> Dict[str, Any]:
    if not matches:
        return {"source": "zoomeye", "found": False,
                "summary": f"ZoomEye: no results for {label}."}
    ports: set = set()
    services: set = set()
    countries: set = set()
    for m in matches:
        p = (m.get("portinfo") or {}).get("port")
        if p: ports.add(p)
        s = (m.get("portinfo") or {}).get("service")
        if s: services.add(s)
        c = ((m.get("geoinfo") or {}).get("country") or {}).get("names", {}).get("en")
        if c: countries.add(c)
    return {
        "source":       "zoomeye",
        "found":        True,
        "total":        total,
        "returned":     len(matches),
        "ports":        sorted(ports)[:20],
        "services":     sorted(services)[:10],
        "countries":    sorted(countries)[:5],
        "sample":       [
            {"ip": m.get("ip"),
             "port": (m.get("portinfo") or {}).get("port"),
             "service": (m.get("portinfo") or {}).get("service"),
             "timestamp": m.get("timestamp")}
            for m in matches[:5]
        ],
        "details_url":  f"https://www.zoomeye.org/searchResult?q={label}",
        "verdict":      "UNKNOWN",
        "summary":      (f"ZoomEye: {total} total result"
                         f"{'s' if total != 1 else ''}, "
                         f"{len(ports)} unique port"
                         f"{'s' if len(ports) != 1 else ''}"),
    }


async def _run(session, query: str, label: str, api_key: str) -> Dict[str, Any]:
    if not api_key:
        return {"source": "zoomeye", "found": False,
                "error": "ZOOMEYE_KEY not configured",
                "error_type": "missing_key"}
    try:
        r = await _search(session, query, api_key)
    except Exception as e:
        return {"source": "zoomeye", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "zoomeye", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error"):
        return {"source": "zoomeye", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    matches = r.get("matches") or []
    total = r.get("total") or len(matches)
    return _build([m for m in matches if isinstance(m, dict)], total, label)


async def lookup_ip(session, ip: str, api_key: str = "") -> Dict[str, Any]:
    return await _run(session, f"ip:{ip}", ip, api_key)


async def lookup_domain(session, domain: str, api_key: str = "") -> Dict[str, Any]:
    return await _run(session, f"hostname:{domain}", domain, api_key)
