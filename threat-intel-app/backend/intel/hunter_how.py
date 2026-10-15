"""
Hunter.how search engine lookup (IP / domain).

Source: https://hunter.how/ — commercial internet-scan + fingerprint
engine (alternative to Shodan/ZoomEye/Censys). Free tier available.

  GET https://api.hunter.how/search?api-key=<KEY>&query=<b64>&page=1&page_size=10

Query is base64url-encoded:
  IP:     ip="<ip>"
  Domain: domain="<domain>"

Response:
  {
    "code": 200,
    "data": {
      "total": N,
      "list": [{"ip": "...", "port": N, "domain": "...",
                "country": "...", "web_title": "...",
                "server": "...", "updated_at": "..."}]
    }
  }
"""

from __future__ import annotations

import base64
import logging
from typing import Any, Dict, List

_log = logging.getLogger("recon.intel.hunter_how")

_BASE = "https://api.hunter.how/search"


def _encode_query(query: str) -> str:
    return base64.urlsafe_b64encode(query.encode("utf-8")).decode("ascii")


async def _search(session, query: str, api_key: str) -> Any:
    from agents.enrichment import _get
    encoded = _encode_query(query)
    url = (f"{_BASE}?api-key={api_key}&query={encoded}"
           "&page=1&page_size=10")
    return await _get(session, url,
                       headers={"Accept": "application/json"},
                       timeout=10)


def _build(records: List[Dict[str, Any]], total: int, label: str) -> Dict[str, Any]:
    if not records:
        return {"source": "hunter_how", "found": False,
                "summary": f"Hunter.how: no results for {label}."}
    ports = sorted({r.get("port") for r in records if r.get("port")})
    countries = sorted({r.get("country") for r in records if r.get("country")})
    servers = sorted({r.get("server") for r in records if r.get("server")})
    return {
        "source":        "hunter_how",
        "found":         True,
        "total":         total,
        "returned":      len(records),
        "ports":         list(ports)[:20],
        "countries":     list(countries)[:5],
        "servers":       [s for s in servers if s][:10],
        "sample":        [
            {"ip": r.get("ip"), "port": r.get("port"),
             "domain": r.get("domain"), "web_title": r.get("web_title"),
             "updated": r.get("updated_at")}
            for r in records[:5]
        ],
        "details_url":   f"https://hunter.how/search?searchValue={label}",
        "verdict":       "UNKNOWN",
        "summary":       (f"Hunter.how: {total} result"
                          f"{'s' if total != 1 else ''}, "
                          f"{len(ports)} unique port"
                          f"{'s' if len(ports) != 1 else ''}"),
    }


async def _run(session, query: str, label: str, api_key: str) -> Dict[str, Any]:
    if not api_key:
        return {"source": "hunter_how", "found": False,
                "error": "HUNTER_HOW_KEY not configured",
                "error_type": "missing_key"}
    try:
        r = await _search(session, query, api_key)
    except Exception as e:
        return {"source": "hunter_how", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "hunter_how", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error") or r.get("code") not in (None, 200):
        return {"source": "hunter_how",
                "error": r.get("message") or r.get("error") or "API error",
                "error_type": "api_error"}
    data = r.get("data") or {}
    records = data.get("list") or []
    total = data.get("total") or 0
    return _build([e for e in records if isinstance(e, dict)], total, label)


async def lookup_ip(session, ip: str, api_key: str = "") -> Dict[str, Any]:
    return await _run(session, f'ip="{ip}"', ip, api_key)


async def lookup_domain(session, domain: str, api_key: str = "") -> Dict[str, Any]:
    return await _run(session, f'domain="{domain}"', domain, api_key)
