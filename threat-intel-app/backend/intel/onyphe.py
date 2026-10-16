"""
Onyphe IP / domain / hostname summary lookup.

Source: https://www.onyphe.io/ — internet-scan + passive data: open
ports, DNS, SSL certs, vulnerabilities. Summary endpoint returns an
aggregated view across categories. Free API tier available.

  GET https://www.onyphe.io/api/v2/summary/<ip|domain|hostname>/<x>
  Header: Authorization: apikey <ONYPHE_KEY>

Response:
  {
    "status": "ok",
    "count": N,
    "results": [
      {"@category": "resolver", "subject": {...}, ...},
      {"@category": "datascan", "port": N, ...},
      ...
    ]
  }
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

_log = logging.getLogger("recon.intel.onyphe")

_BASE = "https://www.onyphe.io/api/v2/summary"


async def _query(session, kind: str, value: str, api_key: str) -> Any:
    from agents.enrichment import _get
    return await _get(
        session, f"{_BASE}/{kind}/{value}",
        headers={"Authorization": f"apikey {api_key}",
                 "Accept": "application/json"},
        timeout=10,
    )


def _build(records: List[Dict[str, Any]], label: str) -> Dict[str, Any]:
    if not records:
        return {"source": "onyphe", "found": False,
                "summary": f"Onyphe: no records for {label}."}
    categories: Dict[str, int] = {}
    ports: set = set()
    vulns: set = set()
    for r in records:
        if not isinstance(r, dict):
            continue
        cat = r.get("@category") or r.get("category")
        if cat:
            categories[cat] = categories.get(cat, 0) + 1
        if r.get("port"):
            ports.add(r.get("port"))
        cve_list = r.get("cve")
        if isinstance(cve_list, list):
            for cve in cve_list:
                if isinstance(cve, str):
                    vulns.add(cve)
        elif isinstance(cve_list, str):
            vulns.add(cve_list)
    verdict = "UNKNOWN"
    if vulns:
        verdict = "SUSPICIOUS"
    return {
        "source":       "onyphe",
        "found":        True,
        "record_count": len(records),
        "categories":   categories,
        "ports":        sorted(ports)[:20],
        "vulns":        sorted(vulns)[:10],
        "details_url":  f"https://www.onyphe.io/search?q={label}",
        "verdict":      verdict,
        "summary":      (f"Onyphe: {len(records)} record"
                         f"{'s' if len(records) != 1 else ''} across "
                         f"{len(categories)} categor"
                         f"{'ies' if len(categories) != 1 else 'y'}"
                         + (f", {len(vulns)} CVE{'s' if len(vulns) != 1 else ''}"
                            if vulns else "")),
    }


async def _run(session, kind: str, value: str, api_key: str) -> Dict[str, Any]:
    if not api_key:
        return {"source": "onyphe", "found": False,
                "error": "ONYPHE_KEY not configured",
                "error_type": "missing_key"}
    try:
        r = await _query(session, kind, value, api_key)
    except Exception as e:
        return {"source": "onyphe", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "onyphe", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error"):
        return {"source": "onyphe", "error": str(r.get("error"))[:160],
                "error_type": r.get("error_type", "unreachable")}
    # Onyphe wraps error responses as {"status": "error", "message": "..."}
    # when authentication fails. Treat anything non-ok as an auth error.
    status = (r.get("status") or "").lower()
    if status and status != "ok":
        return {"source": "onyphe", "found": False,
                "error": str(r.get("message") or r.get("text") or status)[:160],
                "error_type": "api_error"}
    results = r.get("results") or []
    if not isinstance(results, list):
        return {"source": "onyphe", "found": False,
                "error": "results not a list", "error_type": "format_error"}
    return _build([e for e in results if isinstance(e, dict)], value)


async def lookup_ip(session, ip: str, api_key: str = "") -> Dict[str, Any]:
    return await _run(session, "ip", ip, api_key)


async def lookup_domain(session, domain: str, api_key: str = "") -> Dict[str, Any]:
    return await _run(session, "domain", domain, api_key)


async def lookup_hostname(session, hostname: str, api_key: str = "") -> Dict[str, Any]:
    return await _run(session, "hostname", hostname, api_key)
