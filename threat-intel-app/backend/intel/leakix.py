"""
LeakIX host-level attack-surface lookup.

Source: https://leakix.net/ — surfaces exposed services, open S3 /
Elasticsearch / MongoDB, config leaks, and public web vulnerabilities
per IP. Free API tier available.

  GET https://leakix.net/host/<ip>
  Header: api-key: <LEAKIX_KEY>

Response:
  {
    "Services": [{"port": N, "protocol": "...", "software": {...}, ...}],
    "Leaks":    [{"event_source": "...", "severity": "...", ...}],
    "Reputation": {"score": N, "threat_score": N}
  }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

_log = logging.getLogger("recon.intel.leakix")


async def lookup_ip(session, ip: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"source": "leakix", "found": False,
                "error": "LEAKIX_KEY not configured",
                "error_type": "missing_key"}
    if not isinstance(ip, str) or not ip:
        return {"source": "leakix", "found": False,
                "error": "missing ip"}
    try:
        from agents.enrichment import _get
        r = await _get(
            session, f"https://leakix.net/host/{ip}",
            headers={"api-key": api_key, "Accept": "application/json"},
            timeout=10,
        )
    except Exception as e:
        return {"source": "leakix", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "leakix", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error"):
        return {"source": "leakix", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}

    services = r.get("Services") or []
    leaks = r.get("Leaks") or []
    rep = r.get("Reputation") or {}
    threat_score = rep.get("threat_score")

    ports = sorted({s.get("port") for s in services if s.get("port")})
    software = sorted({
        (s.get("software") or {}).get("name") or ""
        for s in services
        if (s.get("software") or {}).get("name")
    })
    leak_sources = sorted({l.get("event_source") for l in leaks if l.get("event_source")})

    if not services and not leaks:
        return {"source": "leakix", "found": False,
                "summary": f"LeakIX: no exposed services or leaks for {ip}."}

    verdict = "UNKNOWN"
    try:
        ts = int(threat_score) if threat_score is not None else 0
    except (TypeError, ValueError):
        ts = 0
    if ts >= 50 or len(leaks) >= 3:
        verdict = "SUSPICIOUS"
    if ts >= 80 or any((l.get("severity") or "").lower() in ("critical", "high")
                       for l in leaks):
        verdict = "MALICIOUS"

    return {
        "source":        "leakix",
        "found":         True,
        "service_count": len(services),
        "ports":         list(ports)[:20],
        "software":      [s for s in software if s][:10],
        "leak_count":    len(leaks),
        "leak_sources":  list(leak_sources)[:8],
        "threat_score":  threat_score,
        "reputation":    rep.get("score"),
        "details_url":   f"https://leakix.net/host/{ip}",
        "verdict":       verdict,
        "summary":       (f"LeakIX: {len(services)} service"
                          f"{'s' if len(services) != 1 else ''} exposed"
                          + (f", {len(leaks)} leak"
                             f"{'s' if len(leaks) != 1 else ''}"
                             if leaks else "")),
    }
