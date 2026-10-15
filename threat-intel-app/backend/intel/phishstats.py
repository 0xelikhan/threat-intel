"""
PhishStats URL / domain / IP phishing database lookup.

Source: https://phishstats.info/ — PhishStats aggregates phishing URL
reports from multiple feeds, scored by heuristics. Free, no key.

  GET https://api.phishstats.info/api/phishing?_where=<filter>&_sort=-date

Supported filters:
  URL:    (url,like,~<string>~)
  IP:     (ip,eq,<ip>)
  Domain: (url,like,~<domain>~)   # same as URL — PhishStats indexes
                                   # full URLs, so we match substring

Response: a JSON array of records. Each record has:
  {
    "id": N, "date": "...", "url": "...", "ip": "...",
    "countrycode": "US", "score": 7.6, "host": "...",
    "domain_registered_n_days_ago": N, "title": "...", "hash": "..."
  }
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List
from urllib.parse import urlparse

_log = logging.getLogger("recon.intel.phishstats")

_BASE = "https://api.phishstats.info/api"


async def _query(session, where_clause: str) -> List[Dict[str, Any]]:
    from agents.enrichment import _get
    url = f"{_BASE}/phishing?_where={where_clause}&_sort=-date&_size=10"
    r = await _get(session, url, headers={"Accept": "application/json"}, timeout=8)
    if isinstance(r, list):
        return [e for e in r if isinstance(e, dict)]
    return []


def _build_result(records: List[Dict[str, Any]], label: str,
                  details_filter: str) -> Dict[str, Any]:
    if not records:
        return {"source": "phishstats", "found": False,
                "summary": f"PhishStats: no phishing records for {label}."}
    # Highest score wins
    top = max(records, key=lambda e: float(e.get("score") or 0) or 0)
    try:
        top_score = float(top.get("score") or 0)
    except (TypeError, ValueError):
        top_score = 0.0
    # PhishStats scores run 0-10. 7+ is high-confidence phish.
    if top_score >= 7:
        verdict = "MALICIOUS"
    elif top_score >= 4 or len(records) >= 3:
        verdict = "SUSPICIOUS"
    else:
        verdict = "UNKNOWN"
    return {
        "source":        "phishstats",
        "found":         True,
        "match_count":   len(records),
        "top_score":     top_score,
        "top_url":       top.get("url"),
        "top_ip":        top.get("ip"),
        "top_country":   top.get("countrycode"),
        "top_title":     (top.get("title") or "")[:120],
        "top_date":      top.get("date"),
        "recent":        [
            {"url": e.get("url"), "ip": e.get("ip"),
             "score": e.get("score"), "date": e.get("date"),
             "country": e.get("countrycode")}
            for e in records[:5]
        ],
        "details_url":   f"https://phishstats.info/?s={label}",
        "verdict":       verdict,
        "summary":       (f"PhishStats: {len(records)} phishing record"
                          f"{'s' if len(records) != 1 else ''} for {label}"
                          + (f" (top score {top_score:.1f})"
                             if top_score > 0 else "")),
    }


async def lookup_url(session, url: str) -> Dict[str, Any]:
    """PhishStats lookup by URL substring. If URL contains an IP, also
    tries the IP endpoint."""
    if not isinstance(url, str) or not url:
        return {"source": "phishstats", "found": False,
                "error": "missing url"}
    host = urlparse(url).hostname or url
    try:
        records = await _query(session, f"(url,like,~{host}~)")
    except Exception as e:
        return {"source": "phishstats", "error": str(e)[:120],
                "error_type": "unreachable"}
    return _build_result(records, url, host)


async def lookup_domain(session, domain: str) -> Dict[str, Any]:
    if not isinstance(domain, str) or not domain:
        return {"source": "phishstats", "found": False,
                "error": "missing domain"}
    try:
        records = await _query(session, f"(url,like,~{domain}~)")
    except Exception as e:
        return {"source": "phishstats", "error": str(e)[:120],
                "error_type": "unreachable"}
    return _build_result(records, domain, domain)


async def lookup_ip(session, ip: str) -> Dict[str, Any]:
    if not isinstance(ip, str) or not ip:
        return {"source": "phishstats", "found": False,
                "error": "missing ip"}
    try:
        records = await _query(session, f"(ip,eq,{ip})")
    except Exception as e:
        return {"source": "phishstats", "error": str(e)[:120],
                "error_type": "unreachable"}
    return _build_result(records, ip, ip)
