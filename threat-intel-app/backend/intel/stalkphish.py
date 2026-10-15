"""
Stalkphish phishing-kit / URL tracker lookup.

Source: https://www.stalkphish.io/ — Stalkphish indexes active
phishing kits + phishing URLs, with associated infrastructure.
Requires a free API key (Token-based auth header).

  GET https://api.stalkphish.io/api/v1/search/url/<url>
  GET https://api.stalkphish.io/api/v1/search/ipv4/<ip>
  Header: Authorization: Token <STALKPHISH_KEY>

Response: array of records with:
  {
    "siteURL": "...", "siteIP": "...", "siteDomain": "...",
    "siteASNum": "...", "country_name": "...",
    "firstseentime": "...", "lastseentime": "...",
    "titledom": "...", "schema": "..."
  }
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

_log = logging.getLogger("recon.intel.stalkphish")

_BASE = "https://api.stalkphish.io/api/v1"


async def _query(session, path: str, api_key: str) -> Any:
    from agents.enrichment import _get
    headers = {
        "User-Agent": "RECON-ThreatIntel/1.0",
        "Authorization": f"Token {api_key}",
    }
    return await _get(session, f"{_BASE}/{path}", headers=headers, timeout=8)


def _build(records: List[Dict[str, Any]], label: str) -> Dict[str, Any]:
    if not records:
        return {"source": "stalkphish", "found": False,
                "summary": f"Stalkphish: no phishing kit records for {label}."}
    first = records[0]
    kit_hits: List[str] = []
    for r in records:
        schema = r.get("schema")
        if schema:
            kit_hits.append(schema)
    return {
        "source":        "stalkphish",
        "found":         True,
        "match_count":   len(records),
        "first_seen":    first.get("firstseentime"),
        "last_seen":     first.get("lastseentime"),
        "site_url":      first.get("siteURL"),
        "site_ip":       first.get("siteIP"),
        "site_domain":   first.get("siteDomain"),
        "site_asn":      first.get("siteASNum"),
        "country":       first.get("country_name"),
        "title":         (first.get("titledom") or "")[:120],
        "kit_schemas":   list(dict.fromkeys(kit_hits))[:5],
        "details_url":   f"https://stalkphish.io/search/{label}",
        "verdict":       "MALICIOUS",
        "summary":       (f"Stalkphish: {len(records)} phishing kit record"
                          f"{'s' if len(records) != 1 else ''} for {label}"
                          + (f" (kit: {kit_hits[0]})" if kit_hits else "")),
    }


async def _run(session, path: str, label: str, api_key: str) -> Dict[str, Any]:
    if not api_key:
        return {"source": "stalkphish", "found": False,
                "error": "STALKPHISH_KEY not configured",
                "error_type": "missing_key"}
    try:
        r = await _query(session, path, api_key)
    except Exception as e:
        return {"source": "stalkphish", "error": str(e)[:120],
                "error_type": "unreachable"}
    if isinstance(r, dict) and r.get("error"):
        return {"source": "stalkphish", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    if isinstance(r, dict):
        # Some error shapes come back as a dict rather than a list.
        if r.get("results") and isinstance(r["results"], list):
            return _build(r["results"], label)
        return {"source": "stalkphish", "found": False,
                "summary": f"Stalkphish: unexpected shape for {label}."}
    if isinstance(r, list):
        return _build([e for e in r if isinstance(e, dict)], label)
    return {"source": "stalkphish", "found": False,
            "summary": f"Stalkphish: unexpected shape for {label}."}


async def lookup_url(session, url: str, api_key: str = "") -> Dict[str, Any]:
    if not isinstance(url, str) or not url:
        return {"source": "stalkphish", "found": False,
                "error": "missing url"}
    return await _run(session, f"search/url/{url}", url, api_key)


async def lookup_domain(session, domain: str, api_key: str = "") -> Dict[str, Any]:
    if not isinstance(domain, str) or not domain:
        return {"source": "stalkphish", "found": False,
                "error": "missing domain"}
    return await _run(session, f"search/url/{domain}", domain, api_key)


async def lookup_ip(session, ip: str, api_key: str = "") -> Dict[str, Any]:
    if not isinstance(ip, str) or not ip:
        return {"source": "stalkphish", "found": False,
                "error": "missing ip"}
    return await _run(session, f"search/ipv4/{ip}", ip, api_key)
