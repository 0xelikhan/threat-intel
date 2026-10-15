"""
Hudson Rock Cavalier API — infostealer-compromised credentials
lookup.

Source: https://www.hudsonrock.com/ — Hudson Rock operates the
Cavalier platform tracking compromised credentials from infostealer
infections. Returns per-employee / per-user / per-domain stealer
exposure, including which URLs, IPs, and software are compromised.
Requires a Cavalier API key.

  Header: api-key: <HUDSONROCK_KEY>

Endpoints used (IntelOwl pattern):
  Email:  GET https://cavalier.hudsonrock.com/api/json/v2/search-by-login?login=<email>
  Domain: GET https://cavalier.hudsonrock.com/api/json/v2/search-by-domain?domain=<domain>
  IP:     GET https://cavalier.hudsonrock.com/api/json/v2/search-by-ip?ip=<ip>

Response structure varies per endpoint; we surface the headline count
+ a sample. Any stealer-tracked hit is a strong credential-exposure
signal that goes beyond HIBP (which only knows about public dumps).
"""

from __future__ import annotations

import logging
from typing import Any, Dict

_log = logging.getLogger("recon.intel.hudsonrock")

_BASE = "https://cavalier.hudsonrock.com/api/json/v2"


async def _get_json(session, path: str, api_key: str) -> Any:
    from agents.enrichment import _get
    return await _get(
        session, f"{_BASE}/{path}",
        headers={"api-key": api_key, "Accept": "application/json"},
        timeout=10,
    )


def _build(records_count: int, sample_records: list, label: str,
            kind: str) -> Dict[str, Any]:
    if not records_count:
        return {"source": "hudsonrock", "found": False,
                "summary": f"Hudson Rock: no stealer records for {label}."}
    verdict = "MALICIOUS"  # Any infostealer hit is a credential compromise
    return {
        "source":        "hudsonrock",
        "found":         True,
        "kind":          kind,
        "stealer_count": records_count,
        "sample":        sample_records[:5],
        "details_url":   "https://cavalier.hudsonrock.com/",
        "verdict":       verdict,
        "summary":       (f"Hudson Rock Cavalier: {records_count} "
                          f"infostealer-compromised record"
                          f"{'s' if records_count != 1 else ''} for {label}"),
    }


def _extract_records(payload: Any, keys: tuple) -> list:
    """Hudson Rock responses nest records under various keys depending
    on the endpoint. Try all probable fields."""
    if isinstance(payload, list):
        return [e for e in payload if isinstance(e, dict)]
    if isinstance(payload, dict):
        for k in keys:
            v = payload.get(k)
            if isinstance(v, list):
                return [e for e in v if isinstance(e, dict)]
    return []


async def lookup_email(session, email: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"source": "hudsonrock", "found": False,
                "error": "HUDSONROCK_KEY not configured",
                "error_type": "missing_key"}
    if not isinstance(email, str) or "@" not in email:
        return {"source": "hudsonrock", "found": False,
                "error": "invalid email"}
    try:
        r = await _get_json(session, f"search-by-login?login={email}", api_key)
    except Exception as e:
        return {"source": "hudsonrock", "error": str(e)[:120],
                "error_type": "unreachable"}
    if isinstance(r, dict) and r.get("error"):
        return {"source": "hudsonrock", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    records = _extract_records(r, ("stealers", "records", "data", "results"))
    sample = [{"stealer_family": x.get("stealer_family") or x.get("family"),
                "date": x.get("date_compromised") or x.get("date"),
                "computer_name": x.get("computer_name"),
                "ip": x.get("ip")} for x in records[:5]]
    return _build(len(records), sample, email, "email")


async def lookup_domain(session, domain: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"source": "hudsonrock", "found": False,
                "error": "HUDSONROCK_KEY not configured",
                "error_type": "missing_key"}
    if not isinstance(domain, str) or not domain:
        return {"source": "hudsonrock", "found": False,
                "error": "missing domain"}
    try:
        r = await _get_json(session, f"search-by-domain?domain={domain}", api_key)
    except Exception as e:
        return {"source": "hudsonrock", "error": str(e)[:120],
                "error_type": "unreachable"}
    if isinstance(r, dict) and r.get("error"):
        return {"source": "hudsonrock", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    records = _extract_records(r, ("stealers", "records", "data", "results", "employees"))
    sample = [{"login": x.get("login") or x.get("employee_email"),
                "stealer_family": x.get("stealer_family") or x.get("family"),
                "date": x.get("date_compromised") or x.get("date")} for x in records[:5]]
    return _build(len(records), sample, domain, "domain")


async def lookup_ip(session, ip: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"source": "hudsonrock", "found": False,
                "error": "HUDSONROCK_KEY not configured",
                "error_type": "missing_key"}
    if not isinstance(ip, str) or not ip:
        return {"source": "hudsonrock", "found": False,
                "error": "missing ip"}
    try:
        r = await _get_json(session, f"search-by-ip?ip={ip}", api_key)
    except Exception as e:
        return {"source": "hudsonrock", "error": str(e)[:120],
                "error_type": "unreachable"}
    if isinstance(r, dict) and r.get("error"):
        return {"source": "hudsonrock", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    records = _extract_records(r, ("stealers", "records", "data", "results"))
    sample = [{"login": x.get("login") or x.get("employee_email"),
                "stealer_family": x.get("stealer_family") or x.get("family"),
                "date": x.get("date_compromised") or x.get("date")} for x in records[:5]]
    return _build(len(records), sample, ip, "ip")
