"""
Polyswarm multi-AV + IOC search lookup.

Source: https://polyswarm.io/ — decentralised marketplace of AV
engines; hash lookups return per-engine verdicts (microengines) +
first/last-seen. Domain/IP lookups return known-host matches. Free
tier: 5k events/month.

  Hash:   GET https://api.polyswarm.network/v3/search/hash/<hash>
  Known hosts (domain): GET https://api.polyswarm.network/v3/consumer/community/<community>/scanners/known-hosts?domains=<d>
  Known hosts (ip):     ...?ips=<ip>

  Header: Authorization: <POLYSWARM_KEY>
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

_log = logging.getLogger("recon.intel.polyswarm")

_BASE = "https://api.polyswarm.network/v3"
_DEFAULT_COMMUNITY = "default"


async def _get_json(session, path: str, api_key: str) -> Any:
    from agents.enrichment import _get
    return await _get(
        session, f"{_BASE}/{path}",
        headers={"Authorization": api_key, "Accept": "application/json"},
        timeout=12,
    )


async def lookup_hash(session, hash_val: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"source": "polyswarm", "found": False,
                "error": "POLYSWARM_KEY not configured",
                "error_type": "missing_key"}
    if not isinstance(hash_val, str) or not hash_val:
        return {"source": "polyswarm", "found": False,
                "error": "missing hash"}
    try:
        r = await _get_json(session, f"search/hash/{hash_val}", api_key)
    except Exception as e:
        return {"source": "polyswarm", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "polyswarm", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error") or r.get("status") in ("ERROR", "NOT_FOUND"):
        if r.get("status") == "NOT_FOUND":
            return {"source": "polyswarm", "found": False,
                    "summary": "Polyswarm: hash not in dataset."}
        return {"source": "polyswarm", "error": r.get("error") or "API error",
                "error_type": "api_error"}

    result = r.get("result")
    if not isinstance(result, dict):
        # Some Polyswarm error responses set `result` to a string
        # ("unauthorized", "not found") rather than a nested dict.
        if isinstance(result, str):
            return {"source": "polyswarm", "found": False,
                    "error": result[:160], "error_type": "api_error"}
        result = r
    assertions = result.get("assertions") or []
    malicious_count = sum(1 for a in assertions
                             if isinstance(a, dict) and a.get("verdict") is True)
    total = len(assertions)
    polyscore = result.get("polyscore")

    verdict = "UNKNOWN"
    try:
        ps = float(polyscore) if polyscore is not None else None
    except (TypeError, ValueError):
        ps = None
    if ps is not None:
        if ps >= 0.8:
            verdict = "MALICIOUS"
        elif ps >= 0.4:
            verdict = "SUSPICIOUS"
        elif ps <= 0.1:
            verdict = "CLEAN"
    elif total:
        ratio = malicious_count / total
        if ratio >= 0.3:
            verdict = "MALICIOUS"
        elif ratio > 0:
            verdict = "SUSPICIOUS"

    return {
        "source":          "polyswarm",
        "found":           True,
        "polyscore":       polyscore,
        "assertion_count": total,
        "malicious_count": malicious_count,
        "sha256":          result.get("sha256"),
        "first_seen":      result.get("first_seen"),
        "last_seen":       result.get("last_seen"),
        "details_url":     f"https://polyswarm.network/scan/hash/{hash_val}",
        "verdict":         verdict,
        "summary":         (f"Polyswarm: {malicious_count}/{total} engines flagged malicious"
                            + (f" (polyscore {ps:.2f})" if ps is not None else "")),
    }


async def _known_hosts(session, query_param: str, label: str, api_key: str) -> Dict[str, Any]:
    if not api_key:
        return {"source": "polyswarm", "found": False,
                "error": "POLYSWARM_KEY not configured",
                "error_type": "missing_key"}
    try:
        r = await _get_json(
            session,
            f"consumer/community/{_DEFAULT_COMMUNITY}/scanners/known-hosts?{query_param}",
            api_key,
        )
    except Exception as e:
        return {"source": "polyswarm", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, (dict, list)):
        return {"source": "polyswarm", "error": "unexpected shape",
                "error_type": "unreachable"}
    rows = r if isinstance(r, list) else (r.get("result") or r.get("results") or [])
    if not rows:
        return {"source": "polyswarm", "found": False,
                "summary": f"Polyswarm: no known-host record for {label}."}
    first = rows[0] if isinstance(rows, list) and rows else {}
    return {
        "source":       "polyswarm",
        "found":        True,
        "label":        label,
        "match_count":  len(rows) if isinstance(rows, list) else 1,
        "first":        first if isinstance(first, dict) else {},
        "details_url":  f"https://polyswarm.network/scan/search?q={label}",
        "verdict":      "SUSPICIOUS",
        "summary":      f"Polyswarm: known-host match for {label}.",
    }


async def lookup_domain(session, domain: str, api_key: str = "") -> Dict[str, Any]:
    return await _known_hosts(session, f"domains={domain}", domain, api_key)


async def lookup_ip(session, ip: str, api_key: str = "") -> Dict[str, Any]:
    return await _known_hosts(session, f"ips={ip}", ip, api_key)
