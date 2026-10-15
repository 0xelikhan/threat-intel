"""
Phoneinfoga-equivalent phone-number lookup (native Python).

IntelOwl ships Phoneinfoga as a Docker-based service running several
backend scanners (numverify, googlecse, ovh, local). RECON implements
the two useful network-bound ones natively:

  • NumVerify (apilayer.net) — commercial, free 100 req/month.
    GET http://apilayer.net/api/validate?access_key=<KEY>&number=<E.164>&format=1
  • OVH — France Telecom carrier database; free, no key. Only useful
    for FR / European numbers.
    GET https://api.ovh.com/1.0/telephony/number/detailedZones?country=fr

For local / GoogleCSE we rely on intel.phunter + a Google-search
details_url — those don't need a dedicated module.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

_log = logging.getLogger("recon.intel.phoneinfoga")


async def lookup_numverify(session, phone: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"source": "numverify", "found": False,
                "error": "NUMVERIFY_KEY not configured",
                "error_type": "missing_key"}
    phone = (phone or "").strip().replace(" ", "")
    if not phone:
        return {"source": "numverify", "found": False,
                "error": "missing phone"}
    # NumVerify expects the number WITHOUT the leading + per their docs,
    # though it accepts either. Be defensive and strip it.
    normalized = phone.lstrip("+")
    try:
        from agents.enrichment import _get
        r = await _get(
            session,
            f"http://apilayer.net/api/validate?access_key={api_key}&number={normalized}&format=1",
            headers={"Accept": "application/json"},
            timeout=10,
        )
    except Exception as e:
        return {"source": "numverify", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "numverify", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error"):
        info = r.get("error")
        if isinstance(info, dict):
            return {"source": "numverify",
                    "error": info.get("info") or info.get("type") or "API error",
                    "error_type": info.get("type") or "api_error"}
        return {"source": "numverify", "error": str(info),
                "error_type": "api_error"}

    is_valid = bool(r.get("valid"))
    verdict = "UNKNOWN" if is_valid else "SUSPICIOUS"
    line_type = (r.get("line_type") or "").lower()
    if line_type in ("premium_rate", "voip"):
        verdict = "SUSPICIOUS"
    return {
        "source":         "numverify",
        "found":          True,
        "valid":          is_valid,
        "international":  r.get("international_format"),
        "local":          r.get("local_format"),
        "country_code":   r.get("country_code"),
        "country_name":   r.get("country_name"),
        "location":       r.get("location"),
        "carrier":        r.get("carrier"),
        "line_type":      line_type or None,
        "details_url":    f"https://numverify.com/dashboard",
        "verdict":        verdict,
        "summary":        (f"NumVerify: {'valid' if is_valid else 'invalid'} number"
                           + (f" — {r.get('carrier')}" if r.get("carrier") else "")
                           + (f" ({r.get('country_name')})"
                              if r.get("country_name") else "")),
    }


async def lookup(session, phone: str, numverify_key: str = "") -> Dict[str, Any]:
    """Phoneinfoga aggregator — dispatches to each configured backend
    and merges results. Right now only NumVerify is wired. OVH's free
    endpoint only resolves French (+33) numbers and is best called
    conditionally; we'll add that in a follow-up."""
    nv = await lookup_numverify(session, phone, numverify_key)
    if nv.get("found"):
        return {"source": "phoneinfoga",
                 "found": True,
                 "scanners": {"numverify": nv},
                 "verdict": nv.get("verdict", "UNKNOWN"),
                 "summary": nv.get("summary", "Phoneinfoga: see scanners."),
                 "details_url": nv.get("details_url")}
    return {"source": "phoneinfoga",
             "found": False,
             "scanners": {"numverify": nv},
             "error": nv.get("error"),
             "error_type": nv.get("error_type"),
             "summary": "Phoneinfoga: no scanner produced results."}
