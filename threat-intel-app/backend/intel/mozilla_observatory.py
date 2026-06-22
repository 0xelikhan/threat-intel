"""
Mozilla Observatory web-security grader API client.

Source: https://observatory.mozilla.org (MPL-2.0 on the tool; the API
is free + no-key + lightly rate-limited).

Grades a domain's HTTP security headers: CSP, HSTS, X-Frame-Options,
referrer-policy, public-key-pins, etc. Returns A through F.

For RECON this is a niche but useful "domain hygiene" signal. A
domain with grade A+ is almost certainly a well-run org; grade F is
either freshly-stood-up infrastructure or an abandoned legacy site —
both worth flagging in the domain enrichment summary.

The endpoint accepts a GET; the result reflects the LAST scan stored
in Mozilla's backend (often days old) rather than triggering a fresh
scan. That suits us — we want a quick reference, not a live test.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

_log = logging.getLogger("recon.intel.mozilla_observatory")


async def scan(session, hostname: str) -> Dict[str, Any]:
    """Return Observatory's stored result for `hostname`. Empty dict
    with found=False when there's no prior scan."""
    if not isinstance(hostname, str) or not hostname:
        return {"source": "mozilla_observatory", "found": False,
                "error": "missing hostname"}
    host = hostname.strip().lower().rstrip(".")
    # Strip protocol if the caller passed a URL accidentally.
    if "://" in host:
        host = host.split("://", 1)[1].split("/", 1)[0]
    try:
        from agents.enrichment import _get
        # Observatory v2 API. Older v1 returned slightly different shape;
        # v2 is the documented current path.
        r = await _get(
            session,
            f"https://observatory-api.mdn.mozilla.net/api/v2/scan?host={host}",
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "application/json"},
            timeout=8,
        )
    except Exception as e:
        return {"source": "mozilla_observatory", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "mozilla_observatory", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error"):
        msg = str(r["error"]).lower()
        if "404" in msg or "no" in msg and "scan" in msg:
            return {"source": "mozilla_observatory", "found": False,
                    "summary": f"Mozilla Observatory has no scan for {host}."}
        return {"source": "mozilla_observatory", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}

    grade = (r.get("grade") or r.get("scanResult", {}).get("grade") or "")[:4]
    score = r.get("score")
    if score is None:
        score = r.get("scanResult", {}).get("score")
    details_url = f"https://developer.mozilla.org/en-US/observatory/analyze?host={host}"

    verdict = "UNKNOWN"
    if isinstance(grade, str):
        first = grade[:1].upper()
        if first in ("A",):
            verdict = "CLEAN"
        elif first in ("D", "E", "F"):
            verdict = "SUSPICIOUS"

    return {
        "source":      "mozilla_observatory",
        "found":       bool(grade),
        "grade":       grade,
        "score":       score,
        "scan_id":     r.get("id") or r.get("scanResult", {}).get("id"),
        "details_url": details_url,
        "verdict":     verdict,
        "summary":     (f"Mozilla Observatory grade {grade} for {host}"
                         + (f" (score {score})" if score is not None else "")),
    }
