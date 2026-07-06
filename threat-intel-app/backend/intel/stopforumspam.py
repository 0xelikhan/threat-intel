"""
StopForumSpam — free, no key. Community-maintained spam-source
database with both IP and email reputation.

Two lookups:
  - IP:    /api?ip=X&json     → {appears, frequency, confidence, torexit, asn, country, lastseen}
  - Email: /api?email=X&json  → {appears, frequency}

`confidence` is 0-100 (SFS's own probability estimate). Any `appears=1`
is a real report signal — SFS is conservative and won't flag benign
IPs. The IP endpoint also returns `torexit=1` for Tor exit nodes,
which we already track via intel.deception; treat as an independent
confirmation.

Rate limits: 20 req/min per IP without a key. That's plenty for
per-alert lookups; a burst analysis on hundreds of IOCs would need
to serialise or accept the throttle.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

_log = logging.getLogger("recon.intel.sfs")


async def lookup_ip(session, ip: str) -> Dict[str, Any]:
    """Query SFS by IP. Returns a normalised dict or an error blob."""
    if not isinstance(ip, str) or not ip:
        return {}
    from agents.enrichment import _get
    raw = await _get(
        session,
        "https://api.stopforumspam.org/api",
        params={"ip": ip, "json": ""},
        headers={"User-Agent": "RECON-ThreatIntel/1.0"},
    )
    if not isinstance(raw, dict):
        return {}
    if raw.get("error"):
        return {"source": "StopForumSpam", "error": raw.get("error"),
                "error_type": raw.get("error_type", "unreachable")}
    ip_row = raw.get("ip") or {}
    appears = int(ip_row.get("appears") or 0)
    freq    = int(ip_row.get("frequency") or 0)
    conf    = float(ip_row.get("confidence") or 0.0)
    torexit = bool(int(ip_row.get("torexit") or 0)) if "torexit" in ip_row else False

    verdict = "UNKNOWN"
    if appears and conf >= 80:      verdict = "MALICIOUS"
    elif appears and conf >= 50:    verdict = "SUSPICIOUS"
    elif appears:                   verdict = "SUSPICIOUS"

    if not appears:
        return {
            "source":  "StopForumSpam",
            "found":   False,
            "summary": f"IP {ip} has no spam reports on SFS.",
        }

    bits = [f"reported {freq}x"]
    if conf: bits.append(f"{conf:.0f}% confidence")
    if torexit: bits.append("Tor exit")
    if ip_row.get("lastseen"):
        bits.append(f"last seen {ip_row['lastseen']}")

    return {
        "source":     "StopForumSpam",
        "found":      True,
        "verdict":    verdict,
        "appears":    appears,
        "frequency":  freq,
        "confidence": conf,
        "torexit":    torexit,
        "asn":        ip_row.get("asn"),
        "country":    ip_row.get("country"),
        "lastseen":   ip_row.get("lastseen"),
        "summary":    " · ".join(bits),
    }


async def lookup_email(session, email: str) -> Dict[str, Any]:
    """Query SFS by email. Returns a normalised dict or empty on no data."""
    if not isinstance(email, str) or "@" not in email:
        return {}
    from agents.enrichment import _get
    raw = await _get(
        session,
        "https://api.stopforumspam.org/api",
        params={"email": email, "json": ""},
        headers={"User-Agent": "RECON-ThreatIntel/1.0"},
    )
    if not isinstance(raw, dict):
        return {}
    if raw.get("error"):
        return {"source": "StopForumSpam", "error": raw.get("error"),
                "error_type": raw.get("error_type", "unreachable")}
    e_row = raw.get("email") or {}
    appears = int(e_row.get("appears") or 0)
    freq    = int(e_row.get("frequency") or 0)

    if not appears:
        return {
            "source":  "StopForumSpam",
            "found":   False,
            "summary": f"Email {email} has no spam reports on SFS.",
        }

    verdict = "MALICIOUS" if freq >= 10 else "SUSPICIOUS"
    return {
        "source":    "StopForumSpam",
        "found":     True,
        "verdict":   verdict,
        "appears":   appears,
        "frequency": freq,
        "summary":   f"Email {email} reported {freq}x on SFS.",
    }
