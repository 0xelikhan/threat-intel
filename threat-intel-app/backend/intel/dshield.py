"""
SANS Internet Storm Center (DShield) API client.

Source: https://isc.sans.edu/api/ — SANS ISC's volunteer-firewall sensor
network. Free, no-key, JSON. Per-IP endpoint:

  GET https://isc.sans.edu/api/ip/<ip>?json

Returns:
  {
    "ip": {
      "number": "1.2.3.4",
      "count":  N,                  # total reports
      "attacks": N,                 # attack reports
      "maxdate": "2024-...",        # last-seen
      "mindate": "...",
      "updated": "...",
      "comment": "..."
    }
  }

For RECON this adds a "this IP has hit N volunteer firewalls N times"
signal that complements DataPlane (honeypot-source) and AbuseIPDB
(crowdsourced reports). All three together form the strongest
"attacker IP" verdict outside of paid feeds.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

_log = logging.getLogger("recon.intel.dshield")


async def lookup(session, ip: str) -> Dict[str, Any]:
    """Return DShield's stored report for an IP. Empty dict with
    found=False when DShield has no record."""
    if not isinstance(ip, str) or not ip:
        return {"source": "dshield", "found": False,
                "error": "missing ip"}
    try:
        from agents.enrichment import _get
        r = await _get(
            session, f"https://isc.sans.edu/api/ip/{ip}?json",
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "application/json"},
            timeout=6,
        )
    except Exception as e:
        return {"source": "dshield", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "dshield", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error"):
        return {"source": "dshield", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}

    blob = r.get("ip") or {}
    if not isinstance(blob, dict) or not blob.get("number"):
        return {"source": "dshield", "found": False,
                "summary": f"DShield has no report for {ip}."}

    try:
        count = int(blob.get("count") or 0)
    except (TypeError, ValueError):
        count = 0
    try:
        attacks = int(blob.get("attacks") or 0)
    except (TypeError, ValueError):
        attacks = 0

    if count == 0 and attacks == 0:
        return {"source": "dshield", "found": False,
                "summary": f"DShield has zero reports for {ip}."}

    verdict = "UNKNOWN"
    if attacks >= 100:
        verdict = "MALICIOUS"
    elif attacks >= 10 or count >= 100:
        verdict = "SUSPICIOUS"

    return {
        "source":   "dshield",
        "found":    True,
        "reports":  count,
        "attacks":  attacks,
        "first_seen": blob.get("mindate"),
        "last_seen":  blob.get("maxdate"),
        "comment":  (blob.get("comment") or "")[:200],
        "asn":      blob.get("asnumber") or "",
        "details_url": f"https://isc.sans.edu/ipinfo.html?ip={ip}",
        "verdict":  verdict,
        "summary":  (f"DShield: {count} report{'s' if count != 1 else ''}, "
                      f"{attacks} flagged as attacks "
                      f"(last seen {blob.get('maxdate') or 'unknown'})."),
    }
