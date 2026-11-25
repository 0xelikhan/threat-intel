"""BGPv6.com keyless BGP + RPKI + GeoIP lookup.

Source: https://bgpv6.com/api/v1 - successor to BGPView (which shut
down November 2025). Free REST API with:
  - IP -> prefix + origin ASN + RPKI status + optional GeoIP
  - ASN -> organization + peer relationships
  - prefix -> routing table entries (currently broken server-side -
    DB connection error; avoid)

Response shape (from live probe):
  {
    "data": {
      "ip": "8.8.8.8",
      "prefix": "8.8.8.0/24",
      "asn": 15169,
      "asn_name": "",
      "country": "",
      "rpki_status": ""
    },
    "geoip": {
      "country": "US",
      "country_name": "United States",
      "latitude": 37.751,
      "longitude": -97.822,
      "asn": 15169,
      "as_org": "Google LLC"
    }
  }

RECON value-add over Robtex:
  - RPKI status - "valid" / "invalid" / "unknown" / "notFound" is a
    real attribution signal; invalid-RPKI prefixes are a yellow flag
    for hijacked / bulletproof hosting.
  - Lives even when Robtex is rate-limited (independent vendor).
  - Includes GeoIP for free so it doubles as a secondary ip-api cross-
    check without a second HTTP call.

Rate limit: 60 req/min keyless. No key.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

_log = logging.getLogger("recon.intel.bgpv6")


_ENDPOINT = "https://bgpv6.com/api/v1/lookup"


async def lookup(session, ip: str) -> Dict[str, Any]:
    """Keyless IP lookup. Returns prefix + ASN + RPKI + GeoIP in one
    hit."""
    if not isinstance(ip, str) or not ip:
        return {"source": "bgpv6", "found": False, "error": "missing ip"}
    from agents.enrichment import _get
    try:
        r = await _get(
            session, f"{_ENDPOINT}/{ip}",
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "application/json"},
            timeout=8,
        )
    except Exception as e:
        return {"source": "bgpv6", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "bgpv6", "error": "unexpected shape",
                "error_type": "unreachable"}
    if "error" in r and "data" not in r:
        # _get-level failure (circuit / timeout / HTTP). The BGPv6
        # payload itself always has `data`, so the absence of `data`
        # on a dict reliably signals a transport failure.
        return {"source": "bgpv6", "error": str(r.get("error"))[:160],
                "error_type": r.get("error_type", "unreachable")}

    data = r.get("data") or {}
    geo  = r.get("geoip") or {}
    if not data and not geo:
        return {"source": "bgpv6", "found": False,
                "summary": f"BGPv6: no data for {ip}"}

    prefix      = data.get("prefix")
    asn         = data.get("asn") or geo.get("asn")
    asn_name    = data.get("asn_name") or geo.get("as_org")
    rpki_status = (data.get("rpki_status") or "").lower()
    country     = data.get("country") or geo.get("country")

    # Verdict logic: RPKI-invalid prefixes are a direct hijack signal
    # (announced by an ASN other than the registered origin). RPKI-
    # valid is a mild trust signal but doesn't override worse signals
    # from other sources - so we leave it UNKNOWN unless invalid.
    verdict = "UNKNOWN"
    if rpki_status == "invalid":
        verdict = "SUSPICIOUS"

    return {
        "source":      "bgpv6",
        "found":       True,
        "ip":          data.get("ip") or ip,
        "prefix":      prefix,
        "asn":         asn,
        "asn_name":    asn_name,
        "country":     country,
        "country_name": geo.get("country_name"),
        "rpki_status": rpki_status or None,
        "lat":         geo.get("latitude"),
        "lon":         geo.get("longitude"),
        "details_url": f"https://bgpv6.com/ip/{ip}",
        "verdict":     verdict,
        "summary":     _summarise(prefix, asn, asn_name, rpki_status),
    }


def _summarise(prefix, asn, asn_name, rpki_status) -> str:
    bits = []
    if prefix:
        bits.append(prefix)
    if asn:
        bits.append(f"AS{asn}" + (f" {asn_name}" if asn_name else ""))
    elif asn_name:
        bits.append(asn_name)
    if rpki_status:
        bits.append(f"RPKI {rpki_status}")
    return "BGPv6: " + " / ".join(bits) if bits else "BGPv6: data returned"
