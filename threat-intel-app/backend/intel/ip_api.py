"""ip-api.com keyless IP geolocation + ASN lookup.

Source: http://ip-api.com/ — free tier is 45 req/min, HTTP only, no
account. Fields returned: country, countryCode, region, regionName,
city, zip, lat, lon, timezone, isp, org, as (ASN string).

Role in RECON: FALLBACK for IPInfo. When IPINFO_TOKEN is unset or
rate-limited (and the Map tab loses coordinates) ip-api.com keeps
the geo pipeline running with the same shape so downstream renderers
don't notice. Also runs in parallel for cross-source agreement —
divergent `country` between IPInfo and ip-api.com has caught bad
GeoIP databases in the past.

Response normalization: we rename ip-api's fields to match the
IPInfo shape (`loc`, `org`, `asn`) so the Map tab can read either
blob interchangeably.

Failure modes: ip-api returns `{"status":"fail","message":"..."}` on
reserved / private / invalid IPs; we treat that as a not-found row
rather than an error row (don't clutter the UI with "unavailable"
for 192.168.x.x lookups).
"""

from __future__ import annotations

import logging
from typing import Any, Dict

_log = logging.getLogger("recon.intel.ip_api")

# Free tier is HTTP-only (the HTTPS endpoint is paid). Using http://
# inside RECON's circuit breaker + timeout envelope is fine - there's
# nothing sensitive in the request (just the IP, which is public data
# we're looking up on behalf of).
_ENDPOINT = "http://ip-api.com/json"

# All fields ip-api.com returns on the free tier. Pinned via the
# `fields` bitmap so the response shape stays stable even if ip-api
# adds new keys later (surprise schema drift killed the Map tab once
# when a vendor added a `continentCode` field between two deploys).
_FIELDS_BITMAP = (
    "status,message,country,countryCode,region,regionName,city,zip,"
    "lat,lon,timezone,isp,org,as,query"
)


async def lookup(session, ip: str) -> Dict[str, Any]:
    """Return a dict normalized to the IPInfo shape so downstream
    renderers can treat ip-api as a drop-in substitute.

    On success: {source, found, ip, country, city, region, loc, org, asn, timezone, isp}
    On miss:    {source, found: False, summary}   (private / reserved IPs)
    On error:   {source, error, error_type}       (rate limit / timeout)
    """
    if not isinstance(ip, str) or not ip:
        return {"source": "ip_api", "found": False, "error": "missing ip"}
    # Import here rather than at module load - avoids the circular
    # import with agents.enrichment that burned us on earlier modules.
    from agents.enrichment import _get
    try:
        r = await _get(
            session, f"{_ENDPOINT}/{ip}",
            params={"fields": _FIELDS_BITMAP},
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "application/json"},
            timeout=8,
        )
    except Exception as e:
        return {"source": "ip_api", "error": str(e)[:120],
                "error_type": "unreachable"}

    if not isinstance(r, dict):
        return {"source": "ip_api", "error": "unexpected shape",
                "error_type": "unreachable"}

    # ip-api's own error envelope: {"status":"fail", "message":"..."}.
    # Common messages: "private range", "reserved range", "invalid query".
    status = (r.get("status") or "").lower()
    if status == "fail":
        msg = (r.get("message") or "").lower()
        # Private/reserved ranges are a normal "not applicable" signal,
        # not a service failure - don't surface as error.
        if "private" in msg or "reserved" in msg:
            return {"source": "ip_api", "found": False,
                    "summary": f"ip-api.com: {msg or 'not routable'}"}
        return {"source": "ip_api",
                "error": r.get("message") or "ip-api error",
                "error_type": "api_error"}
    if "error" in r:
        # Our `_get` helper pre-wrapped an HTTP/circuit-breaker failure.
        return {"source": "ip_api", "error": str(r.get("error"))[:160],
                "error_type": r.get("error_type", "unreachable")}

    # Normalize to the IPInfo shape. `loc` matches ipinfo's "lat,lon"
    # string format so the Map tab can read either blob.
    lat = r.get("lat")
    lon = r.get("lon")
    loc = f"{lat},{lon}" if isinstance(lat, (int, float)) and isinstance(lon, (int, float)) else None

    return {
        "source":     "ip_api",
        "found":      True,
        "ip":         r.get("query") or ip,
        "country":    r.get("countryCode"),
        "country_name": r.get("country"),
        "region":     r.get("regionName") or r.get("region"),
        "city":       r.get("city"),
        "zip":        r.get("zip"),
        "loc":        loc,
        "timezone":   r.get("timezone"),
        "isp":        r.get("isp"),
        "org":        r.get("org") or r.get("isp"),
        "asn":        r.get("as"),
        "verdict":    "UNKNOWN",
        "summary":    _summarise(r),
    }


def _summarise(r: Dict[str, Any]) -> str:
    """Build the one-line label the per-IP renderer shows."""
    bits = []
    if r.get("city"):
        bits.append(r["city"])
    if r.get("regionName"):
        bits.append(r["regionName"])
    if r.get("country"):
        bits.append(r["country"])
    if r.get("org"):
        bits.append(r["org"])
    elif r.get("as"):
        bits.append(r["as"])
    return "ip-api: " + " / ".join(b for b in bits if b) if bits else "ip-api: no geo data"
