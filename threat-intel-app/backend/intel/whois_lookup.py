"""
WHOIS XML API lookup. Returns the registration metadata an analyst cares
about when triaging a suspicious domain — registrar, who registered it,
when it was registered (a domain registered hours or days ago is a strong
phishing/C2 signal), when it expires, name servers, and a derived age
in days.

Vendor: whoisxmlapi.com. Endpoint: /whoisserver/WhoisService. Auth via
apiKey query param. Free tier ships ~500/month.

Failure mode: returns None on any error. Caller (agents.enrichment) is
expected to inspect the returned dict and skip its render when absent.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import aiohttp


_ENDPOINT = "https://www.whoisxmlapi.com/whoisserver/WhoisService"


def _parse_dt(value) -> Optional[datetime]:
    """Whois XML API returns dates in a couple of shapes:
      • ISO 8601 with offset:        "2024-09-12T17:33:21+0000"
      • ISO 8601 no offset:          "2024-09-12T17:33:21"
      • Vendor-original strings:     "2024-09-12 17:33:21 UTC"
    Try each in turn; return None if nothing parses so the caller can
    decide what to do (typically just skip the derived age field)."""
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _age_days(dt: Optional[datetime]) -> Optional[int]:
    if not dt:
        return None
    return max(0, (datetime.now(timezone.utc) - dt).days)


async def lookup(domain: str, api_key: str, session: Optional[aiohttp.ClientSession] = None,
                 timeout: int = 12) -> Optional[dict]:
    """Look up WHOIS for `domain`. Returns a compact dict with the fields
    the Summary card actually shows, or None on any error / no data."""
    if not (domain and api_key):
        return None

    params = {
        "apiKey":       api_key,
        "domainName":   domain,
        "outputFormat": "JSON",
        "preferFresh":  "1",   # bypass the vendor's 1-day cache for new alerts
    }
    own_session = session is None
    try:
        if own_session:
            session = aiohttp.ClientSession()
        async with session.get(_ENDPOINT, params=params,
                               timeout=aiohttp.ClientTimeout(total=timeout)) as r:
            if r.status != 200:
                return None
            data = await r.json(content_type=None)
    except Exception:
        return None
    finally:
        if own_session and session is not None:
            await session.close()

    if not isinstance(data, dict):
        return None
    record = data.get("WhoisRecord") or {}
    if not record or record.get("dataError"):
        return None

    # Prefer the registryData block (authoritative) when present, fall
    # back to the merged record (covers TLDs that don't ship registry data
    # to the vendor, e.g. some ccTLDs).
    reg = record.get("registryData") or record
    registrant = (record.get("registrant") or reg.get("registrant") or {})

    created   = _parse_dt(reg.get("createdDate") or record.get("createdDate"))
    updated   = _parse_dt(reg.get("updatedDate") or record.get("updatedDate"))
    expires   = _parse_dt(reg.get("expiresDate") or record.get("expiresDate"))

    return {
        "domain":              record.get("domainName") or domain,
        "registrar":           record.get("registrarName") or reg.get("registrarName") or "",
        "registrar_iana_id":   record.get("registrarIANAID") or reg.get("registrarIANAID") or "",
        "registrant_org":      registrant.get("organization") or "",
        "registrant_country":  registrant.get("country") or registrant.get("countryCode") or "",
        "registrant_state":    registrant.get("state") or "",
        "registrant_email":    registrant.get("email") or "",
        "created":             created.isoformat() if created else "",
        "updated":             updated.isoformat() if updated else "",
        "expires":             expires.isoformat() if expires else "",
        "age_days":            _age_days(created),
        "days_to_expiry":      None if not expires else max(
            0, (expires - datetime.now(timezone.utc)).days),
        "name_servers":        list(record.get("nameServers", {}).get("hostNames", []) or [])[:6],
        "status":              list(reg.get("status", "").split() or [])[:5] if isinstance(
                                   reg.get("status"), str) else (reg.get("status") or [])[:5],
        "privacy_protected":   bool((registrant.get("organization") or "").lower().startswith(
            ("privacy", "redacted", "withheld", "data redacted", "domains by proxy",
             "whoisguard", "redacted for privacy"))),
    }
