"""
Phunter-equivalent phone-number analysis (native Python).

IntelOwl ships Phunter as a Docker-based service; RECON implements
the same signal set inline using the google phonenumbers library:
  - parse + validate the number
  - E.164 + international + national format
  - region (country) code + name
  - carrier (where known)
  - timezone list
  - line type (mobile / fixed / voip / toll_free / premium / ...)

This is a purely-local lookup — no network calls, no API key. It's
async for API-consistency with the other intel modules; nothing
actually awaits.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

_log = logging.getLogger("recon.intel.phunter")


# phonenumbers is a declared dependency (see requirements.txt). We import
# lazily so an older RECON install that hasn't pinned it still boots —
# the module cleanly returns an error dict instead of crashing on import.
def _load():
    import phonenumbers  # noqa: F401
    from phonenumbers import carrier, geocoder, timezone, number_type, PhoneNumberType
    return phonenumbers, carrier, geocoder, timezone, number_type, PhoneNumberType


_LINE_TYPE = {
    0: "fixed_line", 1: "mobile", 2: "fixed_or_mobile",
    3: "toll_free", 4: "premium_rate", 5: "shared_cost",
    6: "voip", 7: "personal", 8: "pager", 9: "uan",
    10: "unknown", 27: "emergency", 28: "voicemail",
    29: "short_code", 30: "standard_rate",
}


async def lookup(session, phone: str) -> Dict[str, Any]:
    """Parse + classify a phone number. `session` is unused but kept
    for signature symmetry with network-bound modules."""
    phone = (phone or "").strip()
    if not phone:
        return {"source": "phunter", "found": False,
                "error": "missing phone number"}
    try:
        phonenumbers, carrier, geocoder, timezone, number_type, PhoneNumberType = _load()
    except Exception as e:
        return {"source": "phunter", "error": f"phonenumbers import failed: {e}",
                "error_type": "unavailable"}
    try:
        # Numbers starting with + are international; others are passed with no
        # default region (will fail unless the number is already in E.164).
        parsed = phonenumbers.parse(phone, None)
    except Exception as e:
        return {"source": "phunter", "found": False,
                "error": f"parse failed: {e}", "error_type": "invalid_format"}

    is_valid = phonenumbers.is_valid_number(parsed)
    is_possible = phonenumbers.is_possible_number(parsed)

    e164         = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    intl         = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    national     = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)

    region       = phonenumbers.region_code_for_number(parsed) or ""
    region_name  = geocoder.description_for_number(parsed, "en") or ""
    carrier_name = carrier.name_for_number(parsed, "en") or ""
    tzones       = list(timezone.time_zones_for_number(parsed)) or []
    line_type    = _LINE_TYPE.get(int(number_type(parsed)), "unknown")

    if not is_valid:
        verdict = "SUSPICIOUS"  # unparseable or impossible numbers
        summary = f"Phunter: {phone} is {'possible but ' if is_possible else ''}not a valid number"
    else:
        # Phunter in IntelOwl flags toll-free/premium/shared-cost as higher-risk
        # (common BEC / smishing patterns). Otherwise valid is UNKNOWN.
        if line_type in ("premium_rate", "shared_cost", "toll_free", "voip"):
            verdict = "SUSPICIOUS"
            summary = (f"Phunter: valid {line_type.replace('_', ' ')} number "
                       f"({region}{', ' + region_name if region_name else ''})")
        else:
            verdict = "UNKNOWN"
            summary = (f"Phunter: valid {line_type.replace('_', ' ')} number"
                       + (f" ({carrier_name}" if carrier_name else "")
                       + (f"{', ' + region_name}" if region_name else "")
                       + (")" if carrier_name else ""))

    return {
        "source":         "phunter",
        "found":          True,
        "valid":          is_valid,
        "possible":       is_possible,
        "e164":           e164,
        "international":  intl,
        "national":       national,
        "country_code":   region,
        "country_name":   region_name,
        "carrier":        carrier_name,
        "line_type":      line_type,
        "timezones":      tzones[:5],
        "details_url":    f"https://www.google.com/search?q={e164}",
        "verdict":        verdict,
        "summary":        summary,
    }
