"""
Have I Been Pwned — Pwned Passwords k-anonymity API.

Source: https://api.pwnedpasswords.com (free, no key, abuse-rate-limited).
Privacy-preserving: caller sends only the first 5 chars of a SHA-1 hash;
the server returns every hash starting with that prefix and the breach
count. The caller does the final-byte match locally — the password never
leaves their machine.

RECON's hash IOC extractor surfaces SHA-1 hashes. When the analyst
context mentions a leaked credential, we can ask HIBP "is this a
known-compromised password" without exposing the value to the API.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, Optional

_log = logging.getLogger("recon.intel.hibp")


async def check_sha1(session, sha1: str) -> Dict[str, Any]:
    """Look up a SHA-1 password hash against HIBP's k-anonymity API.
    Input is a 40-char hex SHA-1; the request only ships the first
    5 chars (~16M possible prefixes), then we filter locally for the
    full match in the response."""
    if not isinstance(sha1, str) or len(sha1) != 40:
        return {"source": "hibp_passwords", "error": "invalid sha1",
                "error_type": "skipped"}
    sha1_u = sha1.upper().strip()
    prefix = sha1_u[:5]
    suffix = sha1_u[5:]
    try:
        from agents.enrichment import _get
        raw = await _get(
            session, f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "text/plain",
                     # The Add-Padding header obfuscates the popularity of
                     # the prefix to defeat traffic analysis. HIBP's
                     # recommended default. Costs us a few extra KB; worth
                     # it for the privacy guarantee.
                     "Add-Padding": "true"},
            json_response=False,
            timeout=6,
        )
    except TypeError:
        # Older _get signature without json_response kwarg.
        from agents.enrichment import _get
        raw = await _get(
            session, f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "text/plain", "Add-Padding": "true"},
            timeout=6,
        )
    except Exception as e:
        return {"source": "hibp_passwords", "error": str(e)[:120],
                "error_type": "unreachable"}

    text = raw if isinstance(raw, str) else (
        raw.decode("utf-8", errors="ignore") if isinstance(raw, (bytes, bytearray))
        else ""
    )
    if not text:
        return {"source": "hibp_passwords", "error": "empty response",
                "error_type": "unreachable"}

    breach_count = 0
    for line in text.splitlines():
        if ":" not in line:
            continue
        suf, count = line.split(":", 1)
        if suf.strip().upper() == suffix:
            try:
                breach_count = int(count.strip().replace(",", ""))
            except ValueError:
                breach_count = 0
            break

    if breach_count == 0:
        return {
            "source":       "hibp_passwords",
            "found":        False,
            "breach_count": 0,
            "summary":      "HIBP Pwned Passwords: hash not seen in breaches.",
        }

    # Tier the analyst can scan at a glance.
    if breach_count >= 1_000_000:
        tier = "ubiquitous"
    elif breach_count >= 100_000:
        tier = "very common"
    elif breach_count >= 10_000:
        tier = "common"
    elif breach_count >= 100:
        tier = "moderate"
    else:
        tier = "rare"

    return {
        "source":       "hibp_passwords",
        "found":        True,
        "breach_count": breach_count,
        "tier":         tier,
        "verdict":      "MALICIOUS" if breach_count >= 10_000 else "SUSPICIOUS",
        "summary":      (f"HIBP Pwned Passwords: hash seen in "
                          f"{breach_count:,} breaches ({tier})."),
    }


def hash_password(password: str) -> str:
    """Convenience: SHA-1-hex a candidate password for HIBP submission.
    Caller normally does this client-side; RECON's analyst surface
    typically already has a SHA-1 to check (extracted from the alert)."""
    if not isinstance(password, str):
        return ""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
