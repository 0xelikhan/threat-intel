"""
crt.sh — Certificate Transparency log search. Free, no key.

For a domain, returns every certificate ever issued for it or any
subdomain. This surfaces:
  - Newly-issued certs for lookalike domains (phishing infra prep)
  - Subdomain sprawl invisible to WHOIS
  - Shared certs across infrastructure (operator pivot)

The API is `crt.sh/?q=<domain>&output=json`. It's flaky (502s under
load) so we time out fast + degrade to nothing rather than blocking
the enrichment fan-out.

Actionable output shape:
  {
    "found":       True,
    "cert_count":  <total>,
    "recent_30d":  <count issued in last 30 days>,
    "issuers":     ["Let's Encrypt", "Sectigo", ...],   # dedup top 5
    "unique_sans": <count>,
    "notable_sans": [...],   # subdomains that don't match the query
    "first_seen":   "YYYY-MM-DD",
    "last_seen":    "YYYY-MM-DD",
    "summary":      "human-readable one-liner"
  }
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

_log = logging.getLogger("recon.intel.crt_sh")


def _issuer_short(dn: str) -> str:
    """Extract the CN/O bit from a subject/issuer DN string."""
    if not isinstance(dn, str):
        return ""
    for part in dn.split(","):
        p = part.strip()
        if p.startswith(("O=", "CN=")):
            return p.split("=", 1)[1].strip()
    return dn[:60]


async def enrich(session, domain: str) -> Dict[str, Any]:
    if not isinstance(domain, str) or "." not in domain:
        return {"error": "invalid domain"}
    from agents.enrichment import _get

    # `?q=%.<domain>` matches the domain and all subdomains. exclude=expired
    # trims dead history so noise stays low; wildcard= expands SANs.
    raw = await _get(
        session,
        f"https://crt.sh/?q=%25.{domain}&output=json&exclude=expired",
        headers={"User-Agent": "RECON-ThreatIntel/1.0",
                 "Accept": "application/json"},
    )
    if not isinstance(raw, list) or not raw:
        # crt.sh returns `[]` when nothing, or a dict with `error`/`raw` on
        # HTTP problems. _get maps 5xx/timeout to {"error": ..., "error_type": ...}.
        if isinstance(raw, dict) and raw.get("error"):
            return {"source": "crt.sh", "error": raw.get("error"),
                    "error_type": raw.get("error_type", "unreachable")}
        return {"source": "crt.sh", "found": False,
                "summary": f"No public CT log entries for {domain}."}

    now = datetime.now(timezone.utc)
    cutoff_30 = now - timedelta(days=30)
    cutoff_90 = now - timedelta(days=90)

    issuers: Dict[str, int] = {}
    sans: set = set()
    dates: List[datetime] = []
    recent_30 = 0
    recent_90 = 0

    for row in raw[:800]:   # crt.sh can return 5k+ rows for popular domains
        if not isinstance(row, dict):
            continue
        try:
            entry_ts = row.get("entry_timestamp") or row.get("not_before")
            when = None
            if entry_ts:
                # crt.sh timestamps are ISO but may lack a Z
                s = entry_ts.replace("T", " ").rstrip("Z")
                try:
                    when = datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
                    dates.append(when)
                except ValueError:
                    pass
            if when and when >= cutoff_30:
                recent_30 += 1
            if when and when >= cutoff_90:
                recent_90 += 1
        except Exception:
            pass

        iss = _issuer_short(row.get("issuer_name") or "")
        if iss:
            issuers[iss] = issuers.get(iss, 0) + 1

        for s in (row.get("name_value") or "").split("\n"):
            s = s.strip().lower()
            if s and "*" not in s[:1]:
                sans.add(s)

    first_seen = min(dates).date().isoformat() if dates else None
    last_seen  = max(dates).date().isoformat() if dates else None

    # SANs that AREN'T the queried domain or an obvious subdomain of it.
    # These are the pivots — sibling brands, hidden infra, or the
    # attacker's lookalike sitting under the same cert.
    domain_l = domain.lower().rstrip(".")
    notable = sorted([s for s in sans
                      if s != domain_l and not s.endswith("." + domain_l)])[:15]

    top_issuers = sorted(issuers.items(), key=lambda kv: -kv[1])[:5]
    issuer_str  = ", ".join(f"{n}" for n, _ in top_issuers) or "unknown"

    summary_bits = [f"{len(raw)} certs total"]
    if recent_30:
        summary_bits.append(f"{recent_30} in last 30d")
    elif recent_90:
        summary_bits.append(f"{recent_90} in last 90d")
    summary_bits.append(f"issuers: {issuer_str}")
    if notable:
        summary_bits.append(f"{len(notable)} unrelated-SAN pivot(s)")

    # A burst of certs (>= 20 in 30d) OR unrelated SANs is what an
    # analyst wants to look at. Mark verdict accordingly so the frontend
    # renders it in orange/red instead of grey.
    verdict = "UNKNOWN"
    if recent_30 >= 20 or len(notable) >= 5:
        verdict = "SUSPICIOUS"

    return {
        "source":       "crt.sh (Certificate Transparency)",
        "found":        True,
        "cert_count":   len(raw),
        "recent_30d":   recent_30,
        "recent_90d":   recent_90,
        "issuers":      [n for n, _ in top_issuers],
        "unique_sans":  len(sans),
        "notable_sans": notable,
        "first_seen":   first_seen,
        "last_seen":    last_seen,
        "verdict":      verdict,
        "summary":      " · ".join(summary_bits),
    }
