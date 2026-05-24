"""
Team Cymru Malware Hash Registry (MHR).
Free DNS-based hash reputation — no API key required.

Query pattern: <hash>.malware.hash.cymru.com  →  TXT record
TXT response : "<unix_first_seen> <detection_percentage>"
Empty / NXDOMAIN → not known to Team Cymru
"""
import asyncio
from datetime import datetime, timezone


async def lookup(file_hash: str) -> dict | None:
    """Look up a file hash in Team Cymru MHR. Accepts MD5 / SHA-1 / SHA-256."""
    if not file_hash or len(file_hash) not in (32, 40, 64):
        return None
    return await asyncio.to_thread(_sync_lookup, file_hash.lower())


def _sync_lookup(file_hash: str) -> dict | None:
    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        return None
    fqdn = f"{file_hash}.malware.hash.cymru.com"
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4.0
    resolver.timeout = 2.0
    try:
        answers = resolver.resolve(fqdn, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
    except Exception:
        return None
    for rr in answers:
        txt = b"".join(rr.strings).decode("utf-8", errors="ignore").strip()
        parts = txt.split()
        if len(parts) >= 2:
            try:
                first_seen_ts = int(parts[0])
                detection_pct = int(parts[1])
                first_seen = datetime.fromtimestamp(first_seen_ts, tz=timezone.utc)
                age_days = (datetime.now(timezone.utc) - first_seen).days
                return {
                    "source":         "Team Cymru MHR",
                    "hit":            True,
                    "detection_pct":  detection_pct,
                    "first_seen":     first_seen.isoformat(),
                    "first_seen_age_days": age_days,
                    "verdict":        ("malicious"  if detection_pct >= 50
                                       else "suspicious" if detection_pct >= 5
                                       else "low_confidence"),
                }
            except ValueError:
                continue
    return None
