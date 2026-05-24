"""
Spamhaus DBL (Domain Block List).
Free DNS-based domain reputation — no API key.

Query pattern: <domain>.dbl.spamhaus.org → A record
Return codes (from the A record's last octet):
  127.0.1.2  → spam domain
  127.0.1.4  → phish domain
  127.0.1.5  → malware domain
  127.0.1.6  → botnet C&C domain
  127.0.1.102 → abused legit spam
  127.0.1.103 → abused spammed redirector
  127.0.1.104 → abused legit phish
  127.0.1.105 → abused legit malware
  127.0.1.106 → abused legit botnet C&C
  NXDOMAIN   → not on the list (clean)
  127.255.255.252+ → query refused / rate limited
"""
import asyncio


_VERDICTS = {
    "127.0.1.2":   ("spam",                "Spam source"),
    "127.0.1.4":   ("phishing",            "Phishing domain"),
    "127.0.1.5":   ("malware",             "Malware distribution"),
    "127.0.1.6":   ("botnet",              "Botnet C2"),
    "127.0.1.102": ("abused_spam",         "Hijacked / abused for spam"),
    "127.0.1.103": ("abused_redirector",   "Abused redirector"),
    "127.0.1.104": ("abused_phishing",     "Abused legit for phishing"),
    "127.0.1.105": ("abused_malware",      "Abused legit for malware"),
    "127.0.1.106": ("abused_botnet",       "Abused legit for botnet C2"),
}


async def lookup(domain: str) -> dict | None:
    if not domain or "." not in domain:
        return None
    return await asyncio.to_thread(_sync_lookup, domain.lower().strip().lstrip("."))


def _sync_lookup(domain: str) -> dict | None:
    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        return None
    fqdn = f"{domain}.dbl.spamhaus.org"
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4.0
    resolver.timeout = 2.0
    try:
        answers = resolver.resolve(fqdn, "A")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
    except Exception:
        return None
    for rr in answers:
        ip = str(rr)
        if ip.startswith("127.255."):
            return {"source": "Spamhaus DBL", "hit": False, "rate_limited": True}
        verdict_pair = _VERDICTS.get(ip)
        if verdict_pair:
            verdict, label = verdict_pair
            return {
                "source":  "Spamhaus DBL",
                "hit":     True,
                "verdict": verdict,
                "label":   label,
                "code":    ip,
            }
    return None
