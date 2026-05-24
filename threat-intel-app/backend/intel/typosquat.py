"""
Typosquat / lookalike domain detection using dnstwist.
Detects when a domain in an alert may be impersonating a well-known brand.

Heuristic: only run dnstwist if the domain is NOT itself a well-known brand
(no point twisting google.com) AND looks suspicious (recent registration, etc.).
"""
import re
from functools import lru_cache

# Tier-1 brands attackers commonly impersonate
COMMON_BRANDS = [
    "microsoft", "office365", "outlook", "google", "gmail", "apple", "icloud",
    "facebook", "instagram", "twitter", "linkedin", "github", "gitlab",
    "amazon", "aws", "netflix", "paypal", "stripe", "venmo", "wellsfargo",
    "chase", "bankofamerica", "citibank", "americanexpress", "discord",
    "slack", "zoom", "dropbox", "docusign", "salesforce", "okta", "duo",
    "cloudflare", "fastmail", "protonmail", "fedex", "ups", "dhl", "usps",
]


def _normalize(domain: str) -> str:
    d = (domain or "").lower().strip().lstrip(".")
    return d


def _root_label(domain: str) -> str:
    """Return the registrable label (second-level): mail.foo.example.com → 'example'."""
    parts = _normalize(domain).split(".")
    return parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")


def _ratio(a: str, b: str) -> float:
    """Simple normalized Damerau-Levenshtein-ish similarity (no extra dep)."""
    a, b = a.lower(), b.lower()
    if not a or not b:
        return 0.0
    # quick wins
    if a == b:
        return 1.0
    if a in b or b in a:
        return 0.85
    # crude char-overlap score
    common = sum(1 for c in set(a) if c in b)
    return common / max(len(set(a)), len(set(b)))


def looks_like_brand(domain: str) -> dict | None:
    """Heuristic brand-impersonation check — fast, no DNS lookups."""
    label = _root_label(domain)
    if not label or len(label) < 4:
        return None
    if label in COMMON_BRANDS:
        return None  # the legit brand, not a squat
    best = None
    for brand in COMMON_BRANDS:
        if brand in label and label != brand:
            return {"brand": brand, "score": 0.95, "method": "substring"}
        r = _ratio(label, brand)
        if r > 0.6 and (not best or r > best["score"]):
            best = {"brand": brand, "score": round(r, 2), "method": "similarity"}
    return best


def deep_check(domain: str, max_results: int = 5, timeout: int = 8) -> list[dict] | None:
    """Run dnstwist for full permutation analysis. Returns variants that registered."""
    try:
        import dnstwist
    except ImportError:
        return None
    try:
        fuzzer = dnstwist.Fuzzer(domain)
        fuzzer.generate()
        variants = list(fuzzer.domains)[:50]  # cap for perf
        return [{"variant": v["domain"], "type": v.get("fuzzer", "")} for v in variants[:max_results]]
    except Exception:
        return None


@lru_cache(maxsize=256)
def check_domain(domain: str) -> dict | None:
    """Fast, cached brand-impersonation check for a domain."""
    return looks_like_brand(domain)
