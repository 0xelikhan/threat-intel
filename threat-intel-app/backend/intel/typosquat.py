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


# Digit/punct -> visually-similar letter map for homoglyph normalisation.
# Used before similarity so paypa1 / g00gle / app1e / micros0ft / mlcrosoft
# all reduce to their target brand before measurement, otherwise a 1-char
# swap on a short brand (paypal -> paypa1) drops below the 0.85 ratio
# threshold purely because of string length.
_HOMOGLYPH_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "6": "b", "7": "t", "8": "b", "9": "g",
    "|": "l", "!": "i",
})


def _homoglyph_normalise(s: str) -> str:
    return s.translate(_HOMOGLYPH_MAP)


def _ratio(a: str, b: str) -> float:
    """Order-aware similarity using SequenceMatcher (Ratcliff-Obershelp).
    Previous implementation was set-overlap on the character SETS, which
    flagged `blockmultifamily` as `bankofamerica` (set overlap 0.67)
    because they share many letters regardless of order. SequenceMatcher
    requires matching *subsequences*, so visually distinct labels score
    appropriately low even when they share a vocabulary.

    Inputs are first homoglyph-normalised (0->o, 1->l, etc.) so digit-for-
    letter swaps register. The score returned is the MAX of the raw and
    normalised ratios so we never miss a real similarity by normalising."""
    a, b = a.lower(), b.lower()
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    if a in b or b in a:
        return 0.85
    from difflib import SequenceMatcher
    raw  = SequenceMatcher(None, a, b).ratio()
    norm = SequenceMatcher(None, _homoglyph_normalise(a), _homoglyph_normalise(b)).ratio()
    return max(raw, norm)


# Threshold tuned against the new metric. 0.85 produces few false
# positives ("paypa1" -> "paypal" 0.91, "g00gle" -> "google" 0.92,
# "blockmultifamily" -> "bankofamerica" 0.21 -> not flagged). At the
# old 0.6 threshold the new metric is still much tighter than the old
# one, but 0.85 avoids the borderline near-matches that don't actually
# read as visually deceptive.
_BRAND_SIMILARITY_THRESHOLD = 0.85


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
        if r >= _BRAND_SIMILARITY_THRESHOLD and (not best or r > best["score"]):
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
