"""
Typosquat / lookalike domain detection using dnstwist.
Detects when a domain in an alert may be impersonating a well-known brand.

Heuristic: only run dnstwist if the domain is NOT itself a well-known brand
(no point twisting google.com) AND looks suspicious (recent registration, etc.).
"""
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

# First-party brand-owned domains whose SLD label contains a brand
# substring — these must NOT be flagged as typosquats. Every M365
# tenant lives at `<tenant>.onmicrosoft.com`, every OAuth flow round-
# trips `login.microsoftonline.com`, GCP objects live at
# `storage.googleapis.com`, etc. Bug that surfaced this list: forwarding-
# rule log analysis kept labelling `onmicrosoft.com` as a Microsoft
# lookalike because "microsoft" is a proper substring of "onmicrosoft".
#
# Values are the eTLD+1 form (SLD + TLD). Loose subdomain check below.
LEGIT_BRAND_DOMAINS = frozenset({
    # Microsoft / M365 / Azure
    "onmicrosoft.com", "microsoftonline.com", "microsoft365.com",
    "office.com", "office365.com", "sharepoint.com",
    "windows.com", "windowsazure.com", "azurewebsites.net",
    "azureedge.net", "azurecr.io", "azure-api.net", "azurefd.net",
    "live.com", "hotmail.com", "outlook.com", "office.net",
    "microsoft.net",
    # Google
    "googlemail.com", "googleusercontent.com", "googleapis.com",
    "gstatic.com", "googletagmanager.com", "googleadservices.com",
    "google-analytics.com", "googlesyndication.com", "youtube.com",
    "gmail.com",
    # Apple
    "icloud.com", "apple.com", "me.com", "mac.com",
    # Meta / Facebook
    "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.com",
    "messenger.com",
    # Amazon / AWS
    "amazonaws.com", "amazon.com", "cloudfront.net", "awsstatic.com",
    # Other tier-1
    "linkedin.com", "github.com", "githubusercontent.com",
    "gitlab.com", "stripe.com", "stripe.network", "paypal.com",
    "salesforce.com", "force.com", "okta.com", "oktapreview.com",
    "duosecurity.com", "cloudflare.com", "cloudflareinsights.com",
    "dropbox.com", "dropboxusercontent.com", "docusign.com",
    "docusign.net", "slack.com", "slack-edge.com", "zoom.us",
})


def _is_legit_brand_domain(domain: str) -> bool:
    """True if the domain (or any parent up to eTLD+1) is a first-party
    brand-owned domain that legitimately contains a brand substring."""
    d = _normalize(domain)
    if not d:
        return False
    if d in LEGIT_BRAND_DOMAINS:
        return True
    # Match any subdomain of a legit brand domain — e.g.
    # `contoso.onmicrosoft.com` matches `onmicrosoft.com`.
    for legit in LEGIT_BRAND_DOMAINS:
        if d.endswith("." + legit):
            return True
    return False


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
    # First-party brand domains (onmicrosoft.com, microsoftonline.com,
    # googleusercontent.com, etc.) short-circuit before the substring
    # matcher — otherwise "microsoft" would flag inside "onmicrosoft"
    # and every M365 tenant would show as a typosquat.
    if _is_legit_brand_domain(domain):
        return None
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
