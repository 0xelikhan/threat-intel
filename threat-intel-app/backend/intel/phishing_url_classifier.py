"""
Phishing URL classifier.

A small sklearn GradientBoostingClassifier over structural URL features.
Used in RECON's URL scan path to upgrade the heuristic phishing score
to a learned one without external API calls.

Features (all derived from the URL string — no network I/O):
  * URL length, hostname length, path depth
  * Subdomain depth (how many dots in the hostname)
  * Special-char counts: @, -, %, =, ?, &
  * Digit ratio, uppercase ratio
  * IP-in-URL flag (raw IPv4 host instead of a domain)
  * Non-standard port flag
  * Brand-distance min Levenshtein to a curated brand list (Tranco-top
    flavoured) — a 1-char delta from "paypal" or "microsoft" is the
    classic phish telltale
  * TLD-tier flag (free / abused TLDs like .tk, .top, .xyz, .gq)
  * Presence of brand keyword inside the path or query (a brand name
    appearing AFTER the registrable domain rather than as the domain)
  * URL-encoded character density

Output shape matches `dga_classifier.classify(...)`:
  {
    "is_phish":     bool,
    "probability":  0.0–1.0,
    "confidence":   "low" | "medium" | "high",
    "verdict":      "CLEAN" | "SUSPICIOUS" | "MALICIOUS",
    "summary":      one-line analyst-readable verdict,
    "features":     dict (the underlying numeric features — useful in
                    the analyst report for "WHY did the model flag this"),
    "source":       "phishing_url_classifier"
  }
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

_log = logging.getLogger("recon.intel.phishing_url_classifier")


# Curated brand list — common phishing impersonation targets. Used for
# the brand-distance feature and the "brand-in-path" check.
_BRAND_LIST: List[str] = [
    "google", "gmail", "youtube", "facebook", "instagram", "whatsapp",
    "twitter", "linkedin", "tiktok", "snapchat",
    "apple", "icloud", "microsoft", "office365", "outlook", "onedrive",
    "amazon", "ebay", "paypal", "venmo", "cashapp", "zelle",
    "wellsfargo", "bankofamerica", "chase", "citi", "americanexpress",
    "discover", "capitalone", "barclays", "hsbc",
    "netflix", "spotify", "twitch", "discord", "steam",
    "dropbox", "github", "gitlab", "atlassian", "salesforce",
    "shopify", "stripe", "square", "coinbase", "binance",
    "fedex", "ups", "usps", "dhl",
    "irs", "ssa", "treasury", "uspsgov",
    "docusign", "adobe", "zoom", "slack", "teams", "okta", "duo",
]

# Free / abused TLDs disproportionately hosting phishing pages.
_ABUSED_TLDS = {
    "tk", "ml", "ga", "cf", "gq",      # Freenom legacy
    "top", "xyz", "icu", "buzz", "cyou",
    "club", "rest", "support", "country", "cc",
    "ru", "su", "info", "online", "site",
}


# ─── Training data ──────────────────────────────────────────────────────────
# Negatives: known-good fully-formed URLs across common patterns.
_BENIGN_URLS: List[str] = [
    "https://www.google.com/search?q=python+tutorial",
    "https://github.com/torvalds/linux",
    "https://stackoverflow.com/questions/12345/how-to-x",
    "https://docs.python.org/3/library/asyncio.html",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://www.netflix.com/title/80100172",
    "https://twitter.com/elonmusk/status/1234567890",
    "https://www.linkedin.com/in/satyanadella",
    "https://en.wikipedia.org/wiki/Threat_intelligence",
    "https://news.ycombinator.com/item?id=12345678",
    "https://www.reddit.com/r/cybersecurity/",
    "https://api.github.com/repos/cli/cli/releases",
    "https://aws.amazon.com/s3/pricing/",
    "https://cloud.google.com/storage/docs",
    "https://docs.microsoft.com/en-us/azure/active-directory/",
    "https://www.apple.com/iphone-15/",
    "https://www.paypal.com/us/home",
    "https://signin.aws.amazon.com/console",
    "https://outlook.office.com/mail/inbox",
    "https://drive.google.com/file/d/abc123/view",
    "https://www.dropbox.com/sh/abcdef/foo.zip",
    "https://teams.microsoft.com/l/meetup-join/19%3aabc",
    "https://login.salesforce.com/",
    "https://github.io/recon-project",
    "https://www.cloudflare.com/learning/security/",
    "https://www.kaspersky.com/blog/",
    "https://duo.com/docs/two-factor-authentication",
    "https://www.fastly.com/products/edge-cloud",
    "https://blog.cloudflare.com/the-state-of-tls/",
    "https://www.crowdstrike.com/cybersecurity-101/",
    "https://www.mandiant.com/resources/blog/",
    "https://www.sentinelone.com/blog/",
    "https://attack.mitre.org/techniques/T1059/",
    "https://otx.alienvault.com/pulse/abc123",
    "https://www.virustotal.com/gui/file/abc123",
    "https://www.shodan.io/host/1.2.3.4",
    "https://app.any.run/tasks/abc123",
    "https://urlscan.io/result/abc-123-def/",
    "https://www.abuseipdb.com/check/8.8.8.8",
    "https://intelx.io/?s=test",
    "https://search.censys.io/hosts/1.2.3.4",
    "https://hunter.how/list?searchValue=example.com",
    # Numeric / longer paths that LOOK suspicious but aren't
    "https://en.wikipedia.org/wiki/List_of_HTTP_status_codes",
    "https://www.imdb.com/title/tt1234567/fullcredits",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLabc",
    "https://maps.google.com/?q=37.7749,-122.4194",
    # Deeper / hash-ish path components that are benign
    "https://www.npmjs.com/package/lodash",
    "https://pypi.org/project/fastapi/",
    "https://hub.docker.com/r/library/nginx",
    "https://registry.npmjs.org/react",
    "https://cdn.jsdelivr.net/npm/react@18/umd/react.production.min.js",
    "https://unpkg.com/three@0.150.0/build/three.module.js",
    # Short
    "https://t.co/abc123",
    "https://goo.gl/maps/abc",
    "https://bit.ly/3xY9zQ",   # short URLs CAN be benign — model should
                                # learn that brevity alone isn't phishy
]

# Positives: classic phishing URL patterns. NOT from PhishTank/OpenPhish
# (no licence to redistribute) — these are pattern-faithful synthetic
# samples drawn from years of phish IOC reports.
_PHISH_URLS: List[str] = [
    # Brand-in-subdomain
    "https://paypal-login-secure.example.com/account/verify",
    "https://login-microsoft-365.attacker.tk/auth",
    "https://apple-id-verify.evil-cdn.top/auth",
    "https://google-secure-auth.unknown.xyz/login",
    "https://office365-mail-verify.shady.ru/inbox",
    "https://amazon-prime-billing.fakehost.cf/update",
    "https://chase-verify-account.bad-host.gq/login.html",
    "https://wellsfargo-online-secure.dodgy-cdn.club/account",
    "https://netflix-billing-update.attacker.ml/account/billing",
    "https://docusign-secure-sign.evilhost.icu/sign?id=xyz",
    "https://outlook-mail-verify.malicious.online/inbox",
    # Brand-in-path on attacker domain
    "https://attacker.com/paypal/secure/login.php",
    "https://example-evil.tk/microsoft/login/auth",
    "https://compromised-site.com/wp-content/themes/uploads/apple/auth.php",
    "https://random123.xyz/o365/secure/login.html",
    "https://shadyhost.online/chase/secure/verify.php",
    "https://random-domain.support/dropbox/login/index.html",
    # IP-in-URL
    "http://192.168.45.12/login.php",
    "http://203.0.113.45/paypal/secure/login.html",
    "https://198.51.100.7/microsoft/auth.html",
    "http://45.32.123.99/o365.html",
    "http://104.21.7.123:8080/login/verify",
    # Long path with brand keyword + verb
    "https://shadyhost.tk/secure-login-verify-account-paypal/",
    "https://compromised.gq/account/verify/identity/microsoft365/login",
    "https://baddomain.cf/apple-account-verify-secure-login-now",
    # IDN / homoglyph + brand
    "https://paypa1-secure.example.com/login",         # 1 vs l
    "https://micros0ft-login.attacker.com/auth",       # 0 vs o
    "https://gооgle.com/login",                        # cyrillic o (kept; classifier will learn from string entropy)
    "https://app1e-verify.example.com/signin",          # 1 vs l
    # Punycode-ish phishing
    "https://xn--paypl-uta.example.com/login",
    "https://xn--micros0ft-7r0d.com/auth",
    # @-symbol obfuscation
    "https://www.paypal.com@attacker-server.tk/login",
    "https://login.microsoft.com@evil.cf/auth",
    # Excessive subdomains
    "https://login.secure.verify.account.paypal.com.attacker.xyz/",
    "https://signin.verify.update.microsoft.com.shady.tk/auth",
    # URL-encoded obfuscation
    "https://attacker.com/login%2Easpx%3Fid%3D12345%26redirect%3Dhttp",
    "https://compromised.com/auth%2Easpx%3Faction%3Dlogin%26from%3Demail",
    # Non-standard ports
    "http://example-host.tk:8443/paypal/login",
    "https://shady.cf:9000/account/secure/microsoft/login.html",
    # Excessive query parameters
    "https://attacker.com/login?u=user&p=pass&r=redirect&e=email&t=token",
    # Generic credential phish
    "https://secure-update-account.tk/wp-content/uploads/login.php",
    "https://verify-your-account-now.cf/secure/login/index.html",
    "https://account-security-alert.ml/login.php?action=verify",
    "https://email-verification-required.gq/auth/login",
    # Cryptocoin phishing
    "https://coinbase-secure-login.attacker.top/auth",
    "https://binance-login-verify.shady.icu/account/login",
    "https://metamask-recovery-phrase.evil.xyz/restore",
    # Government / IRS phishing
    "https://irs-tax-refund-secure.attacker.top/claim",
    "https://uspsgov-package-tracking.shady.icu/track",
    "https://ssa-benefits-update.evil.cf/account",
    # Shipping / package
    "https://fedex-package-delivery-update.attacker.tk/track",
    "https://ups-redelivery-secure.shady.online/redeliver",
    "https://dhl-customs-clearance.evil.gq/pay",
    # Random hash-like subdomains
    "https://a8d7f6.attacker.com/login",
    "https://kj3h4kj2.shady.cf/microsoft/auth",
    "https://7ahd83hf.evil.top/paypal/secure/login",
]


# ─── Feature extraction ─────────────────────────────────────────────────────
_IPV4_RE  = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_BRAND_PATH_RE = re.compile("|".join(_BRAND_LIST), re.IGNORECASE)


def _lev(a: str, b: str) -> int:
    """Iterative Levenshtein. Bounded sizes here (brand list ≤ 60 short
    strings vs ~30-char SLD) so the O(n*m) cost is trivial."""
    if not a:
        return len(b)
    if not b:
        return len(a)
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            ins = curr[j - 1] + 1
            dele = prev[j] + 1
            sub = prev[j - 1] + (0 if ca == cb else 1)
            curr[j] = min(ins, dele, sub)
        prev = curr
    return prev[-1]


def _extract_features(url: str) -> Dict[str, float]:
    """Build the numeric feature dict + return a parallel ordered list
    when called via _features_vec()."""
    if not isinstance(url, str) or not url.strip():
        return {}
    raw = url.strip()
    try:
        parsed = urlparse(raw if "://" in raw else "http://" + raw)
    except Exception:
        return {}
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full = raw.lower()

    # eTLD+1 SLD label for brand-distance
    parts = host.split(".") if host else []
    sld   = parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")
    tld   = parts[-1] if parts else ""

    is_ip = bool(host and _IPV4_RE.match(host))
    nonstd_port = bool(parsed.port and parsed.port not in (80, 443))

    # Brand distance — min edit distance from the SLD to any brand
    if sld and not is_ip:
        brand_dist = min(_lev(sld, b) for b in _BRAND_LIST)
        # Confusable-but-not-equal: distance 1-2 is the phish sweet spot
        confusable = 1 if 1 <= brand_dist <= 2 else 0
    else:
        brand_dist = 32
        confusable = 0

    # Brand keyword present in path / query (typical of brand-in-path phish)
    brand_in_path = 1 if _BRAND_PATH_RE.search(path) or _BRAND_PATH_RE.search(query) else 0
    # Brand keyword present in subdomain (e.g. paypal-secure.attacker.com)
    if len(parts) >= 3:
        sub_pre = ".".join(parts[:-2])
        brand_in_subdomain = 1 if _BRAND_PATH_RE.search(sub_pre) else 0
    else:
        brand_in_subdomain = 0

    digits   = sum(1 for c in raw if c.isdigit())
    uppers   = sum(1 for c in raw if c.isupper())
    encoded  = raw.count("%")
    at_signs = raw.count("@")
    dashes   = host.count("-")
    n_raw    = max(1, len(raw))

    return {
        "url_len":              float(len(raw)),
        "host_len":             float(len(host)),
        "path_len":             float(len(path)),
        "subdomain_depth":      float(max(0, len(parts) - 2)),
        "path_depth":           float(path.count("/")),
        "n_dots":               float(host.count(".")),
        "n_hyphens":            float(dashes),
        "n_at":                 float(at_signs),
        "n_percent":            float(encoded),
        "n_equals":             float(raw.count("=")),
        "n_question":           float(raw.count("?")),
        "n_ampersand":          float(raw.count("&")),
        "digit_ratio":          digits / n_raw,
        "upper_ratio":          uppers / n_raw,
        "is_ip_host":           1.0 if is_ip else 0.0,
        "nonstd_port":          1.0 if nonstd_port else 0.0,
        "abused_tld":           1.0 if tld in _ABUSED_TLDS else 0.0,
        "brand_dist":           float(brand_dist),
        "brand_confusable":     float(confusable),
        "brand_in_path":        float(brand_in_path),
        "brand_in_subdomain":   float(brand_in_subdomain),
        "https":                1.0 if parsed.scheme == "https" else 0.0,
    }


_FEATURE_ORDER = (
    "url_len", "host_len", "path_len",
    "subdomain_depth", "path_depth", "n_dots",
    "n_hyphens", "n_at", "n_percent",
    "n_equals", "n_question", "n_ampersand",
    "digit_ratio", "upper_ratio",
    "is_ip_host", "nonstd_port", "abused_tld",
    "brand_dist", "brand_confusable",
    "brand_in_path", "brand_in_subdomain",
    "https",
)


def _features_vec(url: str) -> List[float]:
    feats = _extract_features(url) or {}
    return [feats.get(k, 0.0) for k in _FEATURE_ORDER]


@lru_cache(maxsize=1)
def _build_model() -> Optional[Tuple[Any, Any]]:
    """Train at first use; cached. Returns (scaler, model)."""
    try:
        from sklearn.ensemble import GradientBoostingClassifier
        from sklearn.preprocessing import StandardScaler
        import numpy as np
    except ImportError as e:
        _log.warning("sklearn unavailable: %s — phishing URL classifier disabled", e)
        return None

    X_raw = [_features_vec(u) for u in _BENIGN_URLS] + \
            [_features_vec(u) for u in _PHISH_URLS]
    y = [0] * len(_BENIGN_URLS) + [1] * len(_PHISH_URLS)

    X = np.array(X_raw)
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    # GBT handles this small a corpus well; ~50 estimators × depth 3 keeps
    # training under 100 ms.
    model = GradientBoostingClassifier(
        n_estimators=80, max_depth=3, learning_rate=0.15,
        random_state=42,
    )
    model.fit(Xs, y)
    _log.info("Phishing URL classifier trained: %d benign + %d phish samples",
              len(_BENIGN_URLS), len(_PHISH_URLS))
    return scaler, model


def classify(url: str) -> Dict[str, Any]:
    """Score a URL. Always returns the canonical shape."""
    feats = _extract_features(url)
    if not feats:
        return {
            "is_phish":    False,
            "probability": 0.0,
            "confidence":  "low",
            "verdict":     "CLEAN",
            "summary":     "URL too short / unparseable to classify",
            "source":      "phishing_url_classifier",
        }

    built = _build_model()
    if built is None:
        return _heuristic_score(feats, url)

    scaler, model = built
    import numpy as np
    Xs = scaler.transform(np.array([[feats.get(k, 0.0) for k in _FEATURE_ORDER]]))
    proba = float(model.predict_proba(Xs)[0, 1])

    if proba >= 0.85:
        confidence = "high"
        verdict    = "MALICIOUS"
    elif proba >= 0.6:
        confidence = "medium"
        verdict    = "SUSPICIOUS"
    elif proba >= 0.35:
        confidence = "low"
        verdict    = "SUSPICIOUS"
    else:
        confidence = "low"
        verdict    = "CLEAN"

    is_phish = proba >= 0.6
    pct = round(proba * 100, 1)
    # Pick the strongest driver to mention in the summary — the analyst
    # report cares about WHY more than the raw number.
    drivers = []
    if feats.get("brand_confusable"):
        drivers.append("brand-confusable SLD")
    if feats.get("brand_in_subdomain"):
        drivers.append("brand in subdomain")
    if feats.get("brand_in_path"):
        drivers.append("brand in path")
    if feats.get("is_ip_host"):
        drivers.append("IP host (no DNS name)")
    if feats.get("nonstd_port"):
        drivers.append("non-standard port")
    if feats.get("abused_tld"):
        drivers.append("abused TLD")
    if feats.get("n_at", 0) > 0:
        drivers.append("@-obfuscated URL")
    driver_str = ("; drivers: " + ", ".join(drivers[:3])) if drivers else ""
    summary = (f"Phishing classifier: {pct}% likely phish ({confidence} confidence)"
               f"{driver_str}.") if is_phish else \
              (f"Phishing classifier: {pct}% likely phish — below threshold.")

    return {
        "is_phish":    is_phish,
        "probability": round(proba, 3),
        "confidence":  confidence,
        "verdict":     verdict,
        "summary":     summary,
        "features":    feats,
        "source":      "phishing_url_classifier (gradient boosting over URL structural features)",
    }


def _heuristic_score(feats: Dict[str, float], url: str) -> Dict[str, Any]:
    """sklearn-less fallback. Linear combination of the same features."""
    score = 0.0
    score += 0.30 * float(feats.get("brand_confusable", 0))
    score += 0.20 * float(feats.get("brand_in_subdomain", 0))
    score += 0.15 * float(feats.get("brand_in_path", 0))
    score += 0.15 * float(feats.get("is_ip_host", 0))
    score += 0.10 * float(feats.get("nonstd_port", 0))
    score += 0.10 * float(feats.get("abused_tld", 0))
    score += 0.05 * float(min(1.0, feats.get("n_at", 0)))
    score = min(0.99, score)
    is_phish = score >= 0.50
    return {
        "is_phish":    is_phish,
        "probability": round(score, 3),
        "confidence":  "low",
        "verdict":     "SUSPICIOUS" if is_phish else "CLEAN",
        "summary":     (f"Phishing heuristic (sklearn unavailable): "
                        f"{round(score * 100, 1)}% indicative."),
        "features":    feats,
        "source":      "phishing_heuristic",
    }


def stats() -> Dict[str, Any]:
    built = _build_model()
    return {"loaded": built is not None, "fallback": built is None}
