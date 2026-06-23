"""
DGA (Domain Generation Algorithm) classifier.

A small sklearn LogisticRegression over character bigram TF-IDF +
structural features. Trained at first call on a bundled mix of
synthetic DGA samples and benign popular-domain negatives.

RECON's existing heuristic DGA score in intel/domain_analysis.py is
fast but noisy on legitimately hash-like subdomains (AWS S3, CDN
edges, GitHub raw paths). The trained model sharpens precision by
learning the joint distribution of char-ngrams + entropy + vowel
ratio that distinguishes ALG-output from real registered domains.

The model + vectorizer are built once per process via @lru_cache.
Training takes ~50 ms on the bundled data; subsequent calls are O(1)
vectorizer apply + dot product.

Inputs / outputs (kept compact for the analyst-summary surface):
  classify("evil-domain.com") -> {
    "is_dga":      bool,
    "probability": float (0.0 - 1.0),
    "confidence":  "low" | "medium" | "high",
    "verdict":     "CLEAN" | "SUSPICIOUS" | "MALICIOUS",
    "summary":     human-readable one-liner,
  }
"""

from __future__ import annotations

import logging
import math
import re
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger("recon.intel.dga_classifier")


# ─── Training data (bundled in-tree, kept small) ────────────────────────────
# Negatives: high-popularity domains that should NEVER score as DGAs.
# Sourced from Tranco-top + hand-curated mainstream brands. The training
# routine ALSO consults intel.tranco at runtime if the operator has the
# full Tranco corpus loaded; that gives the model 100x more negatives
# without bloating the repo.
_BENIGN_SEED: List[str] = [
    # FAANG + mainstream
    "google", "youtube", "facebook", "instagram", "twitter", "linkedin",
    "amazon", "apple", "microsoft", "github", "gitlab", "stackoverflow",
    "wikipedia", "reddit", "netflix", "spotify", "twitch", "discord",
    "slack", "zoom", "dropbox", "salesforce", "shopify", "cloudflare",
    "fastly", "akamai", "stripe", "paypal", "venmo", "chase",
    # Banks + finance
    "wellsfargo", "bankofamerica", "citi", "americanexpress", "discover",
    "schwab", "fidelity", "vanguard", "robinhood", "coinbase",
    # SaaS
    "atlassian", "jira", "confluence", "notion", "figma", "asana",
    "monday", "trello", "miro", "loom", "calendly", "intercom",
    "zendesk", "hubspot", "marketo", "segment", "datadog", "newrelic",
    "splunk", "elastic", "okta", "auth0", "duo", "onelogin",
    "cloudflare", "fastly", "akamai", "cdn", "fastlydns", "edgekey",
    # Newsy / media
    "nytimes", "washingtonpost", "wsj", "reuters", "bloomberg",
    "cnn", "bbc", "guardian", "ft", "theatlantic", "vox", "wired",
    "techcrunch", "arstechnica", "theverge", "engadget",
    # Cloud + dev infra
    "amazonaws", "azureedge", "googlecloud", "digitalocean", "linode",
    "vultr", "heroku", "vercel", "netlify", "render", "fly",
    "supabase", "planetscale", "neon", "railway",
    # Government + edu
    "irs", "treasury", "cisa", "whitehouse", "nasa", "nih", "noaa",
    "stanford", "harvard", "mit", "berkeley", "cmu", "princeton",
    # Asia / EU
    "alibaba", "tencent", "baidu", "rakuten", "samsung", "lg",
    "deutschebank", "sap", "siemens", "philips",
    # Retail
    "target", "walmart", "costco", "homedepot", "lowes", "bestbuy",
    "ebay", "etsy", "wayfair", "ikea", "nike", "adidas",
    # Auto
    "tesla", "ford", "gm", "toyota", "honda", "bmw", "mercedes",
    # Email + comms
    "gmail", "outlook", "yahoo", "protonmail", "fastmail", "icloud",
    # Misc popular
    "openai", "anthropic", "huggingface", "kaggle", "wolframalpha",
    "duckduckgo", "brave", "mozilla", "chromium", "linkedin",
]

# Positives: synthetic DGA samples generated from public algorithm patterns.
# Real DGA families seen in malware reports (Necurs, Cryptolocker variants,
# Conficker, Pushdo, Suppobox, etc.). Pattern-based synthesis avoids
# shipping copyrighted blocklists.
_DGA_SEED: List[str] = [
    # Conficker / Cryptolocker-style: high entropy, no vowel structure
    "qpvbnzxlmrkj", "wertyhjklmnb", "zxcvbasdfghj", "mnbvcxzpoiuy",
    "tygfvdcrjklq", "pmsxnzvbcwer", "jhkfgdrtweqz", "lkjhgfdsapoi",
    "qweasdzxcrtb", "ufpwzelmqgsn", "nbzqlxmwertc", "vjklmnopqrtx",
    "bkqglsfdwzry", "xmpvbngrwzqf", "njbvtzlxqwer", "fghxcvbnzqep",
    "tvxbnmzlksdy", "ywzpvnxckmrb", "kjsnxbzqmwet", "lprzqnxmcvbf",
    # Pushdo-style: alphabetic with varying length
    "abeyhozarpod", "vewichaboth", "ozaderepoth", "imamaderozer",
    "echasuvowem", "ufodimagigy", "yvosamehosa", "uderowapoh",
    "edowywazoh", "isewahozat", "amapotypov", "evahivozer",
    # Necurs-style: longer, mix of consonants
    "tfsdrgnmbxlckj", "wprtlkgnmbcvz", "jhgfdsapoiuyt",
    "qpwoeirutylakj", "zxcvbnmasdfghj", "tygfvdcjkrtsa",
    # Suppobox-style: dictionary-like but unusual combinations
    "redblueballbase", "thinkpaperjump", "windowboatsalt",
    "earthstrongtea", "yellowdrivecake", "winterforestmail",
    "rivermountainflow", "tablechairnight",
    # Cryptolocker / Locky-style: short + cryptic
    "wjqkx", "vlmpr", "zxqfb", "phznmd", "qrwsx", "fzlpn",
    "kxqvb", "mpwlz", "rxvjn", "qkbpz", "txzlm", "wcvjk",
    "blpxr", "qjznm", "vkrwl", "fxbpz", "ljxqr", "ncvkz",
    # Mid-length random alpha
    "asdjhqweuiy", "lkmnvxzbcgh", "pqozmnvxcbr", "wertyuiopas",
    "dfghjklzxcv", "bnmqwertyui", "opasdfghjkl", "zxcvbnmqwer",
    # With digits (some DGAs include digits)
    "abc123def", "xyz789mnp", "qwer432zxc", "asdf876lkj",
    "bnm321vbc", "tyu654iop", "ghj987qwe", "rty543uik",
    # Long random
    "kjvbnxzlqwpoeiruty", "asdfghjklqwertyuiop",
    "mnbvcxzlkjhgfdsapoi", "zxcvbnmasdfghjqwerty",
    "poiuytrewqlkjhgfdsa", "mnbvcxzlkjhgfasdfgwer",
    # Pseudo-pronounceable but wrong (markov-like)
    "blarn", "frump", "splog", "whern", "thron", "drinx",
    "plonk", "vrond", "skrim", "frung", "blozz", "crunx",
    "ploth", "vrang", "skroth", "frump", "blark", "crowx",
    # Hexadecimal-style (less common, but seen)
    "0a1b2c3d", "deadbeef", "feed1234", "cafebabe",
    "a1b2c3d4e5", "f6e5d4c3b2", "deadbeefcafe",
    # Time-based DGAs often have date components
    "domain20240617", "evil202312abc", "host20250101xyz",
    "bot202403evil", "c2202406bad", "domain202405dga",
    # Longer DGA-like with dashes
    "xq-zb-mp-rl", "kj-vn-zx-cb", "pq-lm-rt-wb",
]


# ─── Feature extraction ─────────────────────────────────────────────────────
_DIGIT_RE   = re.compile(r"\d")
_NONALPH_RE = re.compile(r"[^a-z0-9-]")
_VOWELS = set("aeiou")


def _label(domain: str) -> str:
    """Return the leftmost label (the registrable name) lowercased.
    'malware.attacker.example.com' -> 'malware' for the model's input.
    For DGA detection, the leftmost label carries the strongest signal."""
    if not isinstance(domain, str) or not domain:
        return ""
    d = domain.strip().lower().rstrip(".")
    # Strip protocol if present
    if "://" in d:
        d = d.split("://", 1)[1].split("/", 1)[0]
    # For multi-label domains take the second-to-last (the eTLD+1 SLD)
    # so we don't lose signal to short TLDs. For mail.foo.example.co.uk
    # we want "example" rather than "co".
    parts = d.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return parts[0] if parts else ""


def _structural_features(label: str) -> List[float]:
    """Per-domain structural features the bigram vectorizer doesn't
    capture directly. Length, character-class ratios, entropy."""
    if not label:
        return [0.0] * 7
    n = len(label)
    digits     = sum(1 for c in label if c.isdigit())
    vowels     = sum(1 for c in label if c in _VOWELS)
    hyphens    = label.count("-")
    nonalnum   = len(_NONALPH_RE.findall(label))
    # Shannon entropy of character distribution
    counts: Dict[str, int] = {}
    for c in label:
        counts[c] = counts.get(c, 0) + 1
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    # Longest run of consonants (a DGA tell — real words almost never
    # exceed 4 consonants in a row)
    max_consonant_run = 0
    cur = 0
    for c in label:
        if c.isalpha() and c not in _VOWELS:
            cur += 1
            max_consonant_run = max(max_consonant_run, cur)
        else:
            cur = 0
    return [
        float(n),                              # length
        digits  / max(1, n),                   # digit ratio
        vowels  / max(1, n),                   # vowel ratio
        hyphens / max(1, n),                   # hyphen ratio
        nonalnum / max(1, n),                  # special-char ratio
        entropy,                                # Shannon entropy
        float(max_consonant_run),              # longest consonant run
    ]


@lru_cache(maxsize=1)
def _build_model() -> Optional[Tuple[Any, Any, Any]]:
    """Train at first use. Returns (vectorizer, struct_scaler, lr_model).
    Returns None when sklearn isn't available so the caller can fall
    back gracefully to the heuristic score."""
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.preprocessing import StandardScaler
        import numpy as np
    except ImportError as e:
        _log.warning("sklearn unavailable: %s — DGA classifier disabled", e)
        return None

    # Pull additional benign negatives from the Tranco index when the
    # operator has fetched it. Otherwise we train on the bundled seed
    # only (still usable, just narrower).
    benign_labels = [_label(d + ".com") for d in _BENIGN_SEED if d]
    try:
        from intel.tranco import _state as _tr_state
        for d in (_tr_state.get("rank") or {}):
            label = _label(d)
            if label and len(label) >= 3 and len(label) <= 32:
                benign_labels.append(label)
            if len(benign_labels) >= 8000:
                break
    except Exception:
        pass
    benign_labels = list(dict.fromkeys(benign_labels))

    dga_labels = list(dict.fromkeys(_DGA_SEED))
    # Filter both sets to a reasonable length window so the model learns
    # the right thing.
    def _ok(s: str) -> bool:
        return 3 <= len(s) <= 32 and bool(s)
    benign_labels = [s for s in benign_labels if _ok(s)]
    dga_labels    = [s for s in dga_labels    if _ok(s)]

    X_text = benign_labels + dga_labels
    y      = [0] * len(benign_labels) + [1] * len(dga_labels)

    vectorizer = TfidfVectorizer(
        analyzer="char_wb", ngram_range=(2, 3),
        max_features=2000, sublinear_tf=True,
    )
    X_text_vec = vectorizer.fit_transform(X_text)

    X_struct = np.array([_structural_features(s) for s in X_text])
    scaler = StandardScaler()
    X_struct_scaled = scaler.fit_transform(X_struct)

    # Concatenate sparse text features with dense structural features.
    from scipy.sparse import hstack, csr_matrix
    X = hstack([X_text_vec, csr_matrix(X_struct_scaled)])

    model = LogisticRegression(max_iter=400, C=1.5,
                                class_weight="balanced", solver="liblinear")
    model.fit(X, y)
    _log.info("DGA classifier trained: %d benign + %d DGA samples",
              len(benign_labels), len(dga_labels))
    return vectorizer, scaler, model


def classify(domain: str) -> Dict[str, Any]:
    """Score a domain. Always returns the canonical shape; falls back
    to the heuristic if sklearn is unavailable or the label is empty."""
    label = _label(domain)
    if not label or len(label) < 3:
        return {
            "is_dga":      False,
            "probability": 0.0,
            "confidence":  "low",
            "verdict":     "CLEAN",
            "summary":     "label too short to classify",
            "source":      "dga_classifier",
        }

    built = _build_model()
    if built is None:
        # Fall back to the existing heuristic so the caller still gets
        # a useful score when sklearn isn't installed.
        return _heuristic_score(label, domain)

    vectorizer, scaler, model = built
    import numpy as np
    from scipy.sparse import hstack, csr_matrix
    X_text_vec = vectorizer.transform([label])
    X_struct   = scaler.transform(np.array([_structural_features(label)]))
    X = hstack([X_text_vec, csr_matrix(X_struct)])
    proba = float(model.predict_proba(X)[0, 1])

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

    is_dga = proba >= 0.6
    summary = (
        f"DGA classifier: {round(proba * 100, 1)}% likely DGA-generated"
        f" ({confidence} confidence)."
        if is_dga else
        f"DGA classifier: {round(proba * 100, 1)}% likely DGA-generated"
        f" — below threshold, treat as benign-shaped."
    )

    return {
        "is_dga":      is_dga,
        "probability": round(proba, 3),
        "confidence":  confidence,
        "verdict":     verdict,
        "label":       label,
        "summary":     summary,
        "source":      "dga_classifier (logreg over char-bigram + structural features)",
    }


def _heuristic_score(label: str, domain: str) -> Dict[str, Any]:
    """sklearn-less fallback: lift the existing structural heuristic
    into the same shape the model returns. Used so callers don't have
    to special-case the disabled state."""
    feats = _structural_features(label)
    entropy = feats[5]
    max_cons = feats[6]
    vowel_ratio = feats[2]
    score = 0.0
    score += min(0.5, max(0.0, (entropy - 3.0) / 2.0))
    score += min(0.3, max(0.0, (max_cons - 4) / 6.0))
    score += min(0.2, max(0.0, (0.25 - vowel_ratio) / 0.25))
    score = min(0.99, score)
    is_dga = score >= 0.55
    return {
        "is_dga":      is_dga,
        "probability": round(score, 3),
        "confidence":  "low",
        "verdict":     "SUSPICIOUS" if is_dga else "CLEAN",
        "label":       label,
        "summary":     ("DGA heuristic (sklearn unavailable): "
                        f"{round(score * 100, 1)}% indicative."),
        "source":      "dga_heuristic",
    }


def stats() -> Dict[str, Any]:
    built = _build_model()
    return {
        "loaded": built is not None,
        "fallback": built is None,
    }
