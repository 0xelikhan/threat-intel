"""
Domain-level heuristics SOC analysts rely on:
  - Newly Registered Domain (NRD) age check
  - Domain Generation Algorithm (DGA) score
  - Internationalized Domain Name (IDN) / Punycode homoglyph detection
All offline, fast, no API calls.
"""
import math
import re
from datetime import datetime, timezone


# ─── NRD ──────────────────────────────────────────────────────────────────────
def nrd_check(whois_created: str | None) -> dict | None:
    """Given a WHOIS created-date string, return age + tiered NRD flags.
    Resolves to hour-level precision when the source includes a timestamp,
    so same-day registrations are flagged explicitly (highest-risk phishing signal)."""
    if not whois_created:
        return None
    raw = str(whois_created).strip()

    # Try full-timestamp parses first (preserves hours)
    created = None
    iso_attempts = [
        raw,                              # 2026-05-23T14:32:00Z
        raw.replace("Z", "+00:00"),       # ISO with explicit UTC
        raw.replace(" ", "T"),            # 2026-05-23 14:32:00 → 2026-05-23T14:32:00
    ]
    for attempt in iso_attempts:
        try:
            created = datetime.fromisoformat(attempt)
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            break
        except (ValueError, TypeError):
            continue

    # Date-only fallback (loses hours, conservative 0:00 assumption)
    if not created:
        date_part = raw.split("T")[0].split(" ")[0][:10]
        for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%d/%m/%Y", "%Y%m%d"):
            try:
                created = datetime.strptime(date_part, fmt).replace(tzinfo=timezone.utc)
                break
            except ValueError:
                continue
    if not created:
        return None

    now = datetime.now(timezone.utc)
    delta = now - created
    age_hours = max(0, int(delta.total_seconds() // 3600))
    age_days = delta.days

    signals = []
    if age_hours < 24:
        signals.append("registered TODAY (high-risk phishing signal)")
    elif age_days < 7:
        signals.append(f"registered {age_days} day{'s' if age_days != 1 else ''} ago")
    elif age_days < 30:
        signals.append(f"newly registered ({age_days} days old)")

    return {
        "age_hours":     age_hours,
        "age_days":      age_days,
        "created":       created.isoformat(),
        "is_same_day":   age_hours < 24,
        "is_this_week":  age_days < 7,
        "is_very_new":   age_days < 14,
        "is_nrd":        age_days < 90,
        "signals":       signals,
    }


# ─── DGA ──────────────────────────────────────────────────────────────────────
# Common English bigrams — domains with random characters score low.
_COMMON_BIGRAMS = {
    "th","he","in","er","an","re","on","at","en","nd","ti","es","or","te","of",
    "ed","is","it","al","ar","st","to","nt","ng","se","ha","as","ou","io","le",
    "ve","co","me","de","hi","ri","ro","ic","ne","ea","ra","ce","li","ch","ll",
    "be","ma","si","om","ur","ca","el","ta","la","ns","di","fo","ho","pe","ec",
}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    total = len(s)
    return -sum((n/total) * math.log2(n/total) for n in counts.values())


def dga_score(domain: str) -> dict:
    """Score 0..1 — higher = more likely algorithmically generated."""
    if not domain:
        return {"score": 0.0, "flagged": False, "signals": []}
    label = domain.lower().split(".")[0]
    if len(label) < 5:
        return {"score": 0.0, "flagged": False, "signals": []}

    ent = _entropy(label)
    consonants = sum(1 for c in label if c in "bcdfghjklmnpqrstvwxz")
    vowels     = sum(1 for c in label if c in "aeiou")
    digits     = sum(1 for c in label if c.isdigit())

    # Bigram dictionary score — what fraction of bigrams are common English?
    bigrams = [label[i:i+2] for i in range(len(label)-1)]
    common  = sum(1 for b in bigrams if b in _COMMON_BIGRAMS) / max(len(bigrams), 1)

    signals = []
    score = 0.0

    if ent > 3.5:
        score += 0.3; signals.append(f"high entropy ({ent:.2f})")
    if common < 0.2 and len(label) >= 8:
        score += 0.3; signals.append(f"low English-bigram ratio ({common:.0%})")
    # consonant-heavy / vowel-starved (works even when vowels==0)
    expected_vowels = max(2, len(label) // 5)
    if vowels < expected_vowels and consonants >= 5:
        score += 0.2; signals.append(f"vowel-starved ({vowels} vowels in {len(label)} chars)")
    if digits / len(label) > 0.3:
        score += 0.2; signals.append(f"{digits} digits in {len(label)}-char label")
    if len(label) >= 15 and vowels < 3:
        score += 0.2; signals.append("long with few vowels")
    if re.search(r"[aeiou]{4,}", label) or re.search(r"[bcdfghjklmnpqrstvwxz]{5,}", label):
        score += 0.1; signals.append("unusual letter runs")

    score = round(min(score, 1.0), 2)
    return {
        "score":   score,
        "flagged": score >= 0.5,
        "entropy": round(ent, 2),
        "signals": signals,
    }


# ─── IDN / Punycode / Homoglyph ───────────────────────────────────────────────
# Cyrillic/Greek/etc. characters that look like ASCII letters
_HOMOGLYPHS = {
    "а":"a","е":"e","о":"o","р":"p","с":"c","у":"y","х":"x","і":"i","ӏ":"l",
    "α":"a","ε":"e","ο":"o","ρ":"p","ѕ":"s","ν":"v","ɴ":"n","ʟ":"l",
}


def idn_check(domain: str) -> dict | None:
    """Detect punycode and homoglyph attacks."""
    if not domain:
        return None
    d = domain.strip().lower()
    out: dict = {}

    if "xn--" in d:
        try:
            ascii_form = d.encode("ascii").decode("ascii")
            try:
                unicode_form = ".".join(part.encode().decode("idna") if part.startswith("xn--") else part
                                         for part in ascii_form.split("."))
            except Exception:
                unicode_form = ascii_form
            out["punycode"] = True
            out["unicode_form"] = unicode_form
        except Exception:
            pass

    homo_chars = [c for c in d if c in _HOMOGLYPHS]
    if homo_chars:
        out["homoglyphs"] = list(set(homo_chars))
        out["ascii_lookalike"] = "".join(_HOMOGLYPHS.get(c, c) for c in d)

    if not any(ord(c) < 128 for c in d):
        out["all_non_ascii"] = True

    return out or None


# ─── Combined helper ──────────────────────────────────────────────────────────
def analyze_domain(domain: str, whois_created: str | None = None) -> dict:
    """Return combined NRD / DGA / IDN analysis."""
    out: dict = {}
    nrd = nrd_check(whois_created)
    if nrd:
        out["nrd"] = nrd
    dga = dga_score(domain)
    if dga.get("flagged"):
        out["dga"] = dga
    idn = idn_check(domain)
    if idn:
        out["idn"] = idn
    return out
