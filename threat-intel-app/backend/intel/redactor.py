"""
Fail-closed pre-redaction pipeline.

When a request body contains structured secrets, the redactor replaces them
with stable typed placeholders ({{REDACTED_<TYPE>_<n>}}) before the body
reaches downstream code paths (AI calls, audit logging, persistence). The
redactor returns the redacted text + a per-IOC count + a confidence float;
the caller decides what to do with low confidence.

Fail-closed semantics: when the redactor's confidence drops below the
configured threshold (REDACTION_MIN_CONFIDENCE, default 0.6), the caller
MUST reject the request rather than fall back to "best effort." There is
no soft path that silently sends partially-redacted data anywhere it
shouldn't go.

Detection patterns (regex-based, deterministic, no LLM call):
  - API keys: AWS, Azure storage, GitHub, OpenAI, Anthropic, Slack, Stripe,
    Google, generic high-entropy bearer strings.
  - JWTs: three base64url segments separated by dots, header decodes to
    `{"alg":...}`.
  - Private keys / certificates: PEM blocks.
  - Credentials: `password=`, `pwd=`, `secret=`, `token=` query/inline pairs.
  - Emails, IPv4, IPv6, MAC, internal hostnames, UNC paths.
  - High-entropy hex blobs >= 40 chars (likely credentials / hashes worth
    treating as sensitive).

Two-pass design:
  1. find_matches(text)        — regex scan, returns spans + types.
  2. redact(text, threshold)   — applies replacements + confidence score.
The split lets callers preview detections before committing the rewrite.
"""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple


# ─── pattern catalogue ────────────────────────────────────────────────────────
# Order matters: longer/more-specific patterns first so a JWT isn't first
# matched as a generic high-entropy blob. Every entry: (type-tag, regex,
# weight). Weight feeds the confidence score.

_PATTERNS: List[Tuple[str, "re.Pattern[str]", float]] = [
    # PEM blocks (highest priority — exact framing).
    ("PEM", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PRIVATE |PUBLIC )?(?:PRIVATE KEY|CERTIFICATE|RSA PRIVATE KEY)-----"
        r"[\s\S]+?"
        r"-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PRIVATE |PUBLIC )?(?:PRIVATE KEY|CERTIFICATE|RSA PRIVATE KEY)-----",
    ), 1.0),

    # AWS access keys (AKIA-prefixed + the secret half when it appears with one).
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA|AIDA|AGPA|AROA|ANPA)[0-9A-Z]{16}\b"), 1.0),
    ("AWS_SECRET",     re.compile(r"\baws[_-]?secret(?:_access)?[_-]?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", re.I), 1.0),

    # Azure storage account keys (base64-ish, 88 chars ending in ==).
    ("AZURE_STORAGE",  re.compile(r"\b[A-Za-z0-9+/]{86}==\b"), 0.9),

    # Other cloud / SaaS keys with strong prefixes.
    ("OPENAI_KEY",     re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), 1.0),
    ("ANTHROPIC_KEY",  re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), 1.0),
    ("GITHUB_TOKEN",   re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"), 1.0),
    ("SLACK_TOKEN",    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), 1.0),
    ("STRIPE_KEY",     re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{20,}\b"), 1.0),
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 1.0),

    # JWT (header.payload.signature).
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), 0.95),

    # Inline credential pairs.
    ("CREDENTIAL", re.compile(
        r"(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\s*[=:]\s*['\"]?"
        r"([A-Za-z0-9!@#$%^&*()_+={}\[\]|\\:;\"'<>,.?/~`+-]{6,})"
        r"['\"]?",
        re.IGNORECASE,
    ), 0.7),

    # Email addresses.
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), 0.55),

    # IPv4 + IPv6.
    ("IPV4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), 0.4),
    ("IPV6", re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b"), 0.4),

    # MAC addresses.
    ("MAC", re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b"), 0.55),

    # Internal hostnames (computer names, NetBIOS-style, UNC paths).
    ("UNC_PATH",   re.compile(r"\\\\[A-Za-z0-9._-]{1,63}\\[A-Za-z0-9._$-]+"), 0.7),
    ("HOSTNAME",   re.compile(r"\b(?:DESKTOP|LAPTOP|WORKSTATION|SRV|SERVER|HOST|PC|WIN|DC|FS|DB|APP|WEB|MAIL|VM)-[A-Za-z0-9]{2,12}\b"), 0.7),

    # High-entropy hex blobs — likely hashes or credential material.
    ("HEX_BLOB_LONG", re.compile(r"\b[A-Fa-f0-9]{64,}\b"), 0.55),
    ("HEX_BLOB_MED",  re.compile(r"\b[A-Fa-f0-9]{40,63}\b"), 0.4),
]


@dataclass
class RedactionMatch:
    type: str
    start: int
    end: int
    value: str
    weight: float


@dataclass
class RedactionResult:
    redacted: str
    matches: List[RedactionMatch] = field(default_factory=list)
    by_type: Dict[str, int] = field(default_factory=dict)
    confidence: float = 1.0
    rejected: bool = False
    reject_reason: str = ""

    def to_audit_dict(self) -> dict:
        """Stripped-down record safe to log alongside the request — counts and
        confidence only, never the matched values themselves."""
        return {
            "redaction_confidence": round(self.confidence, 3),
            "redaction_counts":    dict(self.by_type),
            "redaction_rejected":  self.rejected,
        }


# ─── helpers ──────────────────────────────────────────────────────────────────
def _is_valid_jwt(token: str) -> bool:
    """Header segment must base64-decode to JSON with an `alg` field. Anything
    else is a false positive (the JWT regex matches loose dotted base64)."""
    try:
        head = token.split(".", 1)[0]
        pad = "=" * (-len(head) % 4)
        decoded = base64.urlsafe_b64decode(head + pad)
        obj = json.loads(decoded)
        return isinstance(obj, dict) and "alg" in obj
    except Exception:
        return False


def _entropy_ok_for_hex(blob: str) -> bool:
    """Hex blobs that are all-zero, all-one-char, or sequential aren't credentials.
    Keeps "0000000000…" out of the credential bucket."""
    distinct = len(set(blob.lower()))
    return distinct >= 6


# ─── public API ───────────────────────────────────────────────────────────────
def find_matches(text: str) -> List[RedactionMatch]:
    """Run every pattern over `text` and return every non-overlapping match
    (longest-first preference handles overlapping types correctly)."""
    if not text:
        return []
    candidates: List[RedactionMatch] = []
    for tag, pat, weight in _PATTERNS:
        for m in pat.finditer(text):
            value = m.group(0)
            # Per-type sanity checks to suppress obvious false positives.
            if tag == "JWT" and not _is_valid_jwt(value):
                continue
            if tag in ("HEX_BLOB_LONG", "HEX_BLOB_MED") and not _entropy_ok_for_hex(value):
                continue
            if tag == "IPV4" and value in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
                continue
            candidates.append(RedactionMatch(
                type=tag, start=m.start(), end=m.end(),
                value=value, weight=weight,
            ))
    # Sort by start asc, length desc — longer matches at the same position win.
    candidates.sort(key=lambda c: (c.start, -(c.end - c.start)))
    # De-overlap: keep a match only if it doesn't sit inside an already-kept one.
    kept: List[RedactionMatch] = []
    last_end = -1
    for c in candidates:
        if c.start < last_end:
            continue
        kept.append(c)
        last_end = c.end
    return kept


def redact(text: str, min_confidence: float | None = None) -> RedactionResult:
    """Detect and rewrite sensitive substrings. Fail-closed: if the redactor's
    own confidence in completeness falls below `min_confidence`, the result
    is marked rejected and the caller MUST refuse to process the request."""
    threshold = (min_confidence if min_confidence is not None
                 else float(os.environ.get("REDACTION_MIN_CONFIDENCE") or 0.6))
    if not text:
        return RedactionResult(redacted="", confidence=1.0)

    matches = find_matches(text)
    by_type: Dict[str, int] = {}
    per_type_seq: Dict[str, int] = {}

    # Build the replacement in reverse so spans stay valid as we splice.
    out_parts: List[str] = []
    cursor = len(text)
    for m in reversed(matches):
        out_parts.append(text[m.end:cursor])
        per_type_seq[m.type] = per_type_seq.get(m.type, 0) + 1
        out_parts.append(f"{{{{REDACTED_{m.type}_{per_type_seq[m.type]}}}}}")
        cursor = m.start
        by_type[m.type] = by_type.get(m.type, 0) + 1
    out_parts.append(text[:cursor])
    redacted = "".join(reversed(out_parts))

    # Confidence model:
    #   * Start at 1.0.
    #   * Subtract a penalty when the input is long and we matched relatively
    #     few sensitive runs (probability we missed something rises with
    #     length without matches).
    #   * Subtract a penalty when many matches are low-weight types (IPs,
    #     emails) without any high-weight types — likely we caught noise but
    #     not the real secrets.
    text_len = max(1, len(text))
    match_density = sum(m.end - m.start for m in matches) / text_len
    high_weight = any(m.weight >= 0.9 for m in matches)

    confidence = 1.0
    if text_len > 4000 and match_density < 0.005:
        confidence -= 0.15
    if matches and not high_weight and match_density < 0.02:
        confidence -= 0.15
    # When the JWT or AWS-key regex matched but its sanity check stripped
    # everything, callers might still be at risk — but our matches list is
    # already filtered, so no penalty here.
    confidence = max(0.0, min(1.0, confidence))

    rejected = confidence < threshold
    return RedactionResult(
        redacted=redacted,
        matches=matches,
        by_type=by_type,
        confidence=confidence,
        rejected=rejected,
        reject_reason=(
            f"redactor confidence {confidence:.2f} below threshold {threshold:.2f}"
            if rejected else ""
        ),
    )
