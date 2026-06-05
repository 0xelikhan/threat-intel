"""
Multi-format obfuscation detector + safe deobfuscator.

Runs in triage every time we see a chunky text blob, so the deobfuscated
payload feeds the same IOC-extraction + behavioral-pattern pipeline as
the raw input. Catches the obfuscation tricks that show up in real
phishing emails, web shells, malware downloaders, and copy-pasted
attack scripts:

  Decoded server-side (pure Python string transforms, no eval):
    - Hex escape sequences        \\x41\\x42                  -> "AB"
    - Unicode escape sequences    \\u0041\\u0042              -> "AB"
    - Octal escape sequences      \\101\\102                  -> "AB"
    - HTML entities               &#65;&#x42;                 -> "AB"
    - URL percent-encoding        %41%42                      -> "AB"
    - String.fromCharCode chains  String.fromCharCode(65,66)  -> "AB"
    - Concatenation chains        "ab"+"cd"+"ef"              -> "abcdef"
    - Reversed strings            "CBA".reverse()             -> "ABC"
    - PowerShell -EncodedCommand  (base64 UTF-16LE)           -> plaintext
    - Generic base64 blocks       (printable-ascii filter)    -> plaintext
    - String.split(...).reverse().join("") tricks             -> rebuilt

  Detected only (need a JS engine to fully decode — we surface the
  detection so the analyst knows the payload is obfuscated and can
  paste it into a sandbox):
    - JSFuck                      "[][[]]+[+!![]]+..."  (chars: [ ] ( ) ! +)
    - AAEncode                    "ﾟωﾟﾉ= /｀ｍ´）ﾉ..."   (full-width katakana art)
    - JJEncode                    "$=~[];$={___:..."    (heavy $/_ tokens)

Public API:
  deobfuscate(text) -> {
    "detected": [{ "type": str, "confidence": float, "evidence": str }],
    "decoded":  [{ "type": str, "decoded": str, "preview": str }],
  }

  detect_obfuscation_types(text) -> [type, ...]   (cheap detect-only)

Never raises — invalid input returns {"detected": [], "decoded": []}.
Output is capped (decoded text truncated to 4 KB, max 8 decodes per
type) so a single huge alert can't blow up downstream pipelines.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import html
import re
import string
import urllib.parse
import zlib
from typing import Any, Callable, Dict, List, Optional, Tuple

# ─── Bounds ─────────────────────────────────────────────────────────────────
_MAX_DECODE_LEN  = 4_000
_MAX_HITS_PER_T  = 8
_MIN_RUN_LEN     = 12     # ignore tiny incidental matches


def _truncate(s: str, n: int = _MAX_DECODE_LEN) -> str:
    return s if len(s) <= n else s[:n] + "…[truncated]"


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if 0x20 <= ord(c) <= 0x7E or c in "\t\n\r")
    return ok / len(s)


# ─── 1. Hex escapes  \x41\x42  ──────────────────────────────────────────────
_HEX_ESC_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){" + str(_MIN_RUN_LEN // 4) + r",}")


def _decode_hex_escapes(text: str) -> List[str]:
    out = []
    for m in _HEX_ESC_RE.findall(text)[:_MAX_HITS_PER_T]:
        try:
            bytes_ = bytes.fromhex(m.replace("\\x", ""))
            s = bytes_.decode("utf-8", errors="replace")
        except (ValueError, binascii.Error):
            continue
        if _printable_ratio(s) > 0.85:
            out.append(_truncate(s))
    return out


# ─── 2. Unicode escapes  AB  ──────────────────────────────────────
_UNICODE_ESC_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){" + str(_MIN_RUN_LEN // 6) + r",}")


def _decode_unicode_escapes(text: str) -> List[str]:
    out = []
    for m in _UNICODE_ESC_RE.findall(text)[:_MAX_HITS_PER_T]:
        try:
            s = bytes(m, "ascii").decode("unicode-escape")
        except (UnicodeDecodeError, UnicodeEncodeError):
            continue
        if _printable_ratio(s) > 0.85:
            out.append(_truncate(s))
    return out


# ─── 3. Octal escapes  \101\102\103  ────────────────────────────────────────
_OCTAL_ESC_RE = re.compile(r"(?:\\[0-3][0-7]{2}){" + str(_MIN_RUN_LEN // 4) + r",}")


def _decode_octal_escapes(text: str) -> List[str]:
    out = []
    for m in _OCTAL_ESC_RE.findall(text)[:_MAX_HITS_PER_T]:
        try:
            s = bytes(m, "ascii").decode("unicode-escape")
        except (UnicodeDecodeError, UnicodeEncodeError):
            continue
        if _printable_ratio(s) > 0.85:
            out.append(_truncate(s))
    return out


# ─── 4. HTML entities  &#65;&#x42;  ─────────────────────────────────────────
_HTML_ENT_RE = re.compile(r"(?:&#x?[0-9a-fA-F]+;){" + str(_MIN_RUN_LEN // 5) + r",}")


def _decode_html_entities(text: str) -> List[str]:
    out = []
    for m in _HTML_ENT_RE.findall(text)[:_MAX_HITS_PER_T]:
        s = html.unescape(m)
        if s != m and _printable_ratio(s) > 0.85:
            out.append(_truncate(s))
    return out


# ─── 5. URL percent-encoding  %41%42  ───────────────────────────────────────
_URL_ENC_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){" + str(_MIN_RUN_LEN // 3) + r",}")


def _decode_url_encoding(text: str) -> List[str]:
    out = []
    for m in _URL_ENC_RE.findall(text)[:_MAX_HITS_PER_T]:
        try:
            s = urllib.parse.unquote(m, errors="replace")
        except Exception:
            continue
        if _printable_ratio(s) > 0.85:
            out.append(_truncate(s))
    return out


# ─── 6. String.fromCharCode(65,66,67)  ──────────────────────────────────────
_FROMCHARCODE_RE = re.compile(
    r"(?:String\.)?fromCharCode\s*\(\s*([\d,\s]+?)\s*\)",
    re.IGNORECASE,
)


def _decode_fromcharcode(text: str) -> List[str]:
    out = []
    for m in _FROMCHARCODE_RE.findall(text)[:_MAX_HITS_PER_T]:
        try:
            codes = [int(x.strip()) for x in m.split(",") if x.strip()]
            s = "".join(chr(c) for c in codes if 0 < c < 0x110000)
        except (ValueError, OverflowError):
            continue
        if s and _printable_ratio(s) > 0.85:
            out.append(_truncate(s))
    return out


# ─── 7. Concatenation chains  "ab"+"cd"+"ef"  ──────────────────────────────
# Match 3+ consecutive quoted string literals joined by + (with optional
# whitespace). Each literal kept short so we don't accidentally swallow
# whole code blocks.
_CONCAT_RE = re.compile(
    r"""(?:(["'])([^"'\\\n]{0,200})\1\s*\+\s*){2,}(["'])([^"'\\\n]{0,200})\3"""
)


def _decode_concat_chains(text: str) -> List[str]:
    """Walk forward through the text; whenever we see a run of quoted-string
    + quoted-string, glue them together. Returns the joined strings."""
    out: List[str] = []
    # Iterative scan: find longest concat run, extract pieces.
    pos = 0
    chunk_re = re.compile(r"""(["'])([^"'\\\n]{0,200})\1""")
    plus_re  = re.compile(r"\s*\+\s*")
    seen = 0
    while pos < len(text) and seen < _MAX_HITS_PER_T:
        m = chunk_re.search(text, pos)
        if not m:
            break
        pieces = [m.group(2)]
        cur = m.end()
        while True:
            pm = plus_re.match(text, cur)
            if not pm:
                break
            nm = chunk_re.match(text, pm.end())
            if not nm:
                break
            pieces.append(nm.group(2))
            cur = nm.end()
        if len(pieces) >= 3:
            joined = "".join(pieces)
            if len(joined) >= _MIN_RUN_LEN and _printable_ratio(joined) > 0.85:
                out.append(_truncate(joined))
                seen += 1
            pos = cur
        else:
            pos = m.end()
    return out


# ─── 8. Reversed strings  "CBA".split("").reverse().join("")  ──────────────
_REVERSE_RE = re.compile(
    r"""(["'])(.{8,400}?)\1\s*\.\s*split\s*\(\s*["']{2}\s*\)"""
    r"""\s*\.\s*reverse\s*\(\s*\)\s*\.\s*join\s*\(\s*["']{2}\s*\)""",
    re.IGNORECASE,
)


def _decode_reversed(text: str) -> List[str]:
    out = []
    for _, raw in _REVERSE_RE.findall(text)[:_MAX_HITS_PER_T]:
        s = raw[::-1]
        if _printable_ratio(s) > 0.85:
            out.append(_truncate(s))
    return out


# ─── 9. Generic base64  (long base64-looking runs, decoded if printable) ───
# Conservative regex: 16+ chars of the base64 alphabet, optional padding,
# bordered by non-base64-alphabet chars so we don't grab a slice from
# the middle of a longer alphanumeric token (file name, hash, ID).
# Minimum 16 because shorter runs are mostly false positives, but 16
# catches base64 of any plaintext from ~12 chars up (e.g. "this is a
# test" -> 20 chars, "Hello World" -> 16 chars). The decode is still
# gated on >0.90 printable-ASCII ratio so random alphanumeric runs that
# decode to binary garbage don't surface.
_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])")


def _decode_base64_generic(text: str) -> List[Tuple[str, str]]:
    """Returns (decoded_text, kind) where kind is 'base64-utf16le'
    (PowerShell EncodedCommand pattern) or 'base64-utf8'."""
    out = []
    for m in _BASE64_RE.findall(text)[:_MAX_HITS_PER_T]:
        pad = "=" * (-len(m) % 4)
        try:
            raw = base64.b64decode(m + pad, validate=True)
        except (ValueError, binascii.Error):
            continue
        for enc, kind in (("utf-16le", "base64-utf16le"),
                          ("utf-8",    "base64-utf8")):
            try:
                s = raw.decode(enc).strip()
            except (UnicodeDecodeError, ValueError):
                continue
            if len(s) >= 4 and _printable_ratio(s) > 0.90:
                out.append((_truncate(s), kind))
                break
    return out


# ─── 10. JSFuck — detect-only  (chars: [ ] ( ) ! +)  ────────────────────────
# Long runs (>= 80 chars) where the ratio of JSFuck chars is > 95%.
_JSFUCK_CHARSET = set("[]()!+")
_JSFUCK_MIN_LEN = 80


def _detect_jsfuck(text: str) -> Optional[Tuple[float, str]]:
    # Find the longest contiguous run of JSFuck-allowed chars (incl. whitespace).
    best_run = ""
    cur = []
    for ch in text:
        if ch in _JSFUCK_CHARSET or ch.isspace():
            cur.append(ch)
        else:
            run = "".join(cur).strip()
            if len(run) > len(best_run):
                best_run = run
            cur = []
    run = "".join(cur).strip()
    if len(run) > len(best_run):
        best_run = run
    if len(best_run) < _JSFUCK_MIN_LEN:
        return None
    # Ratio of JSFuck chars within the run (excluding whitespace)
    non_ws = [c for c in best_run if not c.isspace()]
    if not non_ws:
        return None
    ratio = sum(1 for c in non_ws if c in _JSFUCK_CHARSET) / len(non_ws)
    if ratio < 0.95:
        return None
    return ratio, best_run[:200]


# ─── 11. AAEncode — detect-only  (Japanese full-width emoji art)  ───────────
# Signature: heavy use of ｲｱｳ ﾟ ω ﾉ ｻ characters and the literal token
# "(ﾟДﾟ)" or "(ﾟｪﾟ=" near the start.
_AAENCODE_SIG = re.compile(
    r"(\(ﾟДﾟ\)|\(ﾟｪﾟ=|ﾟωﾟﾉ\s*=|ﾟΘﾟ\s*=|ﾟｰﾟ\s*=)"
)


def _detect_aaencode(text: str) -> Optional[Tuple[float, str]]:
    m = _AAENCODE_SIG.search(text)
    if not m:
        return None
    return 1.0, text[max(0, m.start() - 20):m.start() + 200]


# ─── 12. JJEncode — detect-only  (heavy $ / _ tokens)  ─────────────────────
# Signature: leading `$=~[];$={...}` boilerplate.
_JJENCODE_SIG = re.compile(r"\$\s*=\s*~\s*\[\s*\]\s*;\s*\$\s*=\s*\{")


def _detect_jjencode(text: str) -> Optional[Tuple[float, str]]:
    m = _JJENCODE_SIG.search(text)
    if not m:
        return None
    return 1.0, text[max(0, m.start() - 20):m.start() + 200]


# ─── public API ─────────────────────────────────────────────────────────────
def detect_obfuscation_types(text: str) -> List[str]:
    """Cheap detection-only pass — returns the obfuscation types present
    in the text without spending time decoding. Used by the orchestrator
    to tag alerts as 'obfuscated' for prioritisation."""
    if not text or not isinstance(text, str):
        return []
    out = []
    if _detect_jsfuck(text)         is not None: out.append("jsfuck")
    if _detect_aaencode(text)       is not None: out.append("aaencode")
    if _detect_jjencode(text)       is not None: out.append("jjencode")
    if _HEX_ESC_RE.search(text):      out.append("hex_escape")
    if _UNICODE_ESC_RE.search(text):  out.append("unicode_escape")
    if _OCTAL_ESC_RE.search(text):    out.append("octal_escape")
    if _HTML_ENT_RE.search(text):     out.append("html_entity")
    if _URL_ENC_RE.search(text):      out.append("url_encoding")
    if _FROMCHARCODE_RE.search(text): out.append("fromcharcode")
    if _REVERSE_RE.search(text):      out.append("string_reverse")
    if _BASE64_RE.search(text):       out.append("base64")
    return out


def deobfuscate(text: str) -> Dict[str, List[Dict[str, Any]]]:
    """Run every detector + decoder. Returns:
      detected: [{ type, confidence, evidence }]
      decoded:  [{ type, decoded, preview }]
    Never raises; degraded input -> empty result."""
    if not text or not isinstance(text, str):
        return {"detected": [], "decoded": []}

    detected: List[Dict[str, Any]] = []
    decoded:  List[Dict[str, Any]] = []

    def _push_decoded(kind: str, items: List[str]) -> None:
        for s in items:
            decoded.append({
                "type":    kind,
                "decoded": s,
                "preview": s[:160],
            })

    # Decoders (each is a safe string transform — no eval)
    _push_decoded("hex_escape",      _decode_hex_escapes(text))
    _push_decoded("unicode_escape",  _decode_unicode_escapes(text))
    _push_decoded("octal_escape",    _decode_octal_escapes(text))
    _push_decoded("html_entity",     _decode_html_entities(text))
    _push_decoded("url_encoding",    _decode_url_encoding(text))
    _push_decoded("fromcharcode",    _decode_fromcharcode(text))
    _push_decoded("string_concat",   _decode_concat_chains(text))
    _push_decoded("string_reverse",  _decode_reversed(text))
    for s, kind in _decode_base64_generic(text):
        decoded.append({"type": kind, "decoded": s, "preview": s[:160]})

    # Detect-only (need a JS engine to fully decode)
    jsf = _detect_jsfuck(text)
    if jsf:
        ratio, snip = jsf
        detected.append({
            "type":       "jsfuck",
            "confidence": round(ratio, 2),
            "evidence":   snip,
            "note":       ("JSFuck-encoded JavaScript detected. Full decode "
                           "requires a sandboxed JS engine; paste the run "
                           "into a quarantined VM or jsfuck.com for the "
                           "plaintext payload."),
        })
    aae = _detect_aaencode(text)
    if aae:
        detected.append({
            "type":       "aaencode",
            "confidence": aae[0],
            "evidence":   aae[1],
            "note":       ("AAEncode-encoded JavaScript detected (Japanese "
                           "full-width-katakana obfuscation). Eval in a "
                           "sandbox for plaintext."),
        })
    jje = _detect_jjencode(text)
    if jje:
        detected.append({
            "type":       "jjencode",
            "confidence": jje[0],
            "evidence":   jje[1],
            "note":       ("JJEncode-encoded JavaScript detected ($/_/~ "
                           "boilerplate). Eval in a sandbox for plaintext."),
        })

    # ── CyberChef-Magic-style recursive decode ────────────────────────────
    # Try every whole-input decoder, score each candidate, recurse on the
    # winner. Catches multi-layer encodings the single-pass decoders
    # above miss (base64 of XOR of gzip, hex of base64, etc.).
    try:
        magic = magic_decode(text)
        if magic.get("improved") and magic.get("chain"):
            detected.append({
                "type":       "magic_chain",
                "confidence": round(magic["final_score"], 2),
                "evidence":   " -> ".join(s["op"] for s in magic["chain"]),
                "note":       (f"Recursive auto-decode succeeded via "
                              f"{len(magic['chain'])} step(s). Score climbed "
                              f"{round(magic['input_score'], 2)} -> "
                              f"{round(magic['final_score'], 2)}."),
            })
            decoded.append({
                "type":    "magic_decode",
                "decoded": magic["final_output"],
                "preview": magic["final_output"][:160],
                "chain":   [s["op"] for s in magic["chain"]],
            })
    except Exception:
        pass

    return {"detected": detected, "decoded": decoded}


# ────────────────────────────────────────────────────────────────────────────
# CyberChef "Magic" — recursive auto-decoder
#
# Idea: try each whole-input decoder, score the result on a
# "how decoded does this look?" metric, pick the winner, recurse. Stop
# when no operation improves the score or we hit the depth cap.
#
# Scoring is a weighted combination of:
#   - printable-ASCII ratio (higher = more text-like)
#   - English n-gram / common-word bonus (recognisable English wins)
#   - length sanity (very short outputs are usually decode artefacts)
#   - entropy (lower entropy on the decoded side beats high-entropy
#     ciphertext / random bytes)
# ────────────────────────────────────────────────────────────────────────────

# Common short English words — cheap dictionary check. Designed to flag
# typical analyst-relevant decoded content: HTTP / cmd / config / log
# fragments. Not meant as a full English detector.
_ENGLISH_HINTS = frozenset((
    "the", "and", "for", "you", "are", "from", "with", "that", "this",
    "have", "not", "your", "http", "https", "www", "com", "net", "org",
    "powershell", "cmd", "exe", "dll", "system", "user", "admin", "root",
    "windows", "linux", "macos", "file", "path", "data", "json", "html",
    "script", "function", "return", "error", "true", "false", "null",
    "select", "from", "where", "insert", "update", "delete",
    "get", "post", "host", "port", "host:", "content-type",
))


def _shannon(bts: bytes) -> float:
    """Shannon entropy in bits/byte — quick proxy for 'is this random?'.
    English text is ~4.2, base64 is ~5.5-6, random bytes ~8."""
    if not bts:
        return 0.0
    from collections import Counter
    n = len(bts)
    freq = Counter(bts)
    import math
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _decode_score(s: str) -> float:
    """Combine printable ratio + English-word density + low-cardinality
    penalty into a single 0-100ish score. Higher = more 'decoded'.
    Returns 0 on pathological / very short inputs.

    Weighting notes — every other ranking we tried failed on this case:
      base64( hex( english ) )
    All three layers are 100%-printable ASCII so a printable-only
    scorer can't tell them apart. Entropy alone mis-rewards hex strings
    (16 unique chars = lower entropy than English's 50+, which the
    naive 'lower entropy is better' bonus would call MORE text-like).
    The only signal that cleanly orders these three layers in the right
    direction is recognised-word density — so it dominates the score.
    """
    if not s or len(s) < 4:
        return 0.0
    pr = _printable_ratio(s)
    # Cheap English-word density — the dominant signal of 'decoded'.
    toks = re.findall(r"[A-Za-z]{3,}", s.lower())
    if toks:
        hits = sum(1 for t in toks if t in _ENGLISH_HINTS)
        eng_ratio = hits / max(1, len(toks))
    else:
        eng_ratio = 0.0
    # Cardinality bonus — strings with too FEW unique chars (hex / base32)
    # are still partially-encoded, even if printable. Penalise narrow
    # alphabets so unwrapping hex of a base64 of a string outscores the
    # intermediate hex layer.
    uniq = len(set(s.lower()))
    # English uses ~50-70 unique chars in mixed-case prose; hex uses
    # 16-22, base64 uses ~65. Reward ranges that look like prose.
    if uniq < 20:
        cardinality_bonus = 0.0
    elif uniq < 40:
        cardinality_bonus = 0.4
    else:
        cardinality_bonus = 1.0
    length_bonus = min(1.0, len(s) / 200.0)
    # English density dominates; cardinality serves as the tiebreaker
    # for "all chars printable, no recognised words" cases.
    return (pr * 15.0
            + eng_ratio * 60.0
            + cardinality_bonus * 20.0
            + length_bonus * 5.0)


# ─── Whole-input decoders for Magic ─────────────────────────────────────────
# Each takes a string, returns the decoded string, or None when the input
# clearly isn't in that format (cheap pre-check before the expensive
# try / except). Magic calls each in turn and keeps the best.
def _magic_base64(s: str) -> Optional[str]:
    s = s.strip()
    # Cheap shape check: base64 alphabet + padding only.
    if not s or not re.fullmatch(r"[A-Za-z0-9+/=\s]+", s):
        return None
    s_clean = re.sub(r"\s+", "", s)
    pad = "=" * (-len(s_clean) % 4)
    try:
        raw = base64.b64decode(s_clean + pad, validate=False)
        for enc in ("utf-8", "utf-16le", "latin-1"):
            try:
                return raw.decode(enc).strip()
            except UnicodeDecodeError:
                continue
    except (binascii.Error, ValueError):
        return None
    return None


def _magic_base32(s: str) -> Optional[str]:
    s = s.strip()
    if not s or not re.fullmatch(r"[A-Z2-7=\s]+", s):
        return None
    s_clean = re.sub(r"\s+", "", s)
    pad = "=" * (-len(s_clean) % 8)
    try:
        raw = base64.b32decode(s_clean + pad, casefold=True)
        return raw.decode("utf-8", errors="replace").strip()
    except (binascii.Error, ValueError):
        return None


def _magic_base85(s: str) -> Optional[str]:
    s = s.strip()
    if not s or len(s) < 12:
        return None
    try:
        raw = base64.b85decode(s)
        return raw.decode("utf-8", errors="replace").strip()
    except (binascii.Error, ValueError):
        return None


def _magic_hex(s: str) -> Optional[str]:
    s = re.sub(r"\s+", "", s.strip())
    # Continuous hex string, even-length, no other chars.
    if len(s) < 8 or len(s) % 2 != 0:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]+", s):
        return None
    try:
        raw = bytes.fromhex(s)
        return raw.decode("utf-8", errors="replace").strip()
    except (ValueError, binascii.Error):
        return None


def _magic_rot13(s: str) -> Optional[str]:
    return codecs.decode(s, "rot_13") if s else None


def _magic_rot47(s: str) -> Optional[str]:
    """ROT47 — same idea as ROT13 but operates on the full printable
    ASCII range 33-126. Common in CTF challenges + occasional malware."""
    if not s:
        return None
    out = []
    for ch in s:
        c = ord(ch)
        if 33 <= c <= 126:
            out.append(chr(33 + ((c - 33 + 47) % 94)))
        else:
            out.append(ch)
    return "".join(out)


def _magic_reverse(s: str) -> Optional[str]:
    return s[::-1] if s else None


def _magic_gzip(s: str) -> Optional[str]:
    """Try gzip-decompress the input as bytes. Useful when an attacker
    base64-encoded gzip output — Magic catches it after the base64 step
    succeeds and recurses."""
    if not s:
        return None
    try:
        raw = s.encode("latin-1")
        out = gzip.decompress(raw)
        return out.decode("utf-8", errors="replace")
    except (OSError, EOFError, UnicodeDecodeError, ValueError):
        return None


def _magic_zlib(s: str) -> Optional[str]:
    if not s:
        return None
    try:
        raw = s.encode("latin-1")
        out = zlib.decompress(raw)
        return out.decode("utf-8", errors="replace")
    except (zlib.error, UnicodeDecodeError, ValueError):
        return None


def _magic_url(s: str) -> Optional[str]:
    if not s or "%" not in s:
        return None
    try:
        out = urllib.parse.unquote(s, errors="replace")
        return out if out != s else None
    except Exception:
        return None


def _magic_html(s: str) -> Optional[str]:
    if not s or "&" not in s:
        return None
    out = html.unescape(s)
    return out if out != s else None


def _magic_xor_brute(s: str) -> Optional[str]:
    """Single-byte XOR brute. Tries every key 1-255, picks the BEST
    scoring candidate (not the first over a threshold — the order-
    dependent variant could return a mediocre key when a stronger one
    came later in the loop). Common in droppers + simple loaders
    ("XOR with key 0x37")."""
    if not s or len(s) < 8:
        return None
    try:
        raw = s.encode("latin-1")
    except UnicodeEncodeError:
        return None
    baseline = _decode_score(s)
    best_score = baseline
    best_out:  Optional[str] = None
    for key in range(1, 256):
        try:
            cand = bytes(b ^ key for b in raw).decode("utf-8", errors="replace")
        except Exception:
            continue
        sc = _decode_score(cand)
        if sc > best_score:   # any improvement wins; final threshold below
            best_score = sc
            best_out   = cand
    # Require meaningful improvement over the input before claiming a
    # successful brute. Otherwise we'd return noise on plain text.
    if best_out and best_score > baseline + 5:
        return best_out
    return None


# Registry — order matters only for tie-breaks (we pick the best
# scorer each round, but if two ops score identically we prefer the
# earlier entry, which is the more common one in real payloads).
_MAGIC_OPS: List[Tuple[str, Callable[[str], Optional[str]]]] = [
    ("base64",   _magic_base64),
    ("hex",      _magic_hex),
    ("url",      _magic_url),
    ("html",     _magic_html),
    ("rot13",    _magic_rot13),
    ("rot47",    _magic_rot47),
    ("reverse",  _magic_reverse),
    ("base32",   _magic_base32),
    ("base85",   _magic_base85),
    ("gzip",     _magic_gzip),
    ("zlib",     _magic_zlib),
    ("xor_brute", _magic_xor_brute),
]


def _best_one_step_score(text: str) -> float:
    """Single-step lookahead: best score achievable by applying any
    single operation to `text`, OR the score of `text` itself if no
    operation improves it. Used by magic_decode to evaluate candidate
    branches one level deeper — fixes the bug where multi-layer
    chains (base64 of hex of english) stop early because the
    intermediate layer scores below the input."""
    base = _decode_score(text)
    best = base
    for _, fn in _MAGIC_OPS:
        try:
            r = fn(text)
        except Exception:
            continue
        if not r or r == text:
            continue
        s = _decode_score(r)
        if s > best:
            best = s
    return best


def magic_decode(text: str, max_depth: int = 4,
                  min_improvement: float = 8.0) -> Dict[str, Any]:
    """Recursive auto-decoder with 1-step lookahead. Apply each
    operation, score the result AND the best score reachable one more
    step deeper, pick the branch whose lookahead score wins, recurse on
    it. Stops when no operation improves the lookahead score by
    `min_improvement` or after `max_depth` rounds.

    Lookahead is what makes multi-layer encodings work: a hex layer
    sandwiched between base64 and english scores below both — but
    looking one step ahead reveals that decoding the hex produces a
    very-high-scoring english string, so the algorithm correctly
    descends through it.

    Returns:
      {
        "input_score":  initial score,
        "final_score":  best achieved score,
        "final_output": best decoded text (truncated to 4KB),
        "chain": [{"op": str, "score": float, "preview": str}, ...],
        "improved": bool — True iff final_score > input_score + threshold
      }
    """
    if not text or not isinstance(text, str):
        return {"input_score": 0.0, "final_score": 0.0,
                "final_output": "", "chain": [], "improved": False}

    work = text[:8000]
    input_score   = _decode_score(work)
    current       = work
    current_score = input_score
    chain: List[Dict[str, Any]] = []

    for _ in range(max_depth):
        best_op:    Optional[str] = None
        best_out:   Optional[str] = None
        best_lookahead = current_score
        best_immediate = current_score
        for op_name, fn in _MAGIC_OPS:
            try:
                result = fn(current)
            except Exception:
                continue
            if not result or result == current:
                continue
            la_score = _best_one_step_score(result)
            if la_score > best_lookahead + min_improvement:
                best_op, best_out, best_lookahead = op_name, result, la_score
                best_immediate = _decode_score(result)
        if best_op is None or best_out is None:
            break
        chain.append({
            "op":      best_op,
            "score":   round(best_immediate, 2),
            "preview": best_out[:160],
        })
        current       = best_out
        current_score = best_immediate

    return {
        "input_score":  round(input_score, 2),
        "final_score":  round(current_score, 2),
        "final_output": _truncate(current),
        "chain":        chain,
        "improved":     current_score > input_score + min_improvement,
    }
