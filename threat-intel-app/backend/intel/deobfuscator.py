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
import html
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

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
# Be conservative: only flag long runs with proper alphabet, then decode
# only if result is mostly-printable text in UTF-8 or UTF-16LE.
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")


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

    return {"detected": detected, "decoded": decoded}
