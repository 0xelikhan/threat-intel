"""
File-analysis engine — spec §1-6 from the all-in-one scanner plan.

Entry point: analyze_file(file_bytes, filename) → comprehensive analysis dict.

Order of operations:
  1. True file-type detection via python-magic (vs. claimed extension)
  2. Every hash (md5, sha1, sha256, sha512, ssdeep when available, tlsh when avail)
  3. Overall entropy (0-8) and per-window entropy for visualization
  4. Printable + UTF-16LE string extraction (min length 6)
  5. IOC extraction from strings (IPs, domains, URLs, hashes, emails, paths)
     + recursive base64 / hex decoding pass
  6. Format-specific deep analysis (delegated to format_*.py modules)
  7. MITRE behavioral mapping (delegated to mitre_capability_map)
  8. YARA scanning (delegated to intel.yara_scanner)
  9. Threat-intel correlation (caller wires this — needs aiohttp session + keys)

All sub-analyses are optional and best-effort: a missing dependency yields a
graceful empty section, never a hard failure.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional


# ─── magic-byte / extension type detection ─────────────────────────────────────
_EXTENSION_TYPE_HINTS = {
    "exe": "application/x-msdownload",
    "dll": "application/x-msdownload",
    "sys": "application/x-msdownload",
    "scr": "application/x-msdownload",
    "com": "application/x-msdownload",
    "doc": "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xls": "application/vnd.ms-excel",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "ppt": "application/vnd.ms-powerpoint",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "rtf": "application/rtf",
    "pdf": "application/pdf",
    "zip": "application/zip",
    "jar": "application/java-archive",
    "7z": "application/x-7z-compressed",
    "rar": "application/x-rar",
    "iso": "application/x-iso9660-image",
    "img": "application/octet-stream",
    "vhd": "application/octet-stream",
    "ps1": "text/x-powershell",
    "vbs": "text/x-vbs",
    "js":  "application/javascript",
    "bat": "text/x-bat",
    "cmd": "text/x-bat",
    "py":  "text/x-python",
    "sh":  "text/x-shellscript",
    "eml": "message/rfc822",
    # Source-code extensions — analysts upload these when triaging
    # commodity loaders / red-team samples / GitHub-borrowed snippets.
    # The bytes are plain ASCII with no PE header, so analysis switches
    # to source-mode patterns instead of PE-import predicates.
    "nim":  "text/x-nim",
    "c":    "text/x-csrc",
    "cpp":  "text/x-c++src",
    "cc":   "text/x-c++src",
    "cs":   "text/x-csharp",
    "go":   "text/x-go",
    "rs":   "text/x-rust",
    "asm":  "text/x-asm",
    "java": "text/x-java",
    "rb":   "text/x-ruby",
    "pl":   "text/x-perl",
    "lua":  "text/x-lua",
    "psm1": "text/x-powershell",
    "psd1": "text/x-powershell",
    "hta":  "application/hta",
    "wsf":  "text/x-vbs",
    "jse":  "application/javascript",
    "vbe":  "text/x-vbs",
}


# Map source-code extension to a human-readable language label. Drives the
# `file_type` source-code banner the frontend renders so analysts know
# they're looking at static *code* analysis, not PE byte analysis.
_SOURCE_LANG_BY_EXT = {
    "nim":  "Nim",
    "c":    "C",
    "cpp":  "C++",
    "cc":   "C++",
    "cs":   "C#",
    "go":   "Go",
    "rs":   "Rust",
    "asm":  "Assembly",
    "java": "Java",
    "rb":   "Ruby",
    "pl":   "Perl",
    "lua":  "Lua",
    "py":   "Python",
    "ps1":  "PowerShell",
    "psm1": "PowerShell",
    "psd1": "PowerShell",
    "vbs":  "VBScript",
    "vbe":  "VBScript",
    "wsf":  "Windows Script",
    "js":   "JavaScript",
    "jse":  "JavaScript",
    "bat":  "Batch",
    "cmd":  "Batch",
    "sh":   "Shell",
    "hta":  "HTML Application",
}


def _detect_type(file_bytes: bytes, filename: str) -> Dict:
    """Returns {detected, claimed, mismatch, summary}."""
    claimed_ext = (filename.rsplit(".", 1)[-1] if "." in filename else "").lower()
    claimed = _EXTENSION_TYPE_HINTS.get(claimed_ext, "unknown")
    try:
        import magic
        try:
            mime = magic.from_buffer(file_bytes, mime=True)
        except Exception:
            mime = "application/octet-stream"
        try:
            desc = magic.from_buffer(file_bytes)
        except Exception:
            desc = ""
    except Exception:
        mime = _fallback_magic(file_bytes)
        desc = ""
    mismatch = bool(claimed != "unknown" and not _types_compatible(mime, claimed))
    is_source, lang = _detect_source_code(file_bytes, claimed_ext, mime)
    return {
        "detected_mime":   mime,
        "detected_desc":   desc[:240] if desc else None,
        "claimed_ext":     claimed_ext,
        "claimed_mime":    claimed,
        "mismatch":        mismatch,
        "mismatch_summary": (
            f"File claims .{claimed_ext} ({claimed}) but bytes detect as {mime}. "
            "Common malware tactic — verify the file before trusting it."
            if mismatch else None
        ),
        "category":        _category_from_mime(mime, claimed_ext),
        "is_source_code":  is_source,
        "source_language": lang,
    }


def _detect_source_code(file_bytes: bytes, claimed_ext: str, mime: str) -> Tuple[bool, str]:
    """Source-code detection. Two signals, either is sufficient:

      1. Claimed extension is in `_SOURCE_LANG_BY_EXT` — analyst literally
         told us this is `foo.nim`.
      2. The bytes start with neither MZ/ELF/PK/PDF/OLE/RAR/7z/gzip nor any
         other recognised binary magic AND >95% of the head is printable
         ASCII or common whitespace. Catches `.txt`-renamed or extensionless
         source dumps.

    Returns (is_source_code, language_label). Language label falls back to
    "Source Code" when we can detect source-ness without knowing the
    specific language."""
    if claimed_ext in _SOURCE_LANG_BY_EXT:
        return True, _SOURCE_LANG_BY_EXT[claimed_ext]

    # Negative path: an extension recognised as a NON-source type (eml /
    # pdf / docx / exe / zip / ...) should never fall through to the
    # printable-ASCII heuristic. EML files in particular are plain ASCII
    # (RFC822 headers + body) so the ratio check trivially classifies them
    # as "Source Code" and they then bypass the format-specific path that
    # would have parsed SPF / DKIM / DMARC, sender chain, attachments, etc.
    # Found live: a phishing-shaped .eml that scored SUSPICIOUS but lost
    # all the email format_specific analysis because of this.
    if claimed_ext and claimed_ext in _EXTENSION_TYPE_HINTS:
        return False, ""

    if not file_bytes:
        return False, ""
    head = file_bytes[:16]
    # Any of these magic prefixes → binary file, not source.
    binary_magics = (b"MZ", b"\x7fELF", b"PK\x03\x04", b"%PDF-",
                     b"\xD0\xCF\x11\xE0", b"Rar!", b"7z\xBC\xAF\x27\x1C",
                     b"\x1F\x8B", b"\xFF\xD8\xFF", b"\x89PNG", b"GIF8",
                     b"BM")
    if any(head.startswith(m) for m in binary_magics):
        return False, ""

    # Email-header sniff for extensionless inputs. RFC822 messages start
    # with one or more `Header-Name: value` lines — if the first 200
    # bytes look like that AND contain at least one canonical email header
    # (From / Subject / To / Date / Received / Return-Path), this is mail,
    # not source. Same downstream concern as the EML-extension path above.
    head200 = file_bytes[:200]
    try:
        h_text = head200.decode("ascii", errors="ignore")
        first_lines = h_text.splitlines()[:5]
        looks_like_headers = bool(first_lines and all(
            ":" in line and not line.startswith(" ")
            for line in first_lines if line.strip()
        ))
        if looks_like_headers and any(
            line.split(":", 1)[0].strip().lower() in (
                "from", "to", "subject", "date", "received", "return-path",
                "message-id", "authentication-results", "delivered-to",
            )
            for line in first_lines if line.strip()
        ):
            return False, ""
    except Exception:
        pass

    # Score the first 4 KiB on printable-ASCII ratio.
    sample = file_bytes[:4096]
    printable = sum(1 for b in sample
                    if (0x20 <= b <= 0x7E) or b in (0x09, 0x0A, 0x0D))
    if not sample:
        return False, ""
    ratio = printable / len(sample)
    if ratio >= 0.95:
        # Mime hints help refine the language when extension is missing.
        if "powershell" in (mime or ""):
            return True, "PowerShell"
        if "python" in (mime or ""):
            return True, "Python"
        if (mime or "").startswith("text/x-"):
            return True, (mime.split("text/x-", 1)[-1].title() or "Source Code")
        return True, "Source Code"
    return False, ""


_EQUIVALENT_MIMES = [
    {"application/x-msdownload", "application/x-dosexec", "application/x-mach-binary"},
    {"application/x-elf", "application/x-executable"},
    {"application/zip", "application/java-archive"},
]


def _types_compatible(detected: str, claimed: str) -> bool:
    if detected == claimed:
        return True
    # Mime equivalence classes (e.g. x-msdownload == x-dosexec)
    for grp in _EQUIVALENT_MIMES:
        if detected in grp and claimed in grp:
            return True
    # Office formats are .zip under the hood
    if claimed.startswith("application/vnd.openxmlformats") and detected == "application/zip":
        return True
    if detected == "application/msword" and claimed.startswith("application/vnd.openxmlformats"):
        return True
    # Text variants
    if detected.startswith("text/") and claimed.startswith("text/"):
        return True
    return False


def _fallback_magic(b: bytes) -> str:
    """Cheap header-based detection if python-magic isn't available."""
    if not b: return "application/octet-stream"
    head = b[:16]
    if head.startswith(b"MZ"): return "application/x-msdownload"
    if head.startswith(b"\x7fELF"): return "application/x-elf"
    if head.startswith(b"PK\x03\x04"): return "application/zip"
    if head.startswith(b"%PDF-"): return "application/pdf"
    if head.startswith(b"\xD0\xCF\x11\xE0"): return "application/x-ole"
    if head.startswith(b"{\\rtf"): return "application/rtf"
    if head.startswith(b"Rar!"): return "application/x-rar"
    if head.startswith(b"7z\xBC\xAF\x27\x1C"): return "application/x-7z-compressed"
    if head.startswith(b"\x1F\x8B"): return "application/gzip"
    try:
        head.decode("utf-8")
        return "text/plain"
    except UnicodeDecodeError:
        return "application/octet-stream"


def _category_from_mime(mime: str, ext: str) -> str:
    if "msdownload" in mime or "x-dosexec" in mime or "x-elf" in mime:
        return "executable"
    if "officedocument" in mime or "msword" in mime or "ms-excel" in mime \
       or "ms-powerpoint" in mime or "x-ole" in mime or "rtf" in mime \
       or ext in {"doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf"}:
        return "office_document"
    if "pdf" in mime: return "pdf"
    if "zip" in mime or "x-7z" in mime or "x-rar" in mime or "jar" in mime: return "archive"
    if "x-iso" in mime or ext in {"iso", "img", "vhd"}: return "disk_image"
    # RFC822 email: detected by either the MIME (`message/rfc822` is what
    # python-magic returns for a real EML) or the `.eml` extension. The
    # file_analyzer_formats dispatcher doesn't have an EML branch yet, so
    # for the moment this just stops the EML from being misrouted as
    # `binary` (which produced empty format_specific) or — after my
    # fall-through ASCII heuristic — as `source_code` (which double-
    # labelled and bypassed the IOC-extraction-on-headers path). Once a
    # dedicated EML analyzer lands it'll hook on `email`.
    if "rfc822" in mime or ext == "eml":
        return "email"
    if mime.startswith("text/") or ext in {"ps1","vbs","js","bat","cmd","py","sh"}: return "script_or_text"
    return "binary"


# ─── hashes (always present) ───────────────────────────────────────────────────
def _all_hashes(b: bytes) -> Dict:
    out = {
        "md5":    hashlib.md5(b).hexdigest(),
        "sha1":   hashlib.sha1(b).hexdigest(),
        "sha256": hashlib.sha256(b).hexdigest(),
        "sha512": hashlib.sha512(b).hexdigest(),
    }
    # TLSH (cross-platform fuzzy hash) — gracefully skip if not installed
    try:
        import tlsh
        h = tlsh.hash(b)
        if h and h != "TNULL":
            out["tlsh"] = h
    except Exception:
        out["tlsh"] = None
    # ssdeep — also optional (Windows wheels are flaky)
    try:
        import ssdeep
        out["ssdeep"] = ssdeep.hash(b)
    except Exception:
        out["ssdeep"] = None
    return out


# ─── entropy ───────────────────────────────────────────────────────────────────
def _shannon_entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = Counter(b)
    length = len(b)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _entropy_analysis(b: bytes, window: int = 4096) -> Dict:
    if not b:
        return {"overall": 0.0, "band": "empty", "windows": [], "flag": None}
    overall = _shannon_entropy(b)
    band, flag = _entropy_band(overall)
    # Per-window for visualization — cap at 256 windows for big files
    step = max(window, len(b) // 256 if len(b) > window * 256 else window)
    windows = []
    for off in range(0, len(b), step):
        chunk = b[off:off + step]
        if chunk:
            windows.append({"offset": off, "entropy": round(_shannon_entropy(chunk), 3)})
    return {
        "overall": round(overall, 3),
        "band":    band,
        "flag":    flag,
        "windows": windows[:256],
    }


def _entropy_band(e: float) -> Tuple[str, Optional[str]]:
    if e < 5.0:   return "normal_text_or_code", None
    if e < 6.5:   return "mixed_or_compressed", None
    if e < 7.5:   return "likely_compressed_or_encrypted", "elevated_entropy"
    return "almost_certainly_packed_or_encrypted", "high_entropy_packed"


# ─── strings ───────────────────────────────────────────────────────────────────
_PRINTABLE = set(range(0x20, 0x7F))
# Cache compiled extractors per min_len. Matching with a C-level regex over the
# raw bytes is orders of magnitude faster than a Python byte-by-byte loop — the
# difference is seconds on a 50 MB sample. Output is identical: runs of printable
# ASCII (≥ min_len), and UTF-16LE runs (printable byte followed by a NUL).
_STRING_RES: Dict[int, Tuple] = {}


def _string_extractors(min_len: int):
    res = _STRING_RES.get(min_len)
    if res is None:
        ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
        utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
        res = (ascii_re, utf16_re)
        _STRING_RES[min_len] = res
    return res


def _extract_strings(b: bytes, min_len: int = 6) -> Dict:
    """Returns {ascii, unicode, total} — capped lists."""
    ascii_re, utf16_re = _string_extractors(min_len)

    ascii_matches = ascii_re.findall(b)
    utf16_matches = utf16_re.findall(b)

    # Decode only the strings we actually keep (after the cap), not every match.
    ascii_hits = [m.decode("ascii", "replace") for m in ascii_matches[:3000]]
    # UTF-16LE match is interleaved with NUL bytes — take every other byte.
    uni_hits = [m[::2].decode("ascii", "replace") for m in utf16_matches[:1500]]

    return {
        "ascii":   ascii_hits,
        "unicode": uni_hits,
        "total":   len(ascii_matches) + len(utf16_matches),
    }


# ─── IOC extraction from strings (with base64/hex decode recursion) ────────────
_RE_IP     = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")
# URL regex: scheme + RFC 3986 unreserved + sub-delims + reserved character
# set. The earlier `[^\s'\"<>]` was too permissive — on a PE binary it
# extracted URLs like `http://ocsp.digicert.com0A` / `0C` / `0X` because the
# DER-encoded ASN.1 length+tag bytes immediately following the OCSP URL
# happen to be printable ASCII characters that pass `[^\s'\"<>]`. Restrict
# to characters that RFC 3986 actually allows in URIs (still post-validated
# by _is_valid_url_netloc to drop trailing junk that slipped through).
_RE_URL    = re.compile(
    r"\bhttps?://[a-zA-Z0-9._~:/?#\[\]@!$&()*+,;=%-]{4,500}",
    re.IGNORECASE,
)
_RE_HASH64 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_HASH40 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_HASH32 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_EMAIL  = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_RE_PATH   = re.compile(r"(?:[a-zA-Z]:\\|\\\\|/usr/|/etc/|/var/|/home/|%APPDATA%|%TEMP%|%PROGRAMDATA%)[^\s'\"<>]{2,200}")
_RE_B64    = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
_RE_HEX    = re.compile(r"\b(?:[0-9a-fA-F]{2}){16,}\b")

# Noise patterns that flood IOC extraction from binaries — drop these
_IOC_NOISE_DOMAINS = {
    "microsoft.com", "windows.com", "schemas.microsoft.com",
    "schemas.openxmlformats.org", "schemas.xmlsoap.org", "w3.org",
    "example.com", "github.com",
}

# Filename extensions the domain regex catches as `something.exe` etc. — never
# real domains, almost always library / executable references.
_NON_DOMAIN_TLDS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "py", "sh", "pdb",
    "txt", "log", "tmp", "ini", "cfg", "xml", "json", "yaml", "yml",
    "lnk", "scr", "com", "drv", "ocx", "cpl", "msi",
}


def _is_noise_domain(d: str) -> bool:
    d = d.lower()
    # filename-shaped — last segment is an executable / library extension
    tld = d.rsplit(".", 1)[-1] if "." in d else ""
    if tld in _NON_DOMAIN_TLDS:
        return True
    if d in _IOC_NOISE_DOMAINS:
        return True
    for nd in _IOC_NOISE_DOMAINS:
        if d.endswith("." + nd):
            return True
    return False


def _is_version_shaped_ip(ip: str) -> bool:
    """True for dotted-quads that look like Windows / .NET version strings
    rather than IPs. PE binaries are loaded with these — `6.0.0.0`,
    `10.0.19041.0`, `5.1.2600.0`, `4.0.30319.0`, `1.0.0.0` — and the
    existing prefix filter (`0.`, `127.`, `169.254.`) doesn't catch them.

    Two heuristics:
      1. Trailing `.0` AND middle `.0.` — `X.0.Y.0` is overwhelmingly a
         build-number, not a host. Catches 6.0.0.0, 5.0.0.0, 1.0.0.0.
      2. Any octet > 255 — guaranteed not an IPv4 address. Catches the
         four-part Defender signature versions like 1.451.195.0 that
         iocextract / iocextract-style scans pick up. Same protection
         the triage agent's _valid_ipv4_octets already enforces.
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return True
    if any(o > 255 for o in octets):
        return True
    # X.0.Y.0 pattern — overwhelmingly version-shaped on PE binaries
    if octets[1] == 0 and octets[3] == 0:
        return True
    return False


def _is_valid_url_netloc(url: str) -> bool:
    """Strip trailing junk that slipped past the (now tighter) URL regex.

    PE binaries embed OCSP URLs immediately followed by DER ASN.1 length
    + tag bytes that often spell printable ASCII — extracting
    `http://ocsp.digicert.com0A` from a binary where the next bytes are
    `0x30 0x0A` for example. Even with the regex tightened, URLs ending
    in junk-suffix that doesn't fit URL grammar are almost certainly
    that pattern.

    Two valid netloc shapes:
      * FQDN with alphabetic TLD (2-24 chars). Catches the DER junk
        because the trailing `0A` / `0C` / `0X` makes the TLD non-alpha.
      * Raw IP address (v4 or v6). Common for lab / pentest / C2 URLs;
        the Nim shellcode loader fixture in the source-code-analysis
        test uses `http://192.168.174.128:4443/...` and must pass.
    """
    try:
        from urllib.parse import urlparse
        import ipaddress
        p = urlparse(url)
        host = (p.hostname or "")
        if not host:
            return False
        # IP-host case: parse via stdlib; raises on garbage.
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            pass
        # FQDN case: TLD must be alphabetic + sane length.
        labels = host.split(".")
        if len(labels) < 2:
            return False
        tld = labels[-1]
        if not tld.isalpha() or not (2 <= len(tld) <= 24):
            return False
        return True
    except Exception:
        return False


def _extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    return {
        "ips":     sorted({m for m in _RE_IP.findall(text)
                            if not m.startswith(("0.", "127.", "169.254."))
                            and not _is_version_shaped_ip(m)}),
        "domains": sorted({m for m in _RE_DOMAIN.findall(text) if not _is_noise_domain(m)}),
        "urls":    sorted({m for m in _RE_URL.findall(text) if _is_valid_url_netloc(m)}),
        "hashes":  sorted({*(m.lower() for m in _RE_HASH64.findall(text)),
                           *(m.lower() for m in _RE_HASH40.findall(text)),
                           *(m.lower() for m in _RE_HASH32.findall(text))}),
        "emails":  sorted({m.lower() for m in _RE_EMAIL.findall(text)}),
        "paths":   sorted({m for m in _RE_PATH.findall(text)}),
    }


def _printable_ascii_ratio(s: str) -> float:
    """Fraction of characters that are printable ASCII (0x20–0x7E) or common
    whitespace (tab / newline / carriage-return). CJK and other non-ASCII code
    points count as non-printable — that's what keeps mojibake out."""
    if not s:
        return 0.0
    ok = sum(1 for c in s if 0x20 <= ord(c) <= 0x7E or c in "\t\n\r")
    return ok / len(s)


def _hex_dump(data: bytes, length: int = 64) -> str:
    """`xxd`-style dump of the first `length` bytes: offset · hex · ASCII gutter."""
    chunk = data[:length]
    lines = []
    for off in range(0, len(chunk), 16):
        row = chunk[off:off + 16]
        hex_cells = " ".join(f"{b:02x}" for b in row).ljust(47)
        ascii_cell = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in row)
        lines.append(f"{off:08x}  {hex_cells}  {ascii_cell}")
    return "\n".join(lines)


def _render_decoded_bytes(raw: bytes) -> Optional[Tuple[str, Optional[str]]]:
    """Decide how to present a chunk of decoded bytes.

    Returns ``(display, scan_text)`` where:
      • ``display``   — what the UI shows for this payload.
      • ``scan_text`` — text to feed back into IOC extraction, or ``None``.

    If the bytes decode to mostly-printable-ASCII text (>90%) we show the text
    and scan it for IOCs. Otherwise the content is binary: we show a "binary
    content detected" banner plus a hex dump of the first 64 bytes (instead of
    rendering raw bytes as garbled CJK/mojibake), and return ``None`` for
    scan_text so the hex dump is never mistaken for real strings.

    Returns ``None`` entirely when there's nothing worth surfacing."""
    if len(raw) < 4:
        return None
    # PowerShell -EncodedCommand is UTF-16LE; plain payloads are UTF-8/ASCII.
    # Decode strictly (no errors="ignore") so binary can't be silently coerced
    # into a short, falsely-"printable" string by dropping the bytes that fail.
    for enc in ("utf-16le", "utf-8"):
        try:
            text = raw.decode(enc).strip()
        except (UnicodeDecodeError, ValueError):
            continue
        if len(text) >= 4 and _printable_ascii_ratio(text) > 0.90:
            return text[:800], text[:800]
    # Non-printable → binary. Show a hex dump rather than garbled text.
    shown = min(len(raw), 64)
    banner = f"[binary content detected — {len(raw)} bytes, showing first {shown}]"
    return f"{banner}\n{_hex_dump(raw, 64)}", None


def _decode_base64_candidates(text: str, max_decodes: int = 25) -> List[Tuple[str, Optional[str]]]:
    """base64-decode each long-enough b64-shaped run. Each element is
    ``(display, scan_text)`` from :func:`_render_decoded_bytes` — printable
    payloads render as text, binary payloads render as a hex dump."""
    out: List[Tuple[str, Optional[str]]] = []
    for m in _RE_B64.findall(text)[:max_decodes]:
        pad = "=" * (-len(m) % 4)
        try:
            raw = base64.b64decode(m + pad)
        except (binascii.Error, ValueError):
            continue
        rendered = _render_decoded_bytes(raw)
        if rendered:
            out.append(rendered)
    return out


def _decode_hex_candidates(text: str, max_decodes: int = 10) -> List[Tuple[str, Optional[str]]]:
    out: List[Tuple[str, Optional[str]]] = []
    for m in _RE_HEX.findall(text)[:max_decodes]:
        try:
            raw = binascii.unhexlify(m)
        except (binascii.Error, ValueError):
            continue
        rendered = _render_decoded_bytes(raw)
        if rendered:
            out.append(rendered)
    return out


def _joined_strings(strings_dict: Dict) -> str:
    """Concatenate every extracted string into one corpus for regex scans.
    Cached on the dict via a sentinel key so _all_iocs and
    _suspicious_string_hits don't each pay the join cost — the joined
    string for a 50 MB sample can be hundreds of KB, doubled when the
    pipeline calls both consumers in sequence."""
    cached = strings_dict.get("_joined_cache")
    if cached is not None:
        return cached
    joined = "\n".join(strings_dict.get("ascii", []) + strings_dict.get("unicode", []))
    strings_dict["_joined_cache"] = joined
    return joined


def _all_iocs(strings_dict: Dict) -> Dict:
    """IOC extraction across raw + b64-decoded + hex-decoded string corpus."""
    joined = _joined_strings(strings_dict)
    iocs = _extract_iocs_from_text(joined)

    decoded = _decode_base64_candidates(joined) + _decode_hex_candidates(joined)
    if decoded:
        # Only re-scan the genuinely-decoded *text* for IOCs — never the binary
        # hex-dump banners (their hex/ASCII gutter would create phantom IOCs).
        scan_text = "\n".join(t for _, t in decoded if t)
        if scan_text:
            secondary = _extract_iocs_from_text(scan_text)
            for k in iocs:
                iocs[k] = sorted(set(iocs[k]) | set(secondary.get(k, [])))
        iocs["decoded_payloads"] = [display for display, _ in decoded][:10]
    return iocs


# ─── suspicious-string pattern flags ───────────────────────────────────────────
_SUSPICIOUS_PATTERNS = [
    ("c2_framework_cobalt",     re.compile(r"\b(?:beacon|MSF\d|metsrv|stager64?)\b", re.IGNORECASE)),
    ("powershell_encoded_cmd",  re.compile(r"-(?:enc|encoded|encodedcommand)\b", re.IGNORECASE)),
    ("registry_run_key",        re.compile(r"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", re.IGNORECASE)),
    ("scheduled_task",          re.compile(r"\bschtasks\b", re.IGNORECASE)),
    ("mutex_creation",          re.compile(r"\b(?:Global|Local)\\[A-Za-z0-9_\-{}]{6,}", re.IGNORECASE)),
    ("amsi_bypass",             re.compile(r"AmsiScanBuffer|\[ref\]\.Assembly\.GetType.*amsi", re.IGNORECASE)),
    ("download_cradle",         re.compile(r"DownloadString|DownloadFile|Invoke-WebRequest|Invoke-Expression", re.IGNORECASE)),
    ("base64_powershell",       re.compile(r"FromBase64String", re.IGNORECASE)),
    ("lateral_psexec",          re.compile(r"PsExec|\\admin\$|\\ipc\$", re.IGNORECASE)),
    ("credential_dump",         re.compile(r"sekurlsa|lsadump|comsvcs\.dll|MiniDump", re.IGNORECASE)),
]


# ─── source-code suspicious patterns ──────────────────────────────────────────
# Patterns scanned ONLY when the input was identified as source code by
# `_detect_source_code()`. Each one names a specific malware-development
# tradecraft (RWX allocator + thread starter, HTTP loader, PowerShell IEX
# cradle, Python b64 subprocess exec, …) that string-extraction alone can
# match because the entire file is text. Used by `file_capability_map`
# to drive T1055 / T1105 / T1059.001 / T1059.006 mappings without needing
# PE imports.
_SOURCE_PATTERNS = [
    # VirtualAlloc / VirtualAllocEx with PAGE_EXECUTE_READWRITE protection
    # — the classic RWX shellcode allocator. The DOTALL match lets the
    # protection constant sit on the next line from the call.
    ("src_virtualalloc_rwx",   re.compile(
        r"VirtualAlloc(?:Ex)?\b[^;{}]*PAGE_EXECUTE_READWRITE", re.IGNORECASE | re.DOTALL)),
    # Thread-spawn primitives. NT-level variants are red-team idioms.
    ("src_create_thread",      re.compile(
        r"\b(?:CreateThread|CreateRemoteThread|RtlCreateUserThread|NtCreateThreadEx)\b",
        re.IGNORECASE)),
    # WaitForSingleObject paired with thread handles is the standard wait
    # after dispatching shellcode-as-thread. On its own benign; combined
    # with create_thread + virtualalloc_rwx it's loader-shaped.
    ("src_wait_thread",        re.compile(r"\bWaitForSingleObject\b", re.IGNORECASE)),
    # Generic HTTP file-download call across languages: Nim httpclient
    # (downloadFile), .NET (DownloadFile / DownloadString), Python
    # (urllib.request.urlretrieve / requests.get), shell utilities
    # (curl / wget), Go (http.Get).
    ("src_http_download_call", re.compile(
        r"\.downloadFile\b|\.DownloadString\b|WebClient\b|"
        r"urlretrieve\(|requests\.get\(|http\.Get\(|"
        r"\bcurl\s+[-a-zA-Z0-9]*\s*['\"]?https?://|\bwget\s+['\"]?https?://",
        re.IGNORECASE)),
    # Nim + winim — Nim's Windows API binding pulled into a source file
    # is a strong "this targets Windows internals" signal. Not malicious
    # on its own but raises the prior on shellcode patterns.
    ("src_nim_winim",          re.compile(
        r"^\s*import\s+winim\b|^\s*import\s+winim/", re.IGNORECASE | re.MULTILINE)),
    # PowerShell IEX cradle — Invoke-Expression on a DownloadString result
    # is the canonical `iex (New-Object Net.WebClient).DownloadString(...)`
    # download-and-execute payload.
    ("src_ps_iex_download",    re.compile(
        r"\b(?:iex|Invoke-Expression)\b[^\r\n]{0,200}\bDownload(?:String|File|Data)\b",
        re.IGNORECASE)),
    # Python subprocess invocation. Benign in many contexts but a strong
    # signal when paired with base64 decoding (next pattern).
    ("src_py_subprocess",      re.compile(
        r"\bsubprocess\.(?:Popen|run|call|check_output|check_call)\b", re.IGNORECASE)),
    # Python base64 decode. Same — benign alone, malicious when paired
    # with subprocess execution of the decoded payload.
    ("src_py_b64_decode",      re.compile(
        r"\bbase64\.(?:b64decode|standard_b64decode|urlsafe_b64decode)\b",
        re.IGNORECASE)),
    # ctypes-loaded WinAPI + memory-protection constants — Python loader
    # shape (ctypes.windll.kernel32.VirtualAlloc + RWX).
    ("src_py_ctypes_winapi",   re.compile(
        r"ctypes\.windll\.kernel32\.|ctypes\.WINFUNCTYPE\b", re.IGNORECASE)),
    # C / C++ low-level memory + thread primitives — same loader shape
    # without language-specific framing.
    ("src_memcpy_rwx",         re.compile(
        r"\b(?:memcpy|RtlCopyMemory|copyMem)\b[^;]{0,80}\bPAGE_EXECUTE",
        re.IGNORECASE | re.DOTALL)),
    # Inline-assembly markers — strong signal a source file embeds shellcode.
    ("src_inline_asm",         re.compile(
        r"\b__asm__\b|\b__asm\b|\basm\s*\(", re.IGNORECASE)),
]


def _suspicious_string_hits(strings_dict: Dict, source_code: bool = False) -> List[Dict]:
    joined = _joined_strings(strings_dict)
    hits = []
    for name, rex in _SUSPICIOUS_PATTERNS:
        m = rex.search(joined)
        if m:
            hits.append({"pattern": name, "match": m.group(0)[:140]})
    # Source-code patterns run unconditionally on text/source files. They're
    # specific enough (RWX VirtualAlloc, IEX DownloadString, ctypes.windll,
    # …) that false positives on real binaries are vanishingly rare — but
    # we still gate on source_code so we don't pay the regex cost on big
    # PE blobs.
    if source_code:
        for name, rex in _SOURCE_PATTERNS:
            m = rex.search(joined)
            if m:
                hits.append({"pattern": name, "match": m.group(0)[:140]})
    return hits


# ─── public entry point ────────────────────────────────────────────────────────
def analyze_file(file_bytes: bytes, filename: str = "uploaded") -> Dict:
    """Synchronous static analysis — TI correlation runs separately (needs aiohttp).

    Returns a dict with these top-level keys:
      filename, size, analyzed_at,
      type, hashes, entropy, strings,
      iocs, suspicious_strings,
      format_specific (filled by deep_format analyzers per category),
      yara_matches (filled by yara_scanner.scan_bytes),
      capabilities (filled by mitre_capability_map),
      verdict, confidence
    """
    if not file_bytes:
        return {"error": "empty file"}

    started = datetime.now(timezone.utc)
    type_info = _detect_type(file_bytes, filename)
    hashes    = _all_hashes(file_bytes)
    entropy   = _entropy_analysis(file_bytes)
    strings   = _extract_strings(file_bytes)
    iocs      = _all_iocs(strings)
    is_source = bool(type_info.get("is_source_code"))
    sus       = _suspicious_string_hits(strings, source_code=is_source)

    # Top-level `file_type` is the discrimination the frontend uses to
    # render either the PE/binary analysis card or the source-code banner.
    # When the input is source code, also surface the language as a
    # human-readable label and a short banner sentence so the UI doesn't
    # have to know how to phrase it.
    if is_source:
        lang = type_info.get("source_language") or "Source Code"
        file_type = "source_code"
        # Avoid the "Source Code source code" double-wording when the
        # language detector fell back to the generic label.
        if lang == "Source Code":
            file_type_label = "source code"
            file_type_banner = (
                "Source code detected — performing static code analysis "
                "(string patterns, hardcoded IOCs, dangerous API "
                "combinations) rather than PE / ELF byte analysis."
            )
        else:
            file_type_label = f"{lang} source code"
            file_type_banner = (
                f"{lang} source code detected — performing static code "
                f"analysis (string patterns, hardcoded IOCs, dangerous API "
                f"combinations) rather than PE / ELF byte analysis."
            )
    else:
        file_type = (type_info.get("category") or "binary")
        file_type_label = (type_info.get("detected_desc")
                           or type_info.get("detected_mime")
                           or "binary")
        file_type_banner = None

    result = {
        "filename":           filename,
        "size":               len(file_bytes),
        "analyzed_at":        started.isoformat(),
        "type":               type_info,
        "file_type":          file_type,
        "file_type_label":    file_type_label,
        "file_type_banner":   file_type_banner,
        "hashes":             hashes,
        "entropy":            entropy,
        "strings":            {
            "ascii_count":   len(strings.get("ascii", [])),
            "unicode_count": len(strings.get("unicode", [])),
            # Send a sample only — full lists go in dedicated endpoint
            "ascii_sample":  strings.get("ascii", [])[:300],
            "unicode_sample": strings.get("unicode", [])[:200],
        },
        "iocs":               iocs,
        "suspicious_strings": sus,
        "format_specific":    {},
        "yara_matches":       [],
        "capabilities":       {},
        "tags":               [],
        "verdict":            "UNKNOWN",
        "confidence":         0,
    }

    # YARA scan (uses existing intel.yara_scanner)
    try:
        from intel.yara_scanner import scan_bytes
        matches = scan_bytes(file_bytes)
        result["yara_matches"] = matches
        if matches:
            result["tags"].append(f"yara:{len(matches)}-match{'es' if len(matches) != 1 else ''}")
    except Exception as e:
        result["yara_matches"] = [{"error": str(e)}]

    # Format-specific deep analysis
    try:
        from intel.file_analyzer_formats import analyze_format
        deep = analyze_format(file_bytes, type_info, filename)
        if deep:
            result["format_specific"] = deep
    except Exception as e:
        result["format_specific"] = {"error": str(e)}

    # MITRE capability mapping (synthesizes from imports + sus_strings + format_specific)
    try:
        from intel.file_capability_map import build_capability_assessment
        result["capabilities"] = build_capability_assessment(result)
    except Exception as e:
        result["capabilities"] = {"error": str(e)}

    # Detection content generation
    try:
        from intel.file_detection_gen import generate_all_detections
        result["detections"] = generate_all_detections(result)
    except Exception as e:
        result["detections"] = {"error": str(e)}

    # Verdict synthesis from all static signals
    result["verdict"], result["confidence"] = _synthesize_verdict(result)
    result["elapsed_ms"] = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
    return result


def _synthesize_verdict(result: Dict) -> Tuple[str, int]:
    score = 0
    yara = result.get("yara_matches") or []
    if yara and not (isinstance(yara[0], dict) and "error" in yara[0]):
        score += 40 + min(30, len(yara) * 5)
    if result.get("type", {}).get("mismatch"):
        score += 15
    if result.get("entropy", {}).get("flag") == "high_entropy_packed":
        score += 20
    elif result.get("entropy", {}).get("flag") == "elevated_entropy":
        score += 10
    sus_count = len(result.get("suspicious_strings") or [])
    score += min(25, sus_count * 5)
    cap = (result.get("capabilities") or {}).get("verdict")
    if cap == "MALICIOUS":
        score += 20
    elif cap == "SUSPICIOUS":
        score += 10
    score = min(100, score)
    # Capability MALICIOUS already encodes the holistic high-signal read
    # (T1055 / T1003 / T1486 etc. via the file_capability_map elevator).
    # Trust it directly — the per-signal score above only adds
    # corroboration; it should not contradict the capability verdict by
    # downgrading to SUSPICIOUS just because YARA didn't match a known-
    # malware rule (modern source-code loaders / commodity payloads
    # routinely have no YARA hit). Keeps the numeric score for the
    # confidence bar but stamps the final label from the capability map.
    if cap == "MALICIOUS":
        return "MALICIOUS", max(score, 80)

    # Authenticode-signed binaries that didn't trip the capability map's
    # MALICIOUS elevator are very rarely real malware. The previous code
    # path could land at MALICIOUS purely from raw YARA match count — a
    # legitimate signed `python.exe` matched 17 generic PE-characteristic
    # rules (`IsPE64`, `HasOverlay`, `HasRichSignature`, `anti_dbg`, ...)
    # which alone contributed 70 points and forced MALICIOUS at the >= 75
    # threshold. None of those rules are malicious indicators on their
    # own; an Authenticode signature is much stronger counter-evidence.
    # Cap signed-and-not-cap-MALICIOUS at SUSPICIOUS so the analyst sees
    # the YARA matches and capability hits in context without the
    # verdict overstating them.
    pe = (result.get("format_specific") or {}).get("pe") or {}
    has_authenticode = bool((pe.get("signature") or {}).get("present"))
    if has_authenticode and score >= 75:
        score = min(score, 60)   # cap into SUSPICIOUS tier

    if score >= 75: verdict = "MALICIOUS"
    elif score >= 45: verdict = "SUSPICIOUS"
    elif score >= 15: verdict = "LOW"
    else: verdict = "CLEAN"
    return verdict, score
