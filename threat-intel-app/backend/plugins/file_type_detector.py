"""File-type detection — maps raw bytes + filename to the file_type
string that FileAnalyzer plugins advertise in supported_file_types.

Deliberately magic-byte-based (not content-type / extension) because
analysts upload samples with scrubbed extensions. The returned type
is one of: pe | elf | macho | pdf | office | rtf | apk | eml |
pcap | js | html | shellcode | zip | unknown.

Multiple returns are possible — e.g. APK is also a ZIP, DOCX is also
a ZIP (OpenXML). The caller gets a prioritised list; file_analyzers
whose supported_file_types intersect with ANY entry are invoked.
"""

from __future__ import annotations

from typing import List


def detect_types(data: bytes, filename: str = "") -> List[str]:
    """Return a list of file_type strings in priority order (most-
    specific first). Always ends with 'any' so format-agnostic
    scanners (YARA, FLOSS) are included."""
    types: List[str] = []
    head = data[:1024] if data else b""
    lower_name = (filename or "").lower()

    # ─── Magic-byte signatures ────────────────────────────────────────
    if head.startswith(b"MZ"):
        types.append("pe")
    elif head.startswith(b"\x7fELF"):
        types.append("elf")
    elif head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                       b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                       b"\xca\xfe\xba\xbe"):
        types.append("macho")
    elif head.startswith(b"%PDF"):
        types.append("pdf")
    elif head.startswith(b"{\\rtf"):
        types.append("rtf")
    elif head.startswith(b"PK\x03\x04"):
        # ZIP container. Could be APK, DOCX, XLSX, JAR, etc. — use
        # name/content heuristics to disambiguate.
        if lower_name.endswith(".apk") or b"AndroidManifest.xml" in head or b"classes.dex" in data[:65536]:
            types.append("apk")
        elif lower_name.endswith((".docx", ".xlsx", ".pptx")) or b"[Content_Types].xml" in data[:4096]:
            types.append("office")
        else:
            types.append("zip")
    elif head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        # Legacy OLE compound-document (.doc, .xls, .ppt, .msi).
        types.append("office")
    elif head.startswith(b"\xd4\xc3\xb2\xa1") or head.startswith(b"\xa1\xb2\xc3\xd4"):
        # Classic PCAP (little- / big-endian)
        types.append("pcap")
    elif head.startswith(b"\x0a\x0d\x0d\x0a"):
        # PCAP-NG
        types.append("pcap")
    elif b"\nFrom:" in head or b"\nSubject:" in head or head.startswith(b"Return-Path:"):
        types.append("eml")
    elif head.lstrip().startswith(b"<html") or head.lstrip().lower().startswith(b"<!doctype html"):
        types.append("html")
    elif head.lstrip().startswith((b"var ", b"function ", b"const ", b"let ", b"//",
                                     b"/*", b"import ", b"require(")):
        types.append("js")

    # ─── Extension-only fallbacks ─────────────────────────────────────
    if not types:
        if lower_name.endswith((".exe", ".dll", ".sys", ".scr")):
            types.append("pe")
        elif lower_name.endswith((".elf", ".so")):
            types.append("elf")
        elif lower_name.endswith(".pdf"):
            types.append("pdf")
        elif lower_name.endswith((".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                                    ".docm", ".xlsm", ".pptm")):
            types.append("office")
        elif lower_name.endswith(".rtf"):
            types.append("rtf")
        elif lower_name.endswith(".apk"):
            types.append("apk")
        elif lower_name.endswith(".dex"):
            types.append("dex")
        elif lower_name.endswith((".eml", ".msg")):
            types.append("eml")
        elif lower_name.endswith(".pcap") or lower_name.endswith(".pcapng"):
            types.append("pcap")
        elif lower_name.endswith((".js", ".mjs", ".ts", ".jse")):
            types.append("js")
        elif lower_name.endswith((".vbs", ".vbe", ".wsf")):
            types.append("js")   # dropper-script bucket; Box-js handles these
        elif lower_name.endswith((".html", ".htm")):
            types.append("html")
        elif lower_name.endswith((".ipa",)):
            types.append("ipa")

    # Shellcode heuristic — small blob (< 4KB) with no identified
    # format. Only fires when nothing else matched; emulators can
    # still try to run it.
    if not types and 0 < len(data) < 4096:
        types.append("shellcode")

    # Everything can be scanned by format-agnostic analyzers (YARA, FLOSS…)
    types.append("any")

    # De-dup while preserving order
    seen = set()
    uniq: List[str] = []
    for t in types:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq
