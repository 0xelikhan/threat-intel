"""
Format-specific deep analyzers — spec §2 of the all-in-one scanner plan.

Dispatched from file_analyzer.analyze_file() based on the detected category.
Each analyzer is best-effort: missing dependency → empty dict, never raises.
"""

from __future__ import annotations

import hashlib
import re
import struct
import zipfile
from datetime import datetime, timezone
from typing import Dict, List, Optional


# ─── dispatch table ────────────────────────────────────────────────────────────
def analyze_format(file_bytes: bytes, type_info: Dict, filename: str) -> Dict:
    cat = type_info.get("category")
    out: Dict = {}
    if cat == "executable":
        out["pe"] = analyze_pe(file_bytes) if file_bytes[:2] == b"MZ" else {}
    elif cat == "office_document":
        out["office"] = analyze_office(file_bytes, filename)
    elif cat == "pdf":
        out["pdf"] = analyze_pdf(file_bytes)
    elif cat == "archive":
        out["archive"] = analyze_archive(file_bytes, type_info.get("detected_mime", ""))
    elif cat == "script_or_text":
        out["script"] = analyze_script(file_bytes, filename)
    elif cat == "disk_image":
        out["disk_image"] = analyze_disk_image(file_bytes)
    return out


# ─── PE analysis (pefile) ─────────────────────────────────────────────────────
# Imports we explicitly call out, grouped by capability. Used by the capability map.
HIGH_RISK_APIS = {
    "Anti-Debug":   {"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                     "NtQueryInformationProcess", "OutputDebugString"},
    "Injection":    {"VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
                     "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
                     "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
                     "RtlDecompressBuffer", "QueueUserAPC", "SetThreadContext"},
    "Network":      {"InternetOpen", "InternetOpenA", "InternetOpenW",
                     "InternetOpenUrl", "InternetOpenUrlA", "InternetOpenUrlW",
                     "URLDownloadToFile", "URLDownloadToFileA", "URLDownloadToFileW",
                     "WinHttpOpen", "HttpSendRequest", "HttpOpenRequest",
                     "WSAStartup", "connect", "send", "recv"},
    "Persistence":  {"RegSetValueEx", "RegSetValueExA", "RegSetValueExW",
                     "RegCreateKey", "RegCreateKeyEx",
                     "CreateService", "CreateServiceA", "CreateServiceW",
                     "OpenSCManager", "StartServiceCtrlDispatcher",
                     "CoCreateInstance"},
    "Keylogging":   {"GetAsyncKeyState", "GetKeyState", "SetWindowsHookEx",
                     "SetWindowsHookExA", "SetWindowsHookExW",
                     "RegisterRawInputDevices", "GetKeyboardState"},
    "Crypto":       {"CryptEncrypt", "CryptDecrypt", "CryptAcquireContext",
                     "CryptCreateHash", "CryptGenKey", "CryptHashData",
                     "BCryptEncrypt", "BCryptDecrypt"},
    "Execution":    {"WinExec", "ShellExecute", "ShellExecuteA", "ShellExecuteW",
                     "CreateProcess", "CreateProcessA", "CreateProcessW",
                     "system"},
    "Discovery":    {"NetShareEnum", "NetWkstaUserEnum", "WNetOpenEnum",
                     "GetComputerName", "GetUserName", "GetAdaptersInfo"},
    "Filesystem":   {"FindFirstFile", "FindFirstFileA", "FindFirstFileW",
                     "FindNextFile", "FindNextFileA", "FindNextFileW",
                     "MoveFileEx", "DeleteFile", "DeleteFileA", "DeleteFileW"},
}


def analyze_pe(file_bytes: bytes) -> Dict:
    try:
        import pefile
    except ImportError:
        return {"error": "pefile not installed"}
    try:
        pe = pefile.PE(data=file_bytes, fast_load=False)
    except Exception as e:
        return {"error": f"not a valid PE: {e}"}

    out: Dict = {}

    # ── basic metadata ────────────────────────────────────────────────────────
    ts = pe.FILE_HEADER.TimeDateStamp
    ts_dt = datetime.fromtimestamp(ts, tz=timezone.utc) if ts else None
    timestamp_flags = []
    if ts_dt:
        now = datetime.now(timezone.utc)
        if ts_dt > now:
            timestamp_flags.append("compiled_in_future")
        if ts_dt.year < 2000:
            timestamp_flags.append("compiled_before_2000")
    out["timestamp"] = {
        "raw":   ts,
        "iso":   ts_dt.isoformat() if ts_dt else None,
        "flags": timestamp_flags,
    }
    out["machine"] = hex(pe.FILE_HEADER.Machine)
    out["machine_name"] = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, "unknown")
    out["subsystem"] = pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "unknown")
    out["linker_version"] = f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"
    out["is_dll"]     = bool(pe.is_dll())
    out["is_driver"]  = bool(pe.is_driver())
    out["is_exe"]     = bool(pe.is_exe())

    # ── imphash + rich header ────────────────────────────────────────────────
    try:
        out["imphash"] = pe.get_imphash()
    except Exception:
        out["imphash"] = None
    try:
        rich = pe.parse_rich_header()
        if rich:
            out["rich_header"] = {
                "checksum": rich.get("checksum"),
                "values":   list(rich.get("values") or [])[:10],
            }
    except Exception:
        pass

    # ── imports — grouped + flagged ──────────────────────────────────────────
    imports: Dict[str, List[str]] = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = (entry.dll or b"").decode("utf-8", "ignore")
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode("utf-8", "ignore"))
            imports[dll] = funcs[:80]
    out["imports"] = imports
    out["import_count"] = sum(len(v) for v in imports.values())

    # Categorize imports by high-risk capability
    flat_imports = {fn for funcs in imports.values() for fn in funcs}
    flagged_by_category: Dict[str, List[str]] = {}
    for cat, apis in HIGH_RISK_APIS.items():
        hits = sorted(flat_imports & apis)
        if hits:
            flagged_by_category[cat] = hits
    out["flagged_imports"] = flagged_by_category

    # ── exports ───────────────────────────────────────────────────────────────
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for e in pe.DIRECTORY_ENTRY_EXPORT.symbols[:50]:
            if e.name:
                exports.append(e.name.decode("utf-8", "ignore"))
    out["exports"] = exports

    # ── sections ──────────────────────────────────────────────────────────────
    standard_names = {".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".rsrc",
                      ".reloc", ".pdata", ".tls", ".debug", ".CRT"}
    sections = []
    for s in pe.sections:
        name = (s.Name or b"").decode("utf-8", "ignore").rstrip("\x00")
        ent  = s.get_entropy()
        flags = []
        if ent > 7.0:                                  flags.append("high_entropy")
        if (s.Characteristics & 0x20000000) and \
           (s.Characteristics & 0x80000000):           flags.append("executable_and_writable")
        if name not in standard_names:                 flags.append("non_standard_name")
        sections.append({
            "name":     name,
            "vaddr":    hex(s.VirtualAddress),
            "vsize":    s.Misc_VirtualSize,
            "rsize":    s.SizeOfRawData,
            "entropy":  round(ent, 3),
            "char":     hex(s.Characteristics),
            "flags":    flags,
        })
    out["sections"] = sections

    # ── resources (with sha256) ───────────────────────────────────────────────
    resources = []
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            type_name = str(rtype.name) if rtype.name else f"id_{rtype.id}"
            for entry in getattr(rtype, "directory", {}).entries if hasattr(rtype, "directory") else []:
                for lang in getattr(entry, "directory", {}).entries if hasattr(entry, "directory") else []:
                    try:
                        rva  = lang.data.struct.OffsetToData
                        size = lang.data.struct.Size
                        data = pe.get_memory_mapped_image()[rva:rva + size]
                        resources.append({
                            "type":    type_name,
                            "size":    size,
                            "sha256":  hashlib.sha256(data).hexdigest(),
                        })
                    except Exception:
                        pass
                    if len(resources) >= 20:
                        break
    out["resources"] = resources

    # ── overlay (data after PE end) ───────────────────────────────────────────
    try:
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset and overlay_offset < len(file_bytes):
            overlay = file_bytes[overlay_offset:]
            out["overlay"] = {
                "size":   len(overlay),
                "sha256": hashlib.sha256(overlay).hexdigest(),
                "entropy": round(_entropy(overlay), 3),
            }
    except Exception:
        pass

    # ── signature / cert chain ────────────────────────────────────────────────
    sig_dir = None
    try:
        sig_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
    except Exception:
        pass
    if sig_dir and sig_dir.Size > 0:
        out["signature"] = {
            "present":       True,
            "size":          sig_dir.Size,
            "note":          "Authenticode signature present (chain validation requires platform OS APIs)",
        }
    else:
        out["signature"] = {"present": False}

    # ── security mitigations (DllCharacteristics) ─────────────────────────────
    dll_char = pe.OPTIONAL_HEADER.DllCharacteristics
    out["mitigations"] = {
        "ASLR":         bool(dll_char & 0x0040),
        "DEP":          bool(dll_char & 0x0100),
        "SafeSEH":      bool(dll_char & 0x0400),
        "CFG":          bool(dll_char & 0x4000),
        "Authenticode": out["signature"]["present"],
    }

    # ── capability rule-of-thumb (matches the spec's heuristic list) ──────────
    fl = flagged_by_category
    caps = []
    if {"VirtualAlloc","VirtualAllocEx"} & set(fl.get("Injection", [])) \
       and "WriteProcessMemory" in fl.get("Injection", []) \
       and "CreateRemoteThread" in fl.get("Injection", []):
        caps.append("likely_process_injector")
    if "GetAsyncKeyState" in fl.get("Keylogging", []) or \
       any(api.startswith("SetWindowsHookEx") for api in fl.get("Keylogging", [])):
        caps.append("likely_keylogger")
    if fl.get("Crypto") and fl.get("Filesystem"):
        caps.append("likely_ransomware")
    if fl.get("Network") and ("URLDownloadToFile" in flat_imports or "URLDownloadToFileA" in flat_imports
                              or "URLDownloadToFileW" in flat_imports):
        caps.append("likely_downloader_or_rat")
    if any(api in flat_imports for api in ("NetShareEnum", "WNetOpenEnum")):
        caps.append("likely_worm_or_lateral_tool")
    out["capabilities"] = caps

    return out


def _entropy(b: bytes) -> float:
    if not b: return 0.0
    from collections import Counter
    import math
    counts = Counter(b)
    return -sum((c/len(b)) * math.log2(c/len(b)) for c in counts.values())


# ─── Office analysis (oletools) ───────────────────────────────────────────────
AUTO_EXEC_FUNCS = {
    "AutoOpen", "AutoExec", "Auto_Open", "Auto_Close",
    "Document_Open", "Document_Close", "Document_BeforeClose",
    "Workbook_Open", "Workbook_BeforeClose", "Workbook_Activate",
    "DocumentOpen", "AutoNew",
}
SUSPICIOUS_OFFICE_PATTERNS = [
    ("Shell",            re.compile(r"\bShell\s*\(", re.IGNORECASE)),
    ("WScript.Shell",    re.compile(r"WScript\.Shell", re.IGNORECASE)),
    ("PowerShell",       re.compile(r"powershell", re.IGNORECASE)),
    ("CreateObject",     re.compile(r"CreateObject\s*\(", re.IGNORECASE)),
    ("Chr_obfuscation",  re.compile(r"Chr\s*\(\s*\d+\s*\)\s*&", re.IGNORECASE)),
    ("Environ",          re.compile(r"Environ\s*\(", re.IGNORECASE)),
    ("URLDownloadToFile", re.compile(r"URLDownloadToFile", re.IGNORECASE)),
]


def analyze_office(file_bytes: bytes, filename: str) -> Dict:
    out: Dict = {"format": "office", "macros": [], "auto_exec": [], "suspicious_patterns": [],
                 "urls": [], "embedded_objects": []}
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        out["error"] = "oletools not installed"
        return out
    try:
        vbap = VBA_Parser(filename, data=file_bytes)
    except Exception as e:
        out["error"] = f"olevba parse failed: {e}"
        return out

    try:
        out["has_macros"] = vbap.detect_vba_macros()
    except Exception:
        out["has_macros"] = False

    macro_text = ""
    if out["has_macros"]:
        try:
            for (fname, stream, vba_filename, vba_code) in vbap.extract_macros():
                if not vba_code:
                    continue
                macro_text += "\n" + vba_code
                out["macros"].append({
                    "filename":      vba_filename,
                    "stream":        stream,
                    "code_preview":  vba_code[:1200],
                    "size":          len(vba_code),
                })
        except Exception as e:
            out["macro_error"] = str(e)

    # Auto-exec function detection
    for fn in AUTO_EXEC_FUNCS:
        if re.search(r"\b" + re.escape(fn) + r"\b", macro_text, re.IGNORECASE):
            out["auto_exec"].append(fn)

    # Suspicious patterns
    for name, rex in SUSPICIOUS_OFFICE_PATTERNS:
        m = rex.search(macro_text)
        if m:
            out["suspicious_patterns"].append({"pattern": name, "match": m.group(0)[:120]})

    # External URLs + UNC paths
    out["urls"]      = sorted({u for u in re.findall(r"https?://[^\s\"'<>]+", macro_text)})[:30]
    out["unc_paths"] = sorted({u for u in re.findall(r"\\\\[A-Za-z0-9._\-]+\\[^\s\"'<>]+", macro_text)})[:20]

    # DDE detection
    out["has_dde"] = bool(re.search(r"\bDDEAuto\b|\bDDE\s+", macro_text, re.IGNORECASE))

    # Embedded OLE objects (rough enumeration on the underlying zip)
    if zipfile.is_zipfile(__import__("io").BytesIO(file_bytes)):
        try:
            with zipfile.ZipFile(__import__("io").BytesIO(file_bytes)) as z:
                for name in z.namelist():
                    if name.startswith("word/embeddings/") or name.startswith("xl/embeddings/") \
                       or name.startswith("ppt/embeddings/"):
                        data = z.read(name)
                        out["embedded_objects"].append({
                            "path":   name,
                            "size":   len(data),
                            "sha256": hashlib.sha256(data).hexdigest(),
                        })
        except Exception:
            pass

    try:
        vbap.close()
    except Exception:
        pass
    return out


# ─── PDF analysis (PyPDF2) ────────────────────────────────────────────────────
def analyze_pdf(file_bytes: bytes) -> Dict:
    out: Dict = {"format": "pdf", "javascript": [], "embedded_files": [],
                 "action_urls": [], "launch_actions": []}
    try:
        from PyPDF2 import PdfReader
        from io import BytesIO
    except ImportError:
        out["error"] = "PyPDF2 not installed"
        return out
    try:
        reader = PdfReader(BytesIO(file_bytes), strict=False)
    except Exception as e:
        out["error"] = f"PDF parse failed: {e}"
        return out

    out["pages"]     = len(reader.pages)
    out["encrypted"] = reader.is_encrypted

    # Walk the object catalog for JS / launch / embedded files
    raw = file_bytes
    # /JS, /JavaScript
    for m in re.finditer(rb"/(?:JS|JavaScript)\s*[\(<]([^)>]{0,2000})", raw, re.IGNORECASE | re.DOTALL):
        try:
            js = m.group(1).decode("latin-1", errors="ignore").strip()
            if js:
                out["javascript"].append(js[:600])
        except Exception:
            continue
        if len(out["javascript"]) >= 5:
            break
    # /Launch
    for m in re.finditer(rb"/Launch\s*<<[^>]{0,500}/F\s*\(([^)]{1,500})\)", raw, re.IGNORECASE):
        try:
            out["launch_actions"].append(m.group(1).decode("latin-1", errors="ignore"))
        except Exception:
            continue
    # URLs in /URI actions
    for m in re.finditer(rb"/URI\s*\(([^)]{4,500})\)", raw):
        try:
            out["action_urls"].append(m.group(1).decode("latin-1", errors="ignore"))
        except Exception:
            continue
    out["action_urls"] = sorted(set(out["action_urls"]))[:30]
    # /EmbeddedFile
    embedded_count = len(re.findall(rb"/EmbeddedFile", raw))
    out["embedded_count"] = embedded_count

    return out


# ─── archive analysis (zip / jar / 7z / rar) ──────────────────────────────────
DOUBLE_EXT_PATTERN = re.compile(r"\.(?:pdf|doc|docx|xls|xlsx|jpg|png|txt)\.[a-z]{2,4}$", re.IGNORECASE)


def analyze_archive(file_bytes: bytes, mime: str) -> Dict:
    out: Dict = {"format": "archive", "members": [], "flags": []}
    from io import BytesIO

    members = []
    try:
        if zipfile.is_zipfile(BytesIO(file_bytes)):
            with zipfile.ZipFile(BytesIO(file_bytes)) as z:
                for info in z.infolist()[:200]:
                    cratio = info.compress_size / max(info.file_size, 1) if info.file_size else 1.0
                    flags = []
                    if DOUBLE_EXT_PATTERN.search(info.filename):
                        flags.append("double_extension")
                    if ".." in info.filename or info.filename.startswith(("/", "\\")):
                        flags.append("path_traversal")
                    if info.file_size > 0 and cratio < 0.01:
                        flags.append("zip_bomb_candidate")
                    members.append({
                        "name":     info.filename,
                        "size":     info.file_size,
                        "csize":    info.compress_size,
                        "ratio":    round(cratio, 4),
                        "flags":    flags,
                    })
                    if flags:
                        out["flags"].extend(f"{info.filename}:{f}" for f in flags)
        elif "x-7z" in mime:
            try:
                import py7zr
                with py7zr.SevenZipFile(BytesIO(file_bytes)) as z:
                    for name in z.getnames()[:200]:
                        members.append({"name": name})
            except Exception as e:
                out["error_7z"] = str(e)
        elif "x-rar" in mime:
            try:
                import rarfile
                rarfile.UNRAR_TOOL = "unrar"
                with rarfile.RarFile(BytesIO(file_bytes)) as r:
                    for info in r.infolist()[:200]:
                        members.append({"name": info.filename, "size": info.file_size})
            except Exception as e:
                out["error_rar"] = str(e)
    except Exception as e:
        out["error"] = str(e)

    out["members"] = members
    out["member_count"] = len(members)
    return out


# ─── script / text deobfuscation ──────────────────────────────────────────────
def analyze_script(file_bytes: bytes, filename: str) -> Dict:
    out: Dict = {"format": "script"}
    try:
        text = file_bytes.decode("utf-8", errors="ignore")
    except Exception:
        text = file_bytes.decode("latin-1", errors="ignore")

    ext = (filename.rsplit(".", 1)[-1] if "." in filename else "").lower()
    out["language"] = {
        "ps1": "powershell", "vbs": "vbscript", "js": "javascript",
        "bat": "batch", "cmd": "batch", "py": "python", "sh": "shell",
    }.get(ext, "unknown")

    out["source_preview"] = text[:4000]
    out["line_count"]     = text.count("\n") + 1
    out["urls"]           = sorted({u for u in re.findall(r"https?://[^\s\"'<>]+", text)})[:20]
    out["ips"]            = sorted({i for i in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)})[:20]

    obfusc_flags = []
    if re.search(r"FromBase64String|-enc(?:oded)?\b", text, re.IGNORECASE):
        obfusc_flags.append("base64_encoded_powershell")
    if re.search(r"Chr\s*\(\s*\d+\s*\)\s*&", text, re.IGNORECASE):
        obfusc_flags.append("char_code_array")
    if text.count(" -join ") > 3 or text.count("+'") > 6:
        obfusc_flags.append("string_concatenation_obfuscation")
    if re.search(r"\$(?:env:)?[a-z]+\s*=\s*\[char\]\d+", text, re.IGNORECASE):
        obfusc_flags.append("char_assignment")
    if "iex" in text.lower() or "invoke-expression" in text.lower():
        obfusc_flags.append("iex_dynamic_execution")
    out["obfuscation_flags"] = obfusc_flags
    return out


# ─── disk image analysis (ISO / IMG / VHD) ────────────────────────────────────
def analyze_disk_image(file_bytes: bytes) -> Dict:
    out: Dict = {"format": "disk_image", "members": [], "flags": []}
    # Cheap content peek for autorun.inf — ISO9660 stores filenames in plaintext
    text = file_bytes[:200_000].decode("latin-1", errors="ignore").lower()
    if "autorun.inf" in text:
        out["flags"].append("autorun_inf_present")
    # Surface .exe / .bat / .ps1 filenames hinted in the volume
    hits = re.findall(r"[\w.\-]{1,40}\.(?:exe|bat|cmd|ps1|vbs|scr|com|dll)", text, re.IGNORECASE)
    out["referenced_executables"] = sorted(set(hits))[:30]
    return out
