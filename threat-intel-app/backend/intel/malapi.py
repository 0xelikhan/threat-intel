"""
MalAPI.io Windows API -> malicious-use map.

Source: https://github.com/mrd0x/MalAPI.io (MIT). Curated dataset of
~500 Windows APIs grouped by their typical malicious purpose
(Enumeration, Injection, Anti-Debug, Hooking, Crypto, Networking, etc.)
plus a brief description per API. Underpins the public malapi.io site.

This module bundles the canonical taxonomy in-tree (small, static)
so RECON's PE-import-based capability assessment can answer

  "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread = Process
   Injection (T1055)"

with a richer, named source than the existing hand-rolled
file_capability_map predicates. When the operator clones the upstream
repo at `vendor/malapi-io/`, the loader will swap the in-tree fallback
for the live data file.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.malapi")

_MALAPI_REPO_FILE = (Path(__file__).parent.parent.parent
                     / "vendor" / "malapi-io" / "api.json")

# Canonical category → (description, MITRE technique). Extracted verbatim
# from the malapi.io taxonomy. Used as the in-tree fallback when the
# vendored repo file isn't present.
_CATEGORY_META: Dict[str, Dict[str, str]] = {
    "Enumeration":         {"desc": "Process / file / registry / system enumeration",
                             "technique": "T1082"},
    "Injection":           {"desc": "Process injection",
                             "technique": "T1055"},
    "Evasion":             {"desc": "Defense evasion / API unhooking / sandbox detection",
                             "technique": "T1562"},
    "Spying":              {"desc": "Keylogging / screen / clipboard capture",
                             "technique": "T1056"},
    "Internet":            {"desc": "Network communication / C2",
                             "technique": "T1071"},
    "Anti-Debugging":      {"desc": "Anti-debug techniques",
                             "technique": "T1622"},
    "Ransomware":          {"desc": "File enumeration + crypto for impact",
                             "technique": "T1486"},
    "Helper":              {"desc": "Generic helper APIs (memory, string, conversion)",
                             "technique": ""},
    "Hooking":             {"desc": "Hooking / detours / function patching",
                             "technique": "T1574"},
    "Antivm":              {"desc": "VM / sandbox detection",
                             "technique": "T1497"},
}

# Canonical API → category mapping. This is a deliberate subset of the
# malapi.io list, biased toward APIs RECON's file_capability_map.py
# already inspects (and a few high-signal additions). The full ~500
# entries are loaded from `vendor/malapi-io/api.json` when present.
_API_CATEGORY_FALLBACK: Dict[str, str] = {
    # Injection
    "VirtualAllocEx":            "Injection",
    "WriteProcessMemory":        "Injection",
    "CreateRemoteThread":        "Injection",
    "QueueUserAPC":              "Injection",
    "SetWindowsHookEx":          "Injection",
    "NtCreateSection":           "Injection",
    "NtMapViewOfSection":        "Injection",
    "RtlCreateUserThread":       "Injection",
    # Enumeration
    "Process32First":            "Enumeration",
    "Process32Next":             "Enumeration",
    "CreateToolhelp32Snapshot":  "Enumeration",
    "EnumProcesses":             "Enumeration",
    "EnumProcessModules":        "Enumeration",
    "GetModuleBaseName":         "Enumeration",
    "GetComputerName":           "Enumeration",
    "GetUserName":               "Enumeration",
    "NetUserEnum":               "Enumeration",
    "NetWkstaUserEnum":          "Enumeration",
    # Evasion / Anti-Debug / AntiVM
    "IsDebuggerPresent":         "Anti-Debugging",
    "CheckRemoteDebuggerPresent": "Anti-Debugging",
    "OutputDebugString":         "Anti-Debugging",
    "NtQueryInformationProcess": "Anti-Debugging",
    "ZwQueryInformationProcess": "Anti-Debugging",
    "GetTickCount":              "Antivm",
    "Sleep":                     "Antivm",
    "NtDelayExecution":          "Antivm",
    # Spying
    "GetAsyncKeyState":          "Spying",
    "GetKeyboardState":          "Spying",
    "GetForegroundWindow":       "Spying",
    "BitBlt":                    "Spying",
    "GetDC":                     "Spying",
    "OpenClipboard":             "Spying",
    "GetClipboardData":          "Spying",
    # Networking
    "InternetOpen":              "Internet",
    "InternetOpenA":             "Internet",
    "InternetOpenW":             "Internet",
    "InternetConnect":           "Internet",
    "InternetReadFile":          "Internet",
    "HttpSendRequest":           "Internet",
    "WinHttpOpen":               "Internet",
    "WinHttpConnect":            "Internet",
    "URLDownloadToFile":         "Internet",
    "URLDownloadToFileA":        "Internet",
    "URLDownloadToFileW":        "Internet",
    "DnsQuery_A":                "Internet",
    "send":                      "Internet",
    "recv":                      "Internet",
    "connect":                   "Internet",
    # Ransomware
    "FindFirstFile":             "Ransomware",
    "FindNextFile":              "Ransomware",
    "CryptEncrypt":              "Ransomware",
    "CryptGenKey":               "Ransomware",
    "CryptAcquireContext":       "Ransomware",
    "BCryptEncrypt":             "Ransomware",
    "BCryptGenerateSymmetricKey": "Ransomware",
    # Hooking
    "SetWindowsHookExA":         "Hooking",
    "SetWindowsHookExW":         "Hooking",
}

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":            False,
    "api_to_category":   {},
    "category_meta":     {},
    "source":            "fallback",
    "error":             None,
}


def _load_vendor_json() -> Optional[Dict[str, str]]:
    if not _MALAPI_REPO_FILE.exists():
        return None
    try:
        payload = json.loads(_MALAPI_REPO_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None
    if isinstance(payload, dict):
        # Expect either {api: category} or {category: [api...]}.
        first_val = next(iter(payload.values()), None)
        if isinstance(first_val, str):
            return {k: v for k, v in payload.items() if isinstance(k, str)}
        if isinstance(first_val, list):
            flat: Dict[str, str] = {}
            for cat, apis in payload.items():
                if not isinstance(apis, list):
                    continue
                for a in apis:
                    if isinstance(a, str):
                        flat[a] = cat
            return flat
    return None


def _build_index() -> None:
    vendor = _load_vendor_json()
    if vendor:
        _state["api_to_category"] = vendor
        _state["source"]          = "vendored"
    else:
        _state["api_to_category"] = dict(_API_CATEGORY_FALLBACK)
        _state["source"]          = "fallback"
    _state["category_meta"] = dict(_CATEGORY_META)
    _state["loaded"]        = True
    _state["error"]         = None
    _log.info("MalAPI.io index ready: %d APIs (source=%s)",
              len(_state["api_to_category"]), _state["source"])


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def classify_apis(api_names: Iterable[str]) -> Dict[str, Any]:
    """Given a set of Win API names (e.g. PE import names), return a
    grouped summary: {category: [api...]} + the inferred MITRE techniques."""
    _ensure_loaded()
    api_map = _state.get("api_to_category") or {}
    by_cat: Dict[str, List[str]] = {}
    for n in api_names or []:
        if not isinstance(n, str):
            continue
        cat = api_map.get(n) or api_map.get(n.rstrip("AW"))  # collapse A/W suffixes
        if cat:
            by_cat.setdefault(cat, []).append(n)
    cat_meta = _state.get("category_meta") or {}
    techniques: List[str] = []
    summary: List[Dict[str, Any]] = []
    for cat, apis in by_cat.items():
        meta = cat_meta.get(cat, {})
        t = meta.get("technique") or ""
        if t and t not in techniques:
            techniques.append(t)
        summary.append({
            "category":     cat,
            "description":  meta.get("desc", ""),
            "technique":    t,
            "apis":         sorted(set(apis))[:8],
            "match_count":  len(apis),
        })
    summary.sort(key=lambda r: -r["match_count"])
    return {
        "by_category":      {c: sorted(set(v)) for c, v in by_cat.items()},
        "summary":          summary,
        "mitre_techniques": techniques,
        "total_matched":    sum(len(v) for v in by_cat.values()),
    }


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":        bool(_state["loaded"]),
        "api_count":     len(_state.get("api_to_category") or {}),
        "category_count": len(_state.get("category_meta") or {}),
        "source":        _state.get("source"),
        "error":         _state.get("error"),
    }
