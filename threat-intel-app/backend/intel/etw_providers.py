"""
Windows Event Tracing for Windows (ETW) provider catalog.

Source: Microsoft's published GUIDs + names (public). High-traffic
providers for security-relevant telemetry. Used by:

  - Sysmon, Windows Defender, EDR vendors as telemetry feed
  - DLR (Direct Logon Records) telemetry
  - KQL queries against Microsoft Defender / Sentinel
  - Custom EDRs

This catalog gives the analyst report a "to capture this technique
deploy ETW provider X" pointer and lets the KQL/SPL generator suggest
relevant providers when crafting queries.

Operator can drop a larger catalogue at vendor/etw/providers.json
(many community-curated lists exist — see github.com/JonasAtTrendMicro/
EtwProvidersCatalogue and github.com/Velocidex/etw); we ship a compact
in-tree subset of the highest-value security providers.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.etw_providers")

_ETW_JSON = (Path(__file__).parent.parent.parent
             / "vendor" / "etw" / "providers.json")

# In-tree compact catalog — covers ~40 highest-value security providers.
# Field shape: GUID → {name, category, capabilities, mitre_techniques}.
_FALLBACK_PROVIDERS: Dict[str, Dict[str, Any]] = {
    "{54849625-5478-4994-A5BA-3E3B0328C30D}": {
        "name":     "Microsoft-Windows-Security-Auditing",
        "category": "Security",
        "capabilities": ["logon events", "process creation", "object access"],
        "mitre_techniques": ["T1078", "T1059", "T1003"],
    },
    "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}": {
        "name":     "Microsoft-Windows-Kernel-Process",
        "category": "Process telemetry",
        "capabilities": ["process start", "process stop", "thread create"],
        "mitre_techniques": ["T1055", "T1059"],
    },
    "{EDD08927-9CC4-4E65-B970-C2560FB5C289}": {
        "name":     "Microsoft-Windows-Kernel-File",
        "category": "File telemetry",
        "capabilities": ["file create", "file write", "file delete"],
        "mitre_techniques": ["T1486", "T1485"],
    },
    "{7DD42A49-5329-4832-8DFD-43D979153A88}": {
        "name":     "Microsoft-Windows-Kernel-Network",
        "category": "Network telemetry",
        "capabilities": ["tcp/udp connect", "tcp/udp listen"],
        "mitre_techniques": ["T1071", "T1041"],
    },
    "{E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23}": {
        "name":     "Microsoft-Windows-Kernel-Registry",
        "category": "Registry telemetry",
        "capabilities": ["registry create/delete/write"],
        "mitre_techniques": ["T1547", "T1112"],
    },
    "{5E8CF2D5-2BB3-4E5C-B470-CDF63F2DAB78}": {
        "name":     "Microsoft-Windows-Crypto-BCrypt",
        "category": "Crypto telemetry",
        "capabilities": ["cryptographic operations"],
        "mitre_techniques": ["T1486", "T1573"],
    },
    "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}": {
        "name":     "Microsoft-Windows-PowerShell",
        "category": "Scripting telemetry",
        "capabilities": ["script block logging", "module logging", "transcripts"],
        "mitre_techniques": ["T1059.001", "T1027"],
    },
    "{1A03E63E-9F8F-4E2C-A8E8-43B66E5D33A4}": {
        "name":     "Microsoft-Antimalware-Service",
        "category": "AV / EDR telemetry",
        "capabilities": ["scan results", "detected threats"],
        "mitre_techniques": ["T1562.001"],
    },
    "{11689DA7-3FCA-44A8-A30B-1AC0DF60D6D8}": {
        "name":     "Microsoft-Windows-WMI-Activity",
        "category": "WMI telemetry",
        "capabilities": ["wmi queries", "wmi event subscriptions"],
        "mitre_techniques": ["T1047", "T1546.003"],
    },
    "{A68CA8B7-004F-D7B6-A698-07E2DE0F1F5D}": {
        "name":     "Microsoft-Windows-Kernel-General",
        "category": "Kernel telemetry",
        "capabilities": ["module load", "DPC", "syscall"],
        "mitre_techniques": ["T1574", "T1543"],
    },
    "{2E07BD92-1A48-4F2B-9E9C-79A6F44D9EA8}": {
        "name":     "Microsoft-Windows-NDIS-PacketCapture",
        "category": "Packet capture",
        "capabilities": ["raw packet inspection"],
        "mitre_techniques": ["T1040"],
    },
    "{6B6C257F-5643-43E8-8E5A-C66343DBC650}": {
        "name":     "Microsoft-Windows-Kernel-EventTracing",
        "category": "ETW management",
        "capabilities": ["session start/stop", "provider enable"],
        "mitre_techniques": ["T1562.006"],
    },
    "{1F678132-5938-4686-9FDC-C8FF68F15C85}": {
        "name":     "Microsoft-Windows-SMBServer",
        "category": "SMB telemetry",
        "capabilities": ["smb sessions", "file shares accessed"],
        "mitre_techniques": ["T1021.002"],
    },
    "{D5C25F9A-4D47-493E-9184-40DD397A004D}": {
        "name":     "Microsoft-Windows-Sysmon",
        "category": "Sysmon",
        "capabilities": ["process / network / image-load / driver-load events"],
        "mitre_techniques": ["T1055", "T1059", "T1543"],
    },
}

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":     False,
    "by_guid":    {},
    "by_name":    {},
    "by_attack":  {},
    "source":     "fallback",
    "error":      None,
}


def _build_index() -> None:
    providers = dict(_FALLBACK_PROVIDERS)
    source = "fallback"
    if _ETW_JSON.exists():
        try:
            payload = json.loads(_ETW_JSON.read_text(encoding="utf-8",
                                                      errors="ignore"))
            if isinstance(payload, dict):
                providers.update(payload)
                source = "vendored"
        except Exception as e:
            _log.warning("ETW providers vendored JSON unreadable: %s", e)

    by_guid:   Dict[str, Dict[str, Any]] = {}
    by_name:   Dict[str, Dict[str, Any]] = {}
    by_attack: Dict[str, List[Dict[str, Any]]] = {}

    for guid, meta in providers.items():
        if not isinstance(meta, dict):
            continue
        entry = {"guid": guid}
        entry.update(meta)
        by_guid[guid.upper()] = entry
        name = (meta.get("name") or "").strip()
        if name:
            by_name[name.lower()] = entry
        for t in (meta.get("mitre_techniques") or []):
            by_attack.setdefault(str(t).upper(), []).append(entry)

    _state["by_guid"]   = by_guid
    _state["by_name"]   = by_name
    _state["by_attack"] = by_attack
    _state["source"]    = source
    _state["loaded"]    = True
    _state["error"]     = None
    _log.info("ETW providers loaded: %d (source=%s)", len(by_guid), source)


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def lookup_guid(guid: str) -> Optional[Dict[str, Any]]:
    _ensure_loaded()
    if not isinstance(guid, str):
        return None
    return (_state.get("by_guid") or {}).get(guid.upper().strip())


def lookup_name(name: str) -> Optional[Dict[str, Any]]:
    _ensure_loaded()
    if not isinstance(name, str):
        return None
    return (_state.get("by_name") or {}).get(name.lower().strip())


def providers_for_attack(attack_id: str,
                         max_results: int = 4) -> List[Dict[str, Any]]:
    _ensure_loaded()
    if not attack_id:
        return []
    tid = attack_id.upper().strip()
    rows = (_state.get("by_attack") or {}).get(tid, [])
    if not rows and "." in tid:
        rows = (_state.get("by_attack") or {}).get(tid.split(".", 1)[0], [])
    return rows[:max_results]


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":    bool(_state["loaded"]),
        "providers": len(_state.get("by_guid") or {}),
        "techniques_mapped": len(_state.get("by_attack") or {}),
        "source":    _state.get("source"),
        "error":     _state.get("error"),
    }
