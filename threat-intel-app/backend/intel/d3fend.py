"""
MITRE D3FEND defensive countermeasure mapping.

Source: https://d3fend.mitre.org + https://github.com/d3fend/d3fend-public
(Apache-2.0). D3FEND extends ATT&CK with a *defensive* ontology — every
offensive technique (T####) maps to one or more defensive techniques
(D3-####) that detect, isolate, or remediate it.

We bundle a compact `attack_to_defend.json` (extracted from D3FEND's
SPARQL-exported JSON-LD) so the response stage can answer:

  "T1059.001 PowerShell — defend with:
   - D3-PMAD (Process Memory Anomaly Detection)
   - D3-FBA  (File Binary Analysis)
   - D3-EALA (Execution Argument Log Analysis)"

Built-in fallback embeds a hand-curated subset of the highest-value
offense→defense mappings so the module produces useful output even
when the operator hasn't fetched the full D3FEND JSON.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.d3fend")

# Optional operator-fetched full mapping. When present, overrides the
# built-in fallback.
_D3FEND_JSON = (Path(__file__).parent.parent.parent
                / "vendor" / "d3fend" / "attack_to_defend.json")

# Hand-curated fallback covering the top techniques RECON sees in
# practice. Maps T-id → list[{d3_id, name}]. Extracted from D3FEND's
# Tactic→Technique→Countermeasure graph; not exhaustive but never
# returns nothing for the headline ATT&CK IDs.
_FALLBACK_MAP: Dict[str, List[Dict[str, str]]] = {
    "T1059":      [{"d3_id": "D3-EALA",  "name": "Execution Argument Log Analysis"},
                   {"d3_id": "D3-PMAD",  "name": "Process Memory Anomaly Detection"}],
    "T1059.001":  [{"d3_id": "D3-EALA",  "name": "Execution Argument Log Analysis"},
                   {"d3_id": "D3-CSPP",  "name": "Client-Server Payload Profiling"},
                   {"d3_id": "D3-FBA",   "name": "File Binary Analysis"}],
    "T1059.003":  [{"d3_id": "D3-EALA",  "name": "Execution Argument Log Analysis"},
                   {"d3_id": "D3-PSA",   "name": "Process Spawn Analysis"}],
    "T1027":      [{"d3_id": "D3-FCA",   "name": "File Content Analysis"},
                   {"d3_id": "D3-FBA",   "name": "File Binary Analysis"},
                   {"d3_id": "D3-DENCR", "name": "Decoy Environment"}],
    "T1003":      [{"d3_id": "D3-PMAD",  "name": "Process Memory Anomaly Detection"},
                   {"d3_id": "D3-FAPA",  "name": "File Access Pattern Analysis"}],
    "T1003.001":  [{"d3_id": "D3-PMAD",  "name": "Process Memory Anomaly Detection"},
                   {"d3_id": "D3-LFAM",  "name": "Local File Access Monitoring"}],
    "T1055":      [{"d3_id": "D3-PMAD",  "name": "Process Memory Anomaly Detection"},
                   {"d3_id": "D3-SCBA",  "name": "System Call Behavior Analysis"}],
    "T1071":      [{"d3_id": "D3-NTA",   "name": "Network Traffic Analysis"},
                   {"d3_id": "D3-CSPP",  "name": "Client-Server Payload Profiling"}],
    "T1071.001":  [{"d3_id": "D3-NTA",   "name": "Network Traffic Analysis"},
                   {"d3_id": "D3-RPA",   "name": "Remote Plug-in Analysis"}],
    "T1071.004":  [{"d3_id": "D3-DNSDA", "name": "DNS Domain Allowlisting"},
                   {"d3_id": "D3-DNSTA", "name": "DNS Traffic Analysis"}],
    "T1105":      [{"d3_id": "D3-NTA",   "name": "Network Traffic Analysis"},
                   {"d3_id": "D3-FBA",   "name": "File Binary Analysis"}],
    "T1041":      [{"d3_id": "D3-NTA",   "name": "Network Traffic Analysis"},
                   {"d3_id": "D3-OFA",   "name": "Outbound File Analysis"}],
    "T1486":      [{"d3_id": "D3-FAPA",  "name": "File Access Pattern Analysis"},
                   {"d3_id": "D3-FENC",  "name": "File Encryption Detection"}],
    "T1490":      [{"d3_id": "D3-FAPA",  "name": "File Access Pattern Analysis"},
                   {"d3_id": "D3-SBV",   "name": "Snapshot Backup Verification"}],
    "T1547":      [{"d3_id": "D3-SFA",   "name": "Startup File Analysis"},
                   {"d3_id": "D3-RKA",   "name": "Registry Key Analysis"}],
    "T1053":      [{"d3_id": "D3-SJA",   "name": "Scheduled Job Analysis"}],
    "T1110":      [{"d3_id": "D3-AAA",   "name": "Authentication Attempt Analysis"},
                   {"d3_id": "D3-MFA",   "name": "Multi-Factor Authentication"}],
    "T1078":      [{"d3_id": "D3-AAA",   "name": "Authentication Attempt Analysis"},
                   {"d3_id": "D3-OTP",   "name": "One-time Password"}],
    "T1133":      [{"d3_id": "D3-AAA",   "name": "Authentication Attempt Analysis"},
                   {"d3_id": "D3-NPA",   "name": "Network Posture Assessment"}],
    "T1190":      [{"d3_id": "D3-NTPM",  "name": "Network Traffic Policy Mapping"},
                   {"d3_id": "D3-WFC",   "name": "Web Filtering Configuration"}],
    "T1566":      [{"d3_id": "D3-MA",    "name": "Message Analysis"},
                   {"d3_id": "D3-UA",    "name": "URL Analysis"},
                   {"d3_id": "D3-FBA",   "name": "File Binary Analysis"}],
    "T1566.001":  [{"d3_id": "D3-FBA",   "name": "File Binary Analysis"},
                   {"d3_id": "D3-FCA",   "name": "File Content Analysis"}],
    "T1566.002":  [{"d3_id": "D3-UA",    "name": "URL Analysis"},
                   {"d3_id": "D3-DNSTA", "name": "DNS Traffic Analysis"}],
    "T1218":      [{"d3_id": "D3-PSA",   "name": "Process Spawn Analysis"},
                   {"d3_id": "D3-EALA",  "name": "Execution Argument Log Analysis"}],
    "T1562":      [{"d3_id": "D3-SCBA",  "name": "System Call Behavior Analysis"},
                   {"d3_id": "D3-PCFA",  "name": "Process Code Fragment Analysis"}],
    "T1021":      [{"d3_id": "D3-RPA",   "name": "Remote Plug-in Analysis"},
                   {"d3_id": "D3-AAA",   "name": "Authentication Attempt Analysis"}],
    "T1021.001":  [{"d3_id": "D3-AAA",   "name": "Authentication Attempt Analysis"},
                   {"d3_id": "D3-RDPA",  "name": "RDP Session Analysis"}],
    "T1021.002":  [{"d3_id": "D3-AAA",   "name": "Authentication Attempt Analysis"},
                   {"d3_id": "D3-NFA",   "name": "Network File Sharing Analysis"}],
    "T1046":      [{"d3_id": "D3-NTA",   "name": "Network Traffic Analysis"},
                   {"d3_id": "D3-NTPM",  "name": "Network Traffic Policy Mapping"}],
    "T1018":      [{"d3_id": "D3-NTA",   "name": "Network Traffic Analysis"}],
    "T1082":      [{"d3_id": "D3-PSA",   "name": "Process Spawn Analysis"},
                   {"d3_id": "D3-EALA",  "name": "Execution Argument Log Analysis"}],
    "T1136":      [{"d3_id": "D3-AAA",   "name": "Authentication Attempt Analysis"},
                   {"d3_id": "D3-UAP",   "name": "User Account Permissions"}],
}

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":   False,
    "map":      {},
    "source":   "fallback",
    "error":    None,
}


def _build_index() -> None:
    """Load the operator-provided D3FEND export if present; else fall
    back to the built-in hand-curated subset above."""
    if _D3FEND_JSON.exists():
        try:
            payload = json.loads(_D3FEND_JSON.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and payload:
                _state["map"]    = payload
                _state["source"] = "vendored"
                _state["loaded"] = True
                _state["error"]  = None
                _log.info("D3FEND vendored map loaded: %d technique entries",
                          len(payload))
                return
        except Exception as e:
            _log.warning("D3FEND vendored JSON unreadable: %s", e)
    _state["map"]    = _FALLBACK_MAP
    _state["source"] = "fallback"
    _state["loaded"] = True
    _state["error"]  = None


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def countermeasures_for(technique_id: str) -> List[Dict[str, str]]:
    """Return D3FEND countermeasures mapped to the given ATT&CK technique.
    Falls back to the parent technique when a sub-technique has no
    explicit mapping (so T1059.001 inherits T1059 entries when missing)."""
    _ensure_loaded()
    tid = (technique_id or "").upper().strip()
    if not tid.startswith("T"):
        return []
    m = _state.get("map") or {}
    out = list(m.get(tid) or [])
    if not out and "." in tid:
        out = list(m.get(tid.split(".", 1)[0]) or [])
    return out


def countermeasures_for_many(technique_ids: Iterable[str]) -> Dict[str, List[Dict[str, str]]]:
    """Convenience: map a set of ATT&CK techniques to their D3FEND
    countermeasures. Caller gets a dict keyed by technique ID."""
    out: Dict[str, List[Dict[str, str]]] = {}
    for t in (technique_ids or []):
        cms = countermeasures_for(t)
        if cms:
            out[t.upper()] = cms
    return out


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    m = _state.get("map") or {}
    return {
        "loaded":     bool(_state["loaded"]),
        "source":     _state.get("source"),
        "technique_count": len(m),
        "error":      _state.get("error"),
    }
