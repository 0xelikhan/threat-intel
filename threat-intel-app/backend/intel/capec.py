"""
MITRE CAPEC (Common Attack Pattern Enumeration and Classification) loader.

Source: https://capec.mitre.org/data/xml/capec_latest.xml (Apache-2.0
content; the data files themselves are public-domain US-government work).
~600 attack patterns with hierarchy, ATT&CK cross-mapping, prerequisites,
mitigations, and consequences.

CAPEC complements ATT&CK by being more abstract — "SQL Injection" lives
at CAPEC-66, with parents (CAPEC-7 Blind SQL Injection, CAPEC-470
Expanding Control over the OS, etc.) and ATT&CK mappings. The investi-
gation result extends each ATT&CK technique with CAPEC parents so the
analyst report can cite both layers.

We accept either the upstream `capec_latest.xml` (when the operator
fetches it) OR a hand-curated JSON fallback at vendor/capec/index.json
with the structure {capec_id: {name, attack_ids[], parents[]}}.
A built-in compact fallback covers the highest-traffic CAPECs so the
module is useful out of the box.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from xml.etree import ElementTree as ET

_log = logging.getLogger("recon.intel.capec")

_CAPEC_XML  = (Path(__file__).parent.parent.parent
               / "vendor" / "capec" / "capec_latest.xml")
_CAPEC_JSON = (Path(__file__).parent.parent.parent
               / "vendor" / "capec" / "index.json")

# Built-in compact subset — high-traffic CAPECs with their ATT&CK cross-
# references. Used when no vendored data is present. Extracted from the
# MITRE-published mappings.
_FALLBACK: Dict[str, Dict[str, Any]] = {
    "CAPEC-66":  {"name": "SQL Injection",
                  "attack_ids": ["T1190"], "parents": ["CAPEC-153"]},
    "CAPEC-7":   {"name": "Blind SQL Injection",
                  "attack_ids": ["T1190"], "parents": ["CAPEC-66"]},
    "CAPEC-63":  {"name": "Cross-Site Scripting (XSS)",
                  "attack_ids": ["T1059.007"], "parents": ["CAPEC-242"]},
    "CAPEC-242": {"name": "Code Injection",
                  "attack_ids": ["T1059"], "parents": ["CAPEC-152"]},
    "CAPEC-88":  {"name": "OS Command Injection",
                  "attack_ids": ["T1059"], "parents": ["CAPEC-248"]},
    "CAPEC-126": {"name": "Path Traversal",
                  "attack_ids": ["T1083"], "parents": ["CAPEC-153"]},
    "CAPEC-153": {"name": "Input Data Manipulation",
                  "attack_ids": [], "parents": ["CAPEC-152"]},
    "CAPEC-159": {"name": "Redirect Access to Libraries",
                  "attack_ids": ["T1574"], "parents": []},
    "CAPEC-555": {"name": "Remote Services with Stolen Credentials",
                  "attack_ids": ["T1078"], "parents": ["CAPEC-549"]},
    "CAPEC-560": {"name": "Use of Known Domain Credentials",
                  "attack_ids": ["T1078.002"], "parents": ["CAPEC-555"]},
    "CAPEC-49":  {"name": "Password Brute Forcing",
                  "attack_ids": ["T1110"], "parents": ["CAPEC-112"]},
    "CAPEC-112": {"name": "Brute Force",
                  "attack_ids": ["T1110"], "parents": []},
    "CAPEC-565": {"name": "Password Spraying",
                  "attack_ids": ["T1110.003"], "parents": ["CAPEC-49"]},
    "CAPEC-509": {"name": "Kerberoasting",
                  "attack_ids": ["T1558.003"], "parents": ["CAPEC-560"]},
    "CAPEC-633": {"name": "Token Impersonation",
                  "attack_ids": ["T1134"], "parents": []},
    "CAPEC-117": {"name": "Interception",
                  "attack_ids": ["T1040"], "parents": []},
    "CAPEC-94":  {"name": "Adversary in the Middle",
                  "attack_ids": ["T1557"], "parents": ["CAPEC-117"]},
    "CAPEC-549": {"name": "Local Execution of Code",
                  "attack_ids": ["T1059"], "parents": []},
    "CAPEC-248": {"name": "Command Injection",
                  "attack_ids": ["T1059"], "parents": []},
    "CAPEC-549.001": {"name": "Use of Stolen Credentials",
                      "attack_ids": ["T1078"], "parents": []},
    "CAPEC-180": {"name": "Exploiting Incorrectly Configured Access Control",
                  "attack_ids": ["T1078"], "parents": []},
    "CAPEC-650": {"name": "Upload a Web Shell",
                  "attack_ids": ["T1505.003"], "parents": []},
    "CAPEC-184": {"name": "Software Integrity Attack",
                  "attack_ids": ["T1195"], "parents": []},
    "CAPEC-438": {"name": "Modification During Manufacture",
                  "attack_ids": ["T1195.003"], "parents": ["CAPEC-184"]},
    "CAPEC-486": {"name": "DLL Side-Loading",
                  "attack_ids": ["T1574.002"], "parents": ["CAPEC-159"]},
    "CAPEC-541": {"name": "Application Fingerprinting",
                  "attack_ids": ["T1592"], "parents": []},
    "CAPEC-204": {"name": "Lifting Sensitive Data Embedded in Cache",
                  "attack_ids": ["T1005"], "parents": []},
    "CAPEC-115": {"name": "Authentication Bypass",
                  "attack_ids": ["T1110"], "parents": []},
}

_TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":         False,
    "by_id":          {},
    "by_attack_id":   {},
    "source":         "fallback",
    "error":          None,
}


def _parse_xml() -> Optional[Dict[str, Dict[str, Any]]]:
    if not _CAPEC_XML.exists():
        return None
    try:
        tree = ET.parse(_CAPEC_XML)
    except Exception as e:
        _log.warning("CAPEC XML parse failed: %s", e)
        return None
    out: Dict[str, Dict[str, Any]] = {}
    ns = ""
    # CAPEC XML uses an unstable namespace; ET handles it implicitly when
    # we use tag.endswith(localname).
    for elem in tree.iter():
        tag = elem.tag.split("}", 1)[-1] if "}" in elem.tag else elem.tag
        if tag != "Attack_Pattern":
            continue
        capec_id = elem.attrib.get("ID")
        name     = elem.attrib.get("Name") or ""
        if not capec_id:
            continue
        capec_key = f"CAPEC-{capec_id}"
        attack_ids: List[str] = []
        parents:    List[str] = []
        for sub in elem.iter():
            sub_tag = sub.tag.split("}", 1)[-1]
            txt     = (sub.text or "").strip()
            # Direct ATT&CK references appear as
            #   <Taxonomy_Mapping Taxonomy_Name="ATT&CK"><Entry_ID>...</Entry_ID></Taxonomy_Mapping>
            if sub_tag == "Taxonomy_Mapping" and \
               (sub.attrib.get("Taxonomy_Name") or "").upper().startswith("ATT&CK"):
                for entry in sub.iter():
                    et_tag = entry.tag.split("}", 1)[-1]
                    if et_tag == "Entry_ID" and entry.text:
                        for m in _TECHNIQUE_RE.finditer(entry.text):
                            attack_ids.append(m.group(1).upper())
            if sub_tag == "Related_Attack_Pattern":
                parent_id = sub.attrib.get("CAPEC_ID")
                nature = (sub.attrib.get("Nature", "") or "").lower()
                if parent_id and nature in ("childof", "parentof"):
                    parents.append(f"CAPEC-{parent_id}")
        out[capec_key] = {
            "name":       name[:200],
            "attack_ids": list(dict.fromkeys(attack_ids))[:10],
            "parents":    list(dict.fromkeys(parents))[:6],
        }
    return out or None


def _parse_json() -> Optional[Dict[str, Dict[str, Any]]]:
    if not _CAPEC_JSON.exists():
        return None
    try:
        payload = json.loads(_CAPEC_JSON.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            return payload
    except Exception:
        return None
    return None


def _build_index() -> None:
    data = _parse_json() or _parse_xml() or dict(_FALLBACK)
    source = ("vendored-json" if _CAPEC_JSON.exists()
              else "vendored-xml" if _CAPEC_XML.exists()
              else "fallback")

    by_id: Dict[str, Dict[str, Any]] = {}
    by_attack: Dict[str, List[Dict[str, Any]]] = {}
    for capec_id, meta in data.items():
        if not isinstance(meta, dict):
            continue
        entry = {
            "capec_id":   capec_id,
            "name":       (meta.get("name") or "")[:200],
            "attack_ids": list(meta.get("attack_ids") or [])[:10],
            "parents":    list(meta.get("parents") or [])[:6],
        }
        by_id[capec_id] = entry
        for at in entry["attack_ids"]:
            by_attack.setdefault(at.upper(), []).append(entry)

    _state["by_id"]        = by_id
    _state["by_attack_id"] = by_attack
    _state["source"]       = source
    _state["loaded"]       = True
    _state["error"]        = None
    _log.info("CAPEC loaded: %d patterns (source=%s)", len(by_id), source)


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def lookup_capec(capec_id: str) -> Optional[Dict[str, Any]]:
    _ensure_loaded()
    if not capec_id:
        return None
    key = capec_id.upper().strip()
    if not key.startswith("CAPEC-"):
        key = f"CAPEC-{key}"
    return (_state.get("by_id") or {}).get(key)


def patterns_for_attack(attack_id: str,
                        max_results: int = 6) -> List[Dict[str, Any]]:
    _ensure_loaded()
    if not attack_id:
        return []
    tid = attack_id.upper().strip()
    rows = (_state.get("by_attack_id") or {}).get(tid, [])
    if not rows and "." in tid:
        rows = (_state.get("by_attack_id") or {}).get(tid.split(".", 1)[0], [])
    return rows[:max_results]


def patterns_for_attacks(attack_ids: Iterable[str]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for t in (attack_ids or []):
        pats = patterns_for_attack(t)
        if pats:
            out[t.upper()] = pats
    return out


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":   bool(_state["loaded"]),
        "patterns": len(_state.get("by_id") or {}),
        "attack_mapped": len(_state.get("by_attack_id") or {}),
        "source":   _state.get("source"),
        "error":    _state.get("error"),
    }
