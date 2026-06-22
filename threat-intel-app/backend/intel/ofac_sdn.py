"""
US Treasury OFAC Specially Designated Nationals (SDN) list loader.

Source: https://home.treasury.gov/policy-issues/financial-sanctions/
specially-designated-nationals-and-blocked-persons-list-sdn-human-
readable-lists (US gov, public domain).

The SDN list contains sanctioned individuals, entities, and identifiers
including:
  - Cryptocurrency wallet addresses (Digital Currency Address - XBT/ETH/etc.)
  - Email addresses
  - Aliases / AKA names
  - Programs (e.g. CYBER2, RUSSIA-EO14024, IRAN-EO13848)

For RECON, the high-value subset is the crypto-wallet + email IDs.
When triage extracts a wallet address or email, this index resolves it
to the sanctioned entity name + sanctions program — a strong signal
for ransomware-payment investigations and BEC attribution.

We accept either:
  - Operator-fetched `sdn.xml` at vendor/ofac/sdn.xml      (full feed)
  - Operator-fetched `sdn_advanced.xml` at vendor/ofac/    (richer schema)
  - Operator-fetched `sdn.csv` at vendor/ofac/sdn.csv      (CSV variant)

The fetcher script pulls the canonical XML on first run.
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree as ET

_log = logging.getLogger("recon.intel.ofac")

_OFAC_DIR = (Path(__file__).parent.parent.parent
             / "vendor" / "ofac")

# OFAC schema namespace — Treasury publishes SDN XML under this NS.
_NS = {"sdn": "http://tempuri.org/sdnList.xsd"}

# Recognised IDType strings that map to RECON IOC types.
_ID_TYPE_MAP = {
    # Crypto addresses
    "digital currency address - xbt":    "btc",
    "digital currency address - bch":    "btc",   # bitcoin cash; same regex family
    "digital currency address - etc":    "etc",
    "digital currency address - eth":    "eth",
    "digital currency address - ltc":    "ltc",
    "digital currency address - xmr":    "xmr",
    "digital currency address - usdt":   "usdt",
    "digital currency address - xvg":    "xvg",
    "digital currency address - dash":   "dash",
    "digital currency address - zec":    "zec",
    "digital currency address - bsv":    "bsv",
    # Email
    "email address":                      "email",
    # Domain (less common but seen)
    "website":                            "domain",
}

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":          False,
    "by_crypto":       {},   # dict[address(lower), {entity, program, list_type}]
    "by_email":        {},   # dict[email(lower), ...]
    "by_domain":       {},   # dict[domain(lower), ...]
    "total_entries":   0,
    "total_addresses": 0,
    "source":          "fallback",
    "error":           None,
}


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _parse_entity(elem) -> Dict[str, Any]:
    """Pull entity name + sanctions program(s) out of an <sdnEntry>."""
    name_parts: List[str] = []
    programs: List[str] = []
    list_type = ""

    for c in elem:
        ct = _strip_ns(c.tag)
        if ct == "lastName" and c.text:
            name_parts.insert(0, c.text.strip())
        elif ct == "firstName" and c.text:
            name_parts.append(c.text.strip())
        elif ct == "title" and c.text:
            # entity-name placeholder for non-individual rows
            name_parts.append(c.text.strip())
        elif ct == "sdnType" and c.text:
            list_type = c.text.strip()
        elif ct == "programList":
            for prog in c:
                if _strip_ns(prog.tag) == "program" and prog.text:
                    programs.append(prog.text.strip())

    return {
        "name":     " ".join(name_parts).strip()[:240] or "(unnamed)",
        "programs": programs[:6],
        "list_type": list_type,
    }


def _parse_xml() -> Dict[str, Any]:
    """Walk the SDN XML tree extracting entity-keyed identifier rows."""
    candidates = [
        _OFAC_DIR / "sdn.xml",
        _OFAC_DIR / "sdn_advanced.xml",
    ]
    path = next((p for p in candidates if p.exists()), None)
    if not path:
        return {"loaded": False,
                "error": f"OFAC SDN XML not present at {_OFAC_DIR}"}

    by_crypto: Dict[str, Dict[str, Any]] = {}
    by_email:  Dict[str, Dict[str, Any]] = {}
    by_domain: Dict[str, Dict[str, Any]] = {}
    total_entries   = 0
    total_addresses = 0

    try:
        tree = ET.parse(path)
    except Exception as e:
        return {"loaded": False, "error": f"OFAC XML parse failed: {e}"}

    for elem in tree.iter():
        if _strip_ns(elem.tag) != "sdnEntry":
            continue
        total_entries += 1
        entity = _parse_entity(elem)

        for c in elem.iter():
            if _strip_ns(c.tag) != "id":
                continue
            id_type = ""
            id_value = ""
            for sub in c:
                st = _strip_ns(sub.tag)
                txt = (sub.text or "").strip()
                if st == "idType":
                    id_type = txt.lower()
                elif st == "idNumber":
                    id_value = txt
            if not id_value:
                continue
            kind = _ID_TYPE_MAP.get(id_type)
            if not kind:
                continue
            row = {
                "entity":   entity["name"],
                "programs": entity["programs"],
                "list_type": entity["list_type"],
                "id_type":  id_type,
            }
            if kind in ("btc", "eth", "etc", "ltc", "xmr", "usdt", "xvg",
                        "dash", "zec", "bsv"):
                key = id_value.strip()
                by_crypto[key] = row
                total_addresses += 1
            elif kind == "email":
                by_email[id_value.lower().strip()] = row
            elif kind == "domain":
                by_domain[id_value.lower().strip().rstrip(".")] = row

    return {
        "loaded":         True,
        "by_crypto":      by_crypto,
        "by_email":       by_email,
        "by_domain":      by_domain,
        "total_entries":  total_entries,
        "total_addresses": total_addresses,
        "source":         path.name,
    }


def _build_index() -> None:
    parsed = _parse_xml()
    if not parsed.get("loaded"):
        _state["error"]  = parsed.get("error")
        _state["loaded"] = True   # one-shot — operator can't fix at runtime
        return
    _state.update(parsed)
    _state["error"] = None
    _state["loaded"] = True
    _log.info("OFAC SDN loaded: %d entries | %d crypto addrs | %d emails | %d domains",
              parsed["total_entries"], len(parsed["by_crypto"]),
              len(parsed["by_email"]), len(parsed["by_domain"]))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def lookup_crypto(address: str) -> Optional[Dict[str, Any]]:
    _ensure_loaded()
    if not isinstance(address, str) or not address:
        return None
    return (_state.get("by_crypto") or {}).get(address.strip())


def lookup_email(email: str) -> Optional[Dict[str, Any]]:
    _ensure_loaded()
    if not isinstance(email, str) or not email:
        return None
    return (_state.get("by_email") or {}).get(email.lower().strip())


def lookup_domain(domain: str) -> Optional[Dict[str, Any]]:
    _ensure_loaded()
    if not isinstance(domain, str) or not domain:
        return None
    return (_state.get("by_domain") or {}).get(domain.lower().strip().rstrip("."))


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":          bool(_state["loaded"]),
        "total_entries":   _state.get("total_entries", 0),
        "crypto_addrs":    len(_state.get("by_crypto") or {}),
        "emails":          len(_state.get("by_email") or {}),
        "domains":         len(_state.get("by_domain") or {}),
        "source":          _state.get("source"),
        "error":           _state.get("error"),
    }
