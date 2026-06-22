"""
Ransomwhe.re crypto-extortion address tracker.

Source: https://ransomwhe.re (academic dataset, Apache-2.0 / CC0).
Crowdsourced ransomware payment-address tracker maintained by Jack
Cable + collaborators. Each entry maps a cryptocurrency address
(BTC, BCH, ETH, XMR-ish) to the named ransomware family that
operates it.

Two-shape support:
  - Live JSON API at https://api.ransomwhe.re/transactions  (full
    transaction log; ~30MB)
  - Vendored compact JSON at vendor/ransomwhere/addresses.json:
       {address: {"family": "Conti", "first_seen": "...", ...}, ...}

When triage extracts a cryptocurrency address, this index resolves
it to the ransomware family.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Optional

_log = logging.getLogger("recon.intel.ransomwhere")

_RW_JSON = (Path(__file__).parent.parent.parent
            / "vendor" / "ransomwhere" / "addresses.json")

# Crypto-address regexes — keep tight to minimise false-positive
# extraction. Covers BTC P2PKH/P2SH, Bech32, ETH, XMR.
ADDRESS_REGEXES = {
    "btc_legacy": re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    "btc_bech32": re.compile(r"\bbc1[ac-hj-np-z02-9]{8,87}\b"),
    "eth":        re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "xmr":        re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
}

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":     False,
    "by_addr":    {},   # dict[address, {family, first_seen, last_seen}]
    "families":   set(),
    "error":      None,
}


def _build_index() -> None:
    if not _RW_JSON.exists():
        _state["error"]  = f"ransomwhere addresses.json not present at {_RW_JSON}"
        _state["loaded"] = True
        return
    try:
        payload = json.loads(_RW_JSON.read_text(encoding="utf-8",
                                                 errors="ignore"))
    except Exception as e:
        _state["error"]  = f"ransomwhere addresses.json unreadable: {e}"
        _state["loaded"] = True
        return

    by_addr: Dict[str, Dict[str, Any]] = {}
    families: set = set()

    # Accept either {addr: meta} dict OR list-of-records shape.
    if isinstance(payload, dict):
        for addr, meta in payload.items():
            if not isinstance(addr, str) or not isinstance(meta, dict):
                continue
            family = (meta.get("family") or meta.get("family_name") or "").strip()
            if not family:
                continue
            by_addr[addr] = {
                "family":     family,
                "first_seen": meta.get("first_seen") or meta.get("first") or "",
                "last_seen":  meta.get("last_seen")  or meta.get("last") or "",
                "blockchain": meta.get("blockchain") or "",
            }
            families.add(family)
    elif isinstance(payload, list):
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            addr = (entry.get("address") or "").strip()
            family = (entry.get("family") or "").strip()
            if not addr or not family:
                continue
            by_addr.setdefault(addr, {
                "family":     family,
                "first_seen": entry.get("first_seen", ""),
                "last_seen":  entry.get("last_seen", ""),
                "blockchain": entry.get("blockchain", ""),
            })
            families.add(family)

    _state["by_addr"]  = by_addr
    _state["families"] = families
    _state["loaded"]   = True
    _state["error"]    = None
    _log.info("ransomwhere loaded: %d addresses across %d families",
              len(by_addr), len(families))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def lookup(address: str) -> Optional[Dict[str, Any]]:
    """Return the ransomware-family record for a crypto address, or None."""
    _ensure_loaded()
    if not isinstance(address, str) or not address:
        return None
    return (_state.get("by_addr") or {}).get(address.strip())


def extract_addresses(text: str) -> Dict[str, list]:
    """Pull crypto addresses out of free-form text. Returns
    {chain: [address, ...]}. Used by extract_iocs when the analyst
    pastes a ransom note."""
    out: Dict[str, list] = {}
    if not isinstance(text, str) or not text:
        return out
    for chain, regex in ADDRESS_REGEXES.items():
        hits = list({m.group(0) for m in regex.finditer(text)})
        if hits:
            out[chain] = hits[:30]
    return out


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":    bool(_state["loaded"]),
        "addresses": len(_state.get("by_addr") or {}),
        "families":  len(_state.get("families") or set()),
        "error":     _state.get("error"),
    }
