"""
FireHOL IP blocklists loader.

Source: https://github.com/firehol/blocklist-ipsets (Apache-2.0). The
canonical aggregate of 400+ curated IP blocklists for Tor exits, malware
C2, spam, brute-forcers, DDoS-bots, and miscellaneous abuse.

Each .ipset / .netset file is a plain text list of IPs / CIDRs with
header comments carrying the list's purpose, source URL, refresh
cadence, and false-positive expectations. We build a single
"IP → list[blocklist names]" inverted index so enrich_ip can answer
"this IP is on 3 blocklists (firehol_level1, blocklist_de_ssh, ...)"
with the same shape as the existing local_feeds branch.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

_log = logging.getLogger("recon.intel.firehol")

_FIREHOL_ROOT = (Path(__file__).parent.parent.parent
                 / "vendor" / "firehol-blocklists")

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":      False,
    "by_ip":       {},     # dict[str, set(blocklist_name)]
    "by_cidr":     {},     # dict[ipaddress.IPv4Network, set(blocklist_name)]
    "blocklists":  set(),
    "total_ips":   0,
    "total_cidrs": 0,
    "error":       None,
}


def _parse_list_file(path: Path,
                     by_ip:   Dict[str, Set[str]],
                     by_cidr: Dict[Any, Set[str]],
                     blocklists: Set[str]) -> None:
    name = path.stem  # e.g. "firehol_level1", "blocklist_de_ssh"
    blocklists.add(name)
    try:
        if path.stat().st_size > 8_000_000:
            return  # very large list; skip to keep memory bounded
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "/" in s:
            try:
                net = ipaddress.ip_network(s, strict=False)
                if isinstance(net, ipaddress.IPv4Network) and net.prefixlen >= 16:
                    # Only index /16 and tighter to keep CIDR walk fast.
                    by_cidr.setdefault(net, set()).add(name)
            except ValueError:
                continue
        else:
            try:
                ipaddress.ip_address(s)
            except ValueError:
                continue
            by_ip.setdefault(s, set()).add(name)


def _build_index() -> None:
    if not _FIREHOL_ROOT.exists():
        _state["error"]  = f"firehol-blocklists dir not present at {_FIREHOL_ROOT}"
        _state["loaded"] = True
        return

    by_ip:      Dict[str, Set[str]] = {}
    by_cidr:    Dict[Any, Set[str]] = {}
    blocklists: Set[str] = set()

    for ext in ("*.ipset", "*.netset"):
        for path in _FIREHOL_ROOT.rglob(ext):
            if not path.is_file():
                continue
            _parse_list_file(path, by_ip, by_cidr, blocklists)

    _state["by_ip"]       = by_ip
    _state["by_cidr"]     = by_cidr
    _state["blocklists"]  = blocklists
    _state["total_ips"]   = len(by_ip)
    _state["total_cidrs"] = len(by_cidr)
    _state["loaded"]      = True
    _state["error"]       = None
    _log.info("FireHOL loaded: %d blocklists | %d ips | %d cidrs",
              len(blocklists), len(by_ip), len(by_cidr))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def lookup(ip: str) -> List[str]:
    """Return the names of every FireHOL blocklist this IP belongs to."""
    _ensure_loaded()
    if not isinstance(ip, str) or not ip:
        return []
    by_ip = _state.get("by_ip") or {}
    direct = by_ip.get(ip)
    if direct:
        return sorted(direct)
    # CIDR walk — only for IPv4 (FireHOL is v4-only in practice).
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return []
    if not isinstance(addr, ipaddress.IPv4Address):
        return []
    hits: Set[str] = set()
    for net, names in (_state.get("by_cidr") or {}).items():
        try:
            if addr in net:
                hits |= names
        except TypeError:
            continue
    return sorted(hits)


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":     bool(_state["loaded"]),
        "blocklists": len(_state.get("blocklists") or set()),
        "ips":        _state.get("total_ips", 0),
        "cidrs":      _state.get("total_cidrs", 0),
        "error":      _state.get("error"),
    }
