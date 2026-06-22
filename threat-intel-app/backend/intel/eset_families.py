"""
ESET malware-ioc family-keyed IOC corpus loader.

The repo (https://github.com/eset/malware-ioc, BSD-2-Clause) publishes
per-family folders — agrius, attor, blacklotus, bootkitty, cdrthief,
danabot, dukes, gamaredon, industroyer, kobalos, lazarus, moustachedbouncer,
mustang-panda, occamy, oceanlotus, oilrig, polonium, stantinko, sandworm,
turla, winnti, etc. Each folder mixes CSV IOC lists, .yar rules, .txt
hash dumps, and PDF reports.

This module builds an in-memory inverted index:

  hash   → family
  domain → family
  ip     → family

so the enrichment fan-out can answer "is this IOC associated with a
known ESET-tracked actor cluster" without an HTTP round-trip.
"""

from __future__ import annotations

import csv
import logging
import re
import threading
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

_log = logging.getLogger("recon.intel.eset_families")

_ESET_ROOT = (Path(__file__).parent.parent.parent
              / "vendor" / "eset-malware-ioc")

# Module-level state — built once on first call, copied/read concurrently.
_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":         False,
    "hash_to_family": {},   # dict[str, str]
    "domain_to_family": {}, # dict[str, str]
    "ip_to_family":   {},   # dict[str, str]
    "families":       set(),
    "error":          None,
}

# IOC regexes. Anchored loosely — these run over CSV/TXT lines, not free-
# form text, so we can be greedy.
_HASH_RE   = re.compile(r"\b([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")
_DOMAIN_RE = re.compile(r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,}"
                        r"[a-zA-Z]{2,24})\b")
_IP_RE     = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}"
                        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\b")


def _ioc_files(family_root: Path) -> List[Path]:
    """The IOC-bearing files in an ESET family folder. Skip PDF reports
    and binary samples — we only scrape text formats."""
    out: List[Path] = []
    for ext in (".csv", ".txt"):
        out.extend(family_root.rglob(f"*{ext}"))
    return out


def _normalise_family(name: str) -> str:
    """ESET folder names are kebab-case. Capitalise for the analyst view."""
    return name.replace("_", "-").lower()


def _ingest_file(path: Path, family: str,
                 hash_idx: Dict[str, str],
                 dom_idx:  Dict[str, str],
                 ip_idx:   Dict[str, str]) -> None:
    try:
        if path.stat().st_size > 4_000_000:  # 4 MB cap per IOC file
            return
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return

    # Try CSV first — many ESET files are tab/comma separated; the regex
    # fallback below catches anything the csv reader misses.
    if path.suffix.lower() == ".csv":
        try:
            reader = csv.reader(StringIO(text))
            for row in reader:
                for cell in row:
                    _scan_blob(cell, family, hash_idx, dom_idx, ip_idx)
        except Exception:
            pass

    # Regex sweep over the whole file — captures hashes/domains/IPs
    # regardless of column shape or whitespace.
    _scan_blob(text, family, hash_idx, dom_idx, ip_idx)


def _scan_blob(blob: str, family: str,
               hash_idx: Dict[str, str],
               dom_idx:  Dict[str, str],
               ip_idx:   Dict[str, str]) -> None:
    for h in _HASH_RE.finditer(blob):
        hkey = h.group(1).lower()
        # First-family-wins per IOC. If two ESET families share a hash
        # that's a notable signal (likely a shared toolset) — we surface
        # the first index and accept the imprecision; downstream code
        # can call match() and dedupe.
        hash_idx.setdefault(hkey, family)
    for d in _DOMAIN_RE.finditer(blob):
        dkey = d.group(1).lower().rstrip(".")
        if "." in dkey and not dkey[0].isdigit():
            # Skip obvious non-IOC tokens that look like domains
            # (filenames with dots, version numbers, etc).
            if dkey.endswith((".exe", ".dll", ".sys", ".pdf", ".doc",
                              ".docx", ".xls", ".xlsx", ".yar", ".yara")):
                continue
            dom_idx.setdefault(dkey, family)
    for i in _IP_RE.finditer(blob):
        ip = i.group(0)
        if ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
            ip_idx.setdefault(ip, family)


def _build_index() -> None:
    if not _ESET_ROOT.exists():
        _state["error"]  = f"eset-malware-ioc dir not present at {_ESET_ROOT}"
        _state["loaded"] = True
        return

    hash_idx:   Dict[str, str] = {}
    dom_idx:    Dict[str, str] = {}
    ip_idx:     Dict[str, str] = {}
    families:   Set[str] = set()

    for child in sorted(_ESET_ROOT.iterdir()):
        if not child.is_dir() or child.name.startswith("."):
            continue
        family = _normalise_family(child.name)
        families.add(family)
        for f in _ioc_files(child):
            _ingest_file(f, family, hash_idx, dom_idx, ip_idx)

    _state["hash_to_family"]   = hash_idx
    _state["domain_to_family"] = dom_idx
    _state["ip_to_family"]     = ip_idx
    _state["families"]         = families
    _state["loaded"]           = True
    _state["error"]            = None
    _log.info("ESET malware-ioc loaded: %d families | %d hashes | %d domains | %d ips",
              len(families), len(hash_idx), len(dom_idx), len(ip_idx))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def lookup_hash(h: str) -> Optional[str]:
    """Return the ESET-tracked family name for a hash, or None."""
    _ensure_loaded()
    if not isinstance(h, str) or not h:
        return None
    return (_state.get("hash_to_family") or {}).get(h.lower().strip())


def lookup_domain(d: str) -> Optional[str]:
    _ensure_loaded()
    if not isinstance(d, str) or not d:
        return None
    return (_state.get("domain_to_family") or {}).get(d.lower().strip().rstrip("."))


def lookup_ip(ip: str) -> Optional[str]:
    _ensure_loaded()
    if not isinstance(ip, str) or not ip:
        return None
    return (_state.get("ip_to_family") or {}).get(ip.strip())


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":   bool(_state["loaded"]),
        "families": len(_state.get("families") or set()),
        "hashes":   len(_state.get("hash_to_family") or {}),
        "domains":  len(_state.get("domain_to_family") or {}),
        "ips":      len(_state.get("ip_to_family") or {}),
        "error":    _state.get("error"),
    }
