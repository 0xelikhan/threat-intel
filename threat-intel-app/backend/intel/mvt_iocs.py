"""
Mobile Verification Toolkit (MVT) IOC loader.

Source: https://github.com/mvt-project/mvt (Apache-2.0). MVT ships
curated STIX2 IOC bundles for mobile-targeted spyware: Pegasus (NSO
Group), Predator, RCS Lab, BadBazaar, Stalkerware Hunting Group, etc.

The IOCs live in vendor/mvt/<bundle>.stix2 — each file is a STIX 2.0
bundle with Indicators carrying patterns like:

  [file:hashes.MD5 = '...']
  [domain-name:value = '...']
  [url:value = '...']
  [ipv4-addr:value = '...']

This module walks the bundles, extracts the patterns into a typed
inverted index, and exposes:

  lookup_hash(h)    → list of {family, bundle, ref}
  lookup_domain(d)  → ...
  lookup_url(u)     → ...
  lookup_ip(ip)     → ...

Fills the mobile-spyware gap that no other RECON data source covers.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.intel.mvt_iocs")

# Possible vendoring layouts: MVT 2.x ships .stix2 files inside the
# `mvt/indicators/` package dir. The fetcher script can target this
# subdir or just clone the whole repo.
_MVT_CANDIDATES = [
    Path(__file__).parent.parent.parent / "vendor" / "mvt" / "indicators",
    Path(__file__).parent.parent.parent / "vendor" / "mvt-indicators",
    Path(__file__).parent.parent.parent / "vendor" / "mvt",
]

_PATTERN_RE = {
    "hash_md5":    re.compile(r"file:hashes\.['\"]?MD5['\"]?\s*=\s*'([^']+)'", re.IGNORECASE),
    "hash_sha1":   re.compile(r"file:hashes\.['\"]?SHA-?1['\"]?\s*=\s*'([^']+)'", re.IGNORECASE),
    "hash_sha256": re.compile(r"file:hashes\.['\"]?SHA-?256['\"]?\s*=\s*'([^']+)'", re.IGNORECASE),
    "domain":      re.compile(r"domain-name:value\s*=\s*'([^']+)'", re.IGNORECASE),
    "url":         re.compile(r"url:value\s*=\s*'([^']+)'", re.IGNORECASE),
    "ipv4":        re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'", re.IGNORECASE),
    "email":       re.compile(r"email-addr:value\s*=\s*'([^']+)'", re.IGNORECASE),
}

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":     False,
    "by_hash":    {},
    "by_domain":  {},
    "by_url":     {},
    "by_ip":      {},
    "by_email":   {},
    "families":   set(),
    "error":      None,
}


def _find_root() -> Optional[Path]:
    for c in _MVT_CANDIDATES:
        if c.exists() and any(c.rglob("*.stix2")):
            return c
    return None


def _family_from_path(path: Path) -> str:
    """Bundle filenames like `pegasus.stix2`, `predator.stix2`,
    `rcs_lab.stix2` map directly to the spyware family."""
    return path.stem.replace("_", " ").title()


def _ingest_bundle(path: Path,
                   by_hash:   Dict[str, Dict[str, str]],
                   by_domain: Dict[str, Dict[str, str]],
                   by_url:    Dict[str, Dict[str, str]],
                   by_ip:     Dict[str, Dict[str, str]],
                   by_email:  Dict[str, Dict[str, str]],
                   families:  set) -> None:
    try:
        if path.stat().st_size > 8_000_000:
            return  # absurdly large STIX bundle — skip
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    try:
        bundle = json.loads(text)
    except Exception:
        # Some MVT bundles are STIX2 NDJSON / YAML; tolerant of either.
        return
    family = _family_from_path(path)
    families.add(family)
    objs = bundle.get("objects") if isinstance(bundle, dict) else []
    if not isinstance(objs, list):
        return
    for obj in objs:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern") or ""
        ref     = obj.get("name") or obj.get("id") or ""
        ref     = ref[:120]
        entry_base = {"family": family, "ref": ref}
        for h in _PATTERN_RE["hash_md5"].findall(pattern):
            by_hash.setdefault(h.lower(), entry_base)
        for h in _PATTERN_RE["hash_sha1"].findall(pattern):
            by_hash.setdefault(h.lower(), entry_base)
        for h in _PATTERN_RE["hash_sha256"].findall(pattern):
            by_hash.setdefault(h.lower(), entry_base)
        for d in _PATTERN_RE["domain"].findall(pattern):
            by_domain.setdefault(d.lower().rstrip("."), entry_base)
        for u in _PATTERN_RE["url"].findall(pattern):
            by_url.setdefault(u, entry_base)
        for ip in _PATTERN_RE["ipv4"].findall(pattern):
            by_ip.setdefault(ip, entry_base)
        for e in _PATTERN_RE["email"].findall(pattern):
            by_email.setdefault(e.lower(), entry_base)


def _build_index() -> None:
    root = _find_root()
    if not root:
        _state["error"]  = ("mvt indicator bundles not present at any of "
                            f"{[str(p) for p in _MVT_CANDIDATES]}")
        _state["loaded"] = True
        return

    by_hash:   Dict[str, Dict[str, str]] = {}
    by_domain: Dict[str, Dict[str, str]] = {}
    by_url:    Dict[str, Dict[str, str]] = {}
    by_ip:     Dict[str, Dict[str, str]] = {}
    by_email:  Dict[str, Dict[str, str]] = {}
    families:  set = set()

    for path in root.rglob("*.stix2"):
        if not path.is_file():
            continue
        _ingest_bundle(path, by_hash, by_domain, by_url, by_ip, by_email,
                       families)

    _state["by_hash"]   = by_hash
    _state["by_domain"] = by_domain
    _state["by_url"]    = by_url
    _state["by_ip"]     = by_ip
    _state["by_email"]  = by_email
    _state["families"]  = families
    _state["loaded"]    = True
    _state["error"]     = None
    _log.info("MVT mobile IOCs loaded: %d families | %d hashes | %d domains "
              "| %d urls | %d ips | %d emails",
              len(families), len(by_hash), len(by_domain), len(by_url),
              len(by_ip), len(by_email))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def lookup_hash(h: str) -> Optional[Dict[str, str]]:
    _ensure_loaded()
    if not isinstance(h, str):
        return None
    return (_state.get("by_hash") or {}).get(h.lower().strip())


def lookup_domain(d: str) -> Optional[Dict[str, str]]:
    _ensure_loaded()
    if not isinstance(d, str):
        return None
    return (_state.get("by_domain") or {}).get(d.lower().strip().rstrip("."))


def lookup_url(u: str) -> Optional[Dict[str, str]]:
    _ensure_loaded()
    if not isinstance(u, str):
        return None
    return (_state.get("by_url") or {}).get(u.strip())


def lookup_ip(ip: str) -> Optional[Dict[str, str]]:
    _ensure_loaded()
    if not isinstance(ip, str):
        return None
    return (_state.get("by_ip") or {}).get(ip.strip())


def lookup_email(e: str) -> Optional[Dict[str, str]]:
    _ensure_loaded()
    if not isinstance(e, str):
        return None
    return (_state.get("by_email") or {}).get(e.lower().strip())


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":   bool(_state["loaded"]),
        "families": len(_state.get("families") or set()),
        "hashes":   len(_state.get("by_hash") or {}),
        "domains":  len(_state.get("by_domain") or {}),
        "urls":     len(_state.get("by_url") or {}),
        "ips":      len(_state.get("by_ip") or {}),
        "emails":   len(_state.get("by_email") or {}),
        "error":    _state.get("error"),
    }
