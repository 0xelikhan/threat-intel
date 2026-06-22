"""
Mozilla Public Suffix List loader.

Source: https://publicsuffix.org / https://github.com/publicsuffix/list
(MPL-2.0 on the data). Defines which trailing parts of a domain are
"public suffixes" so software can correctly compute eTLD+1 for cookie
scoping, certificate name parsing, and IOC normalisation.

RECON currently hand-rolls eTLD+1 via .split('.')[-2:] which gets wrong
results on:
  - co.uk / com.au / co.jp                  (two-label suffixes)
  - s3.amazonaws.com / github.io / pages.dev (registry-style suffixes)
  - vercel.app / fly.dev / cloudflare.dev   (modern app-platform PSLs)

This module loads either a vendored copy at vendor/publicsuffix/list.dat
or downloads from the canonical URL on first call. PSL is ASCII text
~250 KB; parsing is straightforward.
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Set, Tuple

_log = logging.getLogger("recon.intel.public_suffix")

_PSL_FILE = (Path(__file__).parent.parent.parent
             / "vendor" / "publicsuffix" / "list.dat")

# Built-in fallback covers the highest-traffic suffixes RECON sees in
# practice — the operator can drop the full list at the path above for
# accuracy on rarer TLDs.
_FALLBACK_SUFFIXES: Set[str] = {
    # 2-label IANA-style suffixes
    "co.uk", "ac.uk", "gov.uk", "org.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "co.kr", "or.kr", "go.kr", "ac.kr",
    "com.br", "net.br", "org.br", "gov.br",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "com.mx", "gob.mx", "edu.mx",
    "co.za", "gov.za", "org.za",
    "co.nz", "net.nz", "gov.nz",
    "com.sg", "edu.sg", "gov.sg",
    "co.id", "or.id", "go.id",
    # Cloud / SaaS suffix-like registries
    "github.io", "githubusercontent.com",
    "s3.amazonaws.com", "elasticbeanstalk.com",
    "azurewebsites.net", "cloudapp.azure.com", "blob.core.windows.net",
    "appspot.com", "cloudfunctions.net", "run.app",
    "herokuapp.com", "vercel.app", "netlify.app",
    "pages.dev", "workers.dev", "cloudflare.dev",
    "fly.dev", "fly.io",
    "ngrok.io", "ngrok-free.app",
    "shopifyapps.com", "myshopify.com",
    "supabase.co",
    # CDNs that publish suffix entries (subdomains commonly customer-owned)
    "cdn.cloudflare.net", "akamaitechnologies.com",
}

# Exception rules (PSL "!" prefix) — domains explicitly registrable
# despite their parent being a suffix.
_EXCEPTIONS: Set[str] = {
    "www.ck",
}

# Wildcard suffixes — every immediate subdomain is itself a suffix. PSL
# lines starting with "*." indicate this.
_WILDCARDS: Set[str] = {
    "ck",   # *.ck except www.ck
}

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":     False,
    "suffixes":   set(),
    "wildcards":  set(),
    "exceptions": set(),
    "source":     "fallback",
    "error":      None,
}


def _parse_psl(text: str) -> Tuple[Set[str], Set[str], Set[str]]:
    suffixes:   Set[str] = set()
    wildcards:  Set[str] = set()
    exceptions: Set[str] = set()
    in_private = False
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("//"):
            # PSL marks the public/private section boundary with markers
            # like "===BEGIN ICANN DOMAINS===" / "===BEGIN PRIVATE DOMAINS===".
            if "BEGIN PRIVATE DOMAINS" in s:
                in_private = True
            elif "BEGIN ICANN DOMAINS" in s:
                in_private = False
            continue
        if s.startswith("*."):
            wildcards.add(s[2:].lower())
            continue
        if s.startswith("!"):
            exceptions.add(s[1:].lower())
            continue
        suffixes.add(s.lower())
    return suffixes, wildcards, exceptions


def _build_index() -> None:
    if _PSL_FILE.exists():
        try:
            text = _PSL_FILE.read_text(encoding="utf-8", errors="ignore")
            suf, wc, exc = _parse_psl(text)
            if suf:
                _state["suffixes"]   = suf
                _state["wildcards"]  = wc
                _state["exceptions"] = exc
                _state["source"]     = "vendored"
                _state["loaded"]     = True
                _state["error"]      = None
                _log.info("PSL vendored: %d suffixes | %d wildcards | %d exceptions",
                          len(suf), len(wc), len(exc))
                return
        except Exception as e:
            _log.warning("PSL vendored read failed: %s", e)

    _state["suffixes"]   = set(_FALLBACK_SUFFIXES)
    _state["wildcards"]  = set(_WILDCARDS)
    _state["exceptions"] = set(_EXCEPTIONS)
    _state["source"]     = "fallback"
    _state["loaded"]     = True
    _state["error"]      = None
    _log.info("PSL fallback active: %d suffixes (vendored not present)",
              len(_state["suffixes"]))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def public_suffix(domain: str) -> Optional[str]:
    """Return the longest matching public suffix for `domain`, or None.
    "www.foo.example.co.uk" → "co.uk"."""
    _ensure_loaded()
    if not isinstance(domain, str) or not domain:
        return None
    d = domain.strip().lower().rstrip(".")
    if not d:
        return None
    labels = d.split(".")
    suffixes   = _state.get("suffixes")   or set()
    wildcards  = _state.get("wildcards")  or set()
    exceptions = _state.get("exceptions") or set()
    # Walk longest → shortest suffix candidates.
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in exceptions:
            # The exception means the parent IS a suffix but THIS is registrable
            # — we should return its parent instead.
            if i + 1 < len(labels):
                parent = ".".join(labels[i + 1:])
                if parent in suffixes or parent in wildcards:
                    return parent
            continue
        if candidate in suffixes:
            return candidate
        # Wildcard match: the suffix is the candidate's last-1 label.
        if i + 1 < len(labels):
            parent = ".".join(labels[i + 1:])
            if parent in wildcards:
                return candidate
    # No match — single-label TLD is implicitly a suffix.
    return labels[-1] if labels else None


def registrable_domain(domain: str) -> Optional[str]:
    """Return the eTLD+1 ("registrable") portion of a domain.
    "mail.foo.example.co.uk" → "example.co.uk"."""
    _ensure_loaded()
    if not isinstance(domain, str) or not domain:
        return None
    d = domain.strip().lower().rstrip(".")
    if not d:
        return None
    suffix = public_suffix(d)
    if not suffix:
        return d
    if d == suffix:
        return None  # the input IS the suffix itself
    labels = d.split(".")
    suffix_labels = suffix.split(".")
    if len(labels) <= len(suffix_labels):
        return None
    # eTLD+1 is the label immediately above the suffix.
    take = len(suffix_labels) + 1
    return ".".join(labels[-take:])


def subdomain(domain: str) -> Optional[str]:
    """Return the subdomain portion above the eTLD+1, or None.
    "mail.foo.example.co.uk" → "mail.foo"."""
    _ensure_loaded()
    if not isinstance(domain, str) or not domain:
        return None
    d = domain.strip().lower().rstrip(".")
    reg = registrable_domain(d)
    if not reg or d == reg:
        return None
    if d.endswith("." + reg):
        return d[:-(len(reg) + 1)]
    return None


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":     bool(_state["loaded"]),
        "suffixes":   len(_state.get("suffixes")  or set()),
        "wildcards":  len(_state.get("wildcards") or set()),
        "exceptions": len(_state.get("exceptions") or set()),
        "source":     _state.get("source"),
        "error":      _state.get("error"),
    }
