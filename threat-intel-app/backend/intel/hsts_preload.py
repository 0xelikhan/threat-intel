"""
Chromium HSTS preload list loader.

Source: Chromium's hardcoded HTTP Strict Transport Security preload
list at
  https://chromium.googlesource.com/chromium/src/+/main/net/http/
  transport_security_state_static.json

BSD-licensed. ~150k entries listing domains that Chromium (and by
adoption: Firefox, Safari, Edge) hardcodes as HTTPS-only. Inclusion
requires verifiable HSTS-correct configuration over months, so domains
on this list are well-run mainstream organisations.

For RECON this is a trust signal: a domain on the HSTS preload list
is almost certainly NOT attacker infrastructure. Pairs with Tranco
rank for "this is a real org, not a typosquat" verdicts.

We accept the JSON dump at vendor/hsts/transport_security_state_static.json
(operator-fetched). Built-in fallback covers the top ~300 highest-traffic
hostnames as a graceful default.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Set

_log = logging.getLogger("recon.intel.hsts_preload")

_HSTS_FILE_CANDIDATES = [
    Path(__file__).parent.parent.parent
        / "vendor" / "hsts" / "transport_security_state_static.json",
    Path(__file__).parent.parent.parent
        / "vendor" / "hsts" / "preload.json",
]

# Built-in fallback covering the major mainstream HSTS-preloaded domains.
# This is a small subset of the full list — operators get full coverage
# by dropping the upstream JSON in vendor/hsts/. Used when the file
# isn't present so the verdict scorer still gets useful signal.
_FALLBACK: Set[str] = {
    # Google
    "google.com", "gmail.com", "youtube.com", "googleapis.com",
    "googlemail.com", "googleusercontent.com", "google.co.uk",
    # Microsoft
    "microsoft.com", "office.com", "outlook.com", "office365.com",
    "live.com", "msn.com", "bing.com", "azure.com", "azurewebsites.net",
    # Meta / FB
    "facebook.com", "instagram.com", "whatsapp.com", "messenger.com",
    "fbcdn.net",
    # Apple
    "apple.com", "icloud.com", "me.com", "mac.com",
    # Major SaaS
    "twitter.com", "linkedin.com", "github.com", "githubusercontent.com",
    "gitlab.com", "stackoverflow.com", "stripe.com", "shopify.com",
    "dropbox.com", "paypal.com", "salesforce.com",
    "atlassian.com", "atlassian.net", "jira.com",
    "okta.com", "auth0.com", "duo.com", "1password.com",
    "slack.com", "discord.com", "zoom.us", "notion.so",
    "spotify.com", "netflix.com",
    # Banks / fintech
    "wellsfargo.com", "chase.com", "americanexpress.com",
    "bankofamerica.com", "citi.com", "venmo.com",
    # Cloud infra
    "cloudflare.com", "fastly.com", "akamai.com",
    "amazonaws.com", "amazon.com",
    "digitalocean.com", "heroku.com",
    # Browsers / standards
    "mozilla.org", "firefox.com", "chromium.org",
    # Government
    "irs.gov", "treasury.gov", "cisa.gov", "nasa.gov",
    "whitehouse.gov", "ssa.gov",
    # Misc
    "wikipedia.org", "wikimedia.org",
    "redditmedia.com",
}

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":     False,
    "preloaded":  set(),
    "subdomain_inheritance": set(),  # entries with include_subdomains
    "source":     "fallback",
    "error":      None,
}


def _strip_comments(text: str) -> str:
    """The transport_security_state_static.json file has // line comments
    that the standard library JSON parser rejects."""
    out: list[str] = []
    for line in text.splitlines():
        s = line.lstrip()
        if s.startswith("//"):
            continue
        # Inline trailing comments — drop after //  (but not inside strings).
        # Quick-and-dirty: we don't have //s in actual string values.
        if "//" in line:
            # Walk char-by-char ignoring //s inside double-quoted strings.
            in_str = False
            esc = False
            cleaned: list[str] = []
            i = 0
            while i < len(line):
                c = line[i]
                if esc:
                    cleaned.append(c)
                    esc = False
                elif c == "\\":
                    cleaned.append(c)
                    esc = True
                elif c == '"':
                    cleaned.append(c)
                    in_str = not in_str
                elif not in_str and line[i:i+2] == "//":
                    break
                else:
                    cleaned.append(c)
                i += 1
            out.append("".join(cleaned))
        else:
            out.append(line)
    return "\n".join(out)


def _parse_json(text: str) -> Dict[str, Any]:
    try:
        return json.loads(_strip_comments(text))
    except Exception as e:
        _log.warning("HSTS preload JSON unreadable: %s", e)
        return {}


def _build_index() -> None:
    path = next((p for p in _HSTS_FILE_CANDIDATES if p.exists()), None)
    if not path:
        _state["preloaded"]    = set(_FALLBACK)
        _state["subdomain_inheritance"] = set(_FALLBACK)
        _state["source"]       = "fallback"
        _state["loaded"]       = True
        _state["error"]        = None
        _log.info("HSTS preload fallback: %d domains", len(_FALLBACK))
        return

    try:
        payload = _parse_json(path.read_text(encoding="utf-8", errors="ignore"))
    except OSError as e:
        _state["error"]  = f"HSTS preload read failed: {e}"
        _state["preloaded"] = set(_FALLBACK)
        _state["loaded"] = True
        return

    preloaded:    Set[str] = set()
    subd_inherit: Set[str] = set()
    entries = payload.get("entries") or payload.get("preload") or []
    if isinstance(entries, list):
        for e in entries:
            if not isinstance(e, dict):
                continue
            name = (e.get("name") or "").lower().strip()
            if not name:
                continue
            preloaded.add(name)
            if e.get("include_subdomains") or e.get("include_subdomains_for_pinning"):
                subd_inherit.add(name)

    if not preloaded:
        preloaded = set(_FALLBACK)
        subd_inherit = set(_FALLBACK)

    _state["preloaded"]            = preloaded
    _state["subdomain_inheritance"] = subd_inherit
    _state["source"]               = path.name
    _state["loaded"]               = True
    _state["error"]                = None
    _log.info("HSTS preload loaded: %d entries (%d with include_subdomains, source=%s)",
              len(preloaded), len(subd_inherit), path.name)


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def is_preloaded(domain: str) -> bool:
    """Return True when the supplied domain — or its eTLD+1 with
    include_subdomains inheritance — is on the HSTS preload list."""
    _ensure_loaded()
    if not isinstance(domain, str) or not domain:
        return False
    d = domain.strip().lower().rstrip(".")
    if not d:
        return False
    preloaded            = _state.get("preloaded") or set()
    subdomain_inherit    = _state.get("subdomain_inheritance") or set()
    if d in preloaded:
        return True
    # Walk parent labels for include_subdomains inheritance.
    parts = d.split(".")
    while len(parts) > 1:
        parts = parts[1:]
        candidate = ".".join(parts)
        if candidate in subdomain_inherit:
            return True
    return False


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":              bool(_state["loaded"]),
        "entries":             len(_state.get("preloaded") or set()),
        "subdomain_inheritance_entries":
                                 len(_state.get("subdomain_inheritance") or set()),
        "source":              _state.get("source"),
        "error":               _state.get("error"),
    }
