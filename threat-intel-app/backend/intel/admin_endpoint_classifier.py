"""
Admin / sensitive-endpoint classifier.

Detects admin panels, back-office endpoints, and customer-service portals
in a URL by inspecting the leftmost subdomain label OR any path segment.
Adapted from cti-expert (MIT, Hieu Ngo, chongluadao.vn) —
handbook/admin-endpoint-indicators.md + the classify_endpoint() reference
implementation in scripts/stealer_log_parse.py.

The value over a naive `'/admin' in url` check:
  * Prefix matching on subdomain labels — `admin` catches `admin11`,
    `kef` catches `kefu`, `adm` catches `adm1n` (DGA-style admin
    subdomains).
  * Localised keywords — Chinese / Indonesian / Spanish admin/back-office
    keywords (`houtai`, `kefu`, `客服`, `后台`, `administrador`) that
    English-only matchers miss. Scam operators routinely host these.
  * Exact-label tier — generic but high-signal segments like `bo`,
    `cp`, `panel`, `merchant`, `withdraw` that prefix-match would
    overshoot on (`bo` would incorrectly hit `book`, etc.).
  * Generic terms (`login`, `signin`, `api`, `account`) are
    intentionally NOT flagged. Too common to be useful on their own;
    only matter when combined with a scam TLD, multi-account pattern,
    or raw-IP host — those amplifiers are evaluated separately.

Wired into agents.enrichment.enrich_url so every analyzed URL gets a
synchronous, network-free verdict surfaced as a per-source row in the
analyst summary. Returns the standard {verdict, summary, source} shape.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Tuple


# Subdomain-label / path-segment prefixes — anything starting with one
# of these is admin. `admin`, `adm`, `kef`, `houtai`, etc. catch typo-
# obfuscation variants the analyst would never enumerate by hand.
_ADMIN_STARTSWITH: Tuple[str, ...] = (
    "admin", "adm", "adminer", "superadmin", "webadmin", "siteadmin",
    "cpanel", "phpmyadmin", "backoffice", "backstage", "houtai",
    "kef", "kefu", "ador", "wpadmin", "glht", "sysadmin",
)

# Exact label/segment match. Generic enough that prefix-match would
# over-fire (e.g. `bo` as a prefix would catch `book`, `border`); only
# the exact label counts.
_ADMIN_EXACT = frozenset({
    "panel", "cp", "bo", "backend", "dashboard", "dash", "manage", "manager",
    "mgmt", "console", "control", "controlpanel", "master", "agent", "agents",
    "daili", "merchant", "seller", "cashier", "finance", "withdraw", "deposit",
    "recharge", "wallet", "gly", "boss", "operator", "staff", "pma",
    "jenkins", "grafana", "kibana", "portainer", "wp-admin", "wp-login",
    "administrator", "superuser", "root", "godmode",
})

# Localised admin / back-office / customer-service / agent keywords.
# Substring match — these appear inside paths or query strings too.
_LOCAL_ADMIN_RE = re.compile(r"(管理|后台|代理|客服|administrador)")

# Free / abused TLDs that disproportionately host scam admin panels.
_SCAM_TLD_RE = re.compile(
    r"\.(xyz|top|vip|online|club|cc|icu|shop|fun|sbs|lol)(?:[:/]|$)",
    re.I,
)


def classify(url: str) -> Dict[str, Any]:
    """Inspect a URL for admin / sensitive-endpoint indicators.

    Always returns the canonical RECON per-source shape so the frontend
    renderer can drop it into the per-IOC source list without special
    casing. When nothing matches, returns `is_admin=False` and a
    `verdict` of CLEAN.

    Output:
      {
        "is_admin":   bool,
        "indicator":  str  (e.g. "subdomain:kefu", "path:/admin",
                           "keyword:cn-admin", "scam_tld:.top"),
        "strong":     bool (subdomain/path matches; scam-TLD alone is False),
        "verdict":    "CLEAN" | "SUSPICIOUS" | "MALICIOUS",
        "summary":    one-line analyst-readable description,
        "source":     "admin_endpoint_classifier",
      }
    """
    out = {
        "is_admin":  False,
        "indicator": "",
        "strong":    False,
        "verdict":   "CLEAN",
        "summary":   "",
        "source":    "admin_endpoint_classifier (subdomain/path/keyword + scam-TLD amplifier)",
    }
    if not isinstance(url, str) or not url.strip():
        return out

    s = url.strip()
    # Drop non-http(s) schemes — android://, chrome-extension://, file://
    # etc. fire false positives because we'd look at the wrong host.
    sm = re.match(r"([a-z][a-z0-9+.\-]*)://", s, re.I)
    if sm and sm.group(1).lower() not in ("http", "https"):
        return out

    m = re.match(r"(?:https?://)?([^/?#]+)([/?#].*)?$", s, re.I)
    host = (m.group(1) if m else s).lower().split("@")[-1].split(":")[0]
    path = (m.group(2) or "") if m else ""
    labels = [x for x in host.split(".") if x]
    segs   = [x for x in re.split(r"[/?#&=]", path) if x]

    indicator = ""
    strong    = False

    for lab in labels:
        if any(lab.startswith(t) for t in _ADMIN_STARTSWITH) or lab in _ADMIN_EXACT:
            indicator = f"subdomain:{lab}"
            strong    = True
            break
    if not indicator:
        for seg in segs:
            sl = seg.lower()
            if any(sl.startswith(t) for t in _ADMIN_STARTSWITH) or sl in _ADMIN_EXACT:
                indicator = f"path:/{seg}"
                strong    = True
                break
    if not indicator and _LOCAL_ADMIN_RE.search(s):
        indicator = "keyword:cn-admin"
        strong    = True

    # Scam-TLD amplifier — by itself we surface it as "suspicious", not
    # admin. When combined with a strong indicator above it bumps the
    # verdict.
    scam_tld_match = _SCAM_TLD_RE.search(s)
    scam_tld = scam_tld_match.group(0).rstrip("/:") if scam_tld_match else ""

    if strong:
        out["is_admin"]  = True
        out["indicator"] = indicator
        out["strong"]    = True
        if scam_tld:
            out["verdict"] = "MALICIOUS"
            out["summary"] = (
                f"Admin / sensitive endpoint ({indicator}) on scam TLD "
                f"{scam_tld} — actor infrastructure or compromised host."
            )
        else:
            out["verdict"] = "SUSPICIOUS"
            out["summary"] = (
                f"Admin / sensitive endpoint detected ({indicator}). "
                f"Pivot via WHOIS, subdomain enumeration, and credential "
                f"reuse checks."
            )
    elif scam_tld:
        out["indicator"] = f"scam_tld:{scam_tld}"
        out["verdict"]   = "SUSPICIOUS"
        out["summary"]   = (
            f"URL on commonly abused TLD ({scam_tld}). Not an admin endpoint "
            f"on its own, but elevates the risk of any other signal."
        )
    return out


def stats() -> Dict[str, Any]:
    """Lightweight introspection for /api/status — number of patterns
    loaded. No on-disk state to verify."""
    return {
        "loaded":     True,
        "prefixes":   len(_ADMIN_STARTSWITH),
        "exact":      len(_ADMIN_EXACT),
        "scam_tlds":  len(_SCAM_TLD_RE.pattern.split("|")),
    }
