"""
endoflife.date API client.

Source: https://endoflife.date (MIT). Crowdsourced, freely-licensed
catalogue of ~250 software product lifecycles — when each major
version was released, when it goes EOL for support, when extended
support ends, etc.

API shape (all free, no key, JSON):
  GET /api/<product>.json                  → all releases
  GET /api/<product>/<cycle>.json          → one release cycle

This module powers a small, focused enrichment: given a product name
and a version observed in an alert, answer "is this version EOL?
when did it go EOL? how many months ago?". Augments CVE context with
temporal urgency: a CVE on Python 3.7 (EOL since 2023-06) is a "no
fix forthcoming" situation; the analyst report should reflect that.
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.intel.endoflife")

# In-memory cache to spare endoflife.date from per-IOC repeat queries.
# {product: {fetched_at, data}}. TTL = 24h since lifecycle data only
# refreshes when upstream publishes new EOL dates.
_TTL_S = 24 * 3600
_CACHE: Dict[str, Dict[str, Any]] = {}


# Map of common product NAMES (free-text from alert) to endoflife.date
# slugs. Keys are lowercase, stripped.
_PRODUCT_SLUGS = {
    # OS
    "windows":           "windows",
    "windows server":    "windows-server",
    "rhel":              "rhel",
    "red hat":           "rhel",
    "ubuntu":            "ubuntu",
    "debian":            "debian",
    "centos":            "centos",
    "rocky linux":       "rocky-linux",
    "amazon linux":      "amazon-linux",
    "fedora":            "fedora",
    "macos":             "macos",
    "android":           "android",
    "ios":               "ios",
    # Languages / runtimes
    "python":            "python",
    "node.js":           "nodejs",
    "nodejs":            "nodejs",
    "node":              "nodejs",
    "ruby":              "ruby",
    "go":                "go",
    "golang":            "go",
    "rust":              "rust",
    "java":              "openjdk",
    "openjdk":           "openjdk",
    "dotnet":            "dotnet",
    ".net":              "dotnet",
    "php":               "php",
    # Browsers
    "chrome":            "chrome",
    "firefox":           "firefox",
    "safari":            "safari",
    # Web servers
    "nginx":             "nginx",
    "apache":            "apache",
    "apache http":       "apache",
    "iis":               "iis",
    # Databases
    "postgresql":        "postgresql",
    "postgres":          "postgresql",
    "mysql":             "mysql",
    "mariadb":           "mariadb",
    "mongodb":           "mongodb",
    "redis":             "redis",
    "elasticsearch":     "elasticsearch",
    "kafka":             "apache-kafka",
    "rabbitmq":          "rabbitmq",
    # Container / orchestration
    "kubernetes":        "kubernetes",
    "k8s":               "kubernetes",
    "docker":            "docker-engine",
    "containerd":        "containerd",
    # Other infra
    "jenkins":           "jenkins",
    "gitlab":            "gitlab",
    "wordpress":         "wordpress",
    "drupal":            "drupal",
    "joomla":            "joomla",
    "exchange":          "exchange-server",
    "sql server":        "mssqlserver",
    "mssql":             "mssqlserver",
    "vmware":            "vmware-vsphere",
    "vsphere":           "vmware-vsphere",
    "vcenter":           "vmware-vsphere",
    "esxi":              "esxi",
}


def slug_for(product_name: str) -> Optional[str]:
    """Look up the endoflife.date slug for a free-text product name."""
    if not isinstance(product_name, str) or not product_name:
        return None
    norm = product_name.strip().lower()
    if norm in _PRODUCT_SLUGS:
        return _PRODUCT_SLUGS[norm]
    # Partial-match: any registered key contained in the input
    for key, slug in _PRODUCT_SLUGS.items():
        if key in norm and len(key) >= 4:
            return slug
    return None


async def _fetch_product(session, slug: str) -> Optional[List[Dict[str, Any]]]:
    cached = _CACHE.get(slug)
    if cached and (time.time() - cached["fetched_at"]) < _TTL_S:
        return cached["data"]
    try:
        from agents.enrichment import _get
        r = await _get(
            session, f"https://endoflife.date/api/{slug}.json",
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "application/json"},
            timeout=8,
        )
    except Exception as e:
        _log.debug("endoflife fetch failed for %s: %s", slug, e)
        return None
    if not isinstance(r, list):
        return None
    _CACHE[slug] = {"fetched_at": time.time(), "data": r}
    return r


def _months_since(date_str: str) -> Optional[int]:
    try:
        d = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except Exception:
        return None
    now = datetime.now(timezone.utc)
    return max(0, (now.year - d.year) * 12 + (now.month - d.month))


async def check(session, product: str, version: str) -> Dict[str, Any]:
    """Return EOL context for `product version`. Empty dict when product
    isn't in the catalogue or version doesn't match any cycle."""
    slug = slug_for(product)
    if not slug:
        return {"source": "endoflife.date", "found": False,
                "summary": f"endoflife.date has no slug for product '{product}'."}
    data = await _fetch_product(session, slug)
    if not data:
        return {"source": "endoflife.date", "found": False,
                "error_type": "unreachable",
                "summary": f"endoflife.date data unavailable for {slug}."}

    # Match version against cycles. endoflife.date entries have shape:
    #   {"cycle":"3.7", "eol":"2023-06-27", "latest":"3.7.17", ...}
    ver_norm = (version or "").strip()
    if not ver_norm:
        return {"source": "endoflife.date", "found": False,
                "summary": f"endoflife.date: {slug} catalogue loaded but no version supplied."}

    # Try direct cycle match; if not, try the major.minor portion of
    # the supplied version.
    candidates = [ver_norm]
    parts = ver_norm.split(".")
    if len(parts) >= 2:
        candidates.append(f"{parts[0]}.{parts[1]}")
    if len(parts) >= 1:
        candidates.append(parts[0])

    cycle_meta: Optional[Dict[str, Any]] = None
    for cand in candidates:
        for cyc in data:
            if str(cyc.get("cycle")) == cand:
                cycle_meta = cyc
                break
        if cycle_meta:
            break
    if not cycle_meta:
        return {"source": "endoflife.date", "found": False,
                "summary": f"endoflife.date: no matching cycle for {slug} {ver_norm}."}

    eol = cycle_meta.get("eol")
    # eol field can be True/False (no-date), or a date string.
    is_eol = False
    eol_date = ""
    months_since = None
    if isinstance(eol, bool):
        is_eol = bool(eol)
    elif isinstance(eol, str):
        eol_date = eol
        m_since = _months_since(eol)
        if m_since is not None:
            is_eol = m_since >= 0   # past date
            months_since = m_since

    summary_bits = [f"endoflife.date: {slug} {cycle_meta.get('cycle')}"]
    if is_eol and eol_date:
        summary_bits.append(f"EOL since {eol_date}"
                            + (f" ({months_since} months ago)"
                               if months_since else ""))
    elif eol_date:
        summary_bits.append(f"EOL planned {eol_date}")
    if cycle_meta.get("latest"):
        summary_bits.append(f"latest patch {cycle_meta['latest']}")

    return {
        "source":         "endoflife.date",
        "found":          True,
        "product":        slug,
        "cycle":          cycle_meta.get("cycle"),
        "is_eol":         is_eol,
        "eol_date":       eol_date or None,
        "months_since_eol": months_since,
        "latest":         cycle_meta.get("latest"),
        "verdict":        "SUSPICIOUS" if is_eol else "CLEAN",
        "summary":        " — ".join(summary_bits),
    }
