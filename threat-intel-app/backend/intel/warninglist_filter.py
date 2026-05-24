"""
MISP Warning List Filter
Source: github.com/MISP/misp-warninglists (MIT License)

Filters known-good IPs, CIDR ranges, domains/hostnames, URLs, and MD5/SHA1/SHA256
hashes from extracted IOCs before enrichment to eliminate false positives.

Per-type sets are loaded once at startup from vendor/misp-warninglists/lists/<*>/list.json
based on each list's `type` field. CIDR ranges are kept as ipaddress.ip_network()
objects so membership checks short-circuit on the first match.

The vendor path is preferred; the legacy `backend/intel/warninglists/` location is
used as a fallback if vendor/ isn't checked out.
"""

import ipaddress
import json
from pathlib import Path
from typing import Set, List, Tuple, Optional

# Per-type stores (populated by load_warninglists)
_benign_ips:      Set[str] = set()
_benign_cidrs:    List[ipaddress._BaseNetwork] = []
_benign_domains:  Set[str] = set()
_benign_md5:      Set[str] = set()
_benign_sha1:     Set[str] = set()
_benign_sha256:   Set[str] = set()
_benign_urls:     Set[str] = set()
_list_sources:    dict = {}     # value -> source list name (for "removed because…" reasons)
_loaded = False

# Search vendor/ first (cloned via setup_vendor.sh), fall back to legacy local copy
_REPO_ROOT = Path(__file__).resolve().parents[3]
_VENDOR_DIR = _REPO_ROOT / "threat-intel-app" / "vendor" / "misp-warninglists" / "lists"
_LOCAL_DIR  = Path(__file__).parent / "warninglists"


def _pick_dir() -> Optional[Path]:
    if _VENDOR_DIR.exists():
        return _VENDOR_DIR
    if _LOCAL_DIR.exists():
        return _LOCAL_DIR
    return None


def load_warninglists() -> dict:
    """Idempotent loader. Returns a dict of counts per type."""
    global _loaded
    if _loaded:
        return _stats()

    base = _pick_dir()
    if not base:
        print("[warninglists] vendor/misp-warninglists not found — "
              "false positive filtering disabled. Run scripts/setup_vendor.sh.")
        _loaded = True
        return _stats()

    for list_dir in sorted(base.iterdir()):
        list_file = list_dir / "list.json"
        if not list_file.exists():
            continue
        try:
            with open(list_file, encoding="utf-8") as f:
                data = json.load(f)
            list_type = (data.get("type") or "").lower()
            name      = data.get("name") or list_dir.name
            values    = data.get("list") or []
            _ingest(list_type, name, values)
        except Exception:
            continue

    _loaded = True
    stats = _stats()
    print(f"[warninglists] loaded: "
          f"{stats['ips']} IPs, {stats['cidrs']} CIDR ranges, "
          f"{stats['domains']} domains, "
          f"{stats['md5']}+{stats['sha1']}+{stats['sha256']} hashes, "
          f"{stats['urls']} URLs from {stats['lists']} lists")
    return stats


def _stats() -> dict:
    return {
        "ips":     len(_benign_ips),
        "cidrs":   len(_benign_cidrs),
        "domains": len(_benign_domains),
        "md5":     len(_benign_md5),
        "sha1":    len(_benign_sha1),
        "sha256":  len(_benign_sha256),
        "urls":    len(_benign_urls),
        "lists":   len({v for v in _list_sources.values()}),
    }


def _ingest(list_type: str, name: str, values):
    """Route values into the correct store based on MISP list type field."""
    for v in values:
        if not isinstance(v, str):
            continue
        v = v.strip()
        if not v:
            continue

        if list_type == "ip":
            # Some IP lists smuggle CIDRs anyway — detect both.
            if "/" in v:
                _add_cidr(v, name)
            else:
                _benign_ips.add(v)
                _list_sources[v] = name
        elif list_type == "cidr":
            _add_cidr(v, name)
        elif list_type in ("hostname", "domain", "fqdn"):
            d = v.lower().lstrip(".")
            _benign_domains.add(d)
            _list_sources[d] = name
        elif list_type == "md5":
            h = v.lower()
            _benign_md5.add(h)
            _list_sources[h] = name
        elif list_type == "sha1":
            h = v.lower()
            _benign_sha1.add(h)
            _list_sources[h] = name
        elif list_type == "sha256":
            h = v.lower()
            _benign_sha256.add(h)
            _list_sources[h] = name
        elif list_type == "url":
            _benign_urls.add(v.lower())
            _list_sources[v.lower()] = name


def _add_cidr(value: str, name: str):
    try:
        net = ipaddress.ip_network(value, strict=False)
        _benign_cidrs.append(net)
        _list_sources[str(net)] = name
    except Exception:
        pass


# ─── individual checks ────────────────────────────────────────────────────────
def is_benign_ip(ip: str) -> Tuple[bool, str]:
    """Return (is_benign, source_list_name)."""
    load_warninglists()
    if ip in _benign_ips:
        return True, _list_sources.get(ip, "MISP warninglist")
    try:
        addr = ipaddress.ip_address(ip)
        for net in _benign_cidrs:
            if addr in net:
                return True, _list_sources.get(str(net), "MISP CIDR")
    except Exception:
        pass
    return False, ""


def is_benign_domain(domain: str) -> Tuple[bool, str]:
    load_warninglists()
    d = domain.lower().lstrip(".")
    if d in _benign_domains:
        return True, _list_sources.get(d, "MISP warninglist")
    # Parent-domain rollup: www.google.com → google.com
    parts = d.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in _benign_domains:
            return True, _list_sources.get(parent, "MISP parent-domain match")
    return False, ""


def is_benign_hash(hash_value: str) -> Tuple[bool, str]:
    load_warninglists()
    h = hash_value.lower()
    if h in _benign_md5 or h in _benign_sha1 or h in _benign_sha256:
        return True, _list_sources.get(h, "MISP warninglist")
    return False, ""


def is_benign_url(url: str) -> Tuple[bool, str]:
    """Extract the host from a URL and check that, plus exact URL match."""
    load_warninglists()
    u = url.lower()
    if u in _benign_urls:
        return True, _list_sources.get(u, "MISP warninglist (url)")
    try:
        from urllib.parse import urlparse
        host = urlparse(u).hostname or ""
        if host:
            ok, src = is_benign_domain(host)
            if ok:
                return True, src
    except Exception:
        pass
    return False, ""


# ─── batch filter (used by triage / enrichment) ──────────────────────────────
def filter_iocs(iocs: dict) -> Tuple[dict, dict]:
    """
    Split an IOC dict into (filtered, removed) where:
      filtered: only IOCs that are NOT known-benign — these go on to enrichment
      removed:  {type: [{"ioc": v, "reason": "list name"}, …]} for analyst visibility
    """
    load_warninglists()

    filtered = {
        "ips":     [],
        "domains": [],
        "hashes":  [],
        "urls":    [],
        "emails":  list(iocs.get("emails", [])),  # never filtered
    }
    removed = {"ips": [], "domains": [], "hashes": [], "urls": []}

    for ip in iocs.get("ips", []):
        ok, src = is_benign_ip(ip)
        if ok:
            removed["ips"].append({"ioc": ip, "reason": src})
        else:
            filtered["ips"].append(ip)

    for d in iocs.get("domains", []):
        ok, src = is_benign_domain(d)
        if ok:
            removed["domains"].append({"ioc": d, "reason": src})
        else:
            filtered["domains"].append(d)

    for h in iocs.get("hashes", []):
        ok, src = is_benign_hash(h)
        if ok:
            removed["hashes"].append({"ioc": h, "reason": src})
        else:
            filtered["hashes"].append(h)

    for u in iocs.get("urls", []):
        ok, src = is_benign_url(u)
        if ok:
            removed["urls"].append({"ioc": u, "reason": src})
        else:
            filtered["urls"].append(u)

    return filtered, removed


# ─── CIRCL hashlookup (async) — known-good file lookup before enrichment ─────
async def check_hashlookup(session, hash_value: str) -> dict:
    """
    Query https://hashlookup.circl.lu/lookup/{sha256|sha1|md5}/{hash} to flag
    legitimate files (OS binaries, signed installers, etc.) before spending
    enrichment quota on them.

    Returns {} if unknown, or dict with FileName/ProductName/trust/source on hit.
    """
    import aiohttp
    h = hash_value.lower()
    htype = "sha256" if len(h) == 64 else "sha1" if len(h) == 40 else "md5" if len(h) == 32 else None
    if not htype:
        return {}
    try:
        async with session.get(
            f"https://hashlookup.circl.lu/lookup/{htype}/{h}",
            timeout=aiohttp.ClientTimeout(total=5),
        ) as r:
            if r.status != 200:
                return {}
            d = await r.json()
            if not isinstance(d, dict):
                return {}
            return {
                "FileName":    d.get("FileName"),
                "ProductName": d.get("ProductName"),
                "FileSize":    d.get("FileSize"),
                "trust":       d.get("hashlookup:trust"),
                "source":      "CIRCL hashlookup",
                "is_known_good": True,
            }
    except Exception:
        return {}


# Legacy alias kept for callers that imported the old name
async def is_known_good_hash(session, hash_value: str) -> Tuple[bool, str]:
    info = await check_hashlookup(session, hash_value)
    if info:
        return True, info.get("FileName") or info.get("ProductName") or "Known-good file"
    return False, ""
