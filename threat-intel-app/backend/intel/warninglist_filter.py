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
import logging
import pickle
import time
from pathlib import Path
from typing import Set, List, Tuple, Optional

_log = logging.getLogger("recon.warninglists")

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
# Cached count snapshot produced once at load — see load_warninglists().
_STATS_CACHE: "Optional[dict]" = None

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


# Pickle cache — parsing 123 warninglist JSON files + constructing
# ~61k ipaddress.ip_network objects costs ~3.5 s per process cold-start.
# The parsed structure includes ip_network objects and per-octet CIDR
# buckets, which don't round-trip through JSON but pickle cleanly.
# Cache is invalidated when the newest .json in the source dir is
# newer than the pickle file.
_CACHE_PKL = Path(__file__).parent / "warninglist_filter.cache.pkl"
_CACHE_VERSION = 1   # bump if the cached structure shape changes


def _source_dir_mtime(base: Path) -> float:
    try:
        return max((f.stat().st_mtime
                    for d in base.iterdir()
                    for f in [d / "list.json"]
                    if f.exists()),
                    default=0.0)
    except Exception:
        return 0.0


def _load_from_cache(base: Path) -> bool:
    """Populate all module-level stores from the pickle cache when it
    exists AND is at least as new as the newest source list.json.
    Returns True on hit.

    Perf: for 1 M-entry sets, .update() from a fresh set of the same
    size adds ~1.5 s of copy overhead vs replacing the module-level
    reference directly. We rebind via `global` here because the module
    is only loaded once and every caller (is_benign_ip/domain/hash)
    resolves the name lazily each call, picking up the new binding
    transparently."""
    global _STATS_CACHE
    global _benign_ips, _benign_cidrs, _benign_domains
    global _benign_md5, _benign_sha1, _benign_sha256
    global _benign_urls, _list_sources
    global _benign_cidrs_by_octet, _benign_cidrs_v6
    try:
        if not _CACHE_PKL.exists():
            return False
        if _CACHE_PKL.stat().st_mtime < _source_dir_mtime(base):
            return False
        with open(_CACHE_PKL, "rb") as f:
            payload = pickle.load(f)
        if not isinstance(payload, dict) or payload.get("version") != _CACHE_VERSION:
            return False
        _benign_ips             = payload["benign_ips"]
        _benign_cidrs           = payload["benign_cidrs"]
        _benign_domains         = payload["benign_domains"]
        _benign_md5             = payload["benign_md5"]
        _benign_sha1            = payload["benign_sha1"]
        _benign_sha256          = payload["benign_sha256"]
        _benign_urls            = payload["benign_urls"]
        _list_sources           = payload["list_sources"]
        _benign_cidrs_by_octet  = payload.get("cidrs_by_octet") or {}
        _benign_cidrs_v6        = payload.get("cidrs_v6") or []
        _STATS_CACHE            = payload.get("stats")
        return True
    except Exception as e:
        _log.debug("warninglist cache load failed: %s", e)
        return False


def _write_cache() -> None:
    try:
        payload = {
            "version":           _CACHE_VERSION,
            "benign_ips":        _benign_ips,
            "benign_cidrs":      _benign_cidrs,
            "benign_domains":    _benign_domains,
            "benign_md5":        _benign_md5,
            "benign_sha1":       _benign_sha1,
            "benign_sha256":     _benign_sha256,
            "benign_urls":       _benign_urls,
            "list_sources":      _list_sources,
            "cidrs_by_octet":    _benign_cidrs_by_octet,
            "cidrs_v6":          _benign_cidrs_v6,
            "stats":             _STATS_CACHE,
        }
        with open(_CACHE_PKL, "wb") as f:
            pickle.dump(payload, f, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception as e:
        _log.debug("warninglist cache write failed: %s", e)


def load_warninglists() -> dict:
    """Idempotent loader. Returns a dict of counts per type.

    Short-circuits without recomputing _stats() when already loaded —
    the per-check entry points (is_benign_ip/domain/hash/url) all call
    this for the side-effect of "data is loaded" and discard the
    return value. _stats() walks _list_sources to build a set
    comprehension over thousands of entries, which used to cost ~48 ms
    per call: for an alert with 10 IPs the redundant stat work added
    nearly half a second to triage. _STATS_CACHE preserves the lazy
    return shape for callers that genuinely want the counts (the
    /api/status intel_layer rollup)."""
    global _loaded, _STATS_CACHE
    if _loaded:
        return _STATS_CACHE if _STATS_CACHE is not None else _stats()

    base = _pick_dir()
    if not base:
        _log.warning("vendor/misp-warninglists not found — false positive "
                     "filtering disabled. Run scripts/setup_vendor.sh.")
        _loaded = True
        return _stats()

    # Try the pickle cache first — saves ~3.5 s of JSON parse + ip_network
    # construction on process cold-start.
    _t0 = time.perf_counter()
    if _load_from_cache(base):
        _loaded = True
        _log.info("loaded from pickle cache: %d IPs, %d CIDR ranges, %d domains, "
                  "%d+%d+%d hashes, %d URLs from %d lists (%.2fs)",
                  _STATS_CACHE['ips'], _STATS_CACHE['cidrs'], _STATS_CACHE['domains'],
                  _STATS_CACHE['md5'], _STATS_CACHE['sha1'], _STATS_CACHE['sha256'],
                  _STATS_CACHE['urls'], _STATS_CACHE['lists'],
                  time.perf_counter() - _t0)
        return _STATS_CACHE

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
    _STATS_CACHE = _stats()
    _write_cache()
    _log.info("loaded: %d IPs, %d CIDR ranges, %d domains, %d+%d+%d hashes, "
              "%d URLs from %d lists (%.2fs; cache written)",
              _STATS_CACHE['ips'], _STATS_CACHE['cidrs'], _STATS_CACHE['domains'],
              _STATS_CACHE['md5'], _STATS_CACHE['sha1'], _STATS_CACHE['sha256'],
              _STATS_CACHE['urls'], _STATS_CACHE['lists'],
              time.perf_counter() - _t0)
    return _STATS_CACHE


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


# Bucket CIDRs by IPv4 first-octet so is_benign_ip only scans the
# networks that COULD plausibly cover the target. MISP warninglists
# ship ~100k CIDR entries (anycast / cloud / ISP ranges); without the
# index every lookup walked all of them and the loop's `addr in net`
# bit-math dominated triage even when the answer was no-match. IPv6
# stays on the full list — it's a much smaller subset and the prefix
# space is too large for a single-byte bucket.
_benign_cidrs_by_octet: "dict[int, list]" = {}
_benign_cidrs_v6:       List[ipaddress._BaseNetwork] = []


def _add_cidr(value: str, name: str):
    try:
        net = ipaddress.ip_network(value, strict=False)
        _benign_cidrs.append(net)
        _list_sources[str(net)] = name
        if isinstance(net, ipaddress.IPv4Network):
            # A /N covers (32 - N) host bits. For prefix lengths >= 8 the
            # first octet is fully determined; for < 8 the CIDR spans
            # multiple /8 buckets so we register it in each.
            if net.prefixlen >= 8:
                first = (int(net.network_address) >> 24) & 0xFF
                _benign_cidrs_by_octet.setdefault(first, []).append(net)
            else:
                # Rare: huge supernets. Pin to every /8 they cover.
                start = (int(net.network_address) >> 24) & 0xFF
                span  = 1 << (8 - net.prefixlen)
                for o in range(start, start + span):
                    _benign_cidrs_by_octet.setdefault(o, []).append(net)
        else:
            _benign_cidrs_v6.append(net)
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
    except Exception:
        return False, ""
    if isinstance(addr, ipaddress.IPv4Address):
        # First-octet bucket: walks only CIDRs whose network shares the
        # target's /8 prefix. Empty bucket → no-match in O(1).
        bucket = _benign_cidrs_by_octet.get((int(addr) >> 24) & 0xFF, ())
        for net in bucket:
            if addr in net:
                return True, _list_sources.get(str(net), "MISP CIDR")
    else:
        for net in _benign_cidrs_v6:
            if addr in net:
                return True, _list_sources.get(str(net), "MISP CIDR")
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

    # Filterable buckets are built explicitly below. Non-filterable
    # buckets (emails / cves / crypto / files / paths) pass through
    # unchanged — there's no MISP warninglist for these types, and
    # dropping them here was silently losing CVE + crypto IOCs before
    # the enrichment fan-out.
    filtered = {
        "ips":     [],
        "domains": [],
        "hashes":  [],
        "urls":    [],
    }
    for pass_through in ("emails", "cves", "crypto", "files", "paths"):
        filtered[pass_through] = list(iocs.get(pass_through, []))
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
