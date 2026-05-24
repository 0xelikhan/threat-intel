"""
MISP Warning List Filter
Source: github.com/MISP/misp-warninglists (MIT License)
Filters known-good IPs, domains, and hashes before enrichment to eliminate false positives.
"""
import json
from pathlib import Path
from typing import Set

_benign_ips:     Set[str] = set()
_benign_domains: Set[str] = set()
_benign_hashes:  Set[str] = set()
_loaded = False

WARNINGLIST_DIR = Path(__file__).parent / "warninglists"


def load_warninglists():
    global _benign_ips, _benign_domains, _benign_hashes, _loaded
    if _loaded:
        return
    if not WARNINGLIST_DIR.exists():
        print("Warning: warninglists not found — false positive filtering disabled")
        _loaded = True
        return
    for list_dir in WARNINGLIST_DIR.iterdir():
        list_file = list_dir / "list.json"
        if not list_file.exists():
            continue
        try:
            with open(list_file) as f:
                data = json.load(f)
            list_type = data.get("type", "")
            values    = data.get("list", [])
            if list_type in ("ip", "cidr"):
                _benign_ips.update(v.strip() for v in values)
            elif list_type in ("hostname", "domain", "fqdn"):
                _benign_domains.update(v.strip().lower() for v in values)
            elif list_type == "md5":
                _benign_hashes.update(v.strip().lower() for v in values)
        except Exception:
            continue
    _loaded = True
    print(f"Warning lists loaded: {len(_benign_ips)} IPs, "
          f"{len(_benign_domains)} domains, {len(_benign_hashes)} hashes")


def is_benign_ip(ip: str) -> bool:
    load_warninglists()
    return ip in _benign_ips


def is_benign_domain(domain: str) -> bool:
    load_warninglists()
    d = domain.lower()
    if d in _benign_domains:
        return True
    parts = d.split(".")
    for i in range(1, len(parts)):
        if ".".join(parts[i:]) in _benign_domains:
            return True
    return False


def is_benign_hash(hash_val: str) -> bool:
    load_warninglists()
    return hash_val.lower() in _benign_hashes


def filter_iocs(iocs: dict) -> tuple[dict, dict]:
    load_warninglists()
    filtered = {
        "ips":     [ip for ip in iocs.get("ips", [])     if not is_benign_ip(ip)],
        "domains": [d  for d  in iocs.get("domains", []) if not is_benign_domain(d)],
        "hashes":  [h  for h  in iocs.get("hashes", [])  if not is_benign_hash(h)],
        "urls":    iocs.get("urls", []),
        "emails":  iocs.get("emails", []),
    }
    removed = {
        "ips":     [ip for ip in iocs.get("ips", [])     if is_benign_ip(ip)],
        "domains": [d  for d  in iocs.get("domains", []) if is_benign_domain(d)],
        "hashes":  [h  for h  in iocs.get("hashes", [])  if is_benign_hash(h)],
    }
    return filtered, removed


async def is_known_good_hash(session, hash_val: str) -> tuple[bool, str]:
    import aiohttp
    hash_type = (
        "md5"    if len(hash_val) == 32 else
        "sha1"   if len(hash_val) == 40 else
        "sha256" if len(hash_val) == 64 else None
    )
    if not hash_type:
        return False, ""
    try:
        async with session.get(
            f"https://hashlookup.circl.lu/lookup/{hash_type}/{hash_val}",
            timeout=aiohttp.ClientTimeout(total=5)
        ) as r:
            if r.status == 200:
                data = await r.json()
                name = data.get("FileName") or data.get("ProductName") or "Known-good file"
                return True, name
    except Exception:
        pass
    return False, ""
