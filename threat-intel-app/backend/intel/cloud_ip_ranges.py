"""
Cloud provider IP range loader.

Major cloud providers publish authoritative IP-range JSON feeds:

  - AWS:        https://ip-ranges.amazonaws.com/ip-ranges.json
  - Cloudflare: https://www.cloudflare.com/ips-v4 + ips-v6
  - Azure:      https://www.microsoft.com/en-us/download/details.aspx?id=56519
                (the actual JSON URL changes weekly; we accept any
                ServiceTags_Public_*.json under vendor/azure-service-tags/)
  - GCP:        https://www.gstatic.com/ipranges/cloud.json
  - Fastly:     https://api.fastly.com/public-ip-list
  - GitHub:     https://api.github.com/meta  (actions, hooks, web, api)

This module fetches all six at lifespan-warm time, caches the parsed
CIDR lists in memory, and exposes:

  lookup(ip) → {"provider": "AWS", "region": "us-east-1",
                "service": "EC2", "cidr": "..."} or None

When triage / enrichment surfaces a cloud-belonging IP, the verdict
scorer treats it as "well-known infrastructure" rather than attacker
infra — same trust-signal class as Tranco for domains.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger("recon.intel.cloud_ip_ranges")

_TTL_S = 24 * 3600  # daily refresh

_FEEDS = {
    "aws":   "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "gcp":   "https://www.gstatic.com/ipranges/cloud.json",
    "github": "https://api.github.com/meta",
    # Fastly + Cloudflare expose JSON-ish or plain-text formats with
    # known stable URLs; we handle both.
    "fastly":     "https://api.fastly.com/public-ip-list",
    "cloudflare_v4": "https://www.cloudflare.com/ips-v4",
    "cloudflare_v6": "https://www.cloudflare.com/ips-v6",
}

_LOAD_LOCK = asyncio.Lock()
_state: Dict[str, Any] = {
    "loaded_at": 0.0,
    "entries":   [],     # list[(network, {provider, region, service})]
    "by_provider": {},   # dict[provider, count]
    "error":     None,
}


def _add_cidr(entries: List[Tuple[Any, Dict[str, str]]],
              cidr: str, provider: str,
              region: str = "", service: str = "") -> None:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        return
    entries.append((net, {"provider": provider, "region": region or "",
                           "service": service or "", "cidr": str(net)}))


def _parse_aws(payload: Any, entries: List[Tuple[Any, Dict[str, str]]]) -> None:
    if not isinstance(payload, dict):
        return
    for r in payload.get("prefixes") or []:
        if isinstance(r, dict):
            _add_cidr(entries, r.get("ip_prefix", ""), "AWS",
                       r.get("region", ""), r.get("service", ""))
    for r in payload.get("ipv6_prefixes") or []:
        if isinstance(r, dict):
            _add_cidr(entries, r.get("ipv6_prefix", ""), "AWS",
                       r.get("region", ""), r.get("service", ""))


def _parse_gcp(payload: Any, entries: List[Tuple[Any, Dict[str, str]]]) -> None:
    if not isinstance(payload, dict):
        return
    for r in payload.get("prefixes") or []:
        if not isinstance(r, dict):
            continue
        cidr = r.get("ipv4Prefix") or r.get("ipv6Prefix") or ""
        _add_cidr(entries, cidr, "GCP",
                   r.get("scope", ""), r.get("service", ""))


def _parse_github(payload: Any, entries: List[Tuple[Any, Dict[str, str]]]) -> None:
    if not isinstance(payload, dict):
        return
    for service in ("hooks", "web", "api", "git", "packages", "pages",
                    "importer", "actions", "dependabot", "copilot"):
        for cidr in payload.get(service) or []:
            _add_cidr(entries, str(cidr), "GitHub", "", service)


def _parse_fastly(payload: Any, entries: List[Tuple[Any, Dict[str, str]]]) -> None:
    if not isinstance(payload, dict):
        return
    for cidr in payload.get("addresses") or []:
        _add_cidr(entries, str(cidr), "Fastly")
    for cidr in payload.get("ipv6_addresses") or []:
        _add_cidr(entries, str(cidr), "Fastly")


def _parse_cloudflare_text(text: str, family: str,
                           entries: List[Tuple[Any, Dict[str, str]]]) -> None:
    if not isinstance(text, str):
        return
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            _add_cidr(entries, s, "Cloudflare", "", family)


def _parse_azure_service_tags(payload: Any,
                              entries: List[Tuple[Any, Dict[str, str]]]) -> None:
    """Azure publishes its ranges as ServiceTags_Public_*.json blobs.
    The schema:
       {"values": [{"name": "AzureCloud.eastus",
                     "properties": {"region": "eastus", "systemService": "",
                                    "addressPrefixes": ["x.x.x.x/y", ...]}}, ...]}
    """
    if not isinstance(payload, dict):
        return
    for v in payload.get("values") or []:
        if not isinstance(v, dict):
            continue
        props = v.get("properties") or {}
        region  = props.get("region") or ""
        service = (props.get("systemService") or v.get("name") or "")[:80]
        for cidr in props.get("addressPrefixes") or []:
            _add_cidr(entries, str(cidr), "Azure", region, service)


async def _fetch(session, url: str, json_mode: bool = True):
    from agents.enrichment import _get
    try:
        if json_mode:
            return await _get(session, url, timeout=15,
                              headers={"User-Agent": "RECON-ThreatIntel/1.0",
                                       "Accept": "application/json"})
        return await _get(session, url, timeout=15, json_response=False,
                          headers={"User-Agent": "RECON-ThreatIntel/1.0",
                                   "Accept": "text/plain"})
    except TypeError:
        return await _get(session, url, timeout=15,
                          headers={"User-Agent": "RECON-ThreatIntel/1.0",
                                   "Accept": "application/json"})


async def _refresh(session) -> None:
    """Fetch every cloud provider IP feed concurrently + parse into the
    in-memory CIDR list. Azure is vendored (no single stable URL)."""
    entries: List[Tuple[Any, Dict[str, str]]] = []
    by_provider: Dict[str, int] = {}

    # Fan out the API/JSON fetches
    aws_r, gcp_r, gh_r, fast_r, cf4_r, cf6_r = await asyncio.gather(
        _fetch(session, _FEEDS["aws"]),
        _fetch(session, _FEEDS["gcp"]),
        _fetch(session, _FEEDS["github"]),
        _fetch(session, _FEEDS["fastly"]),
        _fetch(session, _FEEDS["cloudflare_v4"], json_mode=False),
        _fetch(session, _FEEDS["cloudflare_v6"], json_mode=False),
        return_exceptions=True,
    )
    if isinstance(aws_r, dict):    _parse_aws(aws_r, entries)
    if isinstance(gcp_r, dict):    _parse_gcp(gcp_r, entries)
    if isinstance(gh_r,  dict):    _parse_github(gh_r, entries)
    if isinstance(fast_r, dict):   _parse_fastly(fast_r, entries)
    if isinstance(cf4_r, str):     _parse_cloudflare_text(cf4_r, "v4", entries)
    if isinstance(cf6_r, str):     _parse_cloudflare_text(cf6_r, "v6", entries)

    # Azure: vendored. Walk vendor/azure-service-tags/*.json.
    from pathlib import Path
    azure_root = (Path(__file__).parent.parent.parent
                  / "vendor" / "azure-service-tags")
    if azure_root.exists():
        for path in azure_root.glob("ServiceTags_Public_*.json"):
            try:
                payload = json.loads(path.read_text(encoding="utf-8",
                                                    errors="ignore"))
                _parse_azure_service_tags(payload, entries)
            except Exception:
                continue

    for net, meta in entries:
        by_provider[meta["provider"]] = by_provider.get(meta["provider"], 0) + 1

    _state["entries"]     = entries
    _state["by_provider"] = by_provider
    _state["loaded_at"]   = time.time()
    _state["error"]       = None
    _log.info("Cloud IP ranges loaded: %d CIDRs across %d providers",
              len(entries), len(by_provider))


async def ensure_loaded(session) -> None:
    async with _LOAD_LOCK:
        age = time.time() - _state["loaded_at"]
        if _state["entries"] and age < _TTL_S:
            return
        try:
            await _refresh(session)
        except Exception as e:
            _state["error"] = f"cloud-IP refresh failed: {e}"
            _log.warning("cloud_ip_ranges refresh failed: %s", e)


def lookup(ip: str) -> Optional[Dict[str, str]]:
    """Return the first matching cloud-provider record, or None."""
    if not isinstance(ip, str) or not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net, meta in (_state.get("entries") or []):
        try:
            if addr in net:
                return meta
        except TypeError:
            continue
    return None


def stats() -> Dict[str, Any]:
    age = time.time() - _state["loaded_at"] if _state["loaded_at"] else None
    return {
        "loaded":     bool(_state.get("entries")),
        "total":      len(_state.get("entries") or []),
        "providers":  _state.get("by_provider") or {},
        "age_s":      int(age) if age is not None else None,
        "ttl_s":      _TTL_S,
        "error":      _state.get("error"),
    }
