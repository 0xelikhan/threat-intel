"""
DataPlane.org honeypot feed loader.

Source: https://dataplane.org/ — DataPlane.org's global honeypot mesh
publishes daily-refreshed CSV feeds of IPs caught probing or brute-
forcing specific services. Free, no-key, attribution-only redistribution.

The feeds we ingest:

  sshpwauth.txt    — SSH password-authentication attempts
  sshclient.txt    — SSH client probes (port 22 connect, no banner)
  sipinvitation.txt — SIP INVITE flood / VoIP fraud probes
  sipquery.txt     — SIP OPTIONS / REGISTER scans
  smtpgreet.txt    — SMTP banner-grab / open-relay probes
  vncrfb.txt       — VNC RFB protocol probes
  telnetlogin.txt  — Telnet login attempts (IoT-bot signature)
  dnsrd.txt        — DNS open-recursion probes

For each, the format is

  # comments
  ASN | ASN-name | last-seen | category | IP

We extract the IP, ASN, and last-seen timestamp into a single inverted
index. enrich_ip surfaces "this IP appears on N DataPlane feeds (SSH
brute, SIP fraud)" as a confident "actively-attacking infrastructure"
verdict.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.intel.dataplane")

_FEEDS = [
    ("sshpwauth",    "https://dataplane.org/sshpwauth.txt"),
    ("sshclient",    "https://dataplane.org/sshclient.txt"),
    ("sipinvitation", "https://dataplane.org/sipinvitation.txt"),
    ("sipquery",     "https://dataplane.org/sipquery.txt"),
    ("smtpgreet",    "https://dataplane.org/smtpgreet.txt"),
    ("vncrfb",       "https://dataplane.org/vncrfb.txt"),
    ("telnetlogin",  "https://dataplane.org/telnetlogin.txt"),
    ("dnsrd",        "https://dataplane.org/dnsrd.txt"),
]
_TTL_S = 12 * 3600  # 12-hour refresh; the upstream updates daily

_LOAD_LOCK = asyncio.Lock()
_state: Dict[str, Any] = {
    "loaded_at": 0.0,
    "by_ip":     {},   # dict[ip, list[{feed, last_seen, asn, asn_name}]]
    "feed_sizes": {},
    "total":     0,
    "error":     None,
}


async def _fetch_text(session, url: str) -> Optional[str]:
    from agents.enrichment import _get
    try:
        r = await _get(
            session, url,
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "text/plain"},
            json_response=False,
            timeout=12,
        )
    except TypeError:
        r = await _get(
            session, url,
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "text/plain"},
            timeout=12,
        )
    except Exception as e:
        _log.debug("dataplane fetch failed %s: %s", url, e)
        return None
    if isinstance(r, str):
        return r
    if isinstance(r, (bytes, bytearray)):
        return r.decode("utf-8", errors="ignore")
    return None


def _parse_feed(text: str, slug: str,
                by_ip: Dict[str, List[Dict[str, Any]]]) -> int:
    if not isinstance(text, str):
        return 0
    count = 0
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        # CSV with pipe separators: ASN | ASN-name | last-seen | category | IP
        parts = [p.strip() for p in s.split("|")]
        if len(parts) < 5:
            continue
        asn      = parts[0]
        asn_name = parts[1][:80]
        last_seen = parts[2]
        ip       = parts[4]
        if not ip or " " in ip or "." not in ip and ":" not in ip:
            continue
        by_ip.setdefault(ip, []).append({
            "feed":      slug,
            "asn":       asn,
            "asn_name":  asn_name,
            "last_seen": last_seen[:24],
        })
        count += 1
    return count


async def _refresh(session) -> None:
    by_ip:      Dict[str, List[Dict[str, Any]]] = {}
    feed_sizes: Dict[str, int] = {}

    texts = await asyncio.gather(
        *[_fetch_text(session, url) for _slug, url in _FEEDS],
        return_exceptions=True,
    )
    for (slug, _url), text in zip(_FEEDS, texts):
        if not isinstance(text, str):
            continue
        feed_sizes[slug] = _parse_feed(text, slug, by_ip)

    _state["by_ip"]      = by_ip
    _state["feed_sizes"] = feed_sizes
    _state["total"]      = sum(feed_sizes.values())
    _state["loaded_at"]  = time.time()
    _state["error"]      = None if feed_sizes else "no feeds loaded"
    _log.info("dataplane loaded: %d IPs across %d feeds",
              len(by_ip), len(feed_sizes))


async def ensure_loaded(session) -> None:
    async with _LOAD_LOCK:
        age = time.time() - _state["loaded_at"]
        if _state["by_ip"] and age < _TTL_S:
            return
        try:
            await _refresh(session)
        except Exception as e:
            _state["error"] = f"dataplane refresh failed: {e}"
            _log.warning("dataplane refresh failed: %s", e)


def lookup(ip: str) -> List[Dict[str, Any]]:
    """Return every DataPlane feed-hit for an IP (with feed name, ASN,
    last-seen). Empty list when the IP isn't on any feed or the feeds
    haven't been loaded yet."""
    if not isinstance(ip, str) or not ip:
        return []
    return (_state.get("by_ip") or {}).get(ip.strip(), [])


def stats() -> Dict[str, Any]:
    age = time.time() - _state["loaded_at"] if _state["loaded_at"] else None
    return {
        "loaded":      bool(_state.get("by_ip")),
        "ips":         len(_state.get("by_ip") or {}),
        "total_records": _state.get("total", 0),
        "per_feed":    _state.get("feed_sizes", {}),
        "age_s":       int(age) if age is not None else None,
        "ttl_s":       _TTL_S,
        "error":       _state.get("error"),
    }
