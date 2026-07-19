"""
Shared blocking HTTP helper for intel modules.

Every offline / periodic-refresh module (`tor_exits`, `viriback`,
`threatview_c2`, `wiz_cloud_threats`, `dfiq`, `ransomware_live`, plus
the OFAC/Ransomwhere loaders) fetches large blobs at lifespan warm
time via urllib. That path is DELIBERATELY blocking — it runs on a
worker thread via `asyncio.to_thread` in the lifespan handler — so
the async `agents.enrichment._get` machinery (rate limit, circuit
breaker, aiohttp pool) doesn't apply.

Before this helper existed each module built its own
`urllib.request.Request(url, headers={"User-Agent": ..., "Accept": ...})`
and called `urlopen(req, timeout=X)`. A timeout tweak or a change to the
User-Agent had to be applied in seven places — and drifted at least
once (round-18 ThreatView used a slightly different UA than Onionoo,
caught only by grep).

Two forms:
  fetch_bytes(url, *, timeout=30, accept="*/*") -> bytes
  fetch_json (url, *, timeout=30)               -> dict | list

Both raise urllib.error.URLError / HTTPError / TimeoutError on
failure — callers are already inside a try/except that logs + records
`_state["error"]`.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any

_UA = "RECON-ThreatIntel/1.0"


def fetch_bytes(url: str, *, timeout: float = 30.0,
                accept: str = "*/*") -> bytes:
    """Blocking GET returning raw bytes. Uses the shared User-Agent."""
    req = urllib.request.Request(url, headers={
        "User-Agent": _UA,
        "Accept":     accept,
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def fetch_json(url: str, *, timeout: float = 30.0) -> Any:
    """Blocking GET returning parsed JSON. Sets Accept: application/json."""
    return json.loads(fetch_bytes(url, timeout=timeout,
                                    accept="application/json")
                        .decode("utf-8", errors="ignore"))
