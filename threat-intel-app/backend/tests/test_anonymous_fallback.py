"""Regression test - missing API keys must not break the enrichment
pipeline for sources that support anonymous queries.

The IPInfo + Pulsedive integrations historically sent `?token=` and
`&key=` as empty strings when the respective key was unset. Both
services treat an empty-string token/key as "invalid auth" and 401
the request, which killed the geolocation pipeline (empty loc →
Map tab shows "No geolocation data available") for every operator
who hadn't configured IPINFO_TOKEN.

Fix: drop the param entirely when the key is not set. These tests
pin that behaviour so a future refactor doesn't quietly re-introduce
the `empty_string=` anti-pattern.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _reset_enrichment_state():
    """Two kinds of module-level state leak across tests in this file:

      1. Per-host circuit breaker - prior failures can trip it and
         later calls get short-circuited to `circuit_open` instead of
         actually being issued.
      2. `_cache` - enrich_ip / enrich_domain memoize results by
         (ioc_type, value) and skip fan-out on cache hits. Without
         clearing, the SECOND call for 1.2.3.4 returns the first
         call's cached result and the capturing session sees no
         requests at all.
    """
    try:
        from agents.enrichment import get_breaker, _cache
        breaker = get_breaker()
        if hasattr(breaker, "_hosts"):
            lock = getattr(breaker, "_lock", None)
            if lock is not None:
                with lock:
                    breaker._hosts.clear()
            else:
                breaker._hosts.clear()
        _cache.clear()
    except Exception:
        pass
    yield


class _CapturingResp:
    def __init__(self):
        self.status = 200
        self.content_type = "application/json"
        self.headers = {"Content-Type": "application/json"}
    async def __aenter__(self): return self
    async def __aexit__(self, *_a): return False
    async def json(self): return {"loc": "37.4,-122.07", "country": "US"}
    async def text(self): return "{}"


def _make_capturing_session(captured_calls: list):
    """aiohttp.ClientSession stand-in that records every GET call's
    (url, kwargs) before returning a canned 200 response."""
    def _get(url, **kwargs):
        captured_calls.append({"url": url, "kwargs": kwargs})
        return _CapturingResp()
    s = MagicMock()
    s.get = _get
    s.post = _get
    s.closed = False
    return s


def _find_ipinfo_call(captured: list):
    for c in captured:
        if "ipinfo.io" in c["url"]:
            return c
    return None


def _find_pulsedive_call(captured: list):
    for c in captured:
        if "pulsedive.com" in c["url"]:
            return c
    return None


# ─── IPInfo ────────────────────────────────────────────────────────────────

def test_ipinfo_drops_token_param_when_key_unset():
    """When IPINFO_TOKEN is empty / absent, the request must NOT include
    a `token=` query param. Empty-string tokens are rejected by IPInfo
    as invalid auth, which killed the Map tab's geolocation."""
    from agents.enrichment import enrich_ip

    captured = []
    session = _make_capturing_session(captured)

    asyncio.run(enrich_ip(session, "1.2.3.4", keys={}))

    call = _find_ipinfo_call(captured)
    assert call is not None, "enrich_ip never called ipinfo.io"
    params = call["kwargs"].get("params")
    # Either params is None, or it's a dict/mapping without a `token` key.
    # Both forms are acceptable; `{"token": ""}` is NOT.
    if params is None:
        pass  # explicit no-param - ideal
    else:
        assert "token" not in params, (
            "IPInfo request still carries token= with an unset key. "
            "aiohttp will serialise `{'token': ''}` as `?token=` which "
            "IPInfo treats as auth failure - the exact bug this test exists "
            "to prevent."
        )


def test_ipinfo_includes_token_when_configured():
    """Conversely: when a token IS configured, it must be passed. This
    pins the happy path so the defensive edit doesn't accidentally
    strip legitimate keys too."""
    from agents.enrichment import enrich_ip

    captured = []
    session = _make_capturing_session(captured)

    asyncio.run(enrich_ip(session, "1.2.3.4", keys={"IPINFO_TOKEN": "tok_abc"}))

    call = _find_ipinfo_call(captured)
    assert call is not None
    params = call["kwargs"].get("params") or {}
    assert params.get("token") == "tok_abc", (
        f"configured IPINFO_TOKEN wasn't forwarded: params={params}"
    )


# ─── Pulsedive ─────────────────────────────────────────────────────────────

def test_pulsedive_drops_key_param_when_unset():
    """Pulsedive's info.php accepts anonymous queries but 401s on
    empty-string keys. Drop the param entirely when PULSEDIVE_KEY is
    unset."""
    from agents.enrichment import enrich_domain

    captured = []
    session = _make_capturing_session(captured)

    asyncio.run(enrich_domain(session, "example.com", keys={}))

    call = _find_pulsedive_call(captured)
    assert call is not None, "enrich_domain never called pulsedive.com"
    params = call["kwargs"].get("params") or {}
    assert "key" not in params, (
        "Pulsedive request still carries key= with an unset key. "
        "Pulsedive treats empty-string keys as invalid and 401s the "
        "request, silently killing the Pulsedive card."
    )


def test_pulsedive_includes_key_when_configured():
    from agents.enrichment import enrich_domain

    captured = []
    session = _make_capturing_session(captured)

    asyncio.run(enrich_domain(session, "example.com",
                               keys={"PULSEDIVE_KEY": "pk_abc"}))

    call = _find_pulsedive_call(captured)
    assert call is not None
    params = call["kwargs"].get("params") or {}
    assert params.get("key") == "pk_abc", (
        f"configured PULSEDIVE_KEY wasn't forwarded: params={params}"
    )
