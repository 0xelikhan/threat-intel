"""Regression: abuse.ch (mb-api / threatfox-api / urlhaus-api) returns
transient HTTP 401 when the shared Auth-Key's quota is hot-spiked
from concurrent fan-out calls. The 401 self-heals in <1s, but the
old flow recorded it as auth_failure → circuit breaker opened →
knocked all 3 subdomains offline for 5 minutes.

The fix is a silent retry-on-401 for *.abuse.ch hosts inside _get /
_post. This test proves that a first-call 401 followed by a
second-call 200 returns the 200 body (not the 401 error) and does
NOT trip the breaker.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch, MagicMock

from agents.enrichment import _get, _post
from intel.circuit_breaker import get_breaker


class _FakeResp:
    def __init__(self, status, payload, ctype="application/json"):
        self.status = status
        self._p = payload
        self.content_type = ctype
    async def __aenter__(self): return self
    async def __aexit__(self, *_a): return False
    async def json(self): return self._p
    async def text(self): return "raw"


class _FakeSession:
    """Yields _FakeResp(payload=payloads[call_i]) on each successive
    .get / .post call."""
    def __init__(self, payloads):
        self._payloads = list(payloads)
        self.calls = 0
    def _next(self):
        self.calls += 1
        return self._payloads[min(self.calls - 1, len(self._payloads) - 1)]
    def get(self, *_a, **_k):  return self._next()
    def post(self, *_a, **_k): return self._next()


def test_abusech_401_then_200_returns_200_no_breaker_failure():
    """First call: 401. Retry: 200 with valid body. Expected:
    caller gets the 200 body, breaker records success not failure."""
    get_breaker().reset()
    sess = _FakeSession([
        _FakeResp(401, {"error": "auth failed"}),
        _FakeResp(200, {"query_status": "ok", "data": [{"family": "Amadey"}]}),
    ])
    async def _run():
        # Patch the retry-sleep to zero without recursing.
        _real_sleep = asyncio.sleep
        async def _zero_sleep(*_a, **_k): await _real_sleep(0)
        with patch("agents.enrichment.asyncio.sleep", new=_zero_sleep):
            return await _post(sess, "https://threatfox-api.abuse.ch/api/v1/",
                                 json={"query": "search_hash"})
    r = asyncio.run(_run())
    assert sess.calls == 2, "expected exactly one retry"
    assert r.get("query_status") == "ok"
    # Breaker sees success — no failure recorded
    stats = get_breaker().stats().get("threatfox-api.abuse.ch") or {}
    assert stats.get("state") == "closed"


def test_abusech_persistent_401_is_recorded_as_auth_failure():
    """Both calls 401 → still surfaces as auth_failed and records a
    breaker failure (so a genuinely broken key still trips the guard)."""
    get_breaker().reset()
    sess = _FakeSession([
        _FakeResp(401, {"error": "auth"}),
        _FakeResp(401, {"error": "auth"}),
    ])
    async def _run():
        _real_sleep = asyncio.sleep
        async def _zero_sleep(*_a, **_k): await _real_sleep(0)
        with patch("agents.enrichment.asyncio.sleep", new=_zero_sleep):
            return await _get(sess, "https://mb-api.abuse.ch/api/v1/")
    r = asyncio.run(_run())
    assert sess.calls == 2
    assert r.get("error_type") == "auth_failed"
    # Failure recorded
    stats = get_breaker().stats().get("mb-api.abuse.ch") or {}
    assert stats.get("failures") == 1
    assert stats.get("streak") == 1


def test_non_abusech_401_does_not_retry():
    """Retry only applies to abuse.ch. Other hosts hitting 401 fail
    immediately (a persistent key config bug should show up ASAP)."""
    get_breaker().reset()
    sess = _FakeSession([_FakeResp(401, {"error": "auth"})])
    async def _run():
        return await _get(sess, "https://api.virustotal.com/api/v3/files/x")
    r = asyncio.run(_run())
    assert sess.calls == 1, "no retry for non-abuse.ch hosts"
    assert r.get("error_type") == "auth_failed"


def test_abusech_200_first_call_no_retry():
    """Happy path — first call succeeds. No retry, no wasted latency."""
    get_breaker().reset()
    sess = _FakeSession([_FakeResp(200, {"query_status": "no_result"})])
    async def _run():
        return await _post(sess, "https://urlhaus-api.abuse.ch/v1/url/",
                             data="url=x")
    r = asyncio.run(_run())
    assert sess.calls == 1
    assert r.get("query_status") == "no_result"
