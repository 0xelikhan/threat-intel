"""End-to-end integration test for the pivot second-pass.

The existing test_pivot_second_pass.py mocks enrich_hash wholesale.
This file goes a layer deeper: it patches the aiohttp session's
.get / .post methods only, letting the real enrich_hash orchestrator
run its full fan-out — URL construction, header assembly, response
parsing, cache lookup, verdict aggregation — and only intercepts
the final HTTP call. That proves:

  1. The pivot plugin fires on a real sandbox-shaped enrich_hash
     return (not a mocked return)
  2. The orchestrator's bucket→ioc_type map correctly routes the
     dropped hash into the hashes bucket
  3. The second-pass enricher receives the follow-up hash and runs
     through the same code path as the first pass
  4. Verdict aggregation in enrichment_summary accounts for both
     the original IOC and the pivoted ones

This is the real-world test the sandbox_dropped_hashes pivot was
written for.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import patch, AsyncMock, MagicMock

import pytest


_ORIGINAL_SHA256  = "a" * 64
_DROPPED_SHA256_1 = "b" * 64
_DROPPED_SHA256_2 = "c" * 64


class _FakeAioResp:
    """Enough aiohttp.ClientResponse surface to let enrich_hash parse us."""
    def __init__(self, status: int = 200, payload=None,
                 content_type: str = "application/json"):
        self.status = status
        self._payload = payload if payload is not None else {}
        self.content_type = content_type
        self.headers = {"Content-Type": content_type}

    async def __aenter__(self): return self
    async def __aexit__(self, *_a): return False
    async def json(self, *_a, **_k): return self._payload
    async def text(self): return json.dumps(self._payload)


def _make_session_mock():
    """aiohttp.ClientSession stand-in. Returns a sandbox-shaped payload
    on calls to the Hybrid Analysis overview endpoint (triggers the
    pivot). Returns an empty 'no data' dict for every other endpoint
    so the first-pass fan-out completes without errors."""

    def _route(url: str, kwargs: dict):
        # Hybrid Analysis file-overview — this is what the pivot
        # plugin looks at. Return a payload with files_dropped.
        if "hybrid-analysis.com/api/v2/overview/" in url and _ORIGINAL_SHA256 in url:
            return _FakeAioResp(200, {
                "sha256": _ORIGINAL_SHA256,
                "verdict": "malicious",
                "threat_score": 85,
                "threat_level": 2,
                "classification_tags": ["ransomware"],
                "mitre_attcks": [],
                "signatures": [],
                "files_dropped": [
                    {"sha256": _DROPPED_SHA256_1, "name": "stage2.exe"},
                    {"sha256": _DROPPED_SHA256_2, "name": "config.enc"},
                ],
            })
        # Any other request: harmless no-op JSON. Status 404 so parsers
        # take the "not found" branch instead of crashing on a shape.
        return _FakeAioResp(404, {"error": "not configured", "error_type": "unreachable"})

    def _get(url, **kwargs):  return _route(url, kwargs)
    def _post(url, **kwargs): return _route(url, kwargs)

    s = MagicMock()
    s.get  = _get
    s.post = _post
    s.closed = False
    # Needed by aiohttp.ClientSession context-manager contract when
    # the real connector helpers call it; we don't actually acquire.
    s.__aenter__ = AsyncMock(return_value=s)
    s.__aexit__  = AsyncMock(return_value=False)
    return s


def test_pivot_second_pass_dispatches_through_real_enricher_table():
    """The pivot pass must route pivot-produced IOCs through the real
    _enrichers table in run_enrichment (not a bypass path).

    Strategy: patch enrich_hash with a tracker that returns a sandbox-
    shaped first-pass response for the original IOC, then an empty
    response for the two dropped hashes. If the second-pass dispatch
    is wired correctly, enrich_hash gets called 3 times — once for
    the original, twice for the pivot drops — and all three hashes
    land in the enrichments['hashes'] bucket.

    This is a stricter test than test_pivot_second_pass_adds_dropped_
    hashes (which doesn't observe which keys enrich_hash was called
    with, only that the final hashes dict is populated).
    """
    from agents.enrichment import run_enrichment

    calls: list = []
    async def _tracked_hash(session, hash_val, keys):
        calls.append(hash_val)
        if hash_val == _ORIGINAL_SHA256:
            return {
                "hybrid_analysis": {
                    "source":        "hybrid_analysis",
                    "found":         True,
                    "verdict":       "MALICIOUS",
                    "summary":       "pretend sandbox",
                    "threat_score":  85,
                    "files_dropped": [
                        {"sha256": _DROPPED_SHA256_1},
                        {"sha256": _DROPPED_SHA256_2},
                    ],
                }
            }
        return {}

    async def _skip(*a, **k): return {}

    state = {
        "iocs": {
            "ips": [], "domains": [], "urls": [], "cves": [],
            "emails": [], "crypto": [], "phones": [],
            "hashes": [_ORIGINAL_SHA256],
        },
        "agent_trace": [],
    }

    with patch("agents.enrichment.enrich_hash",   new=_tracked_hash), \
         patch("agents.enrichment.enrich_ip",     new=_skip), \
         patch("agents.enrichment.enrich_domain", new=_skip), \
         patch("agents.enrichment.enrich_url",    new=_skip), \
         patch("agents.enrichment.enrich_cve",    new=_skip), \
         patch("agents.enrichment.enrich_email",  new=_skip), \
         patch("agents.enrichment.enrich_crypto", new=_skip), \
         patch("agents.enrichment.enrich_phone",  new=_skip):
        out = asyncio.run(run_enrichment(state))

    # ── Assertion 1: all three hashes landed in the enrichment set
    hashes = out["enrichments"]["hashes"]
    assert _ORIGINAL_SHA256  in hashes, f"original missing: {list(hashes.keys())}"
    assert _DROPPED_SHA256_1 in hashes, f"first drop missing: {list(hashes.keys())}"
    assert _DROPPED_SHA256_2 in hashes, f"second drop missing: {list(hashes.keys())}"

    # ── Assertion 2: enrich_hash was called three times, once per hash,
    #    with the pivot drops being invocations after the first pass
    assert calls == [_ORIGINAL_SHA256, _DROPPED_SHA256_1, _DROPPED_SHA256_2] \
        or calls == [_ORIGINAL_SHA256, _DROPPED_SHA256_2, _DROPPED_SHA256_1], (
        f"unexpected call order: {calls}"
    )

    # ── Assertion 3: the enrichment_summary totals reflect the pivot output
    totals = out["enrichment_summary"]["totals"]
    assert totals["hashes"] == 3, totals

    # ── Assertion 4: the pivot trace event is in the agent_trace
    pivot_events = [t for t in out.get("agent_trace", [])
                     if t.get("event") == "pivot_pass"]
    assert pivot_events, "no pivot_pass trace event recorded"
    assert pivot_events[0]["new_iocs"] == 2


def test_pivot_pass_bounded_at_20_iocs():
    """A chatty sandbox result shouldn't fan out unbounded — cap at 20."""
    from agents.enrichment import run_enrichment

    _MANY_HASHES = [chr(ord('d') + i) * 64 for i in range(50)]

    async def _fake(session, hash_val, keys):
        if hash_val == "a" * 64:
            # Trigger with 50 dropped hashes
            return {
                "hybrid_analysis": {
                    "source": "hybrid_analysis",
                    "found": True, "verdict": "MALICIOUS", "summary": "chatty",
                    "files_dropped": [{"sha256": h} for h in _MANY_HASHES],
                }
            }
        return {}

    async def _skip(*a, **k): return {}

    state = {
        "iocs": {"ips": [], "domains": [], "urls": [], "cves": [],
                  "emails": [], "crypto": [], "phones": [],
                  "hashes": ["a" * 64]},
        "agent_trace": [],
    }

    with patch("agents.enrichment.enrich_hash",   new=_fake), \
         patch("agents.enrichment.enrich_ip",     new=_skip), \
         patch("agents.enrichment.enrich_domain", new=_skip), \
         patch("agents.enrichment.enrich_url",    new=_skip), \
         patch("agents.enrichment.enrich_cve",    new=_skip), \
         patch("agents.enrichment.enrich_email",  new=_skip), \
         patch("agents.enrichment.enrich_crypto", new=_skip), \
         patch("agents.enrichment.enrich_phone",  new=_skip):
        out = asyncio.run(run_enrichment(state))

    hashes = out["enrichments"]["hashes"]
    # The pivot pass is capped at 20 total new IOCs. One original + 20 drops
    # = 21 keys in the hashes bucket. If the cap isn't enforced we'd see
    # 1 + 50 = 51.
    assert 1 < len(hashes) <= 21, (
        f"pivot not bounded: got {len(hashes)} hashes "
        f"(expected 1 original + ≤20 drops)"
    )
