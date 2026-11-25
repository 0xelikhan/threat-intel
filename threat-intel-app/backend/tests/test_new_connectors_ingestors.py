"""Regression coverage for the new OpenCTI + Webhook connectors and
the Crowdsec ingestor.

Each test exercises the plugin at a boundary that would catch the
most likely regressions:
  * Plugin registers itself under the expected name
  * Missing/bad config short-circuits with error_type (doesn't crash)
  * Happy path produces the expected output / cache mutation when a
    fake HTTP layer is injected

No real HTTP calls - we stub aiohttp.ClientSession or inject a mock
session so the tests run offline.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from plugins import AnalysisResult, Artifact, registry


# ─── Registry ──────────────────────────────────────────────────────────────

def test_opencti_connector_registered():
    """Without a registry entry the connector is invisible in
    /api/plugins and can't be invoked by main.py."""
    assert registry.get("opencti") is not None, (
        "opencti connector didn't register; check module-level register() call"
    )


def test_webhook_connector_registered():
    assert registry.get("webhook") is not None


def test_crowdsec_ingestor_registered():
    assert registry.get("crowdsec") is not None


def test_connector_count_bumped():
    """We shipped misp + thehive previously; now +2 (opencti, webhook)."""
    conns = {c.name for c in registry.connectors()}
    assert {"misp", "thehive", "opencti", "webhook"}.issubset(conns), (
        f"missing connectors from registry: {conns}"
    )


def test_ingestor_count_bumped():
    ingestors = {i.name for i in registry.ingestors()}
    assert {"taxii", "crowdsec"}.issubset(ingestors), (
        f"missing ingestors from registry: {ingestors}"
    )


# ─── OpenCTI connector ────────────────────────────────────────────────────

def _artifact(value="1.2.3.4", type_="ipv4") -> Artifact:
    return Artifact(id="x", type=type_, value=value)


def _result(source="virustotal", found=True, verdict="MALICIOUS") -> AnalysisResult:
    return AnalysisResult(
        source=source, ioc_type="ipv4", ioc_value="1.2.3.4",
        found=found, verdict=verdict,
    )


def test_opencti_missing_keys_short_circuits():
    """Without OPENCTI_URL + TOKEN the connector must return
    error_type=missing_key without attempting any HTTP call."""
    conn = registry.get("opencti")
    out = asyncio.run(conn.export(_artifact(), [_result()], keys={}))
    assert out["ok"] is False
    assert out["error_type"] == "missing_key"


def test_opencti_unsupported_ioc_type_short_circuits():
    """Phones aren't in the STIX-type map; connector should reject
    rather than send a malformed observable upstream."""
    conn = registry.get("opencti")
    out = asyncio.run(conn.export(
        Artifact(id="x", type="phone", value="+14155550123"),
        [_result()],
        keys={"OPENCTI_URL": "https://opencti.example", "OPENCTI_TOKEN": "t"},
    ))
    assert out["ok"] is False
    assert out["error_type"] == "unsupported_ioc_type"


# ─── Webhook connector ────────────────────────────────────────────────────

def test_webhook_missing_url_short_circuits():
    conn = registry.get("webhook")
    out = asyncio.run(conn.export(_artifact(), [_result()], keys={}))
    assert out["ok"] is False
    assert out["error_type"] == "missing_key"


def test_webhook_verdict_threshold_skips_clean():
    """The default RECON_WEBHOOK_MIN_VERDICT is SUSPICIOUS. A CLEAN
    verdict must NOT trigger a POST (to keep the receiver quiet on
    noise). `skipped: True` with a readable reason covers both the
    'did it fire' assertion AND lets the caller log why."""
    conn = registry.get("webhook")
    clean = _result(verdict="CLEAN")
    out = asyncio.run(conn.export(
        _artifact(), [clean],
        keys={"RECON_WEBHOOK_URL": "http://localhost/not-real"},
    ))
    assert out.get("skipped") is True
    assert "below threshold" in out.get("reason", "")


def test_webhook_signs_body_when_secret_present():
    """RECON_WEBHOOK_SECRET must produce an HMAC-SHA256 signature in
    the X-Recon-Signature header. Without this, downstream receivers
    can't verify the request came from RECON."""
    conn = registry.get("webhook")
    captured = {}

    class _FakeResp:
        status = 200
        async def text(self): return "ok"
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False

    class _FakeSession:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        def post(self, url, data=None, headers=None):
            captured["url"]     = url
            captured["headers"] = headers
            captured["body"]    = data
            return _FakeResp()

    with patch("plugins.connectors.webhook.aiohttp.ClientSession", _FakeSession):
        out = asyncio.run(conn.export(
            _artifact(), [_result()],      # MALICIOUS -> passes threshold
            keys={
                "RECON_WEBHOOK_URL":    "http://localhost/sink",
                "RECON_WEBHOOK_SECRET": "topsecret",
            },
        ))

    assert out["ok"] is True
    sig = (captured.get("headers") or {}).get("X-Recon-Signature", "")
    assert sig.startswith("sha256="), f"missing HMAC header: {captured.get('headers')}"


def test_webhook_extra_headers_merged():
    """RECON_WEBHOOK_HEADERS should merge custom headers (e.g.
    Authorization: Bearer ...) into the outbound request."""
    conn = registry.get("webhook")
    captured = {}

    class _FakeResp:
        status = 200
        async def text(self): return "ok"
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False

    class _FakeSession:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        def post(self, url, data=None, headers=None):
            captured["headers"] = headers
            return _FakeResp()

    with patch("plugins.connectors.webhook.aiohttp.ClientSession", _FakeSession):
        asyncio.run(conn.export(
            _artifact(), [_result()],
            keys={
                "RECON_WEBHOOK_URL":     "http://localhost/sink",
                "RECON_WEBHOOK_HEADERS": '{"Authorization": "Bearer xyz"}',
            },
        ))

    assert (captured.get("headers") or {}).get("Authorization") == "Bearer xyz"


# ─── Crowdsec ingestor ─────────────────────────────────────────────────────

def test_crowdsec_ingest_record_populates_cache():
    """Direct call to the normaliser - simulates what the poll loop
    does after fetching one record."""
    from plugins.ingestors import crowdsec
    crowdsec._CROWDSEC_CACHE.clear()
    crowdsec._ingest_record("9.9.9.9", {
        "ip": "9.9.9.9",
        "behaviors": [{"name": "ssh-bf", "label": "SSH bruteforce"}],
        "history": {"first_seen": "2026-11-20T10:00:00Z",
                     "last_seen":  "2026-11-25T18:00:00Z"},
        "attack_details_count": 42,
    })
    hit = crowdsec.lookup("9.9.9.9")
    assert hit is not None
    assert hit["found"] is True
    assert hit["scenarios"] == ["ssh-bf"]
    assert hit["attack_count"] == 42
    assert hit["verdict"] == "SUSPICIOUS"
    assert "Crowdsec community reports" in hit["summary"]


def test_crowdsec_cache_expires_stale_entries():
    """24h TTL - stale entries must be evicted on read, otherwise an
    operator who disables the ingestor would see forever-stale hits."""
    from plugins.ingestors import crowdsec
    crowdsec._CROWDSEC_CACHE.clear()
    crowdsec._ingest_record("8.8.8.8", {"ip": "8.8.8.8"})
    # Backdate the entry past the TTL window
    crowdsec._CROWDSEC_CACHE["8.8.8.8"]["cached_at"] = (
        crowdsec._CROWDSEC_CACHE["8.8.8.8"]["cached_at"] - 25 * 3600
    )
    assert crowdsec.lookup("8.8.8.8") is None
    assert "8.8.8.8" not in crowdsec._CROWDSEC_CACHE, "stale entry wasn't evicted"


def test_crowdsec_lookup_miss_returns_none():
    from plugins.ingestors.crowdsec import lookup, _CROWDSEC_CACHE
    _CROWDSEC_CACHE.clear()
    assert lookup("127.0.0.1") is None


def test_crowdsec_cache_feeds_enrich_ip():
    """End-to-end wiring: seed the cache, run enrich_ip against a
    fully-mocked aiohttp session, confirm the crowdsec row surfaces
    in the returned dict. If the integration regresses, this test
    fires BEFORE any UI check - which is where silent bugs hide."""
    from plugins.ingestors import crowdsec
    crowdsec._CROWDSEC_CACHE.clear()
    crowdsec._ingest_record("5.6.7.8", {
        "ip": "5.6.7.8",
        "scenarios": ["http-probing", "credential-stuffing"],
        "events_count": 7,
    })

    # Minimal fake session - every external call returns an empty
    # payload. We only care that crowdsec lands in the result.
    class _FakeResp:
        status = 200
        content_type = "application/json"
        headers = {"Content-Type": "application/json"}
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def json(self): return {}
        async def text(self): return "{}"
    class _FakeSession:
        closed = False
        def get(self, *a, **kw): return _FakeResp()
        def post(self, *a, **kw): return _FakeResp()

    # Clear the module-level cache so enrich_ip actually runs
    from agents.enrichment import enrich_ip, _cache
    _cache.clear()

    out = asyncio.run(enrich_ip(_FakeSession(), "5.6.7.8", keys={}))
    assert "crowdsec" in out, (
        f"crowdsec row didn't surface in enrich_ip output. "
        f"keys present: {sorted(out.keys())}"
    )
    assert out["crowdsec"]["found"] is True
    assert "http-probing" in out["crowdsec"]["scenarios"]
