"""Tests for the MISP feed lookup module.

The fetch itself touches public networks, which we don't want to do in
unit tests. We exercise the in-memory parser + lookup logic by injecting
synthetic state directly into the module, the same shape _fetch_one
produces.
"""

from __future__ import annotations

import asyncio

import pytest

from intel import misp_feeds


@pytest.fixture(autouse=True)
def _reset_state():
    """Each test starts with empty state and fresh lock."""
    misp_feeds._state.clear()
    misp_feeds._ensure_state()
    yield
    misp_feeds._state.clear()


def _inject_hash(feed_name: str, h: str, event_uuid: str = "evt-1",
                 fname: str = "x.exe") -> None:
    """Helper: mark a feed as 'just fetched' and seed it with one hash."""
    misp_feeds._state[feed_name].update({
        "fetched_at": 9_999_999_999,   # far future so _stale() returns False
        "by_hash":    {h.lower(): {"event_uuid": event_uuid, "filename": fname}},
        "error":      None,
    })


def test_lookup_returns_empty_for_unknown_hash():
    result = asyncio.run(misp_feeds.lookup_hash(
        "a" * 64))   # valid sha256 shape, but never seeded
    assert result == []


def test_lookup_finds_seeded_hash_in_one_feed():
    h = "deadbeef" * 8                                  # 64-char hex
    _inject_hash("CIRCL OSINT", h, "evt-circl", "sample.exe")
    result = asyncio.run(misp_feeds.lookup_hash(h))
    assert len(result) == 1
    assert result[0]["feed"] == "CIRCL OSINT"
    assert result[0]["event_uuid"] == "evt-circl"
    assert result[0]["filename"] == "sample.exe"


def test_lookup_finds_same_hash_in_multiple_feeds():
    h = "ab" * 16                                       # 32-char md5 shape
    _inject_hash("CIRCL OSINT", h, "evt-1")
    _inject_hash("Botvrij OSINT", h, "evt-2")
    result = asyncio.run(misp_feeds.lookup_hash(h))
    assert len(result) == 2
    feeds = {r["feed"] for r in result}
    assert feeds == {"CIRCL OSINT", "Botvrij OSINT"}


def test_lookup_is_case_insensitive():
    h = "CDCDCDCD" * 8                                  # mixed-case input
    _inject_hash("CIRCL OSINT", h.lower())              # seed lowercase
    result = asyncio.run(misp_feeds.lookup_hash(h))     # query uppercase
    assert len(result) == 1


def test_lookup_rejects_wrong_length_strings():
    # 5 chars: not md5/sha1/sha256 length, must be rejected before search.
    result = asyncio.run(misp_feeds.lookup_hash("abc12"))
    assert result == []


def test_lookup_ioc_dispatches_to_hash_only():
    h = "ff" * 32
    _inject_hash("CIRCL OSINT", h)
    hits = asyncio.run(misp_feeds.lookup_ioc("hash", h))
    assert len(hits) == 1
    # Other IOC types not implemented yet → empty list, not crash.
    assert asyncio.run(misp_feeds.lookup_ioc("ip", "1.2.3.4")) == []
    assert asyncio.run(misp_feeds.lookup_ioc("domain", "evil.test")) == []
    assert asyncio.run(misp_feeds.lookup_ioc("url", "http://x")) == []


def test_stats_shape():
    s = misp_feeds.stats()
    # One entry per configured feed.
    assert set(s.keys()) == {name for name, _ in misp_feeds._FEEDS}
    for v in s.values():
        assert set(v.keys()) >= {"loaded_at", "entry_count", "error"}
