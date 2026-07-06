"""Tests for the _BoundedDict module-level cache in main.py.

Covers the eviction contract that prevents the in-memory _results /
_chats stores from growing unbounded (which used to let a long-running
container accumulate GBs of stale state — see 447deb6 / 5a36e36)."""

from __future__ import annotations

import pytest


@pytest.fixture
def BoundedDict():
    from bg_utils import BoundedDict
    return BoundedDict


def test_under_cap_keeps_everything(BoundedDict):
    d = BoundedDict(cap=3)
    d["a"] = 1
    d["b"] = 2
    d["c"] = 3
    assert dict(d) == {"a": 1, "b": 2, "c": 3}


def test_exceeding_cap_evicts_oldest(BoundedDict):
    d = BoundedDict(cap=3)
    d["a"] = 1
    d["b"] = 2
    d["c"] = 3
    d["new"] = 4
    assert "a" not in d
    assert dict(d) == {"b": 2, "c": 3, "new": 4}


def test_overwrite_refreshes_position(BoundedDict):
    d = BoundedDict(cap=3)
    d["a"] = 1
    d["b"] = 2
    d["c"] = 3
    # Touching "a" should move it to the most-recent position, so the
    # next insert evicts "b" instead of "a".
    d["a"] = 99
    d["d"] = 4
    assert "a" in d
    assert "b" not in d
    assert d["a"] == 99


def test_cap_of_one(BoundedDict):
    d = BoundedDict(cap=1)
    d["a"] = 1
    d["b"] = 2
    assert dict(d) == {"b": 2}


def test_pop_does_not_count_against_cap(BoundedDict):
    d = BoundedDict(cap=2)
    d["a"] = 1
    d["b"] = 2
    d.pop("a")
    assert dict(d) == {"b": 2}
    # Cap is still 2, so inserting one more keeps both...
    d["c"] = 3
    assert dict(d) == {"b": 2, "c": 3}
    # ...and the next insert evicts the oldest.
    d["d"] = 4
    assert dict(d) == {"c": 3, "d": 4}


def test_iteration_order_is_insertion_order(BoundedDict):
    d = BoundedDict(cap=10)
    for k in "abcdef":
        d[k] = k.upper()
    assert list(d.keys()) == list("abcdef")
