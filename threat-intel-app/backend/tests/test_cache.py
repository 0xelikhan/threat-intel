"""TTLCache unit tests — covers TTL expiry, hit/miss accounting, clear(),
and namespaced rollup. Uses time.monotonic patches rather than real
sleeps so the suite stays fast."""

from __future__ import annotations

from unittest.mock import patch

from intel.cache import (
    TTLCache,
    cache_for,
    clear_all,
    global_stats,
    DEFAULT_TTL_BY_NAMESPACE,
)


def test_get_miss_returns_none_and_counts_miss():
    c = TTLCache()
    assert c.get("nope") is None
    assert c.stats()["misses"] == 1
    assert c.stats()["hits"] == 0


def test_set_then_get_returns_value_and_counts_hit():
    c = TTLCache()
    c.set("k", {"v": 1})
    assert c.get("k") == {"v": 1}
    s = c.stats()
    assert s["hits"] == 1 and s["sets"] == 1 and s["entries"] == 1


def test_ttl_expiry_evicts_lazily_and_returns_miss():
    c = TTLCache(default_ttl=10)
    with patch("intel.cache.time.monotonic", side_effect=[100.0, 100.0, 200.0, 200.0]):
        c.set("k", "v")          # consumes 100.0
        assert c.get("k") == "v" # consumes 100.0 (within TTL)
        # Next get is at t=200 — well past the 10s TTL → miss + eviction
        assert c.get("k") is None
    s = c.stats()
    assert s["evictions"] == 1
    assert s["entries"] == 0


def test_per_call_ttl_overrides_default():
    c = TTLCache(default_ttl=10)
    with patch("intel.cache.time.monotonic", side_effect=[0.0, 50.0]):
        c.set("k", "v", ttl=100)
    # Now check expiry calculation by patching the *get* time
    with patch("intel.cache.time.monotonic", return_value=50.0):
        assert c.get("k") == "v"


def test_clear_resets_data_and_stats():
    c = TTLCache()
    c.set("k", "v")
    c.get("k")
    c.get("missing")
    c.clear()
    s = c.stats()
    assert s == {
        "entries": 0, "hits": 0, "misses": 0, "sets": 0,
        "evictions": 0, "hit_rate": 0.0, "miss_rate": 0.0,
        "bytes_estimate": 0,
    }


def test_hit_rate_percent_calculation():
    c = TTLCache()
    c.set("k", 1)
    c.get("k"); c.get("k"); c.get("k")  # 3 hits
    c.get("missing")                     # 1 miss
    assert c.stats()["hit_rate"] == 75.0
    assert c.stats()["miss_rate"] == 25.0


def test_cache_for_returns_singleton_per_namespace():
    clear_all()
    a1 = cache_for("foo")
    a2 = cache_for("foo")
    b  = cache_for("bar")
    assert a1 is a2
    assert a1 is not b


def test_cache_for_picks_namespace_default_ttl():
    clear_all()
    mitre = cache_for("mitre")
    other = cache_for("does_not_exist_in_defaults")
    assert mitre._default_ttl == DEFAULT_TTL_BY_NAMESPACE["mitre"]
    assert other._default_ttl == 3600


def test_global_stats_rolls_up_across_namespaces():
    clear_all()
    a = cache_for("a"); b = cache_for("b")
    a.set("k1", "v"); b.set("k2", "v")
    a.get("k1"); b.get("missing")
    g = global_stats()
    assert g["totals"]["entries"]    == 2
    assert g["totals"]["hits"]       == 1
    assert g["totals"]["misses"]     == 1
    assert g["totals"]["namespaces"] == 2
    assert "a" in g["namespaces"] and "b" in g["namespaces"]


def test_delete_removes_entry():
    c = TTLCache()
    c.set("k", "v")
    c.delete("k")
    assert c.get("k") is None
    assert c.stats()["entries"] == 0


def test_delete_missing_key_is_noop():
    c = TTLCache()
    c.delete("never_set")  # must not raise
