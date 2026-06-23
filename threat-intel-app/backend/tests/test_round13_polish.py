"""
Round-13 polish tests:

  * intel/network_timing histogram via agents.enrichment._record_timing
  * /api/status/timings/reset endpoint (logic only — no HTTP test here)
  * Settings UI flow is React-side, covered manually
"""

from __future__ import annotations


def test_record_timing_counts_ok_and_errors():
    from agents.enrichment import (
        _record_timing, network_timings_snapshot, reset_network_timings,
    )
    reset_network_timings()
    _record_timing("api.example.com", 120.5, ok=True,  status=200)
    _record_timing("api.example.com",  85.3, ok=True,  status=200)
    _record_timing("api.example.com", 250.0, ok=False, status=429)
    _record_timing("slow.example.org", 5000.0, ok=False, status=0)
    snap = network_timings_snapshot()
    by_host = {r["host"]: r for r in snap}
    assert "api.example.com" in by_host
    assert by_host["api.example.com"]["count"]  == 3
    assert by_host["api.example.com"]["ok"]     == 2
    assert by_host["api.example.com"]["errors"] == 1
    # Mean is (120.5 + 85.3 + 250.0) / 3 ≈ 151.9
    assert 145 <= by_host["api.example.com"]["mean_ms"] <= 160
    # Snapshot is sorted by mean_ms descending — the slow host is on top
    assert snap[0]["host"] == "slow.example.org"


def test_record_timing_unknown_host_uses_fallback():
    from agents.enrichment import (
        _record_timing, network_timings_snapshot, reset_network_timings,
    )
    reset_network_timings()
    _record_timing(None, 50.0, ok=True, status=200)
    _record_timing("",   60.0, ok=True, status=200)
    hosts = [r["host"] for r in network_timings_snapshot()]
    assert "?unknown" in hosts


def test_reset_network_timings_clears_state():
    from agents.enrichment import (
        _record_timing, network_timings_snapshot, reset_network_timings,
    )
    reset_network_timings()
    _record_timing("example.com", 100.0, ok=True, status=200)
    assert network_timings_snapshot()
    reset_network_timings()
    assert network_timings_snapshot() == []


def test_timing_snapshot_top_n_caps_results():
    from agents.enrichment import (
        _record_timing, network_timings_snapshot, reset_network_timings,
    )
    reset_network_timings()
    for i in range(40):
        _record_timing(f"h{i}.example.com", float(i * 10), ok=True, status=200)
    snap = network_timings_snapshot(top=5)
    assert len(snap) == 5
    # Sorted by mean_ms desc → h39 / h38 / h37 / h36 / h35
    assert snap[0]["host"] == "h39.example.com"
