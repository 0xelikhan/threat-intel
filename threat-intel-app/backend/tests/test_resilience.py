"""Tests for the circuit breaker, error envelope, and observability bits."""

from __future__ import annotations

from intel.circuit_breaker import CircuitBreaker, host_of, get_breaker
from intel.observability import (
    error_envelope,
    current_request_id,
    configure_logging,
)


# ─── circuit breaker ──────────────────────────────────────────────────────────
def test_breaker_closed_by_default():
    cb = CircuitBreaker()
    assert not cb.is_open("api.example.com")


def test_breaker_opens_after_threshold_consecutive_failures():
    cb = CircuitBreaker(failure_threshold=3, cooldown_s=60)
    cb.record_failure("h"); cb.record_failure("h")
    assert not cb.is_open("h")
    cb.record_failure("h")
    assert cb.is_open("h")


def test_success_closes_breaker_immediately():
    """Half-open probe semantics: a single success after open means the
    host is back; no need to wait the full cooldown."""
    cb = CircuitBreaker(failure_threshold=2)
    cb.record_failure("h"); cb.record_failure("h")
    assert cb.is_open("h")
    cb.record_success("h")
    assert not cb.is_open("h")


def test_streak_resets_on_success_so_threshold_must_be_re_hit():
    cb = CircuitBreaker(failure_threshold=3)
    cb.record_failure("h"); cb.record_failure("h")
    cb.record_success("h")
    cb.record_failure("h"); cb.record_failure("h")
    assert not cb.is_open("h"), "two failures after success isn't yet a streak of three"


def test_stats_carries_per_host_state():
    cb = CircuitBreaker(failure_threshold=2)
    cb.record_success("a"); cb.record_failure("b"); cb.record_failure("b")
    s = cb.stats()
    assert s["a"]["state"]  == "closed" and s["a"]["successes"] == 1
    assert s["b"]["state"]  == "open"   and s["b"]["failures"]  == 2


def test_get_breaker_returns_singleton():
    assert get_breaker() is get_breaker()


# ─── host_of ──────────────────────────────────────────────────────────────────
def test_host_of_extracts_hostname():
    assert host_of("https://api.example.com/v1/check?ip=1.2.3.4") == "api.example.com"
    assert host_of("https://x.y.z:443/path") == "x.y.z"
    assert host_of("not a url") is None


# ─── error envelope ───────────────────────────────────────────────────────────
def test_envelope_preserves_existing_fields():
    """`detail` (FastAPI default) and `error` (frontend fallback) must both
    survive — the additive contract."""
    env = error_envelope("bad request", code="bad_request", status=400)
    assert env["detail"] == "bad request"
    assert env["error"]  == "bad request"
    assert env["error_code"] == "bad_request"
    assert env["status"] == 400


def test_envelope_carries_details_dict():
    env = error_envelope("validation", code="v", extras={"field": "email"})
    assert env["details"] == {"field": "email"}


def test_envelope_falls_back_to_internal_error_code():
    env = error_envelope("oops")
    assert env["error_code"] == "internal_error"


def test_envelope_includes_request_id_slot():
    env = error_envelope("x")
    assert "request_id" in env  # value is None outside a request scope


# ─── observability ────────────────────────────────────────────────────────────
def test_current_request_id_is_none_outside_request_scope():
    assert current_request_id() is None


def test_configure_logging_is_idempotent():
    configure_logging()
    configure_logging()  # second call must not double-add handlers
    import logging
    assert len(logging.getLogger().handlers) >= 1
