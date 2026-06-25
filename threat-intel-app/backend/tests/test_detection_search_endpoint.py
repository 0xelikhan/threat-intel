"""HTTP-level coverage for the round-14 /api/detection/search route.

The semantic_search_detections skill is exercised in test_round14_ml.py;
this file rounds out the coverage by going through the FastAPI route +
auth middleware + error envelope so we catch wiring regressions
(missing import, wrong default param type, response shape drift).
"""

from __future__ import annotations

import os
import sys

import bcrypt
import pytest

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

_USER = "detection-search-test"
_PW   = "detection-search-test-pw"


@pytest.fixture(scope="module")
def client():
    # intel.auth snapshots AUTH_USERNAME / AUTH_PASSWORD_HASH at import
    # time (line 33-34), and any other test file that imported main
    # first will have won the env-var race. Patch the module attributes
    # directly so this test's credentials work regardless of import
    # order across the full pytest session.
    from fastapi.testclient import TestClient
    import main as _main
    from intel import auth as _auth

    _auth._USERNAME      = _USER
    _auth._PASSWORD_HASH = bcrypt.hashpw(
        _PW.encode(), bcrypt.gensalt(rounds=4))

    c = TestClient(_main.app)
    r = c.post("/api/auth/login",
               json={"username": _USER, "password": _PW})
    assert r.status_code == 200, f"login failed: {r.text}"
    return c


def test_unauthenticated_request_blocked_with_envelope():
    """Without an auth cookie the AuthGateMiddleware must intercept and
    return the standard error envelope (detail / error / status). Uses
    a fresh TestClient (no shared fixture cookie) so the no-cookie
    state is clean. Auth-credential patching isn't needed here — we're
    testing the no-cookie path, which fires before bcrypt verify."""
    from fastapi.testclient import TestClient
    import main as _main
    c = TestClient(_main.app)
    r = c.get("/api/detection/search?q=test")
    assert r.status_code == 401, f"expected 401, got {r.status_code}: {r.text}"
    body = r.json()
    assert body.get("detail"), f"401 missing detail: {body}"
    assert body.get("error"),  f"401 missing error:  {body}"


def test_search_returns_envelope_shape(client):
    """A vanilla query must return the documented envelope:
    {query, results, total, backend}. The skill returns an empty
    results list when the corpora aren't loaded — that's fine; we're
    asserting the wire shape, not search quality."""
    r = client.get("/api/detection/search",
                   params={"q": "powershell encoded command", "top_k": 5})
    assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
    body = r.json()
    for key in ("query", "results", "total", "backend"):
        assert key in body, f"envelope missing '{key}': {body}"
    assert body["query"] == "powershell encoded command"
    assert isinstance(body["results"], list)
    assert isinstance(body["total"], int)
    assert body["total"] == len(body["results"])


def test_empty_query_returns_zero_results(client):
    """The skill short-circuits empty / whitespace queries to an empty
    list. The route must not 500 — it's a valid request with a vacuous
    answer."""
    r = client.get("/api/detection/search", params={"q": ""})
    assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
    body = r.json()
    assert body.get("results") == []
    assert body.get("total")   == 0


def test_top_k_caps_results(client):
    """When the query returns hits, top_k caps the response length.
    When the index is empty (no corpora loaded under test) this devolves
    to asserting top_k is forwarded — empty results still respect the
    cap. Either way the response must not exceed the cap."""
    r = client.get("/api/detection/search",
                   params={"q": "lateral movement", "top_k": 3})
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["results"]) <= 3


def test_sources_filter_accepted(client):
    """The route splits the `sources` comma-list and forwards to the
    skill as a filter. Result count can be 0; the assertion here is
    that the request is parsed without 500 and the envelope shape
    survives the filter."""
    r = client.get("/api/detection/search",
                   params={"q": "credential dump",
                           "sources": "sigma,panther,splunk"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "results" in body and "total" in body


def test_min_score_filter_accepted(client):
    """`min_score` is a float query param. Passing 0.0 (the default) is
    a no-op; passing 0.99 should filter most hits out. The route must
    not 500 on either."""
    r = client.get("/api/detection/search",
                   params={"q": "anything", "min_score": 0.99})
    assert r.status_code == 200, r.text
    body = r.json()
    # Every result that DID survive the filter must have score >= 0.99.
    for hit in body.get("results", []):
        assert hit.get("score", 0) >= 0.99, hit


def test_stats_endpoint_shape(client):
    """/api/detection/search/stats wraps intel.semantic_search.stats —
    the operator-facing surface that reports which embedder backend is
    active. Must return loaded / backend / rule_count keys regardless
    of whether the index has corpora to load."""
    r = client.get("/api/detection/search/stats")
    assert r.status_code == 200, r.text
    body = r.json()
    for key in ("loaded", "backend", "rule_count"):
        assert key in body, f"stats missing '{key}': {body}"
    assert isinstance(body["loaded"], bool)
    assert isinstance(body["rule_count"], int)


def test_request_id_header_on_envelope(client):
    """Every endpoint response carries X-Request-ID for log correlation
    (documented in CLAUDE.md as part of the error-envelope contract).
    Detection-search shouldn't be the exception."""
    r = client.get("/api/detection/search", params={"q": "test"})
    assert r.status_code == 200
    assert r.headers.get("X-Request-ID"), \
        "X-Request-ID header missing from /api/detection/search response"
