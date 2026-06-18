"""Regression test for AuditMiddleware's 50 MB body cap.

CLAUDE.md has documented this cap as part of the platform's hardening
since spec §9; the previous implementation never actually enforced it,
so every JSON endpoint that took `req: dict` (chat_send, scan_compare,
urlscan_submit, email_draft_save, email_send_test) was open to a DOS via
a multi-GB POST that FastAPI would parse into memory before the
handler's field-level checks could reject it.

These tests use FastAPI's TestClient — no real network, no real LLM,
just an in-process exercise of the middleware chain.
"""

from __future__ import annotations

import os
import sys

import pytest

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)


@pytest.fixture(scope="module")
def client():
    # Configure auth so the auth gate doesn't intercept our probes.
    # Generate the bcrypt hash at fixture-build time so the password +
    # hash are guaranteed to match (a hardcoded hash drifted when this
    # file was first authored).
    import bcrypt
    pw = "body-cap-test-pw"
    os.environ["AUTH_USERNAME"]       = "body-cap-test"
    os.environ["AUTH_PASSWORD_HASH"]  = bcrypt.hashpw(
        pw.encode(), bcrypt.gensalt(rounds=4)).decode()
    os.environ["AUTH_SESSION_SECRET"] = "body-cap-test-secret-XXXXXXXXXXXXX"

    # Import AFTER env vars are set so auth wires up correctly.
    from fastapi.testclient import TestClient
    import main as _main

    c = TestClient(_main.app)
    # Authenticate so the AuditMiddleware path actually fires for /api/*.
    r = c.post("/api/auth/login",
               json={"username": "body-cap-test", "password": pw})
    assert r.status_code == 200, f"login failed: {r.text}"
    return c


def test_normal_size_body_passes_through(client):
    """A 1 KB POST to an endpoint that accepts dict bodies should be
    handled normally (the response code depends on the endpoint's own
    validation, but the body itself must not be rejected by the cap)."""
    # /api/urlscan/submit accepts a dict body. With no URLSCAN_KEY set
    # it'll return 400 — that's fine; we only want to confirm the body
    # was NOT rejected at the middleware layer for being too large.
    body = {"url": "https://example.com/" + "x" * 500}  # ~ 530 bytes
    r = client.post("/api/urlscan/submit", json=body)
    assert r.status_code != 413, f"normal-size body wrongly rejected as too large: {r.text}"


def test_oversize_content_length_rejected_with_envelope(client):
    """Setting Content-Length to 100 MB (well above the cap) must be
    rejected by AuditMiddleware before reaching the handler. The
    response body must carry the project's standard error envelope
    (detail / error / error_code / status) so the frontend's err.detail
    || err.error parser works the same way as every other error."""
    OVERSIZE = 100 * 1024 * 1024
    # Don't actually send 100 MB; the middleware reads Content-Length
    # from headers and rejects before reading the body. We send a small
    # body but lie about Content-Length in the header.
    r = client.post(
        "/api/urlscan/submit",
        headers={
            "Content-Type":   "application/json",
            "Content-Length": str(OVERSIZE),
        },
        content=b'{"url":"https://example.com"}',
    )
    assert r.status_code == 413, f"100 MB Content-Length was NOT rejected: {r.status_code} {r.text}"
    body = r.json()
    # Envelope shape — the frontend reads .detail || .error.
    assert body.get("detail"), f"413 missing detail field: {body}"
    assert body.get("error"),  f"413 missing error field: {body}"
    assert body.get("status") == 413
    assert body.get("error_code") == "request_too_large"


def test_50mib_file_upload_envelope_passes_through(client):
    """A 50 MiB file wrapped in multipart/form-data has multipart envelope
    overhead (boundary markers + Content-Disposition headers) that pushes
    the actual Content-Length above 50 MiB. The middleware envelope cap
    must accommodate this so the file-scan handler's authoritative
    `len(data) > 50 MiB` check is the gate, not the middleware. This is
    the regression: a previous version of the cap matched 50 MiB exact
    and rejected every legitimate 50 MiB upload."""
    # 50 MiB + ~500 bytes of multipart framing — well within the
    # middleware's 51 MiB envelope cap.
    SIMULATED_MULTIPART = 50 * 1024 * 1024 + 500
    r = client.post(
        "/api/urlscan/submit",
        headers={
            "Content-Type":   "application/json",
            "Content-Length": str(SIMULATED_MULTIPART),
        },
        content=b'{"url":"https://example.com"}',
    )
    assert r.status_code != 413, (
        "50 MiB + multipart overhead was wrongly rejected by the envelope "
        "cap; the handler's authoritative size check should be the gate. "
        f"got {r.status_code} {r.text}"
    )


def test_boundary_at_envelope_cap_is_accepted(client):
    """A POST at exactly the envelope cap boundary should still pass
    through. The middleware uses `>` not `>=`, so 51 MiB exact is allowed."""
    BOUNDARY = 51 * 1024 * 1024
    r = client.post(
        "/api/urlscan/submit",
        headers={
            "Content-Type":   "application/json",
            "Content-Length": str(BOUNDARY),
        },
        content=b'{"url":"https://example.com"}',
    )
    assert r.status_code != 413, (
        f"body exactly at the envelope cap was wrongly rejected: "
        f"{r.status_code} {r.text}"
    )


def test_one_byte_above_envelope_cap_is_rejected(client):
    """The cap is `>`, not `>=`. Exactly cap+1 bytes must trigger 413."""
    ONE_PAST = (51 * 1024 * 1024) + 1
    r = client.post(
        "/api/urlscan/submit",
        headers={
            "Content-Type":   "application/json",
            "Content-Length": str(ONE_PAST),
        },
        content=b'{"url":"https://example.com"}',
    )
    assert r.status_code == 413, (
        f"body one byte over the envelope cap was NOT rejected: "
        f"{r.status_code} {r.text}"
    )


def test_malformed_content_length_falls_through(client):
    """A non-integer Content-Length header should NOT cause the middleware
    to crash. The cap check falls back to letting the downstream parser
    handle it. (Realistic clients never send this, but defensive code
    matters for fuzzers / misbehaving libraries.)"""
    r = client.post(
        "/api/urlscan/submit",
        headers={
            "Content-Type":   "application/json",
            "Content-Length": "not-a-number",  # would be rejected by the OS-level parser already
        },
        content=b'{"url":"https://example.com"}',
    )
    # Whatever happens, it must not be a 500 from the middleware crashing.
    assert r.status_code != 500, f"malformed Content-Length crashed the middleware: {r.text}"
