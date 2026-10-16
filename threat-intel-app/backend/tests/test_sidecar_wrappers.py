"""Smoke tests for the file-analyzer sidecar wrappers.

Each service module (docker/sidecars/*_service.py) exposes a Flask
app at module scope so `gunicorn service:app` works inside its
container. These tests exercise the shared `_base_wrapper.build_app`
+ the module-level `app` binding using Flask's test client — no
Docker required.

Covers:
  - /health returns 200 + the service name
  - /analyze with multipart file bytes returns the adapter's dict
  - /analyze with no file field returns 400
  - unknown route returns 404 + json error
"""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path

import pytest


_SIDECARS_DIR = Path(__file__).resolve().parents[2] / "docker" / "sidecars"


@pytest.fixture(scope="module")
def wrapper_module(monkeypatch_session=None):
    """Load _base_wrapper from the docker/sidecars dir."""
    sys.path.insert(0, str(_SIDECARS_DIR))
    try:
        import _base_wrapper
    except Exception as e:
        pytest.skip(f"_base_wrapper import failed: {e}")
    yield _base_wrapper


def _echo_analyze(data: bytes, filename: str) -> dict:
    return {"verdict": "UNKNOWN",
            "summary": f"echo: {len(data)} bytes from {filename}",
            "size": len(data), "filename": filename}


def test_build_app_health(wrapper_module):
    app = wrapper_module.build_app("echo", _echo_analyze)
    client = app.test_client()
    r = client.get("/health")
    assert r.status_code == 200
    body = r.get_json()
    assert body["service"] == "echo"
    assert body["ok"] is True


def test_build_app_analyze_returns_adapter_dict(wrapper_module):
    app = wrapper_module.build_app("echo", _echo_analyze)
    client = app.test_client()
    r = client.post("/analyze", data={
        "file": (io.BytesIO(b"hello world"), "greeting.txt"),
    }, content_type="multipart/form-data")
    assert r.status_code == 200
    body = r.get_json()
    assert body["size"] == 11
    assert body["filename"] == "greeting.txt"
    assert body["verdict"] == "UNKNOWN"


def test_build_app_analyze_rejects_missing_file(wrapper_module):
    app = wrapper_module.build_app("echo", _echo_analyze)
    client = app.test_client()
    r = client.post("/analyze", data={}, content_type="multipart/form-data")
    assert r.status_code == 400
    assert r.get_json()["error_type"] == "invalid_request"


def test_build_app_analyze_rejects_empty_file(wrapper_module):
    app = wrapper_module.build_app("echo", _echo_analyze)
    client = app.test_client()
    r = client.post("/analyze", data={
        "file": (io.BytesIO(b""), "empty.bin"),
    }, content_type="multipart/form-data")
    assert r.status_code == 400


def test_build_app_404_returns_json(wrapper_module):
    app = wrapper_module.build_app("echo", _echo_analyze)
    client = app.test_client()
    r = client.get("/does-not-exist")
    assert r.status_code == 404
    assert r.get_json()["error_type"] == "invalid_request"


def test_adapter_exception_surfaced_as_500(wrapper_module):
    def _boom(_data: bytes, _filename: str) -> dict:
        raise RuntimeError("boom")
    app = wrapper_module.build_app("boom", _boom)
    client = app.test_client()
    r = client.post("/analyze", data={
        "file": (io.BytesIO(b"x"), "x.bin"),
    }, content_type="multipart/form-data")
    assert r.status_code == 500
    body = r.get_json()
    assert body["error_type"] == "runtime_error"
    assert "boom" in body["error"]


# ─── Per-service module smoke tests ─────────────────────────────────────────

_SERVICE_MODULES = [
    "qiling_service", "speakeasy_service", "thug_service", "box_js_service",
    "mobsf_service", "quark_service", "clamav_service", "suricata_service",
    "hfinger_service", "stringsifter_service",
]


@pytest.mark.parametrize("mod_name", _SERVICE_MODULES)
def test_service_module_exposes_app(wrapper_module, mod_name):
    """Every sidecar module must bind a Flask `app` at module scope so
    gunicorn's `service:app` works in the container."""
    import importlib
    try:
        mod = importlib.import_module(mod_name)
    except Exception as e:
        pytest.skip(f"{mod_name} import skipped: {e}")
    assert hasattr(mod, "app"), f"{mod_name} missing module-level `app`"
    # Flask app has a `test_client` method
    assert hasattr(mod.app, "test_client"), f"{mod_name}.app isn't a Flask instance"


@pytest.mark.parametrize("mod_name", _SERVICE_MODULES)
def test_service_module_health_works(wrapper_module, mod_name):
    """Every sidecar's /health endpoint should 200."""
    import importlib
    try:
        mod = importlib.import_module(mod_name)
    except Exception as e:
        pytest.skip(f"{mod_name} import skipped: {e}")
    client = mod.app.test_client()
    r = client.get("/health")
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True
    assert body["service"]  # some non-empty service name
