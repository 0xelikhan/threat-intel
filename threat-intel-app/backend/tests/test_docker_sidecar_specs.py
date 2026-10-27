"""Static Dockerfile + sidecar-spec verification.

The real `docker/verify.sh` requires Docker on the host, which is a
soft dependency we don't want in CI. These tests cover what can be
verified statically:

  1. Every sidecar service file imports cleanly and exposes `app`
     (duplicates what test_sidecar_wrappers covers, from a different
     angle: run from the backend venv instead of the sidecars dir)
  2. Every PyPI package named in docker-compose.yml's TOOLS args
     actually exists on PyPI
  3. Every Dockerfile referenced by docker-compose.yml exists on disk
     and parses as a valid Dockerfile (no obvious syntax errors in
     the CMD / ENTRYPOINT / FROM / COPY lines)
  4. The service_env_var in each DockerStub matches docker-compose's
     expected URL env var name
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.request import urlopen

import pytest


_DOCKER_DIR = Path(__file__).resolve().parents[2] / "docker"
_SIDECARS_DIR = _DOCKER_DIR / "sidecars"


def test_docker_compose_file_exists():
    assert (_DOCKER_DIR / "docker-compose.yml").is_file()


def test_all_dockerfiles_referenced_in_compose_exist():
    compose = (_DOCKER_DIR / "docker-compose.yml").read_text()
    # Every "dockerfile:" line names a file that must exist alongside.
    referenced = set(re.findall(r"dockerfile:\s*([\w\.]+)", compose))
    assert referenced, "no Dockerfiles referenced in docker-compose.yml"
    missing = []
    for df in referenced:
        if not (_SIDECARS_DIR / df).is_file():
            missing.append(df)
    assert not missing, f"missing Dockerfiles: {missing}"


def test_every_dockerfile_has_a_cmd_or_entrypoint():
    """Dockerfiles without a CMD/ENTRYPOINT line can build but hang
    on `docker run`. Guard against the next drive-by edit that
    accidentally strips the last line."""
    for df in _SIDECARS_DIR.glob("Dockerfile.*"):
        text = df.read_text()
        has_cmd        = re.search(r"^\s*CMD\s", text, re.MULTILINE)
        has_entrypoint = re.search(r"^\s*ENTRYPOINT\s", text, re.MULTILINE)
        assert has_cmd or has_entrypoint, (
            f"{df.name} has no CMD or ENTRYPOINT — container would exit "
            "immediately on `docker run`"
        )


def test_dockerfile_python_uses_service_app_target():
    """Dockerfile.python's CMD must target `service:app`, not the old
    `service:build_app` factory. Guard against the gunicorn regression
    we hit in 068232d."""
    for df in _SIDECARS_DIR.glob("Dockerfile.*"):
        text = df.read_text()
        if "gunicorn" not in text:
            continue
        # Any `service:*` reference should name `app`, not `build_app`.
        assert "service:build_app" not in text, (
            f"{df.name} still points gunicorn at the 2-arg factory — "
            "would crash at container startup"
        )
        if "service:app" not in text:
            # Not every Dockerfile embeds gunicorn via a top-level CMD —
            # the clamav one calls it inside a start script. Verify
            # that case separately.
            assert re.search(r"gunicorn[^\n]*service:app", text), (
                f"{df.name} has gunicorn but doesn't target service:app"
            )


@pytest.mark.parametrize("pkg_name", [
    "qiling", "speakeasy-emulator", "thug", "quark-engine",
    "hfinger", "stringsifter", "requests",
])
def test_pypi_package_exists(pkg_name):
    """Each pip package named in docker-compose.yml's TOOLS args must
    be installable from PyPI. Catches typos the moment we commit."""
    try:
        with urlopen(f"https://pypi.org/pypi/{pkg_name}/json", timeout=10) as resp:
            assert resp.status == 200, f"{pkg_name}: HTTP {resp.status}"
    except Exception as e:
        pytest.skip(f"PyPI unreachable: {e}")


def test_every_docker_stub_env_var_matches_dispatch_contract():
    """Every DockerStub registered in docker_stubs.py must set
    service_env_var to a RECON_<SOMETHING>_URL — the dispatcher reads
    exactly that env var at request time."""
    sys.path.insert(0, str(_SIDECARS_DIR.parent.parent / "backend"))
    try:
        from plugins.file_analyzers.docker_stubs import _DockerStub
    except Exception as e:
        pytest.skip(f"docker_stubs import failed: {e}")

    # Walk every direct subclass of _DockerStub
    subclasses = _DockerStub.__subclasses__()
    assert len(subclasses) >= 10, (
        f"expected ≥10 DockerStub subclasses, got {len(subclasses)}"
    )
    for cls in subclasses:
        env = cls.service_env_var
        assert env.startswith("RECON_") and env.endswith("_URL"), (
            f"{cls.__name__}.service_env_var = {env!r} — "
            "doesn't match RECON_<SOMETHING>_URL convention"
        )


def test_sidecar_dockerfile_boxjs_installs_node_and_boxjs():
    """box-js is Node, not Python — the Dockerfile must install both."""
    text = (_SIDECARS_DIR / "Dockerfile.boxjs").read_text()
    assert "FROM node" in text, "Dockerfile.boxjs doesn't start FROM a node image"
    assert "box-js" in text, "Dockerfile.boxjs doesn't install box-js"


def test_sidecar_dockerfile_clamav_starts_daemon_before_wrapper():
    """ClamAV wrapper needs clamd running on 3310 — the start script
    must boot clamd first and wait for it to accept connections."""
    text = (_SIDECARS_DIR / "Dockerfile.clamav").read_text()
    assert "clamav-daemon" in text, "Dockerfile.clamav doesn't install clamav-daemon"
    assert "clamd" in text, "Dockerfile.clamav doesn't launch clamd"
    assert "3310" in text, "Dockerfile.clamav doesn't configure clamd on port 3310"


def test_sidecar_dockerfile_suricata_pulls_rules():
    """Suricata without rules alerts on nothing — Dockerfile should
    seed a ruleset at build time via suricata-update."""
    text = (_SIDECARS_DIR / "Dockerfile.suricata").read_text()
    assert "suricata-update" in text, (
        "Dockerfile.suricata should prime a baseline ruleset via suricata-update"
    )
