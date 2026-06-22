"""
FLARE capa runner — identifies capabilities in PE/.NET/ELF/shellcode files
and maps them to MITRE ATT&CK techniques.

Wraps Mandiant FLARE capa (https://github.com/mandiant/capa, Apache-2.0).
We invoke capa as a subprocess (`python -m capa.main -j`) rather than via
its Python API because:

  1. capa's Python API is large and changes between major versions; the
     CLI's `-j` JSON output is the stable contract.
  2. capa loads heavy native code (vivisect, idalib) — running it in a
     subprocess gives us process-level isolation, so a capa crash on a
     malformed PE can't take RECON down.
  3. The CLI accepts a tempfile path; we already use the same tempfile
     pattern for sigma-cli validation in agents/response.py, so the
     "no analyst data on disk" rule is satisfied via NamedTemporaryFile
     + finally:unlink.

The runner returns a normalised dict shape:

  {
    "available":   bool,
    "capabilities": [
        {"rule": str, "namespace": str, "matches": int,
         "mitre_techniques": [str], "mbc": [str], "att_ck": [str]},
        ...
    ],
    "mitre_techniques":  list[str],  # de-duped, sorted
    "namespaces":        list[str],
    "rule_count":        int,
    "error":             str|None,
  }
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Sequence

_log = logging.getLogger("recon.intel.capa")

# Cap the per-file analysis at 90s; capa on a complex PE can take ~30s,
# and the front-of-queue scan path can't block indefinitely. The async
# wait_for re-raises TimeoutError, which the caller surfaces as an error.
_CAPA_TIMEOUT_S = 90

# Resolve the venv's Python so subprocess goes through the same
# interpreter that has capa + vivisect installed. Falls back to sys.executable.
_PY = sys.executable

# Limits — analyst output should be readable, not exhaustive.
_MAX_CAPABILITIES_RETURNED = 30


def run_capa_sync(file_bytes: bytes,
                  filename:    Optional[str] = None,
                  timeout_s:   int = _CAPA_TIMEOUT_S) -> Dict[str, Any]:
    """Blocking variant of run_capa. Used by the sync file_analyzer flow
    (which runs inside asyncio.to_thread already, so blocking here is
    safe and saves us from nested event-loop juggling)."""
    if not file_bytes:
        return _empty(error="empty input")

    try:
        import capa  # noqa: F401
    except Exception as e:
        return _empty(error=f"capa not available: {e}", available=False)

    suffix = _suffix_for(filename)
    tmp_path: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(prefix="recon-capa-", suffix=suffix,
                                          delete=False) as f:
            f.write(file_bytes)
            tmp_path = f.name

        cmd = [_PY, "-m", "capa.main", "-j", "-q", tmp_path]
        try:
            r = subprocess.run(cmd, capture_output=True,
                               timeout=timeout_s, check=False)
        except subprocess.TimeoutExpired:
            return _empty(error=f"capa timed out after {timeout_s}s")

        if r.returncode != 0:
            err = (r.stderr or b"").decode("utf-8", errors="ignore")[:300]
            return _empty(error=err or f"capa exit code {r.returncode}")
        try:
            payload = json.loads(r.stdout or b"{}")
        except Exception as e:
            return _empty(error=f"capa JSON parse failed: {e}")
        return _parse(payload)
    except Exception as e:
        _log.warning("capa runner crashed: %s", e)
        return _empty(error=f"capa runner crashed: {e}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


async def run_capa(file_bytes: bytes,
                   filename:    Optional[str] = None,
                   timeout_s:   int = _CAPA_TIMEOUT_S) -> Dict[str, Any]:
    """Async variant — delegates to run_capa_sync via to_thread so the
    event loop stays responsive while capa's subprocess runs."""
    return await asyncio.to_thread(run_capa_sync, file_bytes, filename,
                                   timeout_s)


def _suffix_for(filename: Optional[str]) -> str:
    if not filename:
        return ""
    _, ext = os.path.splitext(filename)
    if ext and len(ext) < 12:
        return ext
    return ""


def _empty(error: Optional[str] = None,
           available: bool = True) -> Dict[str, Any]:
    return {
        "available":         available,
        "capabilities":      [],
        "mitre_techniques":  [],
        "namespaces":        [],
        "rule_count":        0,
        "error":             error,
    }


def _parse(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise capa's JSON result-document into a small, readable shape.
    capa's JSON is deeply nested (capa.render.result_document); we only
    surface the parts an analyst cares about: rule names, namespaces,
    MITRE/MBC tags, match counts."""
    rules = (payload.get("rules") or {})
    if not isinstance(rules, dict):
        return _empty(error="capa output missing 'rules' object")

    capabilities: List[Dict[str, Any]] = []
    seen_techniques: set = set()
    seen_namespaces: set = set()

    for rule_name, rule_obj in rules.items():
        if not isinstance(rule_obj, dict):
            continue
        meta    = rule_obj.get("meta") or {}
        namespace = (meta.get("namespace") or "").strip()
        matches   = len(rule_obj.get("matches") or [])
        att_ck    = _extract_attack_tags(meta)
        mbc       = _extract_mbc_tags(meta)
        techs     = sorted({t for t in att_ck if t.startswith("T")})

        for t in techs:
            seen_techniques.add(t)
        if namespace:
            seen_namespaces.add(namespace)

        capabilities.append({
            "rule":              rule_name,
            "namespace":         namespace,
            "matches":           matches,
            "mitre_techniques":  techs,
            "att_ck":            att_ck,
            "mbc":               mbc,
        })

    # Order by namespace then rule name — gives a stable, grouped view.
    capabilities.sort(key=lambda c: (c["namespace"], c["rule"]))

    return {
        "available":         True,
        "capabilities":      capabilities[:_MAX_CAPABILITIES_RETURNED],
        "mitre_techniques":  sorted(seen_techniques),
        "namespaces":        sorted(seen_namespaces),
        "rule_count":        len(capabilities),
        "error":             None,
    }


def _extract_attack_tags(meta: Dict[str, Any]) -> List[str]:
    """capa's MITRE tag shape varies by version. Most recent shape:
    `meta["attack"]` is a list of {"id": "T1059.001", "tactic": "Execution"}.
    Older shape: list of {"id": "T1059.001"} or a list of strings."""
    out: List[str] = []
    raw = meta.get("attack") or meta.get("att&ck") or []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                tid = item.get("id") or item.get("technique")
                if tid:
                    out.append(str(tid))
            elif isinstance(item, str):
                out.append(item)
    return out


def _extract_mbc_tags(meta: Dict[str, Any]) -> List[str]:
    """Same shape as attack but for the Malware Behavior Catalog."""
    out: List[str] = []
    raw = meta.get("mbc") or []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                obj = item.get("objective") or item.get("behavior")
                if obj:
                    out.append(str(obj))
            elif isinstance(item, str):
                out.append(item)
    return out


def stats() -> Dict[str, Any]:
    """Reportable in /api/status. Cheap — just an availability probe."""
    try:
        import capa
        return {"capa_available": True,
                "capa_version": getattr(capa, "__version__", "unknown")}
    except Exception as e:
        return {"capa_available": False, "capa_error": str(e)[:120]}
