"""
GitHub Security Advisories (GHSA) database loader.

Source: https://github.com/github/advisory-database (CC-BY-4.0). The
canonical structured advisory database for ~10 package ecosystems
(npm, PyPI, RubyGems, Composer, Maven, Go, NuGet, Pub, Cargo, Erlang).
Each advisory is a JSON file with shape:

  {
    "schema_version": "1.4.0",
    "id":      "GHSA-xxxx-xxxx-xxxx",
    "summary": "...",
    "details": "...",
    "aliases": ["CVE-2023-1234"],
    "affected": [{"package": {"ecosystem": "PyPI", "name": "..."},
                   "ranges": [...], "versions": [...]}, ...],
    "references": [{"url": "..."}],
    "database_specific": {"severity": "HIGH", "github_reviewed": true, ...}
  }

Indexed by both GHSA-id and CVE-alias so cve_enrichment can resolve a
CVE-XXXX-YYYY query directly into the GHSA record. Complements OSV.dev
(which also indexes GHSA) with the upstream editorial-curated copy.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.ghsa")

_GHSA_ROOT = (Path(__file__).parent.parent.parent
              / "vendor" / "ghsa-advisory-database")

_CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":         False,
    "by_ghsa":        {},   # dict[GHSA-id, advisory]
    "by_cve":         {},   # dict[CVE-id, list[advisory]]
    "by_ecosystem":   {},   # dict[ecosystem, list[advisory]]
    "total":          0,
    "error":          None,
}


def _ingest_advisory(doc: Dict[str, Any],
                     by_ghsa: Dict[str, Dict[str, Any]],
                     by_cve:  Dict[str, List[Dict[str, Any]]],
                     by_eco:  Dict[str, List[Dict[str, Any]]]) -> None:
    ghsa_id = (doc.get("id") or "").strip()
    if not ghsa_id.upper().startswith("GHSA-"):
        return
    summary = (doc.get("summary") or "")[:240]
    details = (doc.get("details") or "")[:600]
    aliases = doc.get("aliases") or []
    if not isinstance(aliases, list):
        aliases = []
    cves: List[str] = []
    for a in aliases:
        s = str(a or "").upper()
        m = _CVE_RE.match(s) or _CVE_RE.search(s)
        if m:
            cves.append(m.group(1).upper())

    affected = doc.get("affected") or []
    ecosystems: List[str] = []
    packages:   List[str] = []
    if isinstance(affected, list):
        for a in affected[:20]:
            if not isinstance(a, dict):
                continue
            pkg = a.get("package") or {}
            if isinstance(pkg, dict):
                eco  = (pkg.get("ecosystem") or "").strip()
                name = (pkg.get("name") or "").strip()
                if eco:
                    ecosystems.append(eco)
                if name:
                    packages.append(f"{eco}:{name}" if eco else name)
    ecosystems = list(dict.fromkeys(ecosystems))[:6]
    packages   = list(dict.fromkeys(packages))[:10]

    dbspec = doc.get("database_specific") or {}
    severity = ""
    if isinstance(dbspec, dict):
        severity = str(dbspec.get("severity") or "").lower()
    references = []
    for ref in (doc.get("references") or [])[:6]:
        if isinstance(ref, dict) and ref.get("url"):
            references.append({"type": ref.get("type", "WEB"),
                                "url":  ref["url"][:200]})

    entry = {
        "ghsa_id":    ghsa_id,
        "cves":       cves,
        "summary":    summary,
        "details":    details,
        "ecosystems": ecosystems,
        "packages":   packages,
        "severity":   severity,
        "references": references,
        "source":     "GitHub Security Advisories",
    }
    by_ghsa[ghsa_id] = entry
    for cve in cves:
        by_cve.setdefault(cve, []).append(entry)
    for eco in ecosystems:
        by_eco.setdefault(eco, []).append(entry)


def _build_index() -> None:
    if not _GHSA_ROOT.exists():
        _state["error"]  = f"ghsa-advisory-database dir not present at {_GHSA_ROOT}"
        _state["loaded"] = True
        return

    by_ghsa: Dict[str, Dict[str, Any]] = {}
    by_cve:  Dict[str, List[Dict[str, Any]]] = {}
    by_eco:  Dict[str, List[Dict[str, Any]]] = {}

    # The repo layout is advisories/github-reviewed/YYYY/MM/GHSA-xxxx/{GHSA-xxxx.json,...}
    # We walk every *.json under advisories/.
    advisories_root = _GHSA_ROOT / "advisories"
    if not advisories_root.exists():
        advisories_root = _GHSA_ROOT
    parsed = 0
    for path in advisories_root.rglob("*.json"):
        if not path.is_file() or path.stat().st_size > 256_000:
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        _ingest_advisory(doc, by_ghsa, by_cve, by_eco)
        parsed += 1

    _state["by_ghsa"]      = by_ghsa
    _state["by_cve"]       = by_cve
    _state["by_ecosystem"] = by_eco
    _state["total"]        = parsed
    _state["loaded"]       = True
    _state["error"]        = None
    _log.info("ghsa-advisory-database loaded: %d advisories | %d CVEs | %d ecosystems",
              parsed, len(by_cve), len(by_eco))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def lookup_cve(cve_id: str, max_results: int = 6) -> List[Dict[str, Any]]:
    _ensure_loaded()
    if not cve_id:
        return []
    rows = (_state.get("by_cve") or {}).get(cve_id.upper().strip(), [])
    return rows[:max_results]


def lookup_ghsa(ghsa_id: str) -> Optional[Dict[str, Any]]:
    _ensure_loaded()
    return (_state.get("by_ghsa") or {}).get((ghsa_id or "").strip())


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":     bool(_state["loaded"]),
        "advisories": _state.get("total", 0),
        "cves":       len(_state.get("by_cve") or {}),
        "ecosystems": list((_state.get("by_ecosystem") or {}).keys()),
        "error":      _state.get("error"),
    }
