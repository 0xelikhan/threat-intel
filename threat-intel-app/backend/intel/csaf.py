"""
OASIS CSAF 2.0 (Common Security Advisory Framework) loader.

Source: OASIS CSAF spec (https://docs.oasis-open.org/csaf/csaf/v2.0/).
Vendors publishing CSAF JSON include Cisco, Red Hat, Siemens, SAP,
Schneider Electric, Bosch, BSI, NCSC-NL, and CERT-Bund.

CSAF 2.0 documents are JSON with shape:

  {
    "document": {"title": "...", "tracking": {"id": "cisco-sa-...", ...}, ...},
    "vulnerabilities": [
       {"cve": "CVE-2024-12345",
        "title": "...",
        "scores": [{"cvss_v3": {"baseScore": 9.8, ...}}],
        "product_status": {"known_affected": [...], "fixed": [...]},
        "remediations": [{"category": "vendor_fix", "url": "..."}, ...]},
       ...
    ],
    "product_tree": {...}
  }

We walk vendored CSAF documents at vendor/csaf/<vendor>/*.json and
build a CVE-keyed inverted index. enrich_cve fans into this alongside
the existing NVD / OSV / KEV / GHSA / RHSA lookups so vendor-specific
fix context is surfaced when available.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_log = logging.getLogger("recon.intel.csaf")

_CSAF_ROOT = (Path(__file__).parent.parent.parent
              / "vendor" / "csaf")

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":      False,
    "by_cve":      {},   # dict[CVE-id, list[advisory_meta]]
    "vendors":     set(),
    "total":       0,
    "error":       None,
}


def _ingest_doc(doc: Dict[str, Any], path: Path,
                by_cve:  Dict[str, List[Dict[str, Any]]],
                vendors: set) -> int:
    if not isinstance(doc, dict):
        return 0
    document    = doc.get("document") or {}
    if not isinstance(document, dict):
        return 0
    title       = (document.get("title") or "")[:240]
    publisher   = document.get("publisher") or {}
    vendor      = (publisher.get("name") or "").strip()[:120]
    if not vendor:
        # Fall back to parent dir name (e.g. vendor/csaf/cisco/...).
        try:
            rel = path.relative_to(_CSAF_ROOT)
            vendor = rel.parts[0] if rel.parts else "unknown"
        except ValueError:
            vendor = "unknown"
    vendors.add(vendor)

    tracking   = document.get("tracking") or {}
    advisory_id = (tracking.get("id") or path.stem)[:120]
    initial_release = (tracking.get("initial_release_date") or "")[:32]
    current_release = (tracking.get("current_release_date") or "")[:32]

    vulnerabilities = doc.get("vulnerabilities") or []
    if not isinstance(vulnerabilities, list):
        return 0

    ingested = 0
    for v in vulnerabilities[:200]:
        if not isinstance(v, dict):
            continue
        cve = (v.get("cve") or "").upper().strip()
        if not cve.startswith("CVE-"):
            continue
        # CVSS extraction — CSAF can ship multiple scoring versions per
        # vuln; pull the first cvss_v3.baseScore we see.
        cvss_score: Optional[float] = None
        for scoring in (v.get("scores") or []):
            if not isinstance(scoring, dict):
                continue
            v3 = scoring.get("cvss_v3") or scoring.get("cvss_v31") or {}
            if isinstance(v3, dict) and "baseScore" in v3:
                try:
                    cvss_score = float(v3["baseScore"])
                except (TypeError, ValueError):
                    pass
                if cvss_score is not None:
                    break

        remediations = []
        for rem in (v.get("remediations") or [])[:4]:
            if not isinstance(rem, dict):
                continue
            remediations.append({
                "category": (rem.get("category") or "")[:40],
                "details":  (rem.get("details")  or "")[:240],
                "url":      (rem.get("url")      or "")[:200],
            })

        affected = []
        ps = v.get("product_status") or {}
        if isinstance(ps, dict):
            for k in ("known_affected", "first_affected", "last_affected"):
                ids = ps.get(k) or []
                if isinstance(ids, list):
                    affected.extend(str(p)[:120] for p in ids[:6])

        meta = {
            "advisory_id":   advisory_id,
            "vendor":        vendor,
            "title":         title,
            "cve":           cve,
            "cvss_v3_score": cvss_score,
            "initial_release": initial_release,
            "current_release": current_release,
            "remediations":  remediations,
            "affected_products": affected[:6],
            "source":        "CSAF",
        }
        by_cve.setdefault(cve, []).append(meta)
        ingested += 1
    return ingested


def _build_index() -> None:
    if not _CSAF_ROOT.exists():
        _state["error"]  = f"csaf dir not present at {_CSAF_ROOT}"
        _state["loaded"] = True
        return

    by_cve:  Dict[str, List[Dict[str, Any]]] = {}
    vendors: set = set()
    total = 0

    for path in _CSAF_ROOT.rglob("*.json"):
        if not path.is_file() or path.stat().st_size > 2_000_000:
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        total += _ingest_doc(doc, path, by_cve, vendors)

    _state["by_cve"]  = by_cve
    _state["vendors"] = vendors
    _state["total"]   = total
    _state["loaded"]  = True
    _state["error"]   = None
    _log.info("CSAF advisories loaded: %d vuln entries across %d vendor(s) "
              "covering %d CVE(s)",
              total, len(vendors), len(by_cve))


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


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":   bool(_state["loaded"]),
        "vendors":  sorted(_state.get("vendors") or set()),
        "vuln_entries": _state.get("total", 0),
        "cves":     len(_state.get("by_cve") or {}),
        "error":    _state.get("error"),
    }
