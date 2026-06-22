"""
ProjectDiscovery nuclei-templates CVE index.

We don't run nuclei (Go binary, scanning behaviour, not in our scope).
We *index* its YAML templates so the CVE enricher can tell the analyst
"X public detection templates exist for this CVE" — far more concrete
than "CVE has CVSS 9.8" because it implies active exploitation tooling.

Mirrors the same lazy-load + inverted-index pattern used by
intel/sigma_corpus.py. Looks for `vendor/nuclei-templates/` at startup;
if missing, the index is empty and lookup() returns []. The fetcher
script (scripts/fetch_nuclei_templates.sh) populates the dir.

License: nuclei-templates is MIT (verified). Indexing the metadata is
clearly fair use; if we ever surfaced full template bodies in the UI
we'd preserve their per-file headers.
"""

from __future__ import annotations

import logging
import re
import threading
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.intel.nuclei_index")

_TEMPLATES_ROOT = (Path(__file__).parent.parent.parent
                   / "vendor" / "nuclei-templates")

# nuclei templates are tiny — anything over 32KB is almost certainly not
# a CVE-tagged detection template (it's probably a workflow / preset).
_MAX_FILE_BYTES = 32_000

_CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)

_lock  = threading.Lock()
_state: Dict[str, Any] = {
    "loaded":         False,
    "by_cve":         {},   # dict[str, list[dict]]
    "total_with_cve": 0,
    "error":          None,
}


def _safe_yaml(text: str) -> Optional[Dict[str, Any]]:
    try:
        import yaml
    except Exception:
        return None
    try:
        # Some templates use ---  / multi-doc; first is the spec.
        for doc in yaml.safe_load_all(text):
            if isinstance(doc, dict):
                return doc
    except Exception:
        return None
    return None


def _extract_cves(doc: Dict[str, Any], path: Path) -> List[str]:
    """Pull every CVE-XXXX-YYYY referenced by a template. nuclei's
    classification.cve-id is the canonical field; we also fall back to
    grepping the raw filename + id so older templates aren't missed."""
    out: List[str] = []
    info = doc.get("info") or {}
    cls  = info.get("classification") or {}
    raw = cls.get("cve-id") or cls.get("cve_id")
    if isinstance(raw, str):
        out.append(raw.upper())
    elif isinstance(raw, list):
        for r in raw:
            if isinstance(r, str):
                out.append(r.upper())
    # Fallback: regex the template id + file name. ProjectDiscovery names
    # most CVE templates after the CVE itself (CVE-2023-1234.yaml).
    for blob in (str(doc.get("id") or ""), path.name):
        for m in _CVE_RE.finditer(blob):
            out.append(m.group(1).upper())
    # Dedup preserving order.
    seen: set = set()
    dedup: List[str] = []
    for c in out:
        if c not in seen and c.startswith("CVE-"):
            seen.add(c)
            dedup.append(c)
    return dedup


def _build_index() -> None:
    if not _TEMPLATES_ROOT.exists():
        _state["error"]  = f"nuclei-templates dir not present at {_TEMPLATES_ROOT}"
        _state["loaded"] = True
        return

    by_cve: Dict[str, List[Dict[str, Any]]] = {}
    total = 0

    # We only care about template files; nuclei ships a lot of non-template
    # YAMLs (workflows, presets) we want to skip. The cleanest signal is
    # an `info.classification.cve-id` key. Sweep both `http/cves/` and
    # `cves/` (older trees) plus anything with a CVE in its filename.
    for path in _TEMPLATES_ROOT.rglob("*.yaml"):
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        # Quick gate — skip files that don't mention a CVE at all so we
        # don't YAML-parse 30k templates just to filter on classification.
        try:
            head = path.read_bytes()[:_MAX_FILE_BYTES]
        except OSError:
            continue
        if b"CVE-" not in head and b"cve-id" not in head:
            continue
        doc = _safe_yaml(head.decode("utf-8", errors="ignore"))
        if not isinstance(doc, dict):
            continue
        cves = _extract_cves(doc, path)
        if not cves:
            continue
        info = doc.get("info") or {}
        cls  = info.get("classification") or {}
        cvss_score = cls.get("cvss-score") or cls.get("cvss_score")
        try:
            cvss_score = float(cvss_score) if cvss_score is not None else None
        except (TypeError, ValueError):
            cvss_score = None
        tags = info.get("tags")
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        meta = {
            "id":         str(doc.get("id") or "")[:128],
            "name":       str(info.get("name") or "")[:200],
            "severity":   str(info.get("severity") or "").lower(),
            "cvss_score": cvss_score,
            "tags":       (tags or [])[:12],
            "reference":  (info.get("reference") or [])[:4]
                          if isinstance(info.get("reference"), list)
                          else [],
        }
        for cve in cves:
            by_cve.setdefault(cve, []).append(meta)
        total += 1

    _state["by_cve"]         = by_cve
    _state["total_with_cve"] = total
    _state["loaded"]         = True
    _state["error"]          = None
    _log.info("nuclei-templates index loaded: %d templates across %d CVEs",
              total, len(by_cve))


def _ensure_loaded() -> None:
    if _state["loaded"]:
        return
    with _lock:
        if not _state["loaded"]:
            _build_index()


def lookup(cve_id: str, max_results: int = 8) -> List[Dict[str, Any]]:
    """Return template metadata for a given CVE, capped at max_results.
    Empty list when the CVE isn't indexed or the corpus isn't present."""
    _ensure_loaded()
    cve = (cve_id or "").strip().upper()
    if not cve.startswith("CVE-"):
        return []
    rows = (_state.get("by_cve") or {}).get(cve, [])
    # Order by severity (critical > high > medium > low > info > unknown).
    rows = sorted(
        rows,
        key=lambda r: -_SEV_RANK.get(r.get("severity"), 0),
    )
    return rows[:max_results]


def stats() -> Dict[str, Any]:
    _ensure_loaded()
    return {
        "loaded":      bool(_state["loaded"]),
        "templates":   _state.get("total_with_cve", 0),
        "cves":        len(_state.get("by_cve") or {}),
        "error":       _state.get("error"),
    }


_SEV_RANK = {
    "critical": 5, "high": 4, "medium": 3, "low": 2,
    "info": 1, "unknown": 0,
}
