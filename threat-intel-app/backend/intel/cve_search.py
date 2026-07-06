"""
CIRCL CVE-Search — free NVD mirror. https://cve.circl.lu

Used as a failover when nvd.nist.gov is slow / down (which happens
routinely — NVD's own uptime is a running joke). Returns the same
CVE record shape from the same underlying dataset, so callers can
drop it in without special-casing the schema.

Only queried when the primary NVD call has already failed or returned
empty data. Never called speculatively — that would double the CVE
enrichment latency for no gain.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

_log = logging.getLogger("recon.intel.cve_search")


async def lookup(session, cve_id: str) -> Dict[str, Any]:
    """Fetch a single CVE record from CIRCL. Returns a shape that
    approximates intel.cve_enrichment.nvd_cve so downstream can treat
    the two interchangeably."""
    if not isinstance(cve_id, str) or not cve_id.upper().startswith("CVE-"):
        return {}
    from agents.enrichment import _get

    raw = await _get(
        session,
        f"https://cve.circl.lu/api/cve/{cve_id.upper()}",
        headers={"User-Agent": "RECON-ThreatIntel/1.0",
                 "Accept": "application/json"},
    )
    if not isinstance(raw, dict) or raw.get("error"):
        return {}

    # CIRCL now returns the CVE 5 shape: containers.cna + containers.adp[].
    # CVSS lives in metrics under whichever container scored it (usually
    # CISA-ADP or NVD-ADP for older CVEs). We scan every container.
    containers = raw.get("containers") or {}
    cna = containers.get("cna") or {}
    all_containers = [cna] + list(containers.get("adp") or [])

    # Description — CNA-owned in CVE 5.
    descs = cna.get("descriptions") or raw.get("descriptions") or []
    summary_text = ""
    if isinstance(descs, list):
        for d in descs:
            if isinstance(d, dict) and (d.get("lang") or "en").startswith("en"):
                summary_text = (d.get("value") or "")[:600]
                break
    if not summary_text:
        summary_text = (raw.get("summary") or "")[:600]

    # CVSS — walk cna + every ADP container, prefer v3.1 → v3.0 → v4.
    # For NVD failover the specific version matters less than "any
    # score we can render". Take the first one we find.
    cvss_v3_score: Optional[float] = None
    cvss_v3_severity = ""
    cvss_v3_vector = ""
    for cont in all_containers:
        for m in (cont.get("metrics") or []):
            if not isinstance(m, dict):
                continue
            for k in ("cvssV3_1", "cvssV3", "cvssV3_0", "cvssV4_0"):
                v = m.get(k)
                if isinstance(v, dict) and v.get("baseScore") is not None:
                    cvss_v3_score    = v.get("baseScore")
                    cvss_v3_severity = (v.get("baseSeverity") or "").upper()
                    cvss_v3_vector   = v.get("vectorString") or ""
                    break
            if cvss_v3_score is not None:
                break
        if cvss_v3_score is not None:
            break

    references = []
    for r in (cna.get("references") or raw.get("references") or [])[:8]:
        if isinstance(r, dict):
            u = r.get("url")
            if u: references.append(u)
        elif isinstance(r, str):
            references.append(r)

    return {
        "source":            "CIRCL CVE-Search",
        "cve_id":            cve_id.upper(),
        "summary":           summary_text,
        "cvss_v3_score":     float(cvss_v3_score) if cvss_v3_score is not None else None,
        "cvss_v3_severity":  cvss_v3_severity,
        "cvss_v3_vector":    cvss_v3_vector,
        "published":         raw.get("Published") or raw.get("datePublished") or "",
        "modified":          raw.get("Modified") or raw.get("dateUpdated") or "",
        "references":        references,
    }
