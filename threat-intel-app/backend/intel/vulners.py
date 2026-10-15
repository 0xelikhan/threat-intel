"""
Vulners CVE / exploit database lookup.

Source: https://vulners.com/api/v3/ — large aggregated vuln + exploit
database. Free API key tier covers moderate per-day quota; register
at https://vulners.com/.

  GET https://vulners.com/api/v3/search/id/?id=<CVE-ID>&apiKey=<KEY>

Response shape (result == "OK"):
  {
    "result": "OK",
    "data": {
      "documents": {
        "CVE-xxxx-xxxx": {
          "title":       "...",
          "description": "...",
          "cvss":        {"score": 7.5, "vector": "...", "severity": "HIGH"},
          "cvss2":       {"cvssV2": {"baseScore": 7.5, ...}},
          "cvss3":       {"cvssV3": {"baseScore": 7.5, ...}},
          "references":  ["https://...", ...],
          "enchantments": {
            "exploitation": {"wildExploited": true},
            "exploitPacks": [...]
          },
          "published":   "YYYY-MM-DD...",
          "modified":    "...",
          "bulletinFamily": "NVD" | "exploit" | ...
        }
      }
    }
  }

Vulners is distinct from NVD / EPSS: its value is cross-referencing
NVD-published CVEs against public exploit databases (ExploitDB,
PacketStorm, 0day.today) and marking which CVEs have known PoCs or
exploit packs. Complements our existing cve_pocs and kev modules by
widening exploit-source coverage.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

_log = logging.getLogger("recon.intel.vulners")


async def lookup(session, cve_id: str, api_key: str = "") -> Dict[str, Any]:
    """Look up a CVE in Vulners. Empty dict with found=False when the
    CVE is not in Vulners' index."""
    if not isinstance(cve_id, str) or not cve_id.upper().startswith("CVE-"):
        return {"source": "vulners", "found": False,
                "error": "invalid CVE id"}
    if not api_key:
        return {"source": "vulners", "found": False,
                "error": "VULNERS_KEY not configured",
                "error_type": "missing_key"}
    try:
        from agents.enrichment import _get
        r = await _get(
            session,
            f"https://vulners.com/api/v3/search/id/?id={cve_id}&apiKey={api_key}",
            headers={"Accept": "application/json"},
            timeout=10,
        )
    except Exception as e:
        return {"source": "vulners", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "vulners", "error": "unexpected shape",
                "error_type": "unreachable"}
    if r.get("error"):
        return {"source": "vulners", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}

    result = (r.get("result") or "").upper()
    if result != "OK":
        err = r.get("data", {}).get("error") or r.get("error") or result
        return {"source": "vulners", "found": False,
                "error": f"API returned {err}",
                "error_type": "api_error"}

    docs = (r.get("data") or {}).get("documents") or {}
    doc = docs.get(cve_id) or docs.get(cve_id.upper()) or next(iter(docs.values()), None)
    if not doc:
        return {"source": "vulners", "found": False,
                "summary": f"Vulners has no entry for {cve_id}."}

    cvss = doc.get("cvss") or {}
    cvss_score = cvss.get("score")
    cvss_vector = cvss.get("vector")
    cvss_severity = cvss.get("severity")

    enchant = doc.get("enchantments") or {}
    exploitation = enchant.get("exploitation") or {}
    wild_exploited = bool(exploitation.get("wildExploited"))
    exploit_packs = enchant.get("exploitPacks") or []
    related = (enchant.get("dependencies") or {}).get("references") or []
    # Count related exploit entries by scanning related for bulletinFamily=="exploit"
    exploit_refs: List[str] = []
    for grp in related:
        for item in (grp.get("idList") or []):
            if isinstance(item, str) and (item.upper().startswith(("EDB-", "PACKETSTORM:", "0DAY")) or
                                           "exploit" in item.lower()):
                exploit_refs.append(item)

    exploit_count = len(exploit_refs) + len(exploit_packs)
    verdict = "UNKNOWN"
    if wild_exploited or exploit_count >= 1:
        verdict = "MALICIOUS"

    return {
        "source":         "vulners",
        "found":          True,
        "cve_id":         doc.get("id") or cve_id,
        "title":          doc.get("title"),
        "description":    (doc.get("description") or "")[:400],
        "cvss_score":     cvss_score,
        "cvss_vector":    cvss_vector,
        "cvss_severity":  cvss_severity,
        "wild_exploited": wild_exploited,
        "exploit_count":  exploit_count,
        "exploit_refs":   exploit_refs[:5],
        "exploit_packs":  [p.get("name") or p for p in exploit_packs[:5]
                            if p],
        "published":      doc.get("published"),
        "modified":       doc.get("modified"),
        "details_url":    f"https://vulners.com/cve/{cve_id}",
        "verdict":        verdict,
        "summary":        (f"Vulners: {cve_id}"
                           + (f" CVSS {cvss_score}" if cvss_score else "")
                           + (" — EXPLOITED IN THE WILD"
                              if wild_exploited else "")
                           + (f" ({exploit_count} public exploit"
                              f"{'s' if exploit_count != 1 else ''})"
                              if exploit_count else "")),
    }
