"""
CISA Vulnrichment — Authorized Data Publisher (ADP) enrichment layer
on top of MITRE's CVE records. Free, no key.

MITRE's CVE Awg API (cveawg.mitre.org) returns the canonical CVE 5
record which includes any ADP containers. CISA populates ADP records
with:
  - CWE mappings (root cause)
  - Refined CVSS scores when the CNA's score was undefined or wrong
  - SSVC decisions (technical impact, exploitation status)
  - KEV metadata (when applicable)

For RECON this closes the "CVE-2024-XXXX exists but NVD says awaiting
analysis" gap — CISA often has an SSVC decision + refined severity
weeks before NVD does.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

_log = logging.getLogger("recon.intel.vulnrichment")


async def lookup(session, cve_id: str) -> Dict[str, Any]:
    """Return the CISA ADP subset of the CVE record. Empty dict when
    the CVE isn't yet enriched by CISA."""
    if not isinstance(cve_id, str) or not cve_id.upper().startswith("CVE-"):
        return {}
    from agents.enrichment import _get

    raw = await _get(
        session,
        f"https://cveawg.mitre.org/api/cve/{cve_id.upper()}",
        headers={"User-Agent": "RECON-ThreatIntel/1.0",
                 "Accept": "application/json"},
    )
    if not isinstance(raw, dict) or raw.get("error"):
        return {}

    containers = raw.get("containers") or {}
    adps       = containers.get("adp") or []
    if not isinstance(adps, list) or not adps:
        return {}

    cisa = next(
        (a for a in adps
         if isinstance(a, dict) and (
             (a.get("providerMetadata") or {}).get("shortName") or ""
         ).lower() == "cisa-adp"),
        None,
    )
    if not cisa:
        return {}

    cwes: List[str] = []
    for pt in (cisa.get("problemTypes") or []):
        for d in (pt.get("descriptions") or []):
            cid = d.get("cweId") or d.get("cwe_id")
            if cid: cwes.append(cid)

    refined_cvss = {}
    for m in (cisa.get("metrics") or []):
        for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV3"):
            v = m.get(k)
            if isinstance(v, dict) and v.get("baseScore") is not None:
                refined_cvss = {
                    "version":       k.replace("cvssV", "").replace("_", "."),
                    "score":         v.get("baseScore"),
                    "severity":      (v.get("baseSeverity") or "").upper(),
                    "vector":        v.get("vectorString"),
                }
                break
        if refined_cvss:
            break

    # SSVC — the actionable decision. `Track*` = watch, `Attend` = act,
    # `Act` = drop everything.
    ssvc = {}
    for m in (cisa.get("metrics") or []):
        other = (m.get("other") or {})
        if other.get("type") == "ssvc":
            content = other.get("content") or {}
            options = content.get("options") or []
            ssvc = {
                "role":      content.get("role"),
                "version":   content.get("version"),
                "options":   {k: v for opt in options if isinstance(opt, dict)
                              for k, v in opt.items()},
                "timestamp": content.get("timestamp"),
            }
            break

    bits = []
    if cwes:         bits.append(f"CWE: {', '.join(cwes[:3])}")
    if refined_cvss: bits.append(f"CVSS {refined_cvss.get('severity')} "
                                 f"({refined_cvss.get('score')})")
    if ssvc:
        opts = ssvc.get("options") or {}
        # Exploitation is the decision-driver ('active' / 'poc' / 'none').
        # Automatable is a modifier ('yes' / 'no'). Both are useful; show
        # Exploitation first so 'SSVC: no' doesn't get mistaken for "no
        # exploitation" when the field is actually Automatable=no.
        expl = opts.get("Exploitation")
        auto = opts.get("Automatable")
        if expl and auto:
            bits.append(f"SSVC Exploitation={expl}, Automatable={auto}")
        elif expl:
            bits.append(f"SSVC Exploitation={expl}")
        elif auto:
            bits.append(f"SSVC Automatable={auto}")

    return {
        "source":        "CISA Vulnrichment",
        "cwes":          cwes,
        "refined_cvss":  refined_cvss,
        "ssvc":          ssvc,
        "summary":       " · ".join(bits) if bits else "CISA ADP record present.",
    }
