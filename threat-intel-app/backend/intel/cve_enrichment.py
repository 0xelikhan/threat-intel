"""
Per-CVE live API enrichment.

The platform already had offline KEV + EPSS catalogs cached at startup
(intel/kev.py, intel/epss.py) for fast bulk lookups, but the user spec
calls for a per-investigation live fetch so the CVE intelligence is
fresh every time. This module does that:

  * nvd_cve(cve_id)       — services.nvd.nist.gov per-CVE detail
                            (description, CVSS v3 score + severity,
                             affected products)
  * epss(cve_id)          — api.first.org per-CVE exploitation
                            probability + percentile
  * cisa_kev_check(cve_id) — once-per-investigation live download of the
                              CISA KEV catalog, cached in a module-level
                              dict for the lifetime of the asyncio
                              context. Never written to disk. Returns
                              ACTIVELY EXPLOITED + dateAdded +
                              dueDate when matched.

extract_cves(text) is the IOC extractor used by triage to pull CVE-style
identifiers out of the raw alert text (case-insensitive, deduped,
validated against the 4-7-digit CVE number range).
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.cve_enrichment")


# ─── IOC extraction ──────────────────────────────────────────────────────────
_CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)


def extract_cves(text: str) -> List[str]:
    """Pull CVE IDs out of raw text. Normalises to upper-case 'CVE-YYYY-N'
    and dedupes. CVE year must be >= 1999 (the year the CVE program
    began) and <= current year + 1 (calendar publishing slop)."""
    if not text:
        return []
    now_year = time.gmtime().tm_year
    out: list = []
    seen = set()
    for m in _CVE_RE.finditer(text):
        year = int(m.group(1))
        if year < 1999 or year > now_year + 1:
            continue
        cve = f"CVE-{m.group(1)}-{m.group(2)}"
        if cve not in seen:
            seen.add(cve)
            out.append(cve)
    return out


# ─── NVD CVE ─────────────────────────────────────────────────────────────────
async def nvd_cve(session, cve_id: str) -> Dict[str, Any]:
    """Per-CVE detail from the NVD REST API. No key required, but the
    User-Agent must be set or the API rate-limits aggressively."""
    from agents.enrichment import _get
    r = await _get(
        session,
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
        headers={"User-Agent": "RECON-ThreatIntel/1.0",
                 "Accept": "application/json"},
    )
    return _parse_nvd(r, cve_id)


def _parse_nvd(r: Any, cve_id: str) -> Dict[str, Any]:
    if isinstance(r, dict) and "error" in r:
        return {"source": "nvd", "cve_id": cve_id, "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    if not isinstance(r, dict):
        return {"source": "nvd", "cve_id": cve_id, "error": "unexpected shape"}
    vulns = r.get("vulnerabilities") or []
    if not vulns:
        return {"source": "nvd", "cve_id": cve_id, "found": False,
                "summary": f"NVD has no record for {cve_id}."}
    cve = (vulns[0] or {}).get("cve") or {}
    descs = cve.get("descriptions") or []
    description = next((d.get("value") for d in descs
                        if isinstance(d, dict) and d.get("lang") == "en"),
                       "")

    metrics = cve.get("metrics") or {}
    cvss_v3 = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [{}])[0]
    cvss_data = (cvss_v3.get("cvssData") or {}) if isinstance(cvss_v3, dict) else {}
    score    = cvss_data.get("baseScore")
    severity = (cvss_data.get("baseSeverity") or "").upper()

    # Affected products — collected from CPE matches; cap to keep payload tight
    affected = set()
    for cfg in (cve.get("configurations") or []):
        for node in (cfg.get("nodes") or []):
            for m in (node.get("cpeMatch") or []):
                cpe = m.get("criteria") or ""
                # cpe:2.3:a:vendor:product:version:...
                parts = cpe.split(":")
                if len(parts) > 4:
                    affected.add(f"{parts[3]} {parts[4]}")
            if len(affected) >= 8:
                break
        if len(affected) >= 8:
            break

    verdict = ("MALICIOUS" if severity == "CRITICAL"
               else "SUSPICIOUS" if severity == "HIGH"
               else "UNKNOWN")

    return {
        "source":            "nvd",
        "cve_id":            cve_id,
        "found":             True,
        "description":       (description or "")[:600],
        "cvss_v3_score":     score,
        "cvss_v3_severity":  severity,
        "affected_products": sorted(affected)[:8],
        "published":         cve.get("published"),
        "last_modified":     cve.get("lastModified"),
        "verdict":           verdict,
        "summary":           (f"{cve_id}: CVSS {score or 'unknown'} ({severity or 'unknown'})"
                              + (f" — {description[:140]}…" if len(description) > 140
                                 else (f" — {description}" if description else ""))),
    }


# ─── EPSS ────────────────────────────────────────────────────────────────────
async def epss(session, cve_id: str) -> Dict[str, Any]:
    """EPSS exploitation-probability score for a CVE. No key required."""
    from agents.enrichment import _get
    r = await _get(
        session,
        f"https://api.first.org/data/v1/epss?cve={cve_id}",
        headers={"User-Agent": "RECON-ThreatIntel/1.0",
                 "Accept": "application/json"},
    )
    return _parse_epss(r, cve_id)


def _parse_epss(r: Any, cve_id: str) -> Dict[str, Any]:
    if isinstance(r, dict) and "error" in r:
        return {"source": "epss", "cve_id": cve_id, "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    if not isinstance(r, dict):
        return {"source": "epss", "cve_id": cve_id, "error": "unexpected shape"}
    data = (r.get("data") or [])
    if not data:
        return {"source": "epss", "cve_id": cve_id, "found": False,
                "summary": f"EPSS has no score for {cve_id} (often new CVEs)."}
    row = data[0] if isinstance(data[0], dict) else {}
    try:
        prob = float(row.get("epss") or 0.0)
    except (TypeError, ValueError):
        prob = 0.0
    try:
        pct = float(row.get("percentile") or 0.0)
    except (TypeError, ValueError):
        pct = 0.0

    if prob >= 0.7:
        verdict = "MALICIOUS"
    elif prob >= 0.1:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "source":      "epss",
        "cve_id":      cve_id,
        "found":       True,
        "score":       prob,
        "percentile":  pct,
        "date":        row.get("date"),
        "score_pct":   round(prob * 100, 1),
        "percentile_pct": round(pct * 100, 1),
        "verdict":     verdict,
        "summary":     (f"EPSS {round(prob * 100, 1)}% probability "
                        f"({round(pct * 100, 1)} percentile)"),
    }


# ─── OSV.dev (Google Open Source Vulnerabilities) ────────────────────────────
#
# NVD covers CVEs broadly but misses ecosystem-specific advisories (npm,
# PyPI, RubyGems, Go modules, Cargo, Composer, NuGet, etc.). OSV.dev
# aggregates GitHub Security Advisories + RustSec + GSD + Linux distro
# advisories and serves them via a simple POST endpoint.
async def osv(session, cve_id: str) -> Dict[str, Any]:
    """Look up a CVE in OSV.dev. Free API, no key. POST to v1/vulns."""
    from agents.enrichment import _get
    # OSV's /v1/query endpoint actually takes POST with a JSON body, but
    # they also expose /v1/vulns/<id> for direct GET by ID (CVE or GHSA).
    url = f"https://api.osv.dev/v1/vulns/{cve_id}"
    r = await _get(
        session, url,
        headers={"User-Agent": "RECON-ThreatIntel/1.0",
                 "Accept": "application/json"},
    )
    return _parse_osv(r, cve_id)


def _parse_osv(r: Any, cve_id: str) -> Dict[str, Any]:
    if isinstance(r, dict) and "error" in r:
        return {"source": "osv", "cve_id": cve_id, "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    if not isinstance(r, dict):
        return {"source": "osv", "cve_id": cve_id, "error": "unexpected shape"}
    if "id" not in r and "vulnerabilities" not in r:
        return {"source": "osv", "cve_id": cve_id, "found": False,
                "summary": f"OSV has no record for {cve_id}."}

    affected = r.get("affected") or []
    ecosystems: List[str] = []
    packages:   List[str] = []
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

    # Dedupe preserving order
    ecosystems = list(dict.fromkeys(ecosystems))[:8]
    packages   = list(dict.fromkeys(packages))[:12]
    references = []
    for ref in (r.get("references") or [])[:6]:
        if isinstance(ref, dict) and ref.get("url"):
            references.append({"type": ref.get("type", "WEB"),
                                "url":  ref["url"][:200]})

    summary = (r.get("summary") or r.get("details") or "")[:300]
    aliases = r.get("aliases") or []
    if isinstance(aliases, list):
        aliases = [a for a in aliases if isinstance(a, str)][:6]

    return {
        "source":     "osv",
        "cve_id":     cve_id,
        "found":      True,
        "id":         r.get("id") or cve_id,
        "ecosystems": ecosystems,
        "packages":   packages,
        "aliases":    aliases,
        "references": references,
        "summary":    (summary or f"OSV record: {len(packages)} affected packages"
                                  f" across {len(ecosystems)} ecosystem(s)."),
    }


# ─── Red Hat Security Data API ───────────────────────────────────────────────
#
# Free Red Hat advisory feed (no key). Endpoint:
#   https://access.redhat.com/hydra/rest/securitydata/cve/<CVE>.json
# Returns: RHSA/RHEA/RHBA advisory IDs, affected RHEL packages with
# fixed versions, public_date, CVSS, threat severity, bugzilla refs.
# Strong context for Linux-server CVE triage that NVD doesn't surface.
async def rhsa(session, cve_id: str) -> Dict[str, Any]:
    """Look up Red Hat security advisories tied to a CVE."""
    from agents.enrichment import _get
    url = f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"
    r = await _get(
        session, url,
        headers={"User-Agent": "RECON-ThreatIntel/1.0",
                 "Accept": "application/json"},
    )
    return _parse_rhsa(r, cve_id)


def _parse_rhsa(r: Any, cve_id: str) -> Dict[str, Any]:
    if isinstance(r, dict) and "error" in r:
        msg = (r.get("error") or "").lower()
        # Red Hat returns 404 for CVEs they don't track; treat as not-found.
        if "404" in msg or "not_found" in msg or "no record" in msg:
            return {"source": "rhsa", "cve_id": cve_id, "found": False,
                    "summary": f"Red Hat has no advisory record for {cve_id}."}
        return {"source": "rhsa", "cve_id": cve_id, "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    if not isinstance(r, dict) or not r:
        return {"source": "rhsa", "cve_id": cve_id, "error": "unexpected shape"}

    advisories = []
    for a in (r.get("affected_release") or [])[:12]:
        if not isinstance(a, dict):
            continue
        advisories.append({
            "advisory":     a.get("advisory") or "",
            "product_name": (a.get("product_name") or "")[:120],
            "package":      (a.get("package") or "")[:120],
            "release_date": a.get("release_date") or "",
        })

    threat_severity = (r.get("threat_severity") or "").strip()
    cvss_v3         = r.get("cvss3") or {}
    cvss_score      = cvss_v3.get("cvss3_base_score") if isinstance(cvss_v3, dict) else None
    package_state   = []
    for ps in (r.get("package_state") or [])[:12]:
        if isinstance(ps, dict):
            package_state.append({
                "product":     (ps.get("product_name") or "")[:120],
                "package":     (ps.get("package_name") or "")[:120],
                "fix_state":   (ps.get("fix_state") or "")[:40],
            })

    bugzilla = r.get("bugzilla") or {}
    bz_id    = bugzilla.get("id") if isinstance(bugzilla, dict) else None

    return {
        "source":            "rhsa",
        "cve_id":            cve_id,
        "found":             True,
        "threat_severity":   threat_severity,
        "cvss_v3_score":     cvss_score,
        "advisory_count":    len(advisories),
        "advisories":        advisories,
        "package_state":     package_state,
        "bugzilla_id":       bz_id,
        "details_url":       f"https://access.redhat.com/security/cve/{cve_id}",
        "summary":           (f"Red Hat: {len(advisories)} advisory"
                              f"{'ies' if len(advisories) != 1 else 'y'}"
                              f" tracked"
                              + (f" (severity: {threat_severity})"
                                 if threat_severity else "")),
    }


# ─── Microsoft Security Response Center (MSRC) API ───────────────────────────
#
# Free Microsoft advisory feed (no key). MSRC publishes a CSAF JSON
# document per month containing every CVE Microsoft patched that month;
# we query per-CVE via the MSRC API's `Updates` endpoint, which returns
# the metadata for any update containing the CVE.
async def msrc(session, cve_id: str) -> Dict[str, Any]:
    """Look up Microsoft Security Update Guide entries for a CVE."""
    from agents.enrichment import _get
    # The MSRC API expects the CVE in the format `CVE-YYYY-NNNN` and
    # filters monthly Updates documents to those containing it.
    url = (f"https://api.msrc.microsoft.com/cvrf/v2.0/Updates"
           f"('{cve_id}')")
    r = await _get(
        session, url,
        headers={"User-Agent": "RECON-ThreatIntel/1.0",
                 "Accept": "application/json"},
    )
    return _parse_msrc(r, cve_id)


def _parse_msrc(r: Any, cve_id: str) -> Dict[str, Any]:
    if isinstance(r, dict) and "error" in r:
        msg = (r.get("error") or "").lower()
        if "404" in msg or "no record" in msg or "not_found" in msg:
            return {"source": "msrc", "cve_id": cve_id, "found": False,
                    "summary": f"Microsoft has no advisory record for {cve_id}."}
        return {"source": "msrc", "cve_id": cve_id, "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    if not isinstance(r, dict) or not r:
        return {"source": "msrc", "cve_id": cve_id, "error": "unexpected shape"}

    # Top-level shape from MSRC: {"@odata.context": "...", "value": [{...},...]}
    updates = r.get("value") or []
    if not isinstance(updates, list) or not updates:
        return {"source": "msrc", "cve_id": cve_id, "found": False,
                "summary": f"Microsoft has no Update record for {cve_id}."}

    kb_articles: List[str] = []
    products:    List[str] = []
    titles:      List[str] = []
    for upd in updates[:6]:
        if not isinstance(upd, dict):
            continue
        title = (upd.get("DocumentTitle", {}) or {}).get("Value") or ""
        if title:
            titles.append(title[:120])
        # Each Update document has a CvrfUrl we could fetch for full
        # detail; we just keep the ID + title to stay lightweight.
        for kb in (upd.get("AffectedProducts") or [])[:6]:
            if isinstance(kb, dict):
                p = kb.get("Value") or kb.get("Name") or ""
                if p:
                    products.append(p[:120])

    return {
        "source":         "msrc",
        "cve_id":         cve_id,
        "found":          True,
        "update_titles":  list(dict.fromkeys(titles))[:6],
        "products":       list(dict.fromkeys(products))[:8],
        "details_url":    f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}",
        "summary":        (f"Microsoft tracks {cve_id} in "
                            f"{len(updates)} Update document"
                            f"{'s' if len(updates) != 1 else ''}."),
    }


# ─── CISA KEV (live, per-investigation cache) ────────────────────────────────
#
# The KEV catalog is small (< 1 MB) and only changes when CISA publishes a
# new entry. We pull it ONCE per investigation: the first cve_enrichment
# call this run fetches + populates the module-level cache; subsequent
# calls in the same investigation use the cached dict.
#
# The cache TTL is 60 minutes — short enough to pick up new KEV entries
# during a busy day, long enough to avoid hammering CISA on every IOC.
# Never persisted to disk per the user spec.

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_KEV_TTL_S = 3600
_kev_cache: Dict[str, Any] = {"fetched_at": 0.0, "by_cve": {}}
_kev_lock = asyncio.Lock()


async def _ensure_kev_loaded(session) -> Dict[str, Any]:
    """Idempotent loader. First call this run fetches; the rest reuse the
    in-memory dict until the TTL expires."""
    async with _kev_lock:
        now = time.time()
        if (now - _kev_cache["fetched_at"]) < _KEV_TTL_S and _kev_cache["by_cve"]:
            return _kev_cache["by_cve"]
        from agents.enrichment import _get
        r = await _get(
            session, _KEV_URL,
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "application/json"},
        )
        if not isinstance(r, dict) or "vulnerabilities" not in r:
            _log.warning("KEV download failed or unexpected shape: %s", r)
            return _kev_cache["by_cve"]    # may be empty
        by_cve = {}
        for v in (r.get("vulnerabilities") or []):
            if not isinstance(v, dict):
                continue
            cve = v.get("cveID")
            if cve:
                by_cve[cve.upper()] = v
        _kev_cache["by_cve"] = by_cve
        _kev_cache["fetched_at"] = now
        _log.info("KEV catalog refreshed: %d entries", len(by_cve))
        return by_cve


async def cisa_kev_check(session, cve_id: str) -> Dict[str, Any]:
    """Check a single CVE against the live CISA KEV catalog. Returns
    ACTIVELY EXPLOITED + dateAdded + dueDate when matched, CLEAN
    otherwise. The catalog download is shared across every CVE in the
    same investigation via the module-level cache."""
    by_cve = await _ensure_kev_loaded(session)
    if not by_cve:
        # KEV download failed (offline / 5xx) — fail soft so the rest of
        # the CVE enrichment still runs.
        return {"source": "cisa_kev", "cve_id": cve_id,
                "error": "KEV catalog unavailable",
                "error_type": "unreachable"}
    cve_u = cve_id.upper()
    entry = by_cve.get(cve_u)
    if not entry:
        return {
            "source":   "cisa_kev",
            "cve_id":   cve_id,
            "in_kev":   False,
            "verdict":  "CLEAN",
            "summary":  f"{cve_id} is NOT in the CISA KEV catalog.",
        }
    return {
        "source":              "cisa_kev",
        "cve_id":              cve_id,
        "in_kev":              True,
        "actively_exploited":  True,
        "vendor":              entry.get("vendorProject"),
        "product":             entry.get("product"),
        "name":                entry.get("vulnerabilityName"),
        "date_added":          entry.get("dateAdded"),
        "due_date":            entry.get("dueDate"),
        "required_action":     entry.get("requiredAction"),
        "ransomware_use":      entry.get("knownRansomwareCampaignUse") == "Known",
        "short_description":   (entry.get("shortDescription") or "")[:240],
        "verdict":             "MALICIOUS",
        "summary":             (f"{cve_id} is ACTIVELY EXPLOITED per CISA KEV "
                                f"(added {entry.get('dateAdded')}, "
                                f"due {entry.get('dueDate')})"
                                + (" — ransomware use confirmed"
                                   if entry.get("knownRansomwareCampaignUse") == "Known"
                                   else "")),
    }
