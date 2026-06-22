"""
Vendor-specific advisory RSS aggregator.

Three high-traffic vendor feeds without machine-readable JSON APIs:

  - Apple:   https://security.apple.com/feed/
  - Oracle:  https://www.oracle.com/security-alerts/public-vuln-to-advisory-mapping.json
              (Oracle DOES publish a JSON, but the quarterly CPU pages
              are RSS-only; the JSON is per-CPU + tracks CVE → adv mapping)
  - Adobe:   https://helpx.adobe.com/security/products/advisory-feed.rss
              (Adobe ProductSecurity team's RSS)

We poll all three on a daily cadence (vendors don't ship advisories
more frequently than weekly in practice), parse the CVE references out
of each entry's title + summary, and build a CVE-keyed inverted index
so enrich_cve can cite vendor advisories alongside NVD / OSV / CSAF /
MSRC / RHSA.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import threading
import time
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree as ET

_log = logging.getLogger("recon.intel.vendor_advisories")


_FEEDS = {
    "apple": {
        "name":    "Apple Product Security",
        "url":     "https://security.apple.com/feed/",
        "format":  "atom",
    },
    "adobe": {
        "name":    "Adobe Product Security",
        "url":     "https://helpx.adobe.com/security/products/advisory-feed.rss",
        "format":  "rss",
    },
    "oracle": {
        "name":    "Oracle CPU",
        "url":     "https://www.oracle.com/security-alerts/public-vuln-to-advisory-mapping.json",
        "format":  "json",
    },
}

_TTL_S = 24 * 3600

_CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)

_LOAD_LOCK = asyncio.Lock()
_state: Dict[str, Any] = {
    "loaded_at": 0.0,
    "by_cve":    {},     # dict[CVE-id, list[advisory]]
    "total":     0,
    "per_vendor": {},
    "error":     None,
}


async def _fetch_text(session, url: str) -> Optional[str]:
    from agents.enrichment import _get
    try:
        r = await _get(
            session, url,
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "application/rss+xml,application/atom+xml,"
                                "application/json,application/xml,text/xml"},
            json_response=False,
            timeout=15,
        )
    except TypeError:
        r = await _get(
            session, url,
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "*/*"},
            timeout=15,
        )
    except Exception as e:
        _log.debug("vendor advisory fetch failed %s: %s", url, e)
        return None
    if isinstance(r, str):
        return r
    if isinstance(r, (bytes, bytearray)):
        return r.decode("utf-8", errors="ignore")
    if isinstance(r, dict):
        # Oracle's JSON shape — pass through as-is.
        return json.dumps(r)
    return None


def _parse_atom_or_rss(text: str, vendor: str, vendor_name: str
                       ) -> List[Dict[str, Any]]:
    """Parse Atom or RSS XML. Extract entries with title + link + CVE
    references found in title/summary."""
    out: List[Dict[str, Any]] = []
    try:
        # Strip leading whitespace + BOM the parsers don't like.
        root = ET.fromstring(text.strip())
    except Exception:
        return out
    # Walk every element; we don't care about Atom vs RSS shape — both
    # have a flat list of <entry> / <item> with title/link/summary or
    # description.
    items = []
    for tag_name in ("entry", "item"):
        items.extend([e for e in root.iter()
                      if e.tag.split("}", 1)[-1] == tag_name])
    for item in items[:120]:
        title = ""
        link  = ""
        summary = ""
        date    = ""
        for c in item:
            ct = c.tag.split("}", 1)[-1].lower()
            txt = (c.text or "").strip()
            if ct == "title":
                title = txt[:240]
            elif ct == "link":
                # Atom uses href attr; RSS uses text.
                link = c.attrib.get("href") or txt or ""
                link = link[:240]
            elif ct in ("summary", "description", "content"):
                summary = (txt or "")[:600]
            elif ct in ("updated", "pubdate", "published"):
                date = txt[:32]
        blob = f"{title} {summary}"
        cves = list(dict.fromkeys(
            m.group(1).upper() for m in _CVE_RE.finditer(blob)
        ))
        if not cves:
            continue
        out.append({
            "vendor":     vendor,
            "vendor_name": vendor_name,
            "title":      title,
            "link":       link,
            "summary":    summary,
            "date":       date,
            "cves":       cves,
        })
    return out


def _parse_oracle_json(text: str, vendor_name: str) -> List[Dict[str, Any]]:
    """Oracle ships a JSON map of CVE -> advisory IDs. Convert to our
    common shape (one entry per CVE)."""
    out: List[Dict[str, Any]] = []
    try:
        payload = json.loads(text)
    except Exception:
        return out
    if not isinstance(payload, dict):
        return out
    cve_to_advs = payload.get("public_vuln_to_advisory_mapping") or payload
    if not isinstance(cve_to_advs, dict):
        return out
    for cve, advisories in cve_to_advs.items():
        if not isinstance(cve, str) or not cve.upper().startswith("CVE-"):
            continue
        adv_list = advisories if isinstance(advisories, list) else [advisories]
        out.append({
            "vendor":     "oracle",
            "vendor_name": vendor_name,
            "title":      f"Oracle CPU advisories for {cve}",
            "link":       f"https://www.oracle.com/security-alerts/cpu{cve[:8]}.html",
            "summary":    f"{len(adv_list)} Oracle Critical Patch Update advisor"
                          f"{'ies' if len(adv_list) != 1 else 'y'} reference this CVE.",
            "date":       "",
            "cves":       [cve.upper()],
        })
    return out


async def _refresh(session) -> None:
    by_cve: Dict[str, List[Dict[str, Any]]] = {}
    per_vendor: Dict[str, int] = {}

    tasks = [_fetch_text(session, spec["url"]) for spec in _FEEDS.values()]
    texts = await asyncio.gather(*tasks, return_exceptions=True)
    for (slug, spec), text in zip(_FEEDS.items(), texts):
        if not isinstance(text, str):
            continue
        try:
            if spec["format"] == "json":
                entries = _parse_oracle_json(text, spec["name"])
            else:
                entries = _parse_atom_or_rss(text, slug, spec["name"])
        except Exception as e:
            _log.warning("vendor advisory parse failed for %s: %s", slug, e)
            continue
        per_vendor[slug] = len(entries)
        for entry in entries:
            for cve in entry["cves"]:
                by_cve.setdefault(cve, []).append(entry)

    total = sum(len(v) for v in by_cve.values())
    _state["by_cve"]     = by_cve
    _state["total"]      = total
    _state["per_vendor"] = per_vendor
    _state["loaded_at"]  = time.time()
    _state["error"]      = None
    _log.info("vendor_advisories: %d advisory↔CVE rows across %d vendors",
              total, len(per_vendor))


async def ensure_loaded(session) -> None:
    async with _LOAD_LOCK:
        age = time.time() - _state["loaded_at"]
        if _state["by_cve"] and age < _TTL_S:
            return
        try:
            await _refresh(session)
        except Exception as e:
            _state["error"] = f"vendor_advisories refresh failed: {e}"
            _log.warning("vendor_advisories refresh failed: %s", e)


def lookup_cve(cve_id: str, max_results: int = 6) -> List[Dict[str, Any]]:
    if not cve_id:
        return []
    rows = (_state.get("by_cve") or {}).get(cve_id.upper().strip(), [])
    return rows[:max_results]


def stats() -> Dict[str, Any]:
    age = time.time() - _state["loaded_at"] if _state["loaded_at"] else None
    return {
        "loaded":     bool(_state.get("total")),
        "advisories": _state.get("total", 0),
        "per_vendor": _state.get("per_vendor") or {},
        "age_s":      int(age) if age is not None else None,
        "ttl_s":      _TTL_S,
        "error":      _state.get("error"),
    }
