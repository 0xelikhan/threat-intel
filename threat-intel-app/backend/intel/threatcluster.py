"""ThreatCluster keyless IOC enrichment + feed snapshot.

Source: https://threatcluster.io/ - a 2026-launch CTI platform that
clusters threat reporting + validated IOCs and exposes two useful
keyless surfaces:

  1. Per-IOC lookup:  GET /api/iocs/lookup?value={ioc}
     Returns {count, categories, clusters, lookback_days, ...} with
     up to 25 clusters from the last 7 days. No auth. Hitting ones
     have `count > 0` and populate `clusters` with threat-actor /
     malware-family / campaign tags.

  2. Public blocklist:  GET /api/iocs/public/feed.txt
     Plain text, one value per line (domains + IPv4 + IPv6), 30-day
     window. TLP:CLEAR, redistributable with attribution.

This module covers (1) only - the lookup path. The blocklist ingestor
lives in plugins/ingestors/threatcluster.py and seeds a separate
in-process cache for faster-than-lookup matches.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

_log = logging.getLogger("recon.intel.threatcluster")


_LOOKUP_URL = "https://threatcluster.io/api/iocs/lookup"


async def lookup(session, value: str) -> Dict[str, Any]:
    """Query the keyless per-IOC endpoint. Works for IPv4 / IPv6 /
    domain / url / hash - ThreatCluster auto-detects the entity type.

    Returns:
      {source, found, cluster_count, categories, clusters,
       lookback_days, verdict, summary, details_url}
    """
    if not isinstance(value, str) or not value:
        return {"source": "threatcluster", "found": False,
                "error": "missing value"}
    from agents.enrichment import _get
    try:
        r = await _get(
            session, _LOOKUP_URL,
            params={"value": value},
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "application/json"},
            timeout=10,
        )
    except Exception as e:
        return {"source": "threatcluster", "error": str(e)[:120],
                "error_type": "unreachable"}

    if not isinstance(r, dict):
        return {"source": "threatcluster", "error": "unexpected shape",
                "error_type": "unreachable"}
    # The `_get` helper wrapped a transport failure as {"error": ...}.
    if "error" in r and "value" not in r:
        return {"source": "threatcluster", "error": str(r.get("error"))[:160],
                "error_type": r.get("error_type", "unreachable")}

    count = int(r.get("count") or 0)
    if count <= 0:
        # Not a failure - just no clusters in the 7-day window. Return
        # found=False so the per-IP renderer doesn't light up for CLEAN
        # IOCs. (The notice field still describes tier limits, which is
        # fine to drop on an empty result.)
        return {"source": "threatcluster", "found": False,
                "summary": f"ThreatCluster: no clusters for {value} (7-day window)"}

    clusters = r.get("clusters") or []
    categories = r.get("categories") or []

    # Extract the strongest-signal field from each cluster for a terse
    # label. Clusters typically have {id, title, tags: [...], first_seen,
    # last_seen} - we surface the title(s).
    titles = []
    actors = set()
    families = set()
    for c in clusters[:6]:
        if not isinstance(c, dict):
            continue
        if c.get("title"):
            titles.append(str(c["title"])[:80])
        for tag in (c.get("tags") or []):
            if not isinstance(tag, str):
                continue
            tl = tag.lower()
            if tl.startswith("actor:") or tl.startswith("threat-actor:"):
                actors.add(tag.split(":", 1)[1])
            elif tl.startswith("malware:") or tl.startswith("family:"):
                families.add(tag.split(":", 1)[1])

    return {
        "source":        "threatcluster",
        "found":         True,
        "cluster_count": count,
        "categories":    categories,
        "cluster_titles": titles,
        "actors":        sorted(actors)[:5],
        "families":      sorted(families)[:5],
        "lookback_days": r.get("lookback_days") or 7,
        "older_matches": bool(r.get("older_matches")),
        "details_url":   f"https://threatcluster.io/iocs?value={value}",
        "verdict":       "MALICIOUS" if count >= 3 else "SUSPICIOUS",
        "summary":       _summarise(count, titles, families),
    }


def _summarise(count: int, titles: list, families: set) -> str:
    bits = [f"{count} cluster{'s' if count != 1 else ''}"]
    if families:
        bits.append(", ".join(sorted(families)[:3]))
    elif titles:
        bits.append(titles[0])
    return "ThreatCluster: " + " / ".join(bits)
