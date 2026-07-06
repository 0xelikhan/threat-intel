"""
OpenSanctions — free API, no key.

Superset of OFAC SDN. Aggregates 40+ sanctions lists worldwide:
  - US OFAC SDN + CAPTA + BIS Entity List
  - UN Consolidated
  - EU consolidated
  - UK HMT
  - CH SECO
  - Canada, Australia, Japan, individual EU member states
  - PEP (politically exposed persons) rollup

Live API at api.opensanctions.org — free tier is generous
(~500 req/day, no auth required). We wrap the /search endpoint for
identifier-typed queries: crypto address, email, entity name.

Response is normalised to match the OFAC shape RECON already renders,
so the frontend surface reuses the existing "sanctioned" row.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.intel.opensanctions")

# Datasets to search. `default` is the union of everything; scoping to
# `sanctions` cuts the crime/PEP noise for our threat-intel use.
_DATASET = "sanctions"

_BASE = "https://api.opensanctions.org"


def _bits(entity: Dict[str, Any]) -> Dict[str, Any]:
    """Pull the identifying fields from an OpenSanctions entity."""
    props = entity.get("properties") or {}
    programs = []
    for k in ("program", "topics", "sanctions"):
        v = props.get(k) or []
        if isinstance(v, list): programs.extend(str(x) for x in v)
    return {
        "entity":    (entity.get("caption") or "").strip()[:240] or "(unnamed)",
        "programs":  list(dict.fromkeys(programs))[:6],
        "list_type": entity.get("schema") or "",
        "source":    "OpenSanctions",
        "ref":       f"https://www.opensanctions.org/entities/{entity.get('id')}",
    }


async def _search(session, query: str, entity_types: Optional[List[str]] = None
                  ) -> Optional[Dict[str, Any]]:
    """One /search call. Returns the top-scoring entity or None."""
    if not query:
        return None
    from agents.enrichment import _get

    params = {"q": query, "limit": 1}
    if entity_types:
        params["schema"] = entity_types[0]

    raw = await _get(
        session,
        f"{_BASE}/search/{_DATASET}",
        params=params,
        headers={"User-Agent": "RECON-ThreatIntel/1.0",
                 "Accept": "application/json"},
    )
    if not isinstance(raw, dict):
        return None
    results = raw.get("results") or []
    if not results:
        return None
    top = results[0]
    if not isinstance(top, dict):
        return None
    return top


async def lookup_crypto(session, address: str) -> Optional[Dict[str, Any]]:
    """Match a crypto address against OpenSanctions crypto identifiers."""
    if not isinstance(address, str) or not address.strip():
        return None
    top = await _search(session, address.strip())
    if not top:
        return None
    props = top.get("properties") or {}
    # The address must actually appear on the entity — otherwise the
    # /search fuzzy-match will return random near-matches.
    addrs = []
    for k in ("cryptoWallets", "wallet", "walletAddress", "cryptoAddress"):
        v = props.get(k) or []
        if isinstance(v, list): addrs.extend(str(a).lower() for a in v)
    if address.lower() not in addrs:
        return None
    hit = _bits(top)
    hit["id_type"] = "digital currency address"
    return hit


async def lookup_email(session, email: str) -> Optional[Dict[str, Any]]:
    if not isinstance(email, str) or "@" not in email:
        return None
    top = await _search(session, email.lower().strip())
    if not top:
        return None
    props = top.get("properties") or {}
    emails = []
    for k in ("email", "emailAddress"):
        v = props.get(k) or []
        if isinstance(v, list): emails.extend(str(a).lower() for a in v)
    if email.lower() not in emails:
        return None
    hit = _bits(top)
    hit["id_type"] = "email address"
    return hit
