"""
Canonical TAXII feed catalog — opt-in public feeds the operator can
enable via config or settings.

Each entry is the shape `intel/feed_aggregator.py::TAXII_FEEDS` expects:
{name, url, collection_id, auth, description}. The operator enables a
feed by setting `RECON_TAXII_FEEDS` to a comma-separated list of feed
slugs from the registry below, OR by appending to the live TAXII_FEEDS
list directly.

Includes:
  - CISA AIS (requires enrollment; URL + structure published)
  - hailataxii (free + no key; STIX 1.x/2.0 mirror)
  - OASIS Cyber Threat Intelligence reference TAXII 2.1 server
  - Anomali Limo community feed (was in taxii_poller already)

Operator enables a feed at deploy time by exporting:
  RECON_TAXII_FEEDS=cisa_ais,hailataxii,oasis_cti
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.intel.taxii_catalog")


TAXII_FEED_CATALOG: Dict[str, Dict[str, Any]] = {
    "cisa_ais": {
        "name":          "CISA AIS",
        "url":           "https://ais2.cisa.dhs.gov/taxii2/",
        "collection_id": None,   # operator must set after enrollment
        "auth":          None,   # API key after CISA AIS onboarding
        "description":   ("CISA Automated Indicator Sharing — public-sector "
                           "indicator feed. Requires free enrollment at "
                           "https://www.cisa.gov/topics/cyber-threats-and-"
                           "advisories/information-sharing/automated-"
                           "indicator-sharing-ais"),
        "enroll_url":    "https://www.cisa.gov/ais",
        "requires_enrollment": True,
    },
    "hailataxii": {
        "name":          "hailataxii (TAXII 1.x mirror)",
        "url":           "http://hailataxii.com/taxii-data",
        "collection_id": "guest.Abuse_ch",
        "auth":          ("guest", "guest"),
        "description":   ("Free + no-key mirror of abuse.ch + community "
                           "feeds via legacy TAXII 1.x. Suricata + Snort "
                           "rules carried as feed-collection objects."),
        "requires_enrollment": False,
    },
    "anomali_limo": {
        "name":          "Anomali Limo community",
        "url":           "https://limo.anomali.com/api/v1/taxii2/feeds/",
        "collection_id": "107",
        "auth":          ("guest", "guest"),
        "description":   "Community threat intelligence feed",
        "requires_enrollment": False,
    },
    "mitre_attack_taxii": {
        "name":          "MITRE ATT&CK STIX",
        "url":           "https://attack-taxii.mitre.org/api/v21/",
        "collection_id": None,   # enumerate (enterprise/mobile/ics)
        "auth":          None,
        "description":   ("MITRE's authoritative ATT&CK STIX 2.1 TAXII "
                           "server. Provides Enterprise/Mobile/ICS matrices."),
        "requires_enrollment": False,
    },
    "oasis_cti": {
        "name":          "OASIS CTI reference TAXII 2.1",
        "url":           "https://cti-taxii.mitre.org/taxii/",
        "collection_id": None,
        "auth":          None,
        "description":   ("OASIS Cyber Threat Intelligence reference "
                           "implementation; useful sample for testing "
                           "TAXII clients."),
        "requires_enrollment": False,
    },
}


def get_enabled_feeds(slugs: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Return the list of feeds matching the supplied slugs (or
    those from the `RECON_TAXII_FEEDS` env var when slugs is None).
    Drops entries that still require enrollment unless the operator
    populated collection_id + auth via env."""
    if slugs is None:
        raw = os.environ.get("RECON_TAXII_FEEDS", "")
        slugs = [s.strip().lower() for s in raw.split(",") if s.strip()]
    out: List[Dict[str, Any]] = []
    for slug in slugs:
        spec = TAXII_FEED_CATALOG.get(slug)
        if not spec:
            _log.warning("Unknown TAXII feed slug: %s", slug)
            continue
        # Per-feed env overrides — `RECON_TAXII_<SLUG>_COLLECTION` and
        # `RECON_TAXII_<SLUG>_AUTH` ("user:pass") let the operator supply
        # post-enrollment credentials without editing code.
        ek = f"RECON_TAXII_{slug.upper()}_COLLECTION"
        ak = f"RECON_TAXII_{slug.upper()}_AUTH"
        col_override = os.environ.get(ek)
        auth_override = os.environ.get(ak)
        feed = dict(spec)
        if col_override:
            feed["collection_id"] = col_override
        if auth_override and ":" in auth_override:
            user, _, pw = auth_override.partition(":")
            feed["auth"] = (user, pw)
        if feed.get("requires_enrollment") and not feed.get("collection_id"):
            _log.info("TAXII feed %s requires enrollment but no "
                       "collection_id env override supplied — skipping", slug)
            continue
        out.append(feed)
    return out


def feed_slugs() -> List[str]:
    return sorted(TAXII_FEED_CATALOG.keys())
