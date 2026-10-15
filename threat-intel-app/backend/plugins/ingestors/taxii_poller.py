"""TAXII ingestor — poll configured TAXII 2.1 feeds for new STIX IOCs.

Thin wrapper around intel/taxii_poller.py. Yields {type, value} dicts
on each poll cycle; the orchestrator decides whether to run them
through the analysis pipeline.
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Dict

from plugins import Ingestor, register


class TaxiiIngestor(Ingestor):
    name = "taxii"
    description = ("Poll TAXII 2.1 feeds (RECON_TAXII_FEEDS env var or "
                   "CISA AIS when enabled) for new STIX IOCs. Each new "
                   "observable is yielded as an IOC dict.")
    interval_seconds = 600               # 10-min default poll
    required_keys = []                   # feeds configured via env vars
    optional_keys = ["RECON_TAXII_FEEDS", "RECON_TAXII_CISA_AIS_COLLECTION"]
    homepage = "https://oasis-open.github.io/cti-documentation/taxii/intro.html"

    async def poll(self, session) -> AsyncIterator[Dict[str, Any]]:
        try:
            from intel.taxii_poller import poll_configured_feeds
        except Exception:
            return
        try:
            # The legacy module yields IOC dicts in the shape we want.
            async for ioc in poll_configured_feeds(session):
                if isinstance(ioc, dict) and ioc.get("type") and ioc.get("value"):
                    yield ioc
        except TypeError:
            # Non-async-generator fallback: wrap sync list return
            try:
                iocs = poll_configured_feeds(session)
            except Exception:
                return
            for ioc in (iocs or []):
                if isinstance(ioc, dict) and ioc.get("type") and ioc.get("value"):
                    yield ioc


register(TaxiiIngestor)
