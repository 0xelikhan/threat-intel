"""Regression test for the verdicts-dict KeyError that broke every
analysis whose log contained an email or CVE IOC.

Bug: run_enrichment's per-IOC verdict aggregation used a hardcoded
verdicts = {"ips": {}, "domains": {}, "hashes": {}, "urls": {}} —
when the loop iterated the new "emails" or "cves" bucket added by
later commits, verdicts[cat][ioc] = ... raised KeyError on the
missing bucket name.

The error surfaced in the frontend as a red error box reading
'emails' (the exception detail being just the missing key).
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch, AsyncMock

import pytest

from agents.enrichment import run_enrichment


def _fake_enricher_factory(payload):
    """Return a coroutine that always resolves to `payload`. Used to
    bypass the real HTTP-fan-out so the test exercises just the
    aggregation logic that broke."""
    async def _fake(_session, _ioc, _keys):
        return payload
    return _fake


def test_run_enrichment_with_email_ioc_does_not_keyerror_on_verdicts_dict():
    """The exact failure mode the user reported: analysis stopped before
    enrichment finished and the UI showed a red 'emails' error box.
    Reproduced by feeding an email-only IOC set through run_enrichment."""

    state = {
        "iocs": {
            "ips": [], "domains": [], "hashes": [], "urls": [],
            "emails": ["jaquline@timelistgroup.org"],
            "cves":   ["CVE-2024-1234"],
        },
        "agent_trace": [],
    }

    # Stub every enricher so this test doesn't hit the network and
    # doesn't depend on any API keys being configured.
    fake_email = {"hibp": {"verdict": "CLEAN", "summary": "test"}}
    fake_cve   = {"nvd":  {"verdict": "UNKNOWN", "found": False}}

    with patch("agents.enrichment.enrich_ip",     new=_fake_enricher_factory({})), \
         patch("agents.enrichment.enrich_domain", new=_fake_enricher_factory({})), \
         patch("agents.enrichment.enrich_hash",   new=_fake_enricher_factory({})), \
         patch("agents.enrichment.enrich_url",    new=_fake_enricher_factory({})), \
         patch("agents.enrichment.enrich_email",  new=_fake_enricher_factory(fake_email)), \
         patch("agents.enrichment.enrich_cve",    new=_fake_enricher_factory(fake_cve)):
        out = asyncio.run(run_enrichment(state))

    # Pre-fix: this would have raised KeyError: 'emails' midway through
    # the verdicts loop and never returned. Post-fix: verdicts is built
    # from enrichments.keys() so every bucket is covered.
    assert "enrichment_summary" in out
    assert out["enrichment_summary"]["totals"]["emails"] == 1
    assert out["enrichment_summary"]["totals"]["cves"] == 1
    # The verdicts_per_ioc bucket dict must include the new categories.
    verdicts = out["enrichment_summary"]["verdicts_per_ioc"]
    assert "emails" in verdicts
    assert "cves" in verdicts
    assert "jaquline@timelistgroup.org" in verdicts["emails"]
    assert "CVE-2024-1234" in verdicts["cves"]
