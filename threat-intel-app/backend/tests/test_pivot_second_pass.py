"""Pivot pass regression — a sandbox result with files_dropped must
produce follow-on hash enrichment in run_enrichment's output.

The pivot plugin (sandbox_dropped_hashes) is registered but was
previously inert — the orchestrator never consumed its output. This
test exercises the second-pass flow:

  1. Submit a hash IOC
  2. Mock enrich_hash to return a sandbox result with files_dropped
  3. Confirm the dropped hash shows up in enrichments['hashes'] after
     run_enrichment completes
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest


_DROPPED_SHA256 = "deadbeef" * 8   # 64 chars


def _fake_hash_enricher():
    """Return hashes with files_dropped on the first call, nothing on the
    second (pivot follow-up). This lets us verify the pivot:
      - fires on first-pass result (hybrid_analysis + files_dropped)
      - queues DROPPED_SHA256 for enrichment
      - and that follow-up invocation DOES go through enrich_hash
    """
    call_count = {"n": 0}
    async def _fake(_session, hash_val, _keys):
        call_count["n"] += 1
        if hash_val == _DROPPED_SHA256:
            # Second-pass (pivot follow-up) result
            return {
                "pivot_marker": {
                    "source": "virustotal",
                    "verdict": "CLEAN",
                    "found": True,
                    "summary": "pivot follow-up ran",
                }
            }
        # First-pass: sandbox result with dropped hash
        return {
            "hybrid_analysis": {
                "source": "hybrid_analysis",
                "found": True,
                "verdict": "MALICIOUS",
                "summary": "pretend sandbox",
                "files_dropped": [{"sha256": _DROPPED_SHA256}],
            }
        }
    return _fake


def test_pivot_pass_adds_dropped_hashes_to_enrichments():
    from agents.enrichment import run_enrichment
    state = {
        "iocs": {"ips": [], "domains": [], "urls": [], "cves": [],
                  "emails": [], "crypto": [], "phones": [],
                  "hashes": ["original_hash_1234567890abcdef" + "0"*32]},
        "agent_trace": [],
    }
    async def _skip(*a, **k): return {}
    with patch("agents.enrichment.enrich_hash",   new=_fake_hash_enricher()), \
         patch("agents.enrichment.enrich_ip",     new=_skip), \
         patch("agents.enrichment.enrich_domain", new=_skip), \
         patch("agents.enrichment.enrich_url",    new=_skip), \
         patch("agents.enrichment.enrich_cve",    new=_skip), \
         patch("agents.enrichment.enrich_email",  new=_skip), \
         patch("agents.enrichment.enrich_crypto", new=_skip), \
         patch("agents.enrichment.enrich_phone",  new=_skip):
        out = asyncio.run(run_enrichment(state))

    hashes = out["enrichments"]["hashes"]
    assert _DROPPED_SHA256 in hashes, (
        f"pivot didn't surface dropped hash. hashes keys: {list(hashes.keys())}"
    )
    pivot_result = hashes[_DROPPED_SHA256]
    # Was the pivot_marker (second-pass fake return) what landed?
    assert "pivot_marker" in pivot_result, (
        f"unexpected shape for pivot follow-up: {pivot_result}"
    )


def test_pivot_pass_skips_when_no_sandbox_source():
    """VT marks a file MALICIOUS but doesn't emit files_dropped; the
    pivot should NOT fire and no new hashes should be queued."""
    from agents.enrichment import run_enrichment

    async def _vt_only(*_args, **_kwargs):
        return {
            "virustotal": {
                "source": "virustotal",
                "found": True,
                "verdict": "MALICIOUS",
                "summary": "vt flagged",
                # intentional: no files_dropped field
            }
        }
    async def _skip(*a, **k): return {}

    state = {
        "iocs": {"ips": [], "domains": [], "urls": [], "cves": [],
                  "emails": [], "crypto": [], "phones": [],
                  "hashes": ["aaaaa" * 20]},
        "agent_trace": [],
    }
    with patch("agents.enrichment.enrich_hash",   new=_vt_only), \
         patch("agents.enrichment.enrich_ip",     new=_skip), \
         patch("agents.enrichment.enrich_domain", new=_skip), \
         patch("agents.enrichment.enrich_url",    new=_skip), \
         patch("agents.enrichment.enrich_cve",    new=_skip), \
         patch("agents.enrichment.enrich_email",  new=_skip), \
         patch("agents.enrichment.enrich_crypto", new=_skip), \
         patch("agents.enrichment.enrich_phone",  new=_skip):
        out = asyncio.run(run_enrichment(state))

    hashes = out["enrichments"]["hashes"]
    # Only the original hash — no pivot-produced entries
    assert set(hashes.keys()) == {"aaaaa" * 20}
