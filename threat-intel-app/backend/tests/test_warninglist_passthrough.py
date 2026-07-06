"""Regression test for the warninglist filter dropping non-filterable
IOC buckets.

Bug: `filter_iocs()` in intel/warninglist_filter.py explicitly built a
fresh output dict with only {ips, domains, hashes, urls, emails}. Any
bucket not in that list — cves, crypto, files, paths — was silently
dropped when triage did `iocs = filtered`. Result: CVE IOCs extracted
from the alert text never reached run_enrichment's fan-out, so
enrichments.cves stayed empty. Same for crypto after that bucket was
added. Discovered during HTTP end-to-end verification.
"""

from __future__ import annotations

from intel.warninglist_filter import filter_iocs


def test_filter_iocs_preserves_cves_bucket():
    """CVEs aren't warninglisted anywhere; they must pass through
    untouched to reach enrich_cve."""
    iocs = {
        "ips": [], "domains": [], "hashes": [], "urls": [], "emails": [],
        "cves": ["CVE-2024-6387", "CVE-2023-38408"],
    }
    filtered, _ = filter_iocs(iocs)
    assert filtered["cves"] == ["CVE-2024-6387", "CVE-2023-38408"]


def test_filter_iocs_preserves_crypto_bucket():
    """Crypto addresses have no warninglist gate — passing through is
    critical for ransom-note triage."""
    iocs = {
        "ips": [], "domains": [], "hashes": [], "urls": [], "emails": [],
        "crypto": ["bc1q9h6mvfdz9vt9qmzk8n2p7xvyrn8y92xh5r7lkq"],
    }
    filtered, _ = filter_iocs(iocs)
    assert filtered["crypto"] == ["bc1q9h6mvfdz9vt9qmzk8n2p7xvyrn8y92xh5r7lkq"]


def test_filter_iocs_preserves_files_and_paths():
    """Filenames + filesystem paths flow to behavioral extractors and
    the analyst report even though no external TI service enriches
    them. Losing them lost context downstream."""
    iocs = {
        "ips": [], "domains": [], "hashes": [], "urls": [], "emails": [],
        "files": ["update.exe"],
        "paths": [r"c:\users\alice\appdata\local\temp\update.exe"],
    }
    filtered, _ = filter_iocs(iocs)
    assert filtered["files"] == ["update.exe"]
    assert filtered["paths"] == [r"c:\users\alice\appdata\local\temp\update.exe"]


def test_filter_iocs_still_filters_ips_and_domains():
    """The MISP warninglist gate on filterable buckets still works —
    Cloudflare DNS + Tranco-top domain get suppressed as before."""
    iocs = {
        "ips": ["1.1.1.1", "8.8.8.8", "45.83.220.68"],
        "domains": ["google.com", "evil-attacker.example"],
        "hashes": [], "urls": [], "emails": [],
    }
    filtered, suppressed = filter_iocs(iocs)
    # The MISP-listed IPs / domains land in suppressed; anything not on
    # a warninglist stays in filtered.
    assert "google.com" not in filtered["domains"]
    assert "evil-attacker.example" in filtered["domains"]
    # At least one of the two public DNS resolvers gets flagged.
    supp_ips = {r["ioc"] for r in suppressed["ips"]}
    assert "1.1.1.1" in supp_ips or "8.8.8.8" in supp_ips


def test_filter_iocs_handles_missing_buckets_gracefully():
    """extract_iocs always emits every bucket, but the filter should
    tolerate calls that leave some out (e.g. a skill-registry caller
    that only provides ips + domains)."""
    filtered, _ = filter_iocs({"ips": ["45.83.220.68"], "domains": []})
    # Missing buckets come back as empty lists, not KeyErrors.
    for k in ("emails", "cves", "crypto", "files", "paths",
              "hashes", "urls"):
        assert filtered[k] == []
