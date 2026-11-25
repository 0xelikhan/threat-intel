"""ThreatCluster keyless per-IOC lookup analyzer.

Wraps intel.threatcluster.lookup. Covers IPv4/IPv6/domain/url/hash -
ThreatCluster auto-detects the entity type server-side.
"""

from __future__ import annotations

from plugins import Analyzer, AnalysisResult, register
from intel.threatcluster import lookup as _tc_lookup


class ThreatClusterAnalyzer(Analyzer):
    name = "threatcluster"
    description = (
        "ThreatCluster keyless IOC lookup. Returns clustered threat "
        "reporting with threat-actor + malware-family tags for IPs, "
        "domains, URLs, and hashes. Keyless tier: 25 clusters from "
        "the last 7 days (60 req/min)."
    )
    supported_ioc_types = ["ipv4", "ipv6", "domain", "url",
                            "md5", "sha1", "sha256"]
    homepage = "https://threatcluster.io/"
    free_tier = "25 clusters / 7-day window, keyless"

    async def analyze(self, session, ioc_type, value, keys):
        raw = await _tc_lookup(session, value)
        return AnalysisResult.from_legacy_dict(raw or {}, ioc_type, value)


register(ThreatClusterAnalyzer)
