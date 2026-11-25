"""ip-api.com keyless geolocation + ASN analyzer.

Formal Analyzer wrapper for intel.ip_api. Supports IPv4 + IPv6. No
required keys - the free tier is unauthenticated and stable at 45
req/min. Used by enrich_ip as a fallback when IPINFO_TOKEN is unset.
"""

from __future__ import annotations

from plugins import Analyzer, AnalysisResult, register
from intel.ip_api import lookup as _ip_api_lookup


class IpApiAnalyzer(Analyzer):
    name = "ip_api"
    description = (
        "ip-api.com keyless geolocation + ASN + ISP lookup. Covers "
        "IPv4/IPv6; normalized to the IPInfo shape so downstream "
        "renderers can treat either source interchangeably. Free "
        "tier: 45 req/min, no account."
    )
    supported_ioc_types = ["ipv4", "ipv6"]
    homepage = "https://ip-api.com/"
    free_tier = "45 req/min keyless, no account"

    async def analyze(self, session, ioc_type, value, keys):
        raw = await _ip_api_lookup(session, value)
        return AnalysisResult.from_legacy_dict(raw or {}, ioc_type, value)


register(IpApiAnalyzer)
