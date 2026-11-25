"""BGPv6.com keyless ASN + RPKI + prefix analyzer.

Formal Analyzer wrapper for intel.bgpv6. Supports IPv4 + IPv6. No
required keys. Rate limit: 60 req/min.

Replaces BGPView (which shut down November 2025). Adds the RPKI-
validity signal RECON didn't have anywhere else - invalid-RPKI
prefixes are a direct hijack indicator.
"""

from __future__ import annotations

from plugins import Analyzer, AnalysisResult, register
from intel.bgpv6 import lookup as _bgpv6_lookup


class Bgpv6Analyzer(Analyzer):
    name = "bgpv6"
    description = (
        "BGPv6.com keyless BGP + RPKI + GeoIP lookup. Returns prefix, "
        "origin ASN, RPKI validity, and country - RPKI-invalid is a "
        "direct hijack flag. BGPView successor (that service shut down "
        "Nov 2025)."
    )
    supported_ioc_types = ["ipv4", "ipv6"]
    homepage = "https://bgpv6.com/"
    free_tier = "60 req/min keyless, no account"

    async def analyze(self, session, ioc_type, value, keys):
        raw = await _bgpv6_lookup(session, value)
        return AnalysisResult.from_legacy_dict(raw or {}, ioc_type, value)


register(Bgpv6Analyzer)
