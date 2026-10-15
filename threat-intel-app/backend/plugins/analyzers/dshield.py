"""Reference analyzer — SANS ISC / DShield IP lookup.

Shows the full migration pattern from intel/dshield.py to the plugin
framework: unchanged lookup logic, wrapped in a formal Analyzer
subclass with declared ioc types + descriptor fields.
"""

from __future__ import annotations

from plugins import Analyzer, AnalysisResult, register
from intel.dshield import lookup as _legacy_lookup


class DShieldAnalyzer(Analyzer):
    name = "dshield"
    description = (
        "SANS ISC DShield — volunteer-firewall sensor network. "
        "Reports attack counts, first/last seen, aggregated threatfeed hits."
    )
    supported_ioc_types = ["ipv4", "ipv6"]
    homepage = "https://isc.sans.edu/"
    free_tier = "unlimited (fair-use)"

    async def analyze(self, session, ioc_type, value, keys):
        raw = await _legacy_lookup(session, value)
        return AnalysisResult.from_legacy_dict(raw or {}, ioc_type, value)


register(DShieldAnalyzer)
