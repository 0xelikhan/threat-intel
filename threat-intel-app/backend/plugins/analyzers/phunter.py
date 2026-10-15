"""Reference analyzer — Phunter phone-number parse / validate."""

from __future__ import annotations

from plugins import Analyzer, AnalysisResult, register
from intel.phunter import lookup as _legacy_lookup


class PhunterAnalyzer(Analyzer):
    name = "phunter"
    description = (
        "Native-Python phone-number parse + validate using Google's "
        "phonenumbers library. Returns E.164, carrier, region, line type."
    )
    supported_ioc_types = ["phone"]
    homepage = "https://github.com/google/libphonenumber"
    free_tier = "unlimited (local)"

    async def analyze(self, session, ioc_type, value, keys):
        raw = await _legacy_lookup(session, value)
        return AnalysisResult.from_legacy_dict(raw or {}, ioc_type, value)


register(PhunterAnalyzer)
