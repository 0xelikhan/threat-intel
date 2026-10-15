"""Reference analyzer — abuse.ch YARAify hash lookup."""

from __future__ import annotations

from plugins import Analyzer, AnalysisResult, register
from intel.yaraify import lookup as _legacy_lookup


class YaraifyAnalyzer(Analyzer):
    name = "yaraify"
    description = (
        "abuse.ch YARAify — YARA + ClamAV scan results per sample. "
        "Shares the abuse.ch Auth-Key with URLhaus / ThreatFox / MalwareBazaar."
    )
    supported_ioc_types = ["md5", "sha1", "sha256"]
    required_keys = ["ABUSECH_AUTH_KEY"]
    homepage = "https://yaraify.abuse.ch/"
    free_tier = "generous with abuse.ch Auth-Key"

    async def analyze(self, session, ioc_type, value, keys):
        raw = await _legacy_lookup(session, value, keys.get("ABUSECH_AUTH_KEY", ""))
        return AnalysisResult.from_legacy_dict(raw or {}, ioc_type, value)


register(YaraifyAnalyzer)
