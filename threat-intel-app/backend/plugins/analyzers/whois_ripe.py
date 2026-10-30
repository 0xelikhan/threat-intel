"""WHOIS lookup via WhoisXML API.

Auto-generated from _legacy_registrations.py. Keeps the LegacyAnalyzer
Adapter pattern (import on first call + from_legacy_dict wrap) but
promotes it to a dedicated file so overrides and tests can target
one source at a time.
"""

from __future__ import annotations

from plugins import Analyzer, AnalysisResult, register


class WhoisRipeAnalyzer(Analyzer):
    name = "whois_ripe"
    description = ('WHOIS lookup via WhoisXML API.')
    supported_ioc_types = ['domain']
    required_keys = ['WHOISXML_KEY']
    optional_keys = []
    homepage = 'https://whoisxmlapi.com/'
    free_tier = None

    async def analyze(self, session, ioc_type, value, keys):
        import importlib
        try:
            mod = importlib.import_module("intel.whois_lookup")
            fn = getattr(mod, "lookup")
        except Exception as e:
            return AnalysisResult(
                source=self.name, ioc_type=ioc_type, ioc_value=value,
                found=False, error=f"import failed: {e}",
                error_type="unavailable",
            )
        key = keys.get("WHOISXML_KEY", "")
        if not key:
            return AnalysisResult(
                source=self.name, ioc_type=ioc_type, ioc_value=value,
                found=False, error="WHOISXML_KEY not configured",
                error_type="missing_key",
            )
        try:
            raw = await fn(value, key, session)
        except Exception as e:
            return AnalysisResult(
                source=self.name, ioc_type=ioc_type, ioc_value=value,
                found=False, error=str(e)[:120], error_type="unreachable",
            )
        return AnalysisResult.from_legacy_dict(
            raw if isinstance(raw, dict) else {}, ioc_type, value,
        )


register(WhoisRipeAnalyzer)
