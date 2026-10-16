"""OFAC Specially Designated Nationals sanctioned-entity check.

Auto-generated from _legacy_registrations.py. Keeps the LegacyAnalyzer
Adapter pattern (import on first call + from_legacy_dict wrap) but
promotes it to a dedicated file so overrides and tests can target
one source at a time.
"""

from __future__ import annotations

from plugins import Analyzer, AnalysisResult, register


class OfacSdnAnalyzer(Analyzer):
    name = "ofac_sdn"
    description = ('OFAC Specially Designated Nationals sanctioned-entity check.')
    supported_ioc_types = ['email', 'domain', 'crypto']
    required_keys = []
    optional_keys = []
    homepage = 'https://ofac.treasury.gov/'
    free_tier = None

    async def analyze(self, session, ioc_type, value, keys):
        import importlib
        try:
            mod = importlib.import_module("intel.ofac_sdn")
            fn = getattr(mod, "lookup_email")
        except Exception as e:
            return AnalysisResult(
                source=self.name, ioc_type=ioc_type, ioc_value=value,
                found=False, error=f"import failed: {e}",
                error_type="unavailable",
            )
        key = ""
        for k in (self.required_keys + self.optional_keys):
            if keys.get(k):
                key = keys[k]
                break
        try:
            raw = await fn(session, value, key) if key else await fn(session, value)
        except Exception as e:
            return AnalysisResult(
                source=self.name, ioc_type=ioc_type, ioc_value=value,
                found=False, error=str(e)[:120], error_type="unreachable",
            )
        return AnalysisResult.from_legacy_dict(
            raw if isinstance(raw, dict) else {}, ioc_type, value,
        )


register(OfacSdnAnalyzer)
