"""Maltiverse IOC enrichment (IP/domain/URL/hash).

Auto-generated from _legacy_registrations.py. Keeps the LegacyAnalyzer
Adapter pattern (import on first call + from_legacy_dict wrap) but
promotes it to a dedicated file so overrides and tests can target
one source at a time.
"""

from __future__ import annotations

from plugins import Analyzer, AnalysisResult, register


class MaltiverseAnalyzer(Analyzer):
    name = "maltiverse"
    description = ('Maltiverse IOC enrichment (IP/domain/URL/hash).')
    supported_ioc_types = ['ipv4', 'ipv6', 'domain', 'md5', 'sha1', 'sha256', 'url']
    required_keys = []
    optional_keys = ['MALTIVERSE_KEY']
    homepage = 'https://www.maltiverse.com/'
    free_tier = 'anonymous queries available (rate-limited)'

    async def analyze(self, session, ioc_type, value, keys):
        import importlib
        try:
            mod = importlib.import_module("intel.maltiverse")
            fn = getattr(mod, "lookup")
        except Exception as e:
            return AnalysisResult(
                source=self.name, ioc_type=ioc_type, ioc_value=value,
                found=False, error=f"import failed: {e}",
                error_type="unavailable",
            )
        key = keys.get("MALTIVERSE_KEY", "")
        mt_type = {"ipv4": "ip", "ipv6": "ip", "domain": "hostname",
                   "md5": "hash", "sha1": "hash", "sha256": "hash",
                   "url": "url"}.get(ioc_type)
        if not mt_type:
            return AnalysisResult(
                source=self.name, ioc_type=ioc_type, ioc_value=value,
                found=False, error=f"unsupported ioc_type {ioc_type}",
                error_type="unavailable",
            )
        try:
            raw = await fn(mt_type, value, key)
        except Exception as e:
            return AnalysisResult(
                source=self.name, ioc_type=ioc_type, ioc_value=value,
                found=False, error=str(e)[:120], error_type="unreachable",
            )
        return AnalysisResult.from_legacy_dict(
            raw if isinstance(raw, dict) else {}, ioc_type, value,
        )


register(MaltiverseAnalyzer)
