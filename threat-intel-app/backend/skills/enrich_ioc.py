"""
EnrichIOCSkill — per-IOC enrichment against every configured TI source.

Wraps the existing agents.enrichment functions (enrich_ip / enrich_domain /
enrich_hash / enrich_url) and re-shapes the output into a deterministic
verdict + raw-source dict. The verdict is derived from the same signals
the deterministic GTI scorer uses.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from providers.base import LLMProvider

from .base import Skill


class EnrichIOCSkill(Skill):
    @property
    def name(self) -> str:
        return "enrich_ioc"

    @property
    def description(self) -> str:
        return ("Look up one IOC against every configured TI source "
                "(VirusTotal, AbuseIPDB, OTX, GreyNoise, URLScan, Shodan, "
                "Pulsedive, Maltiverse, WHOIS, DNS, BGP, etc.) and return a "
                "structured verdict alongside the raw per-source payloads.")

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {"ioc_value": "str", "ioc_type": "str (ip|domain|hash|url)"}

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "ioc":      "str",
            "type":     "str",
            "verdict":  "str (MALICIOUS|SUSPICIOUS|CLEAN|UNKNOWN)",
            "score":    "int (0-100)",
            "sources":  "dict",
            "summary":  "list[str]",
        }

    @property
    def test_input(self) -> Dict[str, Any]:
        return {"ioc_value": "1.1.1.1", "ioc_type": "ip"}

    async def execute(
        self,
        inputs:   Dict[str, Any],
        provider: Optional[LLMProvider] = None,
    ) -> Dict[str, Any]:
        ioc_value = (inputs or {}).get("ioc_value") or ""
        ioc_type  = ((inputs or {}).get("ioc_type") or "").lower()
        if not ioc_value or not ioc_type:
            return {"ioc": ioc_value, "type": ioc_type, "verdict": "UNKNOWN",
                    "score": 0, "sources": {}, "summary": ["missing ioc_value / ioc_type"]}

        # Dispatch to the right enrich_* function from agents.enrichment.
        try:
            import logging
            import aiohttp
            from config import config
            from agents import enrichment as _enr
            from intel.cache import cache_for
        except Exception as e:
            return {"ioc": ioc_value, "type": ioc_type, "verdict": "UNKNOWN",
                    "score": 0, "sources": {}, "summary": [f"enrichment unavailable: {e}"]}

        _log = logging.getLogger("recon.skill.enrich_ioc")
        # Full key set so the skill's enrichment matches the main /api/analyze
        # pipeline. Each enrich_* internally cherry-picks what it needs.
        keys = {k: config.get(k, "") for k in (
            "VIRUSTOTAL_KEY", "ABUSEIPDB_KEY", "OTX_KEY", "URLSCAN_KEY",
            "GREYNOISE_KEY", "PULSEDIVE_KEY", "MALTIVERSE_KEY",
            "IPINFO_TOKEN", "WHOISXML_KEY",
            "ABUSECH_AUTH_KEY", "MALWAREBAZAAR_API_KEY", "HYBRID_ANALYSIS_KEY",
            # Canonical Censys names — PAT first, legacy v2 pair as fallback.
            # Both are registered in config.py.
            "CENSYS_API_KEY", "CENSYS_ID", "CENSYS_SECRET",
            "CRIMINAL_IP_KEY", "PROXYCHECK_KEY",
            "GOOGLE_API_KEY", "HONEYPOT_KEY",
            "OPENCTI_URL", "OPENCTI_TOKEN",
        )}

        # ── cache lookup ──────────────────────────────────────────────────────
        # Cache the full per-IOC enrichment payload. The skill is the single
        # entry point so caching here avoids the entire downstream fan-out
        # on a hit. Namespace is "enrich" so each TI bucket can still tune
        # its own TTL independently if we split later.
        cache    = cache_for("enrich")
        cache_key = f"{ioc_type}:{ioc_value.lower()}"
        cached    = cache.get(cache_key)
        if cached is not None:
            _log.debug("cache hit %s", cache_key)
            data = cached
        else:
            _log.debug("cache miss %s", cache_key)
            # Share the enrichment module's process-wide TCP/DNS pool so
            # individual skill calls benefit from the same warm sockets
            # as the full pipeline.
            async with aiohttp.ClientSession(
                connector=_enr._get_connector(), connector_owner=False
            ) as session:
                if ioc_type == "ip":
                    data = await _enr.enrich_ip(session, ioc_value, keys)
                elif ioc_type in ("domain", "hostname"):
                    data = await _enr.enrich_domain(session, ioc_value, keys)
                elif ioc_type in ("hash", "file"):
                    data = await _enr.enrich_hash(session, ioc_value, keys)
                elif ioc_type == "url":
                    data = await _enr.enrich_url(session, ioc_value, keys)
                else:
                    return {"ioc": ioc_value, "type": ioc_type, "verdict": "UNKNOWN",
                            "score": 0, "sources": {}, "summary": ["unknown ioc_type"]}
            # Only cache on a real payload — never store an empty/error-only
            # response or we'd serve the failure forever.
            if data and isinstance(data, dict) and any(
                k for k in data if k != "error"
            ):
                cache.set(cache_key, data)

        # Derive verdict + score via the existing deterministic scorer for
        # parity with the GTI panel. compute_gti_scores takes ONE arg
        # (enrichments) keyed by plural type; the earlier two-arg call
        # was a TypeError that swallowed into UNKNOWN/0 on every call.
        try:
            from gti_score import compute_gti_scores
            bucket_key = "hashes" if ioc_type in ("hash", "file") else f"{ioc_type}s"
            scores = compute_gti_scores({bucket_key: {ioc_value: data}})
            entry = (scores or {}).get(ioc_value) or {}
            verdict = entry.get("verdict") or "UNKNOWN"
            score   = int(entry.get("score") or 0)
            factors = [f for f in (entry.get("contributing_factors") or [])][:6]
        except Exception as _e:
            _log.warning("gti scoring failed in enrich_ioc skill: %s", _e)
            verdict, score, factors = "UNKNOWN", 0, []

        return {
            "ioc":      ioc_value,
            "type":     ioc_type,
            "verdict":  verdict,
            "score":    score,
            "sources":  data or {},
            "summary":  factors,
        }
