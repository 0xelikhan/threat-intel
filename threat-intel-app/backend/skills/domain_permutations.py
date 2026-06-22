"""
DomainPermutationsSkill — generate typo-squat / lookalike permutations for a
domain and surface which ones actually resolve.

Adapted from elceef/dnstwist (Apache-2.0). dnstwist is already shipped as a
dependency and is used in heuristic mode by `intel/typosquat.py`. The skill
extends that by running the full Fuzzer and resolving every candidate against
DNS so the analyst sees which permutations are real registered domains an
adversary could be hosting phishing infrastructure on.

The skill is designed for on-demand UI invocation, not the auto-enrichment
fan-out, because doing DNS resolution on 200+ permutations per analyze would
be too expensive. Trigger from the IOC detail panel.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any, Dict, List, Optional

from providers.base import LLMProvider

from .base import Skill

_log = logging.getLogger("recon.skills.domain_permutations")


# Common permutation types dnstwist emits — used to filter low-signal variants
# (we always include character swaps + homoglyphs; we drop "addition" / "vowel-
# swap" only when the consumer asks for high-confidence mode).
_HIGH_SIGNAL_FUZZERS = {
    "homoglyph", "homophones", "transposition", "replacement",
    "subdomain", "tld-swap", "bitsquatting", "addition",
}


class DomainPermutationsSkill(Skill):
    @property
    def name(self) -> str:
        return "domain_permutations"

    @property
    def description(self) -> str:
        return ("Generate typo-squat / homoglyph / TLD-swap permutations for a "
                "domain via dnstwist and DNS-resolve each to surface live "
                "registered lookalikes.")

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "domain":           "str",
            "max_results":      "int (optional, default 25)",
            "resolve":          "bool (optional, default True)",
            "high_signal_only": "bool (optional, default False)",
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "domain":     "str",
            "total":      "int",
            "registered": "list[dict]",
            "unresolved": "list[dict]",
            "error":      "str|None",
        }

    @property
    def test_input(self) -> Dict[str, Any]:
        # microsoft.com is a long-suffering brand for typosquatting — using
        # it as the test input means we get realistic permutations without
        # leaning on a domain that might disappear between test runs.
        return {"domain": "microsoft.com", "max_results": 10,
                "resolve": False}  # resolve=False so the test stays offline

    async def execute(
        self,
        inputs:   Dict[str, Any],
        provider: Optional[LLMProvider] = None,
    ) -> Dict[str, Any]:
        domain = ((inputs or {}).get("domain") or "").strip().lower()
        if not domain:
            return _empty("", error="missing 'domain' input")
        max_results      = int((inputs or {}).get("max_results") or 25)
        resolve          = bool((inputs or {}).get("resolve", True))
        high_signal_only = bool((inputs or {}).get("high_signal_only", False))

        # dnstwist's Fuzzer is sync + can spend ~100ms generating; isolate it
        # in a worker thread so the event loop stays responsive.
        try:
            variants = await asyncio.to_thread(
                _generate_variants, domain, max_results, high_signal_only,
            )
        except Exception as e:
            _log.warning("dnstwist generate failed for %s: %s", domain, e)
            return _empty(domain, error=f"dnstwist generate failed: {e}")

        if not variants:
            return _empty(domain, total=0)

        if not resolve:
            return {
                "domain":     domain,
                "total":      len(variants),
                "registered": [],
                "unresolved": variants,
                "error":      None,
            }

        # Resolve in parallel with a tight per-host cap. Limit fan-out so a
        # 200-variant set doesn't slam the system DNS resolver.
        sem = asyncio.Semaphore(20)

        async def _check(v: dict) -> dict:
            async with sem:
                ip = await _resolve(v["variant"], timeout_s=1.5)
            out = dict(v)
            if ip:
                out["dns_a"]    = ip
                out["resolves"] = True
            else:
                out["resolves"] = False
            return out

        results = await asyncio.gather(*[_check(v) for v in variants],
                                       return_exceptions=False)
        registered  = [r for r in results if r.get("resolves")]
        unresolved  = [r for r in results if not r.get("resolves")]

        return {
            "domain":     domain,
            "total":      len(results),
            "registered": registered,
            "unresolved": unresolved,
            "error":      None,
        }


def _generate_variants(domain: str, max_results: int,
                       high_signal_only: bool) -> List[Dict[str, Any]]:
    """Sync helper: import dnstwist, run the Fuzzer, return a list of dicts."""
    import dnstwist  # local import; surface ImportError as a clear skill failure

    fuzzer = dnstwist.Fuzzer(domain)
    fuzzer.generate()
    raw = list(getattr(fuzzer, "domains", []) or [])

    out: List[Dict[str, Any]] = []
    seen: set = set()
    for v in raw:
        if not isinstance(v, dict):
            continue
        variant = (v.get("domain") or "").strip().lower()
        fuzzer_kind = v.get("fuzzer") or v.get("type") or ""
        if not variant or variant == domain or variant in seen:
            continue
        if high_signal_only and fuzzer_kind not in _HIGH_SIGNAL_FUZZERS:
            continue
        seen.add(variant)
        out.append({"variant": variant, "fuzzer": fuzzer_kind})
        if len(out) >= max_results:
            break
    return out


async def _resolve(host: str, timeout_s: float = 1.5) -> Optional[str]:
    """Resolve `host` to its first A-record IPv4 string, or None on failure /
    timeout. socket.gethostbyname is blocking, so it goes through to_thread."""
    def _blocking() -> Optional[str]:
        try:
            return socket.gethostbyname(host)
        except (socket.gaierror, OSError):
            return None
    try:
        return await asyncio.wait_for(asyncio.to_thread(_blocking),
                                      timeout=timeout_s)
    except (asyncio.TimeoutError, OSError):
        return None


def _empty(domain: str, total: int = 0,
           error: Optional[str] = None) -> Dict[str, Any]:
    return {
        "domain":     domain,
        "total":      total,
        "registered": [],
        "unresolved": [],
        "error":      error,
    }
