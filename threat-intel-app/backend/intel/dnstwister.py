"""
DNSTwister — free API at dnstwister.report, no key.

The local `intel/typosquat.py` heuristic already flags a domain as
suspicious when it Levenshtein-distance-1 away from a known brand. What
it can't tell the analyst is which of the algorithmically-generated
typo permutations someone has actually gone and registered. That's the
phishing-infra prep signal: the attacker owning `paypa1.com`,
`goog1e-support.com`, `micrsoft-updater.com` right now.

We use DNSTwister for the fuzz-list generation ONLY:
  - GET /api/fuzz/{hex}  → JSON list of typo permutations (dnstwist
                            generators: Bitsquat, Homoglyph, Insertion,
                            Omission, Repetition, Replacement, Subdomain,
                            Transposition, …)

DNSTwister's own /api/ip/ endpoint is broken — returns `ip:false,
error:true` for every domain including known-registered ones. So we
resolve permutations locally via socket.gethostbyname wrapped in
asyncio.to_thread. Bounded parallelism keeps enrich_domain fast.

Design:
  1. Fetch the fuzz list once via DNSTwister.
  2. Take the first N permutations that aren't the seed domain itself.
  3. Resolve each locally in parallel (bounded via a semaphore).
  4. Return the resolving set + summary counts.

Bounded work: default N=15 (a fuzz list can be 200+ entries). Enough to
catch the meaningful hits without turning enrich_domain into a fan-out
of ~30 extra network calls per domain.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any, Dict, Optional

_log = logging.getLogger("recon.intel.dnstwister")

_FUZZ_URL_FMT = "https://dnstwister.report/api/fuzz/{hex}"
_MAX_PERMS_CHECKED = 15
_RESOLVE_TIMEOUT_S = 3.0
# Cap parallel DNS lookups so a fuzzy-domain sweep can't monopolise the
# thread pool or turn into a DoS on the resolver.
_RESOLVE_SEM = asyncio.Semaphore(8)


def _hex_encode(domain: str) -> str:
    return domain.strip().lower().encode("utf-8").hex()


def _resolve_sync(host: str) -> Optional[str]:
    """Blocking DNS A-record lookup with a short timeout. Returns the IP
    string on success, None on NXDOMAIN / SERVFAIL / timeout."""
    if not host:
        return None
    try:
        socket.setdefaulttimeout(_RESOLVE_TIMEOUT_S)
        return socket.gethostbyname(host)
    except Exception:
        return None


async def _resolve(session, entry: Dict[str, Any]) -> Dict[str, Any]:
    """Check whether a single permutation currently resolves to an IP."""
    dom = (entry.get("domain") or "").strip().lower()
    if not dom:
        return {}
    async with _RESOLVE_SEM:
        ip = await asyncio.to_thread(_resolve_sync, dom)
    if not ip:
        return {}
    return {
        "domain":  dom,
        "ip":      ip,
        "fuzzer":  entry.get("fuzzer"),
    }


async def enrich(session, domain: str,
                 max_perms: int = _MAX_PERMS_CHECKED) -> Dict[str, Any]:
    """Return the resolving typo-permutations of `domain`. Empty payload
    when the fuzz endpoint is unreachable or returns no permutations."""
    if not isinstance(domain, str) or "." not in domain:
        return {}
    from agents.enrichment import _get

    hex_d = _hex_encode(domain)
    if not hex_d:
        return {}

    fuzz = await _get(session, _FUZZ_URL_FMT.format(hex=hex_d))
    if not isinstance(fuzz, dict):
        return {}
    if fuzz.get("error"):
        return {"source": "DNSTwister",
                "error":  fuzz.get("error"),
                "error_type": fuzz.get("error_type", "unreachable")}
    entries = fuzz.get("fuzzy_domains") or []
    if not isinstance(entries, list) or not entries:
        return {"source": "DNSTwister", "found": False,
                "summary": f"No permutations returned for {domain}."}

    # Drop the seed row (DNSTwister always includes the queried domain
    # at index 0 with `fuzzer: 'Original*'`).
    perms = [e for e in entries
             if (e.get("domain") or "").lower() != domain.lower()]
    perms = perms[:max_perms]
    if not perms:
        return {"source": "DNSTwister", "found": False,
                "summary": f"No usable permutations for {domain}."}

    results = await asyncio.gather(
        *[_resolve(session, e) for e in perms],
        return_exceptions=True,
    )
    resolving = [r for r in results
                 if isinstance(r, dict) and r.get("domain") and r.get("ip")]

    if not resolving:
        return {
            "source":       "DNSTwister",
            "found":        False,
            "perms_checked": len(perms),
            "summary":      (f"Checked {len(perms)} typo permutations of "
                             f"{domain}, none currently registered."),
        }

    # Actionable finding — someone has registered at least one lookalike.
    fuzzers = sorted({r.get("fuzzer") for r in resolving if r.get("fuzzer")})
    sample  = [f"{r['domain']} → {r['ip']}" for r in resolving[:5]]
    return {
        "source":         "DNSTwister",
        "found":          True,
        "verdict":        "SUSPICIOUS",
        "perms_checked":  len(perms),
        "resolving_count": len(resolving),
        "resolving":      resolving,
        "fuzzers":        fuzzers,
        "summary":        (f"{len(resolving)} of {len(perms)} typo permutations "
                            f"of {domain} are currently registered "
                            f"({', '.join(sample[:3])}"
                            f"{'…' if len(sample) > 3 else ''})."),
    }
