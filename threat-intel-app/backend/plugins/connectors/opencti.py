"""OpenCTI connector - push an analysed artifact + verdict into an
OpenCTI instance as an Observable + Indicator + Note.

RECON already READS from OpenCTI via plugins/analyzers/opencti.py.
This plugin is the WRITE direction - after the analyst confirms an
investigation, the connector records the finding back into OpenCTI so
the organisation's CTI store grows automatically.

Minimum viable integration:
  1. Create (or reuse) a STIX2 Observable for the artifact value.
  2. Create an Indicator with the verdict in the score field.
  3. Attach a Note with RECON's summary + source attribution.

OpenCTI exposes a GraphQL endpoint. We avoid pulling the official
`pycti` client (300+ MB + opinionated connector harness) and talk to
the HTTP endpoint directly with aiohttp - one call per step.

Required config keys:
  OPENCTI_URL     - base URL of the OpenCTI instance (ends with /)
  OPENCTI_TOKEN   - API token (user profile -> API Access)

The export is additive: it never updates verdicts on existing entries.
That's a deliberate trade: analysts should be free to rerun RECON on
the same IOC multiple times without clobbering an earlier curated
score. Downstream OpenCTI users can dedupe by observable value if
they want.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

import aiohttp

from plugins import AnalysisResult, Artifact, Connector, register

_log = logging.getLogger("recon.plugins.connectors.opencti")


# Minimal STIX2 observable type map. OpenCTI accepts the standard
# STIX2 entity_type strings. Any IOC type RECON supports maps here;
# anything unknown short-circuits with a readable error so we never
# push a malformed shape upstream.
_STIX_TYPE_FOR = {
    "ipv4":   "IPv4-Addr",
    "ipv6":   "IPv6-Addr",
    "domain": "Domain-Name",
    "url":    "Url",
    "md5":    "StixFile",
    "sha1":   "StixFile",
    "sha256": "StixFile",
    "email":  "Email-Addr",
    "cve":    "Vulnerability",
}


# Verdict -> OpenCTI score (0 clean, 100 malicious). Matches the way
# the OpenCTI UI colour-codes indicators so analysts eyeball the
# severity on sight.
_SCORE_FOR = {
    "CLEAN":      10,
    "UNKNOWN":    30,
    "SUSPICIOUS": 65,
    "MALICIOUS":  90,
}


class OpenCTIConnector(Connector):
    name = "opencti"
    description = ("Push the analysed artifact + verdict into an OpenCTI "
                   "instance (Observable + Indicator + Note via GraphQL).")
    required_keys = ["OPENCTI_URL", "OPENCTI_TOKEN"]
    homepage = "https://www.opencti.io/"

    async def export(self, artifact: Artifact,
                      results: List[AnalysisResult],
                      keys: Dict[str, str]) -> Dict[str, Any]:
        url_base = (keys.get("OPENCTI_URL") or "").rstrip("/")
        token    = keys.get("OPENCTI_TOKEN") or ""
        if not url_base or not token:
            return {"source": "opencti", "ok": False,
                    "error": "OPENCTI_URL + OPENCTI_TOKEN not configured",
                    "error_type": "missing_key"}

        stix_type = _STIX_TYPE_FOR.get(artifact.type)
        if not stix_type:
            return {"source": "opencti", "ok": False,
                    "error": f"artifact type {artifact.type!r} not supported",
                    "error_type": "unsupported_ioc_type"}

        # Rolled-up summary string from whichever analyzers landed hits.
        found = [r for r in results if r.found and not r.error]
        hit_sources = [r.source for r in found]
        verdicts    = [r.verdict for r in found if r.verdict and r.verdict != "UNKNOWN"]
        # Worst verdict wins (OpenCTI stores a single score per indicator).
        verdict = "UNKNOWN"
        for v in ("MALICIOUS", "SUSPICIOUS", "CLEAN"):
            if v in verdicts:
                verdict = v
                break
        score = _SCORE_FOR.get(verdict, 30)
        summary = (f"RECON investigation: {verdict} "
                   f"({len(found)} sources hit: {', '.join(hit_sources[:8])}"
                   f"{'...' if len(hit_sources) > 8 else ''})")

        gql_url = f"{url_base}/graphql"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
        }

        try:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                obs = await _create_observable(
                    session, gql_url, headers, stix_type, artifact.value,
                )
                if obs.get("error"):
                    return {"source": "opencti", "ok": False, **obs}

                ind = await _create_indicator(
                    session, gql_url, headers, artifact.value, score, summary,
                )
                note = await _attach_note(
                    session, gql_url, headers,
                    obs.get("id"), summary, hit_sources,
                )
        except Exception as e:
            _log.warning("opencti push failed for %s: %s", artifact.value, e)
            return {"source": "opencti", "ok": False,
                    "error": str(e)[:200], "error_type": "unreachable"}

        return {
            "source":        "opencti",
            "ok":            True,
            "observable_id": obs.get("id"),
            "indicator_id":  ind.get("id"),
            "note_id":       note.get("id"),
            "score":         score,
            "verdict":       verdict,
            "sources_hit":   len(hit_sources),
        }


# ─── GraphQL helpers ───────────────────────────────────────────────────────
# Each helper POSTs one mutation and returns a lightweight dict. We
# never raise - callers aggregate failure state via the `error` key.

async def _graphql(session, url: str, headers: Dict[str, str],
                    query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
    body = {"query": query, "variables": variables}
    try:
        async with session.post(url, headers=headers,
                                 data=json.dumps(body)) as r:
            if r.status >= 400:
                text = await r.text()
                return {"error": f"HTTP {r.status}: {text[:160]}",
                        "error_type": "http_error"}
            try:
                return await r.json()
            except Exception:
                return {"error": "non-JSON response",
                        "error_type": "unreachable"}
    except Exception as e:
        return {"error": str(e)[:160], "error_type": "unreachable"}


async def _create_observable(session, url, headers,
                               stix_type: str, value: str) -> Dict[str, Any]:
    """Create (or reuse) a STIX2 observable. `update: true` tells
    OpenCTI to return the existing entity if value+type already match
    rather than raising a uniqueness violation."""
    # OpenCTI's stixCyberObservableAdd mutation. The input shape varies
    # per observable type; we pick the right nested field based on the
    # STIX type.
    field = _observable_input_field(stix_type)
    query = """
    mutation ($type: String!, $value: String!) {
        stixCyberObservableAdd(
            type: $type,
            update: true,
            __INPUT__: { value: $value }
        ) { id, entity_type, observable_value }
    }
    """.replace("__INPUT__", field)
    out = await _graphql(session, url, headers, query, {
        "type": stix_type, "value": value,
    })
    if out.get("error"):
        return out
    data = (out.get("data") or {}).get("stixCyberObservableAdd") or {}
    if not data.get("id"):
        return {"error": f"no id returned: {out}", "error_type": "format_error"}
    return data


def _observable_input_field(stix_type: str) -> str:
    """Map STIX2 type to the GraphQL input-field name OpenCTI expects
    on stixCyberObservableAdd. Fallback to lowercase-hyphen form which
    works for the common entity types."""
    override = {
        "IPv4-Addr":   "IPv4Addr",
        "IPv6-Addr":   "IPv6Addr",
        "Domain-Name": "DomainName",
        "Url":         "Url",
        "StixFile":    "StixFile",
        "Email-Addr":  "EmailAddr",
    }
    return override.get(stix_type, stix_type.replace("-", ""))


async def _create_indicator(session, url, headers, value: str,
                             score: int, summary: str) -> Dict[str, Any]:
    """Create an Indicator attached to the just-created observable.
    Score + description together carry RECON's contribution."""
    query = """
    mutation ($name: String!, $score: Int!, $description: String!) {
        indicatorAdd(input: {
            name: $name,
            pattern: $name,
            pattern_type: "stix",
            x_opencti_score: $score,
            description: $description
        }) { id, name, x_opencti_score }
    }
    """
    out = await _graphql(session, url, headers, query, {
        "name": value, "score": score, "description": summary,
    })
    if out.get("error"):
        return out
    return (out.get("data") or {}).get("indicatorAdd") or {}


async def _attach_note(session, url, headers,
                        observable_id: Optional[str], content: str,
                        sources: List[str]) -> Dict[str, Any]:
    """Attach a Note to the observable capturing which analyzers fired.
    Low-stakes - failure to attach the note is logged but doesn't fail
    the whole export (observable + indicator still landed upstream)."""
    if not observable_id:
        return {}
    note_body = (content + "\n\nAnalyzers that returned hits: "
                 + ", ".join(sources))
    query = """
    mutation ($attribute_abstract: String!, $content: String!, $objects: [String!]) {
        noteAdd(input: {
            attribute_abstract: $attribute_abstract,
            content: $content,
            objects: $objects
        }) { id }
    }
    """
    out = await _graphql(session, url, headers, query, {
        "attribute_abstract": "RECON investigation summary",
        "content":            note_body,
        "objects":            [observable_id],
    })
    if out.get("error"):
        # Non-fatal - log and move on. The observable + indicator are
        # the primary artifacts; the note is enrichment context.
        _log.debug("opencti note attach failed: %s", out)
        return {}
    return (out.get("data") or {}).get("noteAdd") or {}


register(OpenCTIConnector)
