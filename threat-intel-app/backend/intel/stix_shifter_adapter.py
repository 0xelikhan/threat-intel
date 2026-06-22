"""
STIX-Shifter pattern translation adapter.

stix-shifter (https://github.com/opencybersecurityalliance/stix-shifter,
Apache-2.0) is IBM's library for translating STIX 2.0/2.1 patterns into
native SIEM query languages. Targets supported by mainline stix-shifter
modules include Splunk SPL, IBM QRadar AQL, Microsoft Sentinel KQL,
Elastic Lucene/EQL, ArcSight ESM, CrowdStrike Falcon FQL, Carbon Black
EDR, Datadog Cloud SIEM, and many more.

This module exposes a thin wrapper:

  translate_pattern(stix_pattern, target_module="splunk") -> str

When stix-shifter isn't installed, we fall back to a built-in
hand-written translator covering the most common STIX 2.1 comparison
operators for Splunk SPL + KQL — enough to give the analyst a starting
query without forcing the full ~150MB stix-shifter dependency.

The function consumed by /api/export/stix-shifter accepts either a
single pattern string OR a STIX bundle (in which case every indicator's
pattern is translated and concatenated with `OR`).
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.intel.stix_shifter")


# Supported native target dialects via the built-in fallback. The
# stix-shifter library itself ships ~50 modules; we list only the ones
# RECON tests against here.
SUPPORTED_TARGETS = {
    "splunk":           "Splunk SPL",
    "kql":              "Microsoft Sentinel / Defender KQL",
    "qradar":           "IBM QRadar AQL",
    "elastic_ecs":      "Elastic ECS Lucene",
    "crowdstrike":      "CrowdStrike Falcon FQL",
}


# --- Built-in fallback translator -------------------------------------------
# STIX 2.1 patterns are object-path comparisons grouped by [...] braces.
# We support the high-traffic shapes:
#   [ipv4-addr:value = '1.2.3.4']
#   [domain-name:value = 'evil.com']
#   [url:value = 'http://...']
#   [file:hashes.MD5 = '...']
#   [file:hashes.'SHA-1' = '...']
#   [file:hashes.'SHA-256' = '...']
#   [email-addr:value = '...']
# Combined via OR/AND. We extract every object-path comparison and emit
# the equivalent native filter.

_OBJECT_PATH_RE = re.compile(
    r"(?P<type>[a-z0-9_\-]+):(?P<path>[\w'\.\[\]\-]+)\s*"
    r"(?P<op>=|!=|MATCHES|LIKE|IN|NOT IN)\s*"
    r"(?P<value>'[^']*'|\[[^\]]*\])",
    re.IGNORECASE,
)


def _splunk_field(stix_type: str, path: str) -> str:
    """Map a STIX (type, path) to a Splunk field name."""
    if stix_type == "ipv4-addr" and path == "value":
        return "src_ip OR dest_ip"
    if stix_type == "ipv6-addr" and path == "value":
        return "src_ipv6 OR dest_ipv6"
    if stix_type == "domain-name" and path == "value":
        return "query OR dest_host"
    if stix_type == "url" and path == "value":
        return "url"
    if stix_type == "email-addr" and path == "value":
        return "sender_email OR recipient_email"
    if stix_type == "file" and path.lower().startswith("hashes"):
        # hashes.MD5 / hashes.'SHA-1' / hashes.'SHA-256'
        if "md5" in path.lower():       return "file_hash_md5"
        if "sha-1" in path.lower():     return "file_hash_sha1"
        if "sha-256" in path.lower():   return "file_hash_sha256"
        return "file_hash"
    if stix_type == "process" and path == "command_line":
        return "process_command_line"
    return f"{stix_type}_{path}".replace(".", "_").replace("'", "")


def _kql_field(stix_type: str, path: str) -> str:
    """Map a STIX (type, path) to a Sentinel KQL field name (Defender XDR
    Advanced Hunting schema where possible)."""
    if stix_type == "ipv4-addr" and path == "value":
        return "RemoteIP"
    if stix_type == "domain-name" and path == "value":
        return "RemoteUrl"
    if stix_type == "url" and path == "value":
        return "Url"
    if stix_type == "email-addr" and path == "value":
        return "SenderFromAddress"
    if stix_type == "file" and path.lower().startswith("hashes"):
        if "md5" in path.lower():     return "MD5"
        if "sha-1" in path.lower():   return "SHA1"
        if "sha-256" in path.lower(): return "SHA256"
        return "FileHash"
    return f"{stix_type}_{path}".replace(".", "_").replace("'", "")


def _to_splunk(matches: List[Dict[str, str]]) -> str:
    """Convert extracted (type, path, op, value) tuples to an SPL query."""
    if not matches:
        return ""
    terms: List[str] = []
    for m in matches:
        field = _splunk_field(m["type"], m["path"])
        value = m["value"].strip("'\"")
        if " OR " in field:
            sub = " OR ".join(f"{f}=\"{value}\"" for f in field.split(" OR "))
            terms.append(f"({sub})")
        else:
            terms.append(f"{field}=\"{value}\"")
    return "search " + " OR ".join(terms)


def _to_kql(matches: List[Dict[str, str]]) -> str:
    if not matches:
        return ""
    terms: List[str] = []
    for m in matches:
        field = _kql_field(m["type"], m["path"])
        value = m["value"].strip("'\"")
        op = "==" if m["op"] == "=" else m["op"]
        terms.append(f'{field} {op} "{value}"')
    return "// Auto-generated from STIX pattern\n" \
           "union DeviceNetworkEvents, EmailEvents, DeviceFileEvents\n" \
           f"| where {' or '.join(terms)}"


def _to_qradar(matches: List[Dict[str, str]]) -> str:
    if not matches:
        return ""
    terms: List[str] = []
    for m in matches:
        if m["type"] == "ipv4-addr":
            terms.append(f'(sourceip = \'{m["value"].strip(chr(39))}\' or '
                          f'destinationip = \'{m["value"].strip(chr(39))}\')')
        elif m["type"] == "domain-name":
            terms.append(f'"URL Host" = \'{m["value"].strip(chr(39))}\'')
        elif m["type"] == "url":
            terms.append(f'url = \'{m["value"].strip(chr(39))}\'')
        elif m["type"] == "file":
            terms.append(f'"File Hash" = \'{m["value"].strip(chr(39))}\'')
    return "SELECT * FROM events WHERE " + " OR ".join(terms) if terms else ""


def _to_elastic(matches: List[Dict[str, str]]) -> str:
    if not matches:
        return ""
    terms: List[str] = []
    for m in matches:
        value = m["value"].strip("'\"")
        if m["type"] == "ipv4-addr":
            terms.append(f'(source.ip:"{value}" OR destination.ip:"{value}")')
        elif m["type"] == "domain-name":
            terms.append(f'(dns.question.name:"{value}" OR destination.domain:"{value}")')
        elif m["type"] == "url":
            terms.append(f'url.full:"{value}"')
        elif m["type"] == "file":
            field = "file.hash.sha256" if "sha-256" in m["path"].lower() else \
                    "file.hash.sha1"   if "sha-1"   in m["path"].lower() else \
                    "file.hash.md5"
            terms.append(f'{field}:"{value}"')
    return " OR ".join(terms)


def _to_crowdstrike(matches: List[Dict[str, str]]) -> str:
    """Falcon FQL — a SQL-like dialect."""
    if not matches:
        return ""
    terms: List[str] = []
    for m in matches:
        value = m["value"].strip("'\"")
        if m["type"] == "ipv4-addr":
            terms.append(f"RemoteAddressIP4:'{value}'")
        elif m["type"] == "domain-name":
            terms.append(f"DomainName:'{value}'")
        elif m["type"] == "file" and "sha-256" in m["path"].lower():
            terms.append(f"SHA256HashData:'{value}'")
    return " | ".join(terms)


_DIALECT_HANDLERS = {
    "splunk":      _to_splunk,
    "kql":         _to_kql,
    "qradar":      _to_qradar,
    "elastic_ecs": _to_elastic,
    "crowdstrike": _to_crowdstrike,
}


def _extract_matches(pattern: str) -> List[Dict[str, str]]:
    """Parse a single STIX pattern into a list of (type, path, op, value)
    matches. Discards the logical structure (AND/OR) — the dialect
    handlers all default to OR-joining."""
    out: List[Dict[str, str]] = []
    for m in _OBJECT_PATH_RE.finditer(pattern or ""):
        out.append({
            "type":  m.group("type").lower(),
            "path":  m.group("path"),
            "op":    m.group("op").upper(),
            "value": m.group("value"),
        })
    return out


def translate_pattern(pattern: str,
                       target: str = "splunk") -> Dict[str, Any]:
    """Translate a single STIX pattern string into a native query.

    Returns:
      {ok, target, query, source, error}
    """
    target = (target or "splunk").lower()
    if target not in _DIALECT_HANDLERS:
        return {"ok": False,
                "error": f"unknown target '{target}'; supported: "
                          f"{', '.join(sorted(SUPPORTED_TARGETS.keys()))}",
                "error_code": "unknown_target"}

    matches = _extract_matches(pattern)
    if not matches:
        return {"ok": False, "error": "no object-path matches in pattern",
                "error_code": "empty_pattern"}

    query = _DIALECT_HANDLERS[target](matches)
    return {
        "ok":     True,
        "target": target,
        "label":  SUPPORTED_TARGETS[target],
        "query":  query,
        "source": "recon-builtin",
        "match_count": len(matches),
    }


def translate_bundle(bundle: Dict[str, Any],
                     target: str = "splunk") -> Dict[str, Any]:
    """Translate every indicator pattern in a STIX bundle into a single
    native query (OR-joined). Returns the same shape as translate_pattern."""
    if not isinstance(bundle, dict):
        return {"ok": False, "error": "not a STIX bundle",
                "error_code": "bad_input"}
    patterns: List[str] = []
    for obj in (bundle.get("objects") or []):
        if isinstance(obj, dict) and obj.get("type") == "indicator":
            p = obj.get("pattern")
            if isinstance(p, str):
                patterns.append(p)
    if not patterns:
        return {"ok": False, "error": "bundle has no indicators",
                "error_code": "empty_bundle"}
    combined = " OR ".join(patterns)
    out = translate_pattern(combined, target=target)
    if out.get("ok"):
        out["pattern_count"] = len(patterns)
    return out


def is_stix_shifter_available() -> bool:
    """Probe whether the heavy stix-shifter library is installed. When
    True, the operator can switch to the upstream translator via a
    settings toggle; otherwise the built-in fallback is used."""
    try:
        import stix_shifter  # noqa: F401
        return True
    except Exception:
        return False
