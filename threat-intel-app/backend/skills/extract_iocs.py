"""
ExtractIOCsSkill — regex-based IOC extraction with optional MISP warning-
list filtering. No LLM required; this is the first stage of the triage
pipeline ported into a self-contained skill.

Input  : raw_text (str)
Output : ips, domains, hashes, urls, emails (lists)
         suppressed_iocs (dict of type -> [{value, reason}]) when
         MISP warninglist data is available
         total (int sum across all extracted types)
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from providers.base import LLMProvider

import ipaddress

from .base import Skill


# Patterns mirror agents/triage.py — kept in sync so callers get identical
# behaviour whether they hit the legacy agent or the skill.
_RE_IPV4   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# IPv6 candidate matcher — kept in sync with agents/triage._IPV6_CANDIDATE_RE.
# Alternation order matters (trailing :: comes LAST) so the regex engine
# tries longer compressed-with-suffix forms before falling back to the
# prefix-only trailing-:: branch.
_RE_IPV6_CANDIDATE = re.compile(
    r"\b(?:"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})"
    r"|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|::"
    r")\b"
)
_RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,24})\b",
    re.IGNORECASE,
)
_RE_URL    = re.compile(r"\bhttps?://[^\s<>'\"`]+", re.IGNORECASE)
_RE_EMAIL  = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_RE_MD5    = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
_RE_SHA1   = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
_RE_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)


def _noise_ip(ip: str) -> bool:
    # Loopback / unspecified / link-local / multicast / reserved — works for
    # both v4 and v6 via the stdlib `ipaddress` module.
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (a.is_loopback or a.is_unspecified or a.is_link_local
            or a.is_multicast or a.is_reserved or a.is_private)


def _valid_ipv4_octets(ip: str) -> bool:
    """Explicit IPv4 octet validation: every octet must be 0-255. Defender
    Security Intelligence Version strings ("AV: 1.451.195.0") match the
    dotted-quad regex but are not IPs — their second octet exceeds 255."""
    if not ip or ":" in ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or int(p) > 255:
            return False
    return True


# Microsoft Defender Event ID 1116/1117 emits Security Intelligence and
# Engine version strings shaped like dotted-quads. Strip them before regex
# extraction so they never become IOC candidates. Kept in sync with
# agents/triage._DEFENDER_VERSION_RE.
_DEFENDER_VERSION_RE = re.compile(
    r"\b(?:AV|AS|NIS|AM|AntiSpyware|AntiVirus|Engine|"
    r"Security\s+Intelligence|Anti(?:malware|spyware|virus))\s+"
    r"(?:Version|Signature\s+Version)?\s*:\s*"
    r"\d{1,5}(?:\.\d{1,5}){2,3}",
    re.IGNORECASE,
)
_DEFENDER_AV_KV_RE = re.compile(
    r"\b(?:AV|AS|NIS|AM)\s*:\s*\d{1,5}(?:\.\d{1,5}){2,3}\b",
)


def _strip_defender_versions(text: str) -> str:
    if not text:
        return text
    text = _DEFENDER_VERSION_RE.sub(" ", text)
    text = _DEFENDER_AV_KV_RE.sub(" ", text)
    return text


def _extract_ipv6(text: str) -> set:
    """Pull IPv6 addresses out of text and normalise through
    ipaddress.ip_address(). Drops regex-prefix substrings (when both
    '2606:4700::' and '2606:4700::1111' match, only the longer survives —
    the shorter is a regex artefact of the trailing-:: branch)."""
    raw = []
    for cand in _RE_IPV6_CANDIDATE.findall(text or ""):
        try:
            raw.append((cand, str(ipaddress.ip_address(cand))))
        except ValueError:
            pass
    out = set()
    for r, norm in raw:
        if any(r != other and r in other for other, _ in raw):
            continue
        out.add(norm)
    return out


def _noise_domain(d: str) -> bool:
    d = d.lower()
    return (
        d.endswith((".local", ".lan", ".internal", ".corp"))
        or d in ("localhost",)
    )


class ExtractIOCsSkill(Skill):
    @property
    def name(self) -> str:
        return "extract_iocs"

    @property
    def description(self) -> str:
        return ("Regex-extract IPs, domains, hashes, URLs, and emails from raw "
                "text. Optionally filters via MISP warninglists when available.")

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {"raw_text": "str"}

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "ips":             "list[str]",
            "domains":         "list[str]",
            "hashes":          "list[str]",
            "urls":            "list[str]",
            "emails":          "list[str]",
            "suppressed_iocs": "dict",
            "total":           "int",
        }

    @property
    def test_input(self) -> Dict[str, Any]:
        return {
            "raw_text": (
                "Alert: host WORKSTATION-04 reported powershell.exe activity. "
                "Source IP 185.220.101.45 connected to update-service.xyz "
                "and downloaded SHA256 "
                "3395856ce81f2b7382dee72602f798b642f14140abcdef0123456789abcdef01. "
                "User jsmith@contoso.com filed the ticket."
            ),
        }

    async def execute(
        self,
        inputs:   Dict[str, Any],
        provider: Optional[LLMProvider] = None,
    ) -> Dict[str, Any]:
        raw = (inputs or {}).get("raw_text") or ""
        if not isinstance(raw, str):
            raw = str(raw)

        # Scrub Defender version strings before any IPv4 regex match.
        raw = _strip_defender_versions(raw)

        ips     = sorted({m for m in _RE_IPV4.findall(raw)
                            if _valid_ipv4_octets(m) and not _noise_ip(m)} |
                         {m for m in _extract_ipv6(raw) if not _noise_ip(m)})
        domains = sorted({m for m in _RE_DOMAIN.findall(raw) if not _noise_domain(m)})
        urls    = sorted(set(_RE_URL.findall(raw)))
        emails  = sorted({m.lower() for m in _RE_EMAIL.findall(raw)})
        hashes  = sorted({
            *(m.lower() for m in _RE_SHA256.findall(raw)),
            *(m.lower() for m in _RE_SHA1.findall(raw)),
            *(m.lower() for m in _RE_MD5.findall(raw)),
        })

        # MISP warninglist filtering — fail open if the module isn't wired up,
        # we just return zero suppressed entries.
        suppressed: Dict[str, List[Dict[str, str]]] = {
            "ips": [], "domains": [], "urls": [], "emails": [], "hashes": [],
        }
        try:
            from intel.warninglist_filter import filter_iocs  # type: ignore
            kept, supp = filter_iocs({
                "ips": ips, "domains": domains, "urls": urls,
                "emails": emails, "hashes": hashes,
            })
            ips     = kept.get("ips", ips)
            domains = kept.get("domains", domains)
            urls    = kept.get("urls", urls)
            emails  = kept.get("emails", emails)
            hashes  = kept.get("hashes", hashes)
            suppressed = supp or suppressed
        except Exception:
            pass

        total = len(ips) + len(domains) + len(hashes) + len(urls) + len(emails)
        return {
            "ips":             ips,
            "domains":         domains,
            "hashes":          hashes,
            "urls":            urls,
            "emails":          emails,
            "suppressed_iocs": suppressed,
            "total":           total,
        }
