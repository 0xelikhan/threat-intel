"""
Common schema for every plugin result.

Analyzers / connectors / pivots / visualizers / ingestors / playbooks
all produce or consume one of these shapes. Keeping them in a single
module means the frontend can key off a single TypeScript union, and
regression tests have a single source of truth to assert against.

Modelled after IntelOwl's data_model_manager (observable + file
analyzer unified schema) but trimmed to what RECON actually needs:
no multi-tenant / RBAC fields, no job queue state.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


# ─── Enums ──────────────────────────────────────────────────────────────────

IOCType = Literal[
    "ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256",
    "email", "cve", "crypto", "phone", "file",
]

Verdict = Literal["CLEAN", "UNKNOWN", "SUSPICIOUS", "MALICIOUS"]

PluginKind = Literal[
    "analyzer", "file_analyzer", "connector", "pivot", "visualizer",
    "ingestor", "playbook",
]


# ─── Artifact — the thing being analysed ────────────────────────────────────

class Artifact(BaseModel):
    """A representation of an IOC or file that can be analysed multiple
    times. IntelOwl's `artifacts` concept — the stable handle a user
    event can attach to."""
    id: str                              # stable ID (sha256 of value+type)
    type: IOCType
    value: str
    sha256: Optional[str] = None         # for file artifacts
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_analyzed: Optional[datetime] = None
    tags: List[str] = Field(default_factory=list)


# ─── UserEvent — human annotation attached to an artifact ───────────────────

class UserEvent(BaseModel):
    """Analyst-added evaluation on an artifact. Think: 'this is actually
    a false positive, our dev team runs that scanner', or 'confirmed C2
    from campaign X'. IntelOwl's `user_events` concept."""
    artifact_id: str
    author: str
    kind: Literal["note", "verdict_override", "tag", "false_positive",
                  "confirmed_malicious"]
    content: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ─── AnalysisResult — unified analyzer output ──────────────────────────────

class AnalysisResult(BaseModel):
    """What every analyzer returns. Matches the dict shape the existing
    intel/*.py modules already produce (source / verdict / summary /
    details_url / found) so the migration is a wrapping job, not a
    rewrite."""
    source: str                          # e.g. "virustotal", "abuseipdb"
    ioc_type: IOCType
    ioc_value: str
    found: bool = True
    verdict: Verdict = "UNKNOWN"
    summary: str = ""
    details_url: Optional[str] = None
    error: Optional[str] = None
    error_type: Optional[str] = None
    enriched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Source-specific fields go here. Keeping them in a sub-dict rather
    # than at the top level means the schema stays stable even as new
    # analyzers add arbitrary fields.
    raw: Dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_legacy_dict(cls, d: Dict[str, Any], ioc_type: IOCType,
                          ioc_value: str) -> "AnalysisResult":
        """Wrap a legacy intel/*.py return dict into the formal schema.
        Used by the compatibility layer so new consumers can read every
        existing module via a single interface.

        `found` semantics (surprising-but-important):
          * Explicit `found` key present  → use it as-is
          * Error present                 → found=False
          * Dict is empty / None          → found=False  (upstream returned
            no data — bare dict with no fields means "nothing to say";
            many legacy modules short-circuit to None on no-data and the
            caller wraps as {} before passing here)
          * Dict has content, no error    → found=True
        """
        legacy = d or {}
        reserved = {"source", "found", "verdict", "summary",
                     "details_url", "error", "error_type"}
        raw = {k: v for k, v in legacy.items() if k not in reserved}
        has_error = bool(legacy.get("error"))
        if "found" in legacy:
            found_val = bool(legacy["found"]) and not has_error
        else:
            # Empty / error-only / no-content dicts are not-found;
            # anything with real fields counts as a hit.
            found_val = bool(raw) and not has_error
        return cls(
            source=str(legacy.get("source") or "unknown"),
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            found=found_val,
            verdict=legacy.get("verdict") or "UNKNOWN",
            summary=str(legacy.get("summary") or ""),
            details_url=legacy.get("details_url"),
            error=legacy.get("error"),
            error_type=legacy.get("error_type"),
            raw=raw,
        )


# ─── PluginDescriptor — registry metadata ──────────────────────────────────

class PluginDescriptor(BaseModel):
    """What the plugin registry exposes about each registered plugin.
    Powers the /api/plugins endpoint + the frontend Settings panel's
    'enabled plugins' switches."""
    name: str
    kind: PluginKind
    description: str
    enabled: bool = True
    supported_ioc_types: List[IOCType] = Field(default_factory=list)
    required_keys: List[str] = Field(default_factory=list)
    optional_keys: List[str] = Field(default_factory=list)
    homepage: Optional[str] = None
    free_tier: Optional[str] = None      # e.g. "500 req/day"
