"""
Abstract base classes for RECON plugins.

RECON formalises IntelOwl's 9 plugin component types:
  1. Analyzer   — enrich an IOC from an external or internal source
  2. Connector  — export analysis to another platform (MISP, TheHive, …)
  3. Pivot      — chain analyses together (URL → sandbox hashes → VT)
  4. Visualizer — frontend-render-hint for an analyzer's output shape
  5. Ingestor   — stream observables / files INTO the analysis queue
  6. Playbook   — repeatable sequence of plugin invocations
  7. DataModel  — in data_models.py (shared schema)
  8. Artifact   — in data_models.py (the thing being analysed)
  9. UserEvent  — in data_models.py (analyst-added annotations)

All plugins register themselves by subclassing one of these ABCs and
calling @register (see registry.py). The registry discovers plugins
by walking the plugins/ subpackages on startup.

Existing intel/*.py modules keep working — the registry treats them
as "legacy analyzers" via LegacyAnalyzerAdapter until each is migrated
to a formal Analyzer subclass.
"""

from __future__ import annotations

import abc
from typing import Any, AsyncIterator, Dict, List, Optional

from .data_models import (
    AnalysisResult, Artifact, IOCType, PluginDescriptor, PluginKind,
)


# ─── Base Plugin ────────────────────────────────────────────────────────────

class Plugin(abc.ABC):
    """Common interface for every plugin kind. Subclasses declare their
    `kind` and `name` as class attributes; the registry reads these to
    build the catalog."""

    name: str = ""                       # e.g. "virustotal"
    kind: PluginKind                     # set by each specialisation
    description: str = ""
    enabled: bool = True
    homepage: Optional[str] = None
    free_tier: Optional[str] = None
    required_keys: List[str] = []        # config.py entries that MUST be set
    optional_keys: List[str] = []        # entries that enhance behaviour

    def descriptor(self) -> PluginDescriptor:
        return PluginDescriptor(
            name=self.name,
            kind=self.kind,
            description=self.description,
            enabled=self.enabled,
            supported_ioc_types=getattr(self, "supported_ioc_types", []),
            required_keys=self.required_keys,
            optional_keys=self.optional_keys,
            homepage=self.homepage,
            free_tier=self.free_tier,
        )


# ─── Analyzer ──────────────────────────────────────────────────────────────

class Analyzer(Plugin):
    """Enrich a single IOC. Called by run_enrichment orchestrator for
    every IOC bucket the analyzer supports."""

    kind: PluginKind = "analyzer"
    supported_ioc_types: List[IOCType] = []

    @abc.abstractmethod
    async def analyze(self, session, ioc_type: IOCType, value: str,
                       keys: Dict[str, str]) -> AnalysisResult:
        ...


# ─── Connector ─────────────────────────────────────────────────────────────

class Connector(Plugin):
    """Export completed analysis to an external platform."""

    kind: PluginKind = "connector"

    @abc.abstractmethod
    async def export(self, artifact: Artifact,
                      results: List[AnalysisResult],
                      keys: Dict[str, str]) -> Dict[str, Any]:
        ...


# ─── Pivot ─────────────────────────────────────────────────────────────────

class Pivot(Plugin):
    """Watch for conditions in an analysis result that should trigger
    follow-on analyses on OTHER IOCs. E.g.: sandbox report → extract
    the dropped-hashes list → queue each hash for enrichment."""

    kind: PluginKind = "pivot"

    @abc.abstractmethod
    async def should_pivot(self, result: AnalysisResult) -> bool:
        ...

    @abc.abstractmethod
    async def extract_pivot_iocs(self, result: AnalysisResult) -> List[Dict[str, str]]:
        """Return a list of {'type': 'sha256', 'value': '...'} dicts
        that the orchestrator will add to the enrichment queue."""
        ...


# ─── Visualizer ────────────────────────────────────────────────────────────

class Visualizer(Plugin):
    """Describe how the frontend should render a given analyzer's
    output. Returns a declarative hint (card type, which fields to
    highlight) — the actual React component lives in the frontend."""

    kind: PluginKind = "visualizer"
    supported_sources: List[str] = []    # analyzer names it visualises

    @abc.abstractmethod
    def to_component_hint(self, result: AnalysisResult) -> Dict[str, Any]:
        ...


# ─── Ingestor ──────────────────────────────────────────────────────────────

class Ingestor(Plugin):
    """Stream IOCs / files from a feed into the enrichment queue.
    Called on a schedule or on-demand; yields IOC dicts the orchestrator
    picks up."""

    kind: PluginKind = "ingestor"
    interval_seconds: int = 300

    @abc.abstractmethod
    async def poll(self, session) -> AsyncIterator[Dict[str, Any]]:
        ...


# ─── Playbook ──────────────────────────────────────────────────────────────

class Playbook(Plugin):
    """Repeatable sequence of plugin invocations. Think: 'for every
    suspicious IP, run AbuseIPDB → GreyNoise → VT → OTX, then export
    to TheHive if verdict is MALICIOUS'. The orchestrator in main.py
    executes playbooks step-by-step."""

    kind: PluginKind = "playbook"
    steps: List[Dict[str, Any]] = []     # [{'plugin': 'virustotal', 'when': 'always'}, ...]

    @abc.abstractmethod
    async def execute(self, session, artifact: Artifact,
                       keys: Dict[str, str]) -> Dict[str, Any]:
        ...


# ─── Legacy adapter ────────────────────────────────────────────────────────

class LegacyAnalyzerAdapter(Analyzer):
    """Wraps an existing `intel/*.py` module (`async def lookup(session,
    ioc, ...)` returning the legacy dict shape) in the formal Analyzer
    interface. Lets the registry expose every pre-plugin-era source
    through the new interface without rewriting all 148 modules at once.

    Build one of these per legacy module; the registry discovers them
    via plugins/analyzers/_legacy_registrations.py (one entry per
    legacy module to wrap)."""

    def __init__(self, *, name: str, description: str,
                  supported_ioc_types: List[IOCType],
                  module_import_path: str,
                  lookup_fn_name: str = "lookup",
                  required_keys: Optional[List[str]] = None,
                  optional_keys: Optional[List[str]] = None,
                  homepage: Optional[str] = None,
                  free_tier: Optional[str] = None):
        self.name = name
        self.description = description
        self.supported_ioc_types = supported_ioc_types
        self._module_import_path = module_import_path
        self._lookup_fn_name = lookup_fn_name
        self.required_keys = required_keys or []
        self.optional_keys = optional_keys or []
        self.homepage = homepage
        self.free_tier = free_tier

    async def analyze(self, session, ioc_type, value, keys):
        import importlib
        try:
            mod = importlib.import_module(self._module_import_path)
            fn = getattr(mod, self._lookup_fn_name)
        except Exception as e:
            return AnalysisResult(
                source=self.name, ioc_type=ioc_type, ioc_value=value,
                found=False, error=f"import failed: {e}",
                error_type="unavailable",
            )
        # Pass the first required/optional key as the second positional
        # arg if present (matches most intel/*.py signatures: lookup(
        # session, ioc, api_key="")).
        key = ""
        for k in (self.required_keys + self.optional_keys):
            if keys.get(k):
                key = keys[k]
                break
        try:
            if key:
                raw = await fn(session, value, key)
            else:
                raw = await fn(session, value)
        except Exception as e:
            return AnalysisResult(
                source=self.name, ioc_type=ioc_type, ioc_value=value,
                found=False, error=str(e)[:120], error_type="unreachable",
            )
        return AnalysisResult.from_legacy_dict(
            raw if isinstance(raw, dict) else {}, ioc_type, value,
        )
