"""
RECON plugin framework.

Formalises IntelOwl's 9 plugin component types (analyzers, connectors,
pivots, visualizers, ingestors, playbooks, data models, artifacts,
user events) so new sources + output integrations have a stable
interface instead of being hand-wired into agents/enrichment.py.

Entry points:
  from plugins import registry
  registry.descriptors()         # catalog for /api/plugins
  registry.analyzers_for('ipv4') # analyzers supporting IPs

Plugin authors subclass one of plugins.base.{Analyzer, Connector,
Pivot, Visualizer, Ingestor, Playbook} and call `plugins.registry.
register(ClassName)` at module scope.

Existing intel/*.py modules are exposed via LegacyAnalyzerAdapter —
see plugins/analyzers/_legacy_registrations.py for the wrap table.
"""

from __future__ import annotations

from . import base, data_models, registry
from .base import (
    Analyzer, Connector, FileAnalyzer, Ingestor, LegacyAnalyzerAdapter,
    Pivot, Playbook, Plugin, Visualizer,
)
from .data_models import (
    AnalysisResult, Artifact, IOCType, PluginDescriptor, UserEvent, Verdict,
)
from .registry import register

__all__ = [
    "base", "data_models", "registry",
    "Analyzer", "Connector", "FileAnalyzer", "Ingestor",
    "LegacyAnalyzerAdapter", "Pivot", "Playbook", "Plugin", "Visualizer",
    "AnalysisResult", "Artifact", "IOCType", "PluginDescriptor",
    "UserEvent", "Verdict", "register",
]
