"""
Plugin registry — the central lookup for every registered plugin.

The registry is populated at import time via two paths:
  1. Auto-discovery: `discover()` walks plugins/analyzers, plugins/
     connectors, etc. and imports every .py module in those dirs.
     Each module calls `@register` at module scope, which lands its
     class instance in the registry.
  2. Legacy registration: plugins/analyzers/_legacy_registrations.py
     builds LegacyAnalyzerAdapter instances for existing intel/*.py
     modules and registers them explicitly.

Lookups:
  registry.all()              — every registered plugin
  registry.get(name)          — by name
  registry.by_kind(kind)      — all plugins of one kind
  registry.analyzers_for(t)   — analyzers that support IOC type t
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from typing import Dict, List, Optional

from .base import Analyzer, Connector, Ingestor, Pivot, Playbook, Plugin, Visualizer
from .data_models import IOCType, PluginDescriptor, PluginKind

_log = logging.getLogger("recon.plugins.registry")


# ─── Internal state ────────────────────────────────────────────────────────

_by_name: Dict[str, Plugin] = {}
_discovered: bool = False


# ─── Public API ────────────────────────────────────────────────────────────

def register(plugin: Plugin) -> Plugin:
    """Add a plugin instance to the registry. Also usable as a
    decorator over a plugin class — in which case we instantiate it
    with no args and register the instance."""
    if isinstance(plugin, type):  # used as decorator over the class
        instance = plugin()
    else:
        instance = plugin
    if not getattr(instance, "name", ""):
        raise ValueError(f"Plugin {instance.__class__.__name__} has no .name")
    if instance.name in _by_name:
        _log.warning("Plugin %r already registered — overwriting", instance.name)
    _by_name[instance.name] = instance
    return instance


def discover() -> None:
    """Walk plugin subpackages and import every module so each
    module-level @register call fires. Idempotent — subsequent calls
    are no-ops."""
    global _discovered
    if _discovered:
        return
    _discovered = True
    # Import this package first so plugins can import siblings
    import plugins  # noqa: F401
    for subpkg_name in ("analyzers", "connectors", "pivots",
                         "visualizers", "ingestors", "playbooks"):
        try:
            subpkg = importlib.import_module(f"plugins.{subpkg_name}")
        except ModuleNotFoundError:
            continue
        for mod_info in pkgutil.iter_modules(subpkg.__path__):
            if mod_info.name.startswith("_"):
                # _legacy_registrations.py imports last so analyzers
                # discovered via files come first.
                continue
            try:
                importlib.import_module(f"plugins.{subpkg_name}.{mod_info.name}")
            except Exception as e:
                _log.warning("Failed to import plugins.%s.%s: %s",
                             subpkg_name, mod_info.name, e)
        # Now import the _legacy_registrations module last if present
        try:
            importlib.import_module(f"plugins.{subpkg_name}._legacy_registrations")
        except ModuleNotFoundError:
            pass
        except Exception as e:
            _log.warning("Failed to load _legacy_registrations for %s: %s",
                         subpkg_name, e)


def all() -> List[Plugin]:
    discover()
    return list(_by_name.values())


def get(name: str) -> Optional[Plugin]:
    discover()
    return _by_name.get(name)


def by_kind(kind: PluginKind) -> List[Plugin]:
    discover()
    return [p for p in _by_name.values() if p.kind == kind]


def analyzers() -> List[Analyzer]:
    discover()
    return [p for p in _by_name.values() if isinstance(p, Analyzer)]


def analyzers_for(ioc_type: IOCType) -> List[Analyzer]:
    """All analyzers that advertise support for `ioc_type`."""
    return [a for a in analyzers() if ioc_type in a.supported_ioc_types]


def connectors() -> List[Connector]:
    discover()
    return [p for p in _by_name.values() if isinstance(p, Connector)]


def pivots() -> List[Pivot]:
    discover()
    return [p for p in _by_name.values() if isinstance(p, Pivot)]


def visualizers() -> List[Visualizer]:
    discover()
    return [p for p in _by_name.values() if isinstance(p, Visualizer)]


def ingestors() -> List[Ingestor]:
    discover()
    return [p for p in _by_name.values() if isinstance(p, Ingestor)]


def playbooks() -> List[Playbook]:
    discover()
    return [p for p in _by_name.values() if isinstance(p, Playbook)]


def descriptors() -> List[PluginDescriptor]:
    """Serialisable catalog — what /api/plugins returns."""
    return [p.descriptor() for p in all()]
