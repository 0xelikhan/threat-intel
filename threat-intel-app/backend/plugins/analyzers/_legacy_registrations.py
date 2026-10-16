"""Legacy analyzer registrations (drained).

Historically this file wrapped ~50 existing `intel/*.py` modules in
`LegacyAnalyzerAdapter` instances so the plugin registry could surface
them without a per-source migration. All of those entries have since
been promoted to formal `Analyzer` subclasses — one file per source
under this directory (see e.g. `robtex.py`, `urlhaus.py`, `shodan.py`).

The adapter class itself (`plugins.base.LegacyAnalyzerAdapter`) is
still available for anyone who wants to quickly wire a new simple-
pattern intel/* module without creating a dedicated plugin file.
Just construct one and call `plugins.registry.register(adapter)`.

The one-shot generator that produced the formal files lives next
to this one (`_generate_from_legacy.py`) and can be rerun if the
legacy table ever grows again — it skips files that already exist.
"""

from __future__ import annotations

# Intentionally empty — see docstring. Discovery still imports this
# module last to preserve ordering, so leaving it present as a no-op
# avoids a ModuleNotFoundError warning on first boot.
