"""MISP connector — push an analysed artifact + its enrichment into
a MISP event.

Wraps intel/misp_push.py in the formal Connector interface. The old
module remains callable directly from main.py; this plugin surfaces
it in the registry (/api/plugins → connectors).
"""

from __future__ import annotations

from typing import Any, Dict, List

from plugins import AnalysisResult, Artifact, Connector, register


class MISPConnector(Connector):
    name = "misp"
    description = ("Push the analysed artifact + aggregated analyser results "
                   "into a MISP event. Uses the configured MISP_URL + MISP_KEY.")
    required_keys = ["MISP_URL", "MISP_KEY"]
    homepage = "https://www.misp-project.org/"

    async def export(self, artifact: Artifact,
                      results: List[AnalysisResult],
                      keys: Dict[str, str]) -> Dict[str, Any]:
        try:
            from intel.misp_push import push_artifact as _push
        except Exception as e:
            return {"source": "misp", "ok": False,
                    "error": f"intel.misp_push unavailable: {e}"}
        try:
            # Pass the artifact + the raw dict-shaped results so misp_push
            # can keep using its existing field map without a schema change.
            legacy_results = [r.model_dump() for r in results]
            return await _push(artifact.model_dump(), legacy_results, keys)
        except Exception as e:
            return {"source": "misp", "ok": False, "error": str(e)[:200]}


register(MISPConnector)
