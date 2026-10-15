"""TheHive connector — push the artifact + its verdict as a Case."""

from __future__ import annotations

from typing import Any, Dict, List

from plugins import AnalysisResult, Artifact, Connector, register


class TheHiveConnector(Connector):
    name = "thehive"
    description = ("Create a TheHive case with the artifact as observable + "
                   "an aggregated verdict description from the analysers.")
    required_keys = ["THEHIVE_URL", "THEHIVE_KEY"]
    optional_keys = ["THEHIVE_ORG", "THEHIVE_TLP"]
    homepage = "https://thehive-project.org/"

    async def export(self, artifact: Artifact,
                      results: List[AnalysisResult],
                      keys: Dict[str, str]) -> Dict[str, Any]:
        try:
            from intel.thehive_push import push_artifact as _push
        except Exception as e:
            return {"source": "thehive", "ok": False,
                    "error": f"intel.thehive_push unavailable: {e}"}
        try:
            legacy_results = [r.model_dump() for r in results]
            return await _push(artifact.model_dump(), legacy_results, keys)
        except Exception as e:
            return {"source": "thehive", "ok": False, "error": str(e)[:200]}


register(TheHiveConnector)
