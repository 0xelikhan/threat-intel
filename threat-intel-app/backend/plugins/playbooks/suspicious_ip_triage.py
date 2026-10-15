"""Playbook — suspicious IP triage.

A repeatable analysis sequence: run the baseline IP analyzers in
parallel, aggregate verdicts, and auto-export to TheHive when the
consensus is MALICIOUS. Users invoke by POST /api/playbooks/
suspicious_ip_triage/run with {"ioc": "1.2.3.4"}.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from plugins import AnalysisResult, Artifact, Playbook, register, registry


class SuspiciousIPTriagePlaybook(Playbook):
    name = "suspicious_ip_triage"
    description = ("Run baseline IP analyzers (AbuseIPDB, GreyNoise, VT, "
                   "OTX, DShield, ThreatView, Spamhaus), aggregate the "
                   "verdict, and push to TheHive when MALICIOUS.")
    # Steps are declarative; the execute() method is still what runs.
    steps = [
        {"stage": "analyze", "plugins": ["abuseipdb", "greynoise", "virustotal",
                                           "otx", "dshield", "threatview_c2",
                                           "spamhaus_drop", "firehol"],
         "parallel": True},
        {"stage": "aggregate", "op": "majority_verdict"},
        {"stage": "export", "plugin": "thehive",
         "when": "verdict == 'MALICIOUS'"},
    ]

    async def execute(self, session, artifact: Artifact,
                       keys: Dict[str, str]) -> Dict[str, Any]:
        if artifact.type not in ("ipv4", "ipv6"):
            return {"error": "playbook only supports IP artifacts",
                    "artifact_type": artifact.type}

        # Stage 1: analyze — run the configured IP analyzers in parallel.
        step_names = self.steps[0]["plugins"]
        analyzers = [registry.get(n) for n in step_names]
        analyzers = [a for a in analyzers if a is not None]

        coros = [a.analyze(session, artifact.type, artifact.value, keys)
                  for a in analyzers]
        settled = await asyncio.gather(*coros, return_exceptions=True)
        results: List[AnalysisResult] = []
        for r in settled:
            if isinstance(r, AnalysisResult):
                results.append(r)

        # Stage 2: aggregate — majority verdict with MALICIOUS short-circuit
        counts = {"MALICIOUS": 0, "SUSPICIOUS": 0, "CLEAN": 0, "UNKNOWN": 0}
        for r in results:
            if r.found and r.verdict in counts:
                counts[r.verdict] += 1
        if counts["MALICIOUS"] >= 1:
            verdict = "MALICIOUS"
        elif counts["SUSPICIOUS"] >= 2:
            verdict = "SUSPICIOUS"
        elif counts["CLEAN"] and not counts["SUSPICIOUS"]:
            verdict = "CLEAN"
        else:
            verdict = "UNKNOWN"

        # Stage 3: export (conditional)
        export_result = None
        if verdict == "MALICIOUS":
            thehive = registry.get("thehive")
            if thehive and keys.get("THEHIVE_URL") and keys.get("THEHIVE_KEY"):
                try:
                    export_result = await thehive.export(artifact, results, keys)
                except Exception as e:
                    export_result = {"ok": False, "error": str(e)[:200]}

        return {
            "playbook": self.name,
            "artifact": artifact.model_dump(),
            "verdict": verdict,
            "counts": counts,
            "analyzer_count": len(results),
            "analyzers": [r.model_dump() for r in results],
            "exported": export_result,
        }


register(SuspiciousIPTriagePlaybook)
