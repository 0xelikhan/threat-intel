"""Pivot — sandbox analysis → dropped hashes → queue each for enrichment.

Watches for Hybrid Analysis / Triage / Joe Sandbox results. If any
contains dropped-file hashes in its raw payload, surfaces them as new
hash IOCs to analyse. The orchestrator in agents/enrichment.py reads
the pivot output and extends the enrichment queue.
"""

from __future__ import annotations

from typing import Any, Dict, List

from plugins import AnalysisResult, Pivot, register


class SandboxDroppedHashesPivot(Pivot):
    name = "sandbox_dropped_hashes"
    description = ("When a sandbox analyser (Hybrid Analysis, Triage, Joe "
                   "Sandbox) returns a dropped-files list, queue each hash "
                   "for enrichment too.")

    async def should_pivot(self, result: AnalysisResult) -> bool:
        if result.source not in {"hybrid_analysis", "triage", "joesandbox",
                                   "intezer", "mwdb"}:
            return False
        if not result.found or result.error:
            return False
        raw = result.raw or {}
        # Each sandbox stores dropped files under a different key.
        return bool(raw.get("files_dropped")
                    or raw.get("dropped_files")
                    or (raw.get("iocs") or {}).get("files")
                    or raw.get("sample")  # Triage sample list of child analyses
                    )

    async def extract_pivot_iocs(self, result: AnalysisResult) -> List[Dict[str, str]]:
        raw = result.raw or {}
        hashes: set = set()
        for key in ("files_dropped", "dropped_files"):
            for entry in (raw.get(key) or []):
                if isinstance(entry, dict):
                    h = entry.get("sha256") or entry.get("md5") or entry.get("hash")
                    if h:
                        hashes.add(h.lower())
                elif isinstance(entry, str):
                    hashes.add(entry.lower())
        for entry in ((raw.get("iocs") or {}).get("files") or []):
            if isinstance(entry, str):
                hashes.add(entry.lower())
            elif isinstance(entry, dict) and (entry.get("sha256") or entry.get("hash")):
                hashes.add((entry.get("sha256") or entry.get("hash")).lower())
        out = []
        for h in list(hashes)[:20]:
            if len(h) == 64:
                out.append({"type": "sha256", "value": h})
            elif len(h) == 40:
                out.append({"type": "sha1", "value": h})
            elif len(h) == 32:
                out.append({"type": "md5", "value": h})
        return out


register(SandboxDroppedHashesPivot)
