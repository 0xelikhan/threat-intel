"""
AnalyzeCapabilitiesSkill — FLARE capa wrapper.

Runs capa on file bytes and returns a normalised list of capabilities +
the MITRE techniques they map to. The skill is the programmatic entry
point used by the file-scanner flow and the dedicated /api/scan/capa
endpoint; capa itself is invoked via subprocess in intel/capa_runner.py.

Output mirrors RECON's other "produce structured signal from raw input"
skills (extract_iocs, correlate_signals) so the analyst report can
render capabilities side-by-side with YARA matches and PE-import-derived
MITRE techniques (intel/file_capability_map.py).
"""

from __future__ import annotations

import base64
from typing import Any, Dict, Optional

from providers.base import LLMProvider

from .base import Skill


class AnalyzeCapabilitiesSkill(Skill):
    @property
    def name(self) -> str:
        return "analyze_capabilities"

    @property
    def description(self) -> str:
        return ("Identify capabilities in a PE/.NET/ELF/shellcode file via "
                "FLARE capa and map them to MITRE ATT&CK techniques. "
                "Operates on raw bytes; never writes analyst data to disk.")

    @property
    def input_schema(self) -> Dict[str, Any]:
        return {
            "file_bytes": "bytes (raw) OR file_b64 (str, base64-encoded)",
            "filename":   "str (optional, helps capa pick format)",
            "timeout_s":  "int (optional, default 90)",
        }

    @property
    def output_schema(self) -> Dict[str, Any]:
        return {
            "available":        "bool",
            "capabilities":     "list[dict]",
            "mitre_techniques": "list[str]",
            "namespaces":       "list[str]",
            "rule_count":       "int",
            "error":            "str|None",
        }

    @property
    def test_input(self) -> Dict[str, Any]:
        # Test input deliberately gives capa an empty stub so the skill
        # exercises its short-circuit path (zero-byte / not-a-PE) without
        # needing a real malware sample in the test corpus.
        return {"file_bytes": b"", "filename": "empty.bin"}

    async def execute(
        self,
        inputs:   Dict[str, Any],
        provider: Optional[LLMProvider] = None,
    ) -> Dict[str, Any]:
        from intel.capa_runner import run_capa

        raw = (inputs or {}).get("file_bytes")
        if raw is None:
            b64 = (inputs or {}).get("file_b64") or ""
            try:
                raw = base64.b64decode(b64) if b64 else b""
            except Exception:
                raw = b""
        if not isinstance(raw, (bytes, bytearray)):
            raw = b""

        filename  = (inputs or {}).get("filename") or None
        timeout_s = int((inputs or {}).get("timeout_s") or 90)

        return await run_capa(bytes(raw), filename=filename,
                              timeout_s=timeout_s)
