"""FLARE CAPA — PE / ELF capability extraction with MITRE mapping."""

from __future__ import annotations

from plugins import AnalysisResult, FileAnalyzer, register


class CapaFileAnalyzer(FileAnalyzer):
    name = "capa"
    description = ("FLARE CAPA — identifies capabilities (persistence, "
                   "injection, C2 protocol, etc.) by matching rules "
                   "against disassembled binaries, with MITRE ATT&CK "
                   "technique mapping.")
    supported_file_types = ["pe", "elf", "shellcode"]
    max_file_size = 20 * 1024 * 1024
    homepage = "https://github.com/mandiant/capa"
    # CAPA is opt-in because it adds ~150 MB of transitive deps + is slow.
    optional_keys = ["RECON_ENABLE_CAPA"]

    async def analyze_file(self, file_bytes, filename, file_type, keys):
        if (keys.get("RECON_ENABLE_CAPA", "0") or "0") in ("0", "false", "False"):
            return AnalysisResult(
                source="capa",
                ioc_type="file", ioc_value=filename or "",
                found=False, error="CAPA disabled (set RECON_ENABLE_CAPA=1)",
                error_type="disabled",
            )
        try:
            from intel.capa_runner import run_capa_on_bytes
        except Exception as e:
            return AnalysisResult(
                source="capa",
                ioc_type="file", ioc_value=filename or "",
                found=False, error=f"intel.capa_runner unavailable: {e}",
                error_type="unavailable",
            )
        try:
            report = run_capa_on_bytes(file_bytes)
        except Exception as e:
            return AnalysisResult(
                source="capa",
                ioc_type="file", ioc_value=filename or "",
                found=False, error=str(e)[:200],
                error_type="runtime_error",
            )
        caps = (report or {}).get("capabilities") or []
        mitre = (report or {}).get("mitre") or []
        return AnalysisResult(
            source="capa",
            ioc_type="file", ioc_value=filename or "",
            found=bool(caps),
            verdict="SUSPICIOUS" if caps else "UNKNOWN",
            summary=(f"CAPA: {len(caps)} capabilit{'ies' if len(caps) != 1 else 'y'}"
                     + (f", {len(mitre)} MITRE technique{'s' if len(mitre) != 1 else ''}"
                        if mitre else "")),
            raw={"capabilities": caps, "mitre": mitre},
        )


register(CapaFileAnalyzer)
