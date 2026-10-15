"""Blint — binary SBOM + capability analysis.

Blint is a Linux Foundation project that extracts a software bill of
materials and security-relevant metadata (symbols, exposed functions,
security flags) from PE / ELF / Mach-O binaries. Complements CAPA by
catching binary-level supply-chain risk indicators.

pip: `pip install blint`
"""

from __future__ import annotations

from plugins import AnalysisResult, FileAnalyzer, register


class BlintAnalyzer(FileAnalyzer):
    name = "blint"
    description = ("Blint — binary SBOM + security-flag analysis for "
                   "PE / ELF / Mach-O. Flags missing NX / ASLR / CFG, "
                   "known-vulnerable symbol imports.")
    supported_file_types = ["pe", "elf", "macho"]
    max_file_size = 50 * 1024 * 1024
    homepage = "https://github.com/owasp-dep-scan/blint"

    async def analyze_file(self, file_bytes, filename, file_type, keys):
        try:
            from blint.binary import parse as _blint_parse
        except Exception as e:
            return AnalysisResult(
                source="blint",
                ioc_type="file", ioc_value=filename or "",
                found=False, error=f"blint not installed: {e}",
                error_type="unavailable",
            )
        import tempfile, os
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(suffix="_sample")
            os.write(fd, file_bytes)
            os.close(fd)
            metadata = _blint_parse(tmp)
        except Exception as e:
            return AnalysisResult(
                source="blint",
                ioc_type="file", ioc_value=filename or "",
                found=False, error=str(e)[:200],
                error_type="runtime_error",
            )
        finally:
            if tmp and os.path.exists(tmp):
                try: os.unlink(tmp)
                except Exception: pass

        if not isinstance(metadata, dict):
            return AnalysisResult(
                source="blint",
                ioc_type="file", ioc_value=filename or "",
                found=False, error="unexpected blint output",
                error_type="format_error",
            )

        notes = metadata.get("notes") or []
        exe_flags = metadata.get("exe_type") or metadata.get("header", {})
        missing_mitigations = []
        for note in notes:
            if isinstance(note, dict) and (note.get("severity") or "").upper() in ("CRITICAL", "HIGH"):
                missing_mitigations.append(note.get("title") or note.get("description"))

        if missing_mitigations:
            verdict = "SUSPICIOUS"
            summary = (f"Blint: {len(missing_mitigations)} security flag"
                       f"{'s' if len(missing_mitigations) != 1 else ''} "
                       "missing/weak")
        else:
            verdict = "UNKNOWN"
            summary = "Blint: no high-severity flags."

        return AnalysisResult(
            source="blint",
            ioc_type="file", ioc_value=filename or "",
            found=True, verdict=verdict, summary=summary,
            raw={
                "exe_type":            metadata.get("exe_type"),
                "note_count":          len(notes),
                "high_severity_notes": missing_mitigations[:10],
                "symbols_count":       len(metadata.get("functions") or []),
                "imports_count":       len(metadata.get("imports") or []),
            },
        )


register(BlintAnalyzer)
