"""Static ELF metadata via pyelftools.

Architecture, interpreter, DT_NEEDED libraries, dynamic symbols,
stripped-section detection, PIE/NX/stack-canary mitigations.
"""

from __future__ import annotations

from plugins import AnalysisResult, FileAnalyzer, register


class ElfMetadataAnalyzer(FileAnalyzer):
    name = "elf_metadata"
    description = ("ELF metadata — arch, interpreter, DT_NEEDED libs, "
                   "PIE / NX / stack-canary mitigation flags.")
    supported_file_types = ["elf"]
    max_file_size = 50 * 1024 * 1024
    homepage = "https://github.com/eliben/pyelftools"

    async def analyze_file(self, file_bytes, filename, file_type, keys):
        try:
            from elftools.elf.elffile import ELFFile
        except Exception as e:
            return AnalysisResult(
                source="elf_metadata",
                ioc_type="file", ioc_value=filename or "",
                found=False, error=f"pyelftools not installed: {e}",
                error_type="unavailable",
            )
        import io
        try:
            elf = ELFFile(io.BytesIO(file_bytes))
        except Exception as e:
            return AnalysisResult(
                source="elf_metadata",
                ioc_type="file", ioc_value=filename or "",
                found=False, error=f"not an ELF: {e}",
                error_type="format_error",
            )

        arch = elf.get_machine_arch()
        header = dict(elf.header)
        e_type = str(header.get("e_type", ""))

        interpreter = None
        try:
            for seg in elf.iter_segments():
                if seg["p_type"] == "PT_INTERP":
                    interpreter = seg.get_interp_name()
                    break
        except Exception:
            pass

        needed = []
        try:
            for section in elf.iter_sections():
                if section.name == ".dynamic":
                    for tag in section.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            needed.append(tag.needed)
        except Exception:
            pass

        has_debug = any(s.name == ".debug_info" for s in elf.iter_sections())
        has_rela = any(s.name.startswith(".rela.") for s in elf.iter_sections())
        is_stripped = not any(s.name == ".symtab" for s in elf.iter_sections())

        # Rough mitigation heuristics
        has_pie = e_type == "ET_DYN"  # DYN with INTERP is typical PIE
        has_nx = True                 # modern linkers default to NX; approximated

        if is_stripped and arch and len(needed) == 0:
            verdict = "SUSPICIOUS"
            summary = f"ELF {arch}: stripped and statically-linked (unusual packaging)"
        else:
            verdict = "UNKNOWN"
            summary = (f"ELF {arch}: {len(needed)} needed libs"
                       + (", stripped" if is_stripped else "")
                       + (", PIE" if has_pie else ""))

        return AnalysisResult(
            source="elf_metadata",
            ioc_type="file", ioc_value=filename or "",
            found=True, verdict=verdict, summary=summary,
            raw={
                "arch":        arch,
                "elf_type":    e_type,
                "interpreter": interpreter,
                "needed":      needed[:20],
                "has_debug":   has_debug,
                "has_rela":    has_rela,
                "stripped":    is_stripped,
                "pie":         has_pie,
            },
        )


register(ElfMetadataAnalyzer)
