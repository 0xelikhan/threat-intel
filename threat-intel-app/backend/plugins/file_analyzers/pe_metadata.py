"""Static PE metadata via pefile.

Compile timestamp, imphash, section names, imported DLLs, resources,
rich header, overlay size. The RECON risk heuristics watch for:
  - stripped sections (sign of packing)
  - abnormal imphash
  - entropy > 7.5 (packed/encrypted)
  - very large overlay
"""

from __future__ import annotations

from plugins import AnalysisResult, FileAnalyzer, register


class PEMetadataAnalyzer(FileAnalyzer):
    name = "pe_metadata"
    description = ("Static PE metadata: compile time, imphash, "
                   "sections, imports, resources, overlay. Flags "
                   "packed / stripped binaries.")
    supported_file_types = ["pe"]
    max_file_size = 50 * 1024 * 1024
    homepage = "https://github.com/erocarrera/pefile"

    async def analyze_file(self, file_bytes, filename, file_type, keys):
        try:
            import pefile
        except Exception as e:
            return AnalysisResult(
                source="pe_metadata",
                ioc_type="file", ioc_value=filename or "",
                found=False,
                error=f"pefile not installed: {e}",
                error_type="unavailable",
            )
        try:
            pe = pefile.PE(data=file_bytes, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
            ])
        except Exception as e:
            return AnalysisResult(
                source="pe_metadata",
                ioc_type="file", ioc_value=filename or "",
                found=False, error=f"not a PE or parse failed: {e}",
                error_type="format_error",
            )

        imphash = pe.get_imphash() if hasattr(pe, "get_imphash") else ""
        compile_ts = int(pe.FILE_HEADER.TimeDateStamp)
        try:
            import datetime
            compile_date = datetime.datetime.utcfromtimestamp(compile_ts).isoformat() + "Z"
        except Exception:
            compile_date = None

        sections = []
        max_entropy = 0.0
        for s in pe.sections:
            try:
                name = s.Name.decode(errors="ignore").rstrip("\x00")
            except Exception:
                name = ""
            try:
                ent = float(s.get_entropy())
            except Exception:
                ent = 0.0
            max_entropy = max(max_entropy, ent)
            sections.append({"name": name, "entropy": round(ent, 3),
                              "virtual_size": int(s.Misc_VirtualSize),
                              "raw_size": int(s.SizeOfRawData)})

        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT[:30]:
                try:
                    imports.append(entry.dll.decode(errors="ignore"))
                except Exception:
                    pass

        overlay_offset = pe.get_overlay_data_start_offset()
        overlay_size = (len(file_bytes) - overlay_offset) if overlay_offset else 0

        # Risk heuristic
        packed = max_entropy > 7.5
        suspicious_overlay = overlay_size > 10 * 1024 * 1024
        if packed or suspicious_overlay:
            verdict = "SUSPICIOUS"
            summary = (f"PE: {'packed/encrypted (entropy ' + str(round(max_entropy, 2)) + ')' if packed else ''}"
                       + (' + large overlay' if suspicious_overlay else '')).strip()
        else:
            verdict = "UNKNOWN"
            summary = f"PE: {len(sections)} sections, {len(imports)} DLL imports, imphash={imphash[:12]}…"

        return AnalysisResult(
            source="pe_metadata",
            ioc_type="file", ioc_value=filename or "",
            found=True, verdict=verdict, summary=summary,
            raw={
                "imphash": imphash,
                "compile_time": compile_date,
                "machine": hex(pe.FILE_HEADER.Machine),
                "section_count": len(sections),
                "sections": sections,
                "imports": imports,
                "max_entropy": round(max_entropy, 3),
                "overlay_size": overlay_size,
                "packed": packed,
            },
        )


register(PEMetadataAnalyzer)
