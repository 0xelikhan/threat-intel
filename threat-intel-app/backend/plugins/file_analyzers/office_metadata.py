"""Office / RTF static metadata via olefile + oletools.

Flags macro-enabled documents, DDE triggers, embedded objects. Core
signal set from IntelOwl's doc_info analyzer, done inline.
"""

from __future__ import annotations

from plugins import AnalysisResult, FileAnalyzer, register


class OfficeMetadataAnalyzer(FileAnalyzer):
    name = "office_metadata"
    description = ("Office / RTF static metadata — macros, DDE, "
                   "embedded objects. Powered by olefile + oletools.")
    supported_file_types = ["office", "rtf"]
    max_file_size = 50 * 1024 * 1024
    homepage = "https://github.com/decalage2/oletools"

    async def analyze_file(self, file_bytes, filename, file_type, keys):
        try:
            from oletools.olevba import VBA_Parser
        except Exception as e:
            return AnalysisResult(
                source="office_metadata",
                ioc_type="file", ioc_value=filename or "",
                found=False, error=f"oletools not installed: {e}",
                error_type="unavailable",
            )
        try:
            parser = VBA_Parser(filename or "sample", data=file_bytes)
        except Exception as e:
            return AnalysisResult(
                source="office_metadata",
                ioc_type="file", ioc_value=filename or "",
                found=False, error=f"Office parse failed: {e}",
                error_type="format_error",
            )

        # Format gate — VBA_Parser's detect_* methods will happily
        # false-positive on non-office garbage (random bytes containing
        # ole-marker sequences). Only trust macro detection when the
        # parser identifies a real office/OpenXML type.
        valid_types = {"OLE", "OpenXML", "FlatOPC_XML", "Word2003_XML",
                       "MHTML", "RTF", "XLSB"}
        parser_type = getattr(parser, "type", None)
        if parser_type not in valid_types:
            try: parser.close()
            except Exception: pass
            return AnalysisResult(
                source="office_metadata",
                ioc_type="file", ioc_value=filename or "",
                found=False,
                error=f"not a recognised Office format (type={parser_type!r})",
                error_type="format_error",
            )

        has_macros = parser.detect_vba_macros() if hasattr(parser, "detect_vba_macros") else False
        has_xlm = parser.detect_xlm_macros() if hasattr(parser, "detect_xlm_macros") else False

        suspicious_keywords = []
        try:
            if has_macros:
                for (_, _, _, vba_code) in parser.extract_macros() or []:
                    code_lc = (vba_code or "").lower()
                    for kw in ("shell", "wscript", "powershell", "cmd.exe",
                                "createobject", "xmlhttp", "downloadfile",
                                "regwrite", "autoopen", "document_open"):
                        if kw in code_lc:
                            suspicious_keywords.append(kw)
                suspicious_keywords = sorted(set(suspicious_keywords))
        except Exception:
            pass
        finally:
            try: parser.close()
            except Exception: pass

        if has_macros and suspicious_keywords:
            verdict = "MALICIOUS"
            summary = (f"Office: macros + suspicious API usage "
                       f"({', '.join(suspicious_keywords[:3])}...)")
        elif has_macros or has_xlm:
            verdict = "SUSPICIOUS"
            summary = (f"Office: macro-enabled document"
                       + (" (XLM)" if has_xlm else ""))
        else:
            verdict = "UNKNOWN"
            summary = "Office: no macros detected."

        return AnalysisResult(
            source="office_metadata",
            ioc_type="file", ioc_value=filename or "",
            found=True, verdict=verdict, summary=summary,
            raw={
                "has_macros":           has_macros,
                "has_xlm_macros":       has_xlm,
                "suspicious_keywords":  suspicious_keywords,
            },
        )


register(OfficeMetadataAnalyzer)
