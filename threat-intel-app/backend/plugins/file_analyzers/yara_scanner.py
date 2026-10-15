"""YARA file scanner — pure-Python via yara-python.

Wraps intel/yara_scanner.py in the FileAnalyzer plugin interface so
every registered scan runs through a uniform result shape. Scans
every file type ('any') — YARA rules can match PE, ELF, PDF, scripts,
anything.
"""

from __future__ import annotations

from plugins import AnalysisResult, FileAnalyzer, register


class YaraFileScanner(FileAnalyzer):
    name = "yara_scanner"
    description = ("Local YARA rules scan over the file bytes. Loads "
                   "RECON's bundled corpora + any user rules from "
                   "intel/yara_custom.")
    supported_file_types = ["any"]
    max_file_size = 50 * 1024 * 1024     # 50 MB soft cap
    homepage = "https://virustotal.github.io/yara/"

    async def analyze_file(self, file_bytes, filename, file_type, keys):
        try:
            from intel.yara_scanner import scan_bytes
        except Exception as e:
            return AnalysisResult(
                source="yara_scanner",
                ioc_type="file", ioc_value=filename or "",
                found=False, error=f"intel.yara_scanner unavailable: {e}",
                error_type="unavailable",
            )
        try:
            matches = scan_bytes(file_bytes)
        except Exception as e:
            return AnalysisResult(
                source="yara_scanner",
                ioc_type="file", ioc_value=filename or "",
                found=False, error=str(e)[:200],
                error_type="runtime_error",
            )
        if not matches:
            return AnalysisResult(
                source="yara_scanner",
                ioc_type="file", ioc_value=filename or "",
                found=False, verdict="UNKNOWN",
                summary="No YARA rule matches.",
            )
        return AnalysisResult(
            source="yara_scanner",
            ioc_type="file", ioc_value=filename or "",
            found=True, verdict="MALICIOUS",
            summary=f"YARA: {len(matches)} rule match{'es' if len(matches) != 1 else ''}",
            raw={"matches": matches},
        )


register(YaraFileScanner)
