"""FLOSS — FLARE Obfuscated String Solver.

Extracts and deobfuscates strings embedded in malware. Covers:
  - static strings (ASCII + Unicode)
  - stack-stored strings
  - decoded strings (XOR / add / sub single-byte wrappers)
  - tightly-encoded strings (library-identified wrappers)

Pulled in via the optional `flare-floss` pip package. If not
installed, returns error_type='unavailable' and does not raise.
"""

from __future__ import annotations

from plugins import AnalysisResult, FileAnalyzer, register


class FlossAnalyzer(FileAnalyzer):
    name = "floss"
    description = ("FLARE FLOSS — extract + decode strings from PE/ELF "
                   "binaries, including stack-stored, stack-decoded, "
                   "and tight-loop-decoded strings.")
    supported_file_types = ["pe", "elf", "shellcode"]
    max_file_size = 20 * 1024 * 1024
    homepage = "https://github.com/mandiant/flare-floss"

    async def analyze_file(self, file_bytes, filename, file_type, keys):
        try:
            from floss.main import extract_strings
            from floss.render import Analysis, ResultDocument
        except Exception as e:
            return AnalysisResult(
                source="floss",
                ioc_type="file", ioc_value=filename or "",
                found=False, error=f"flare-floss not installed: {e}",
                error_type="unavailable",
            )
        import tempfile, os
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(suffix="_sample")
            os.write(fd, file_bytes)
            os.close(fd)
            # FLOSS has a public entry point that returns a ResultDocument
            doc: ResultDocument = extract_strings(tmp)
        except Exception as e:
            return AnalysisResult(
                source="floss",
                ioc_type="file", ioc_value=filename or "",
                found=False, error=str(e)[:200],
                error_type="runtime_error",
            )
        finally:
            if tmp and os.path.exists(tmp):
                try: os.unlink(tmp)
                except Exception: pass

        strings = doc.strings if hasattr(doc, "strings") else None
        if not strings:
            return AnalysisResult(
                source="floss",
                ioc_type="file", ioc_value=filename or "",
                found=False, verdict="UNKNOWN",
                summary="FLOSS: no strings extracted.",
            )

        static_count   = len(getattr(strings, "static_strings", []) or [])
        stack_count    = len(getattr(strings, "stack_strings", []) or [])
        decoded_count  = len(getattr(strings, "decoded_strings", []) or [])
        tight_count    = len(getattr(strings, "tight_strings", []) or [])
        obfuscated = stack_count + decoded_count + tight_count

        return AnalysisResult(
            source="floss",
            ioc_type="file", ioc_value=filename or "",
            found=True,
            verdict="SUSPICIOUS" if obfuscated >= 5 else "UNKNOWN",
            summary=(f"FLOSS: {static_count} static strings"
                     + (f", {obfuscated} decoded/stack/tight"
                        if obfuscated else "")),
            raw={
                "static_count":   static_count,
                "stack_count":    stack_count,
                "decoded_count":  decoded_count,
                "tight_count":    tight_count,
                "sample": [
                    getattr(s, "string", str(s))[:200]
                    for s in (getattr(strings, "decoded_strings", []) or [])[:10]
                ],
            },
        )


register(FlossAnalyzer)
