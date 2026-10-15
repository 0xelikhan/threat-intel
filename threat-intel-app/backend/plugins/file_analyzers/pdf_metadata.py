"""Static PDF metadata — javascript / embedded files / forms.

pure-Python via `pypdf` or `pdfminer.six`. Flags PDFs with embedded
JavaScript, auto-action triggers, or large embedded binaries — the
IoCs IntelOwl's PDF module surfaces.
"""

from __future__ import annotations

from plugins import AnalysisResult, FileAnalyzer, register


class PdfMetadataAnalyzer(FileAnalyzer):
    name = "pdf_metadata"
    description = ("PDF metadata — producer, author, embedded JS, "
                   "forms, OpenAction / AA triggers, embedded files. "
                   "Flags macro-style PDF malware patterns.")
    supported_file_types = ["pdf"]
    max_file_size = 50 * 1024 * 1024
    homepage = "https://github.com/py-pdf/pypdf"

    async def analyze_file(self, file_bytes, filename, file_type, keys):
        try:
            from pypdf import PdfReader
            from pypdf.generic import IndirectObject
        except Exception as e:
            return AnalysisResult(
                source="pdf_metadata",
                ioc_type="file", ioc_value=filename or "",
                found=False, error=f"pypdf not installed: {e}",
                error_type="unavailable",
            )
        import io
        try:
            reader = PdfReader(io.BytesIO(file_bytes))
        except Exception as e:
            return AnalysisResult(
                source="pdf_metadata",
                ioc_type="file", ioc_value=filename or "",
                found=False, error=f"PDF parse failed: {e}",
                error_type="format_error",
            )
        meta = reader.metadata or {}
        info = {str(k): str(v) for k, v in meta.items()} if hasattr(meta, "items") else {}

        # Scan for suspicious patterns in the raw stream
        raw_lc = file_bytes[:5_000_000].lower()
        has_js = b"/javascript" in raw_lc or b"/js" in raw_lc
        has_openaction = b"/openaction" in raw_lc
        has_aa = b"/aa" in raw_lc  # Additional Actions
        has_launch = b"/launch" in raw_lc
        has_submitform = b"/submitform" in raw_lc
        has_uri = b"/uri" in raw_lc
        has_embedded_file = b"/embeddedfile" in raw_lc

        risky_count = sum([
            has_js, has_openaction and has_js,
            has_launch, has_submitform,
            has_embedded_file,
        ])
        if risky_count >= 2:
            verdict = "SUSPICIOUS"
            summary = (f"PDF: {len(reader.pages)} pages, "
                       f"{risky_count} active-content flag"
                       f"{'s' if risky_count != 1 else ''}")
        else:
            verdict = "UNKNOWN"
            summary = f"PDF: {len(reader.pages)} pages, no risky patterns."

        return AnalysisResult(
            source="pdf_metadata",
            ioc_type="file", ioc_value=filename or "",
            found=True, verdict=verdict, summary=summary,
            raw={
                "page_count":          len(reader.pages),
                "producer":            info.get("/Producer"),
                "author":              info.get("/Author"),
                "creator":             info.get("/Creator"),
                "has_javascript":      has_js,
                "has_openaction":      has_openaction,
                "has_additional_actions": has_aa,
                "has_launch":          has_launch,
                "has_submitform":      has_submitform,
                "has_uri":             has_uri,
                "has_embedded_file":   has_embedded_file,
            },
        )


register(PdfMetadataAnalyzer)
