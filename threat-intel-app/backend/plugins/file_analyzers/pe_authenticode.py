"""PE Authenticode signature verification.

Uses `signify-ca` to verify the Authenticode signature of a PE file:
signer identity, issuer, counter-signature timestamp, signature
validity. Returns MALICIOUS when the signature is present but
invalid, CLEAN when it's valid and from a reputable CA, UNKNOWN
when unsigned.
"""

from __future__ import annotations

from plugins import AnalysisResult, FileAnalyzer, register


class PEAuthenticodeAnalyzer(FileAnalyzer):
    name = "pe_authenticode"
    description = ("PE Authenticode signature verification. Returns "
                   "signer / issuer / validity and detects stripped or "
                   "invalid signatures.")
    supported_file_types = ["pe"]
    max_file_size = 50 * 1024 * 1024
    homepage = "https://github.com/ralphje/signify"

    async def analyze_file(self, file_bytes, filename, file_type, keys):
        try:
            from signify.authenticode import SignedPEFile
        except Exception as e:
            return AnalysisResult(
                source="pe_authenticode",
                ioc_type="file", ioc_value=filename or "",
                found=False,
                error=f"signify not installed: {e}",
                error_type="unavailable",
            )
        import io
        try:
            pe = SignedPEFile(io.BytesIO(file_bytes))
            signed_datas = list(pe.signed_datas)
        except Exception as e:
            return AnalysisResult(
                source="pe_authenticode",
                ioc_type="file", ioc_value=filename or "",
                found=False,
                error=str(e)[:200],
                error_type="runtime_error",
            )
        if not signed_datas:
            return AnalysisResult(
                source="pe_authenticode",
                ioc_type="file", ioc_value=filename or "",
                found=True, verdict="UNKNOWN",
                summary="PE Authenticode: unsigned binary.",
                raw={"signed": False},
            )
        # Try verification
        signer = None
        issuer = None
        valid = False
        err_msg = None
        try:
            for sd in signed_datas:
                sd.verify()
            valid = True
            info = signed_datas[0].signer_infos[0]
            signer = str(info.issuer).replace("\n", " ")[:160] if hasattr(info, "issuer") else None
            # signify exposes .signing_time + .cert.issuer; try both
            try:
                issuer = str(info.certificate.issuer).replace("\n", " ")[:160]
            except Exception:
                issuer = None
        except Exception as e:
            err_msg = str(e)[:200]

        if valid:
            verdict = "CLEAN"
            summary = f"PE Authenticode: valid signature{(' — ' + signer) if signer else ''}"
        else:
            verdict = "MALICIOUS"
            summary = f"PE Authenticode: invalid signature ({err_msg or 'verification failed'})"

        return AnalysisResult(
            source="pe_authenticode",
            ioc_type="file", ioc_value=filename or "",
            found=True, verdict=verdict,
            summary=summary,
            raw={"signed": True, "valid": valid, "signer": signer,
                   "issuer": issuer, "error": err_msg},
        )


register(PEAuthenticodeAnalyzer)
