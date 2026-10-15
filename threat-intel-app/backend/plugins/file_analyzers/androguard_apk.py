"""Androguard — Android APK static analysis.

Package name, main activity, permissions, requested intents, DEX
summary. Reverses the package of IntelOwl's Androguard analyzer
(static-only path; dynamic analysis would need Mobsf or Quark).
"""

from __future__ import annotations

from plugins import AnalysisResult, FileAnalyzer, register


# Dangerous permissions worth highlighting in the summary.
_DANGEROUS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.CALL_PHONE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.FOREGROUND_SERVICE",
}


class AndroguardApkAnalyzer(FileAnalyzer):
    name = "androguard_apk"
    description = ("Androguard — static APK analysis: package name, "
                   "activity, permissions, intents, DEX summary.")
    supported_file_types = ["apk"]
    max_file_size = 100 * 1024 * 1024
    homepage = "https://github.com/androguard/androguard"

    async def analyze_file(self, file_bytes, filename, file_type, keys):
        try:
            from androguard.core.apk import APK
        except Exception as e:
            return AnalysisResult(
                source="androguard_apk",
                ioc_type="file", ioc_value=filename or "",
                found=False,
                error=f"androguard not installed: {e}",
                error_type="unavailable",
            )
        import tempfile, os
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(suffix=".apk")
            os.write(fd, file_bytes)
            os.close(fd)
            apk = APK(tmp)
        except Exception as e:
            return AnalysisResult(
                source="androguard_apk",
                ioc_type="file", ioc_value=filename or "",
                found=False, error=f"APK parse failed: {e}",
                error_type="format_error",
            )
        finally:
            if tmp and os.path.exists(tmp):
                try: os.unlink(tmp)
                except Exception: pass

        try:
            package = apk.get_package()
            main_activity = apk.get_main_activity()
            permissions = sorted(apk.get_permissions() or [])
            activities = apk.get_activities() or []
            services = apk.get_services() or []
            receivers = apk.get_receivers() or []
            min_sdk = apk.get_min_sdk_version()
            target_sdk = apk.get_target_sdk_version()
            certs = []
            try:
                for c in (apk.get_certificates() or []):
                    certs.append({
                        "subject": str(getattr(c, "subject", "")),
                        "issuer":  str(getattr(c, "issuer", "")),
                        "sha256":  (getattr(c, "sha256_fingerprint", None) or "").upper(),
                    })
            except Exception:
                pass
        except Exception as e:
            return AnalysisResult(
                source="androguard_apk",
                ioc_type="file", ioc_value=filename or "",
                found=False, error=f"APK introspection failed: {e}",
                error_type="runtime_error",
            )

        dangerous_perms = [p for p in permissions if p in _DANGEROUS]
        if len(dangerous_perms) >= 5:
            verdict = "SUSPICIOUS"
            summary = (f"APK: {len(dangerous_perms)} dangerous "
                       f"permissions ({package})")
        else:
            verdict = "UNKNOWN"
            summary = f"APK {package}: {len(permissions)} permissions"

        return AnalysisResult(
            source="androguard_apk",
            ioc_type="file", ioc_value=filename or "",
            found=True, verdict=verdict, summary=summary,
            raw={
                "package":            package,
                "main_activity":      main_activity,
                "min_sdk":            min_sdk,
                "target_sdk":         target_sdk,
                "permissions_count":  len(permissions),
                "permissions":        permissions[:50],
                "dangerous_perms":    dangerous_perms,
                "activities_count":   len(activities),
                "services_count":     len(services),
                "receivers_count":    len(receivers),
                "certificates":       certs,
            },
        )


register(AndroguardApkAnalyzer)
