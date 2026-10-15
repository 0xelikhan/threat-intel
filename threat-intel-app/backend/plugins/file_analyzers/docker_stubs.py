"""Docker-service-based file analyzers (stub registrations).

IntelOwl runs these inside dedicated Docker containers because they
require native daemons / emulators / specialised runtimes. RECON ships
the plugin descriptors so users see the full matrix in /api/plugins,
but analyze_file returns error_type='unavailable' until the container
is wired. The gap is Dockerfile work — tracked in a follow-up.

Service URL conventions follow IntelOwl's `http://<service>:<port>`
pattern. Each stub reads from env vars so a side-car container simply
needs to be routable at that URL.
"""

from __future__ import annotations

import os
from typing import Dict

from plugins import AnalysisResult, FileAnalyzer, register


class _DockerStub(FileAnalyzer):
    """Base for Docker-service file analyzers."""
    requires_docker = True
    service_env_var: str = ""

    async def analyze_file(self, file_bytes, filename, file_type, keys):
        url = os.environ.get(self.service_env_var, "")
        if not url:
            return AnalysisResult(
                source=self.name,
                ioc_type="file", ioc_value=filename or "",
                found=False,
                error=(f"{self.name} not configured: set {self.service_env_var}"
                       " and run the matching Docker service."),
                error_type="unavailable",
            )
        return AnalysisResult(
            source=self.name,
            ioc_type="file", ioc_value=filename or "",
            found=False,
            error=f"{self.name} integration stub — service dispatch not implemented.",
            error_type="unavailable",
        )


class QilingStub(_DockerStub):
    name = "qiling"
    description = ("PE / ELF emulation via Qiling (cross-platform user-space "
                   "emulator). Returns executed-API trace. Requires qiling-service.")
    supported_file_types = ["pe", "elf"]
    service_env_var = "RECON_QILING_URL"
    homepage = "https://github.com/qilingframework/qiling"


class SpeakeasyStub(_DockerStub):
    name = "speakeasy"
    description = ("Windows PE emulation via Mandiant Speakeasy. Returns "
                   "executed-API trace + MITRE technique hits.")
    supported_file_types = ["pe"]
    service_env_var = "RECON_SPEAKEASY_URL"
    homepage = "https://github.com/mandiant/speakeasy"


class ThugStub(_DockerStub):
    name = "thug"
    description = ("Thug honeyclient — emulates a browser visiting a URL / "
                   "opening an HTML file; reports exploit kit detections.")
    supported_file_types = ["html", "js", "url_dump"]
    service_env_var = "RECON_THUG_URL"
    homepage = "https://github.com/buffer/thug"


class BoxJsStub(_DockerStub):
    name = "box_js"
    description = ("Node.js emulated JS runner — deobfuscates malicious "
                   "JavaScript droppers.")
    supported_file_types = ["js", "jse", "vbs"]
    service_env_var = "RECON_BOXJS_URL"
    homepage = "https://github.com/CapacitorSet/box-js"


class MobsfStub(_DockerStub):
    name = "mobsf"
    description = ("MobSF — mobile (APK/IPA) static + dynamic analysis. "
                   "Returns findings, exposed services, exported components.")
    supported_file_types = ["apk", "ipa"]
    service_env_var = "RECON_MOBSF_URL"
    homepage = "https://github.com/MobSF/Mobile-Security-Framework-MobSF"


class QuarkStub(_DockerStub):
    name = "quark_engine"
    description = ("Quark Engine — rule-based Android malware scoring. "
                   "Returns threat score and triggered behavior rules.")
    supported_file_types = ["apk", "dex"]
    service_env_var = "RECON_QUARK_URL"
    homepage = "https://github.com/quark-engine/quark-engine"


class ClamAVStub(_DockerStub):
    name = "clamav"
    description = ("ClamAV — rule / signature AV scan. Returns matched "
                   "signature name. Requires clamd daemon.")
    supported_file_types = ["any"]
    service_env_var = "RECON_CLAMAV_URL"
    homepage = "https://www.clamav.net/"


class SuricataStub(_DockerStub):
    name = "suricata"
    description = ("Suricata PCAP analysis — IDS alerts + protocol parse "
                   "over a captured pcap.")
    supported_file_types = ["pcap"]
    service_env_var = "RECON_SURICATA_URL"
    homepage = "https://suricata.io/"


class HfingerStub(_DockerStub):
    name = "hfinger"
    description = ("Hfinger — HTTP request fingerprinting from PCAP for "
                   "malware traffic identification.")
    supported_file_types = ["pcap"]
    service_env_var = "RECON_HFINGER_URL"
    homepage = "https://github.com/CERT-Polska/hfinger"


class StringsifterStub(_DockerStub):
    name = "stringsifter"
    description = ("Stringsifter — ML-ranked strings extraction, surfacing "
                   "the most malware-relevant strings in a sample.")
    supported_file_types = ["pe", "elf"]
    service_env_var = "RECON_STRINGSIFTER_URL"
    homepage = "https://github.com/mandiant/stringsifter"


for cls in (QilingStub, SpeakeasyStub, ThugStub, BoxJsStub, MobsfStub,
             QuarkStub, ClamAVStub, SuricataStub, HfingerStub,
             StringsifterStub):
    register(cls)
