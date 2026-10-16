"""docker_stubs — Docker-service-based file analyzers.

Each sidecar wraps a native tool / emulator / daemon that doesn't
ship in-process (Qiling, Speakeasy, Thug, Mobsf, …) behind a tiny
HTTP service. The stub descriptors always appear in /api/plugins
so the user sees the full matrix in the catalog, and when the
matching RECON_<SERVICE>_URL env var is set + the sidecar is up,
analyze_file dispatches to it over multipart POST.

See docker/docker-compose.yml for a reference stack that starts
all 10 services on their default ports.

Sidecar contract (what each container must implement):
  POST <base>/analyze
    multipart form:
      file:       file bytes
      filename:   optional display name
    → 200 application/json  { verdict?, summary?, ...analysis fields }
    → 4xx/5xx application/json  { error, error_type? }
"""

from __future__ import annotations

from plugins import FileAnalyzer, register
from ._docker_dispatch import dispatch


class _DockerStub(FileAnalyzer):
    """Base for Docker-service file analyzers. Subclasses only need
    to declare metadata (name, env var, supported file types) — all
    the HTTP dispatch is in _docker_dispatch.dispatch."""
    requires_docker = True
    service_env_var: str = ""
    service_endpoint: str = "/analyze"
    timeout_s: float = 60.0

    async def analyze_file(self, file_bytes, filename, file_type, keys):
        return await dispatch(
            service_name=self.name,
            service_env_var=self.service_env_var,
            file_bytes=file_bytes,
            filename=filename or "sample",
            endpoint_path=self.service_endpoint,
            timeout_s=self.timeout_s,
        )


class QilingStub(_DockerStub):
    name = "qiling"
    description = ("PE / ELF emulation via Qiling (cross-platform user-space "
                   "emulator). Returns executed-API trace, syscalls, memory "
                   "accesses. Sidecar: qiling-service.")
    supported_file_types = ["pe", "elf", "shellcode"]
    service_env_var = "RECON_QILING_URL"
    timeout_s = 90.0
    homepage = "https://github.com/qilingframework/qiling"


class SpeakeasyStub(_DockerStub):
    name = "speakeasy"
    description = ("Windows PE emulation via Mandiant Speakeasy. Returns "
                   "executed-API trace + MITRE technique hits + strings.")
    supported_file_types = ["pe"]
    service_env_var = "RECON_SPEAKEASY_URL"
    timeout_s = 90.0
    homepage = "https://github.com/mandiant/speakeasy"


class ThugStub(_DockerStub):
    name = "thug"
    description = ("Thug honeyclient — emulates a browser visiting a URL / "
                   "opening an HTML file; reports exploit kit detections, "
                   "redirect chains, dropped files.")
    supported_file_types = ["html", "js"]
    service_env_var = "RECON_THUG_URL"
    timeout_s = 120.0
    homepage = "https://github.com/buffer/thug"


class BoxJsStub(_DockerStub):
    name = "box_js"
    description = ("Node.js emulated JS runner — deobfuscates malicious "
                   "JavaScript droppers, surfaces network IOCs + commands.")
    supported_file_types = ["js"]
    service_env_var = "RECON_BOXJS_URL"
    timeout_s = 60.0
    homepage = "https://github.com/CapacitorSet/box-js"


class MobsfStub(_DockerStub):
    name = "mobsf"
    description = ("MobSF — mobile (APK/IPA) static + dynamic analysis. "
                   "Returns findings, exposed services, exported components, "
                   "trackers, SBOM.")
    supported_file_types = ["apk", "ipa"]
    service_env_var = "RECON_MOBSF_URL"
    timeout_s = 180.0
    homepage = "https://github.com/MobSF/Mobile-Security-Framework-MobSF"


class QuarkStub(_DockerStub):
    name = "quark_engine"
    description = ("Quark Engine — rule-based Android malware scoring. "
                   "Returns threat score + triggered behavior rules.")
    supported_file_types = ["apk", "dex"]
    service_env_var = "RECON_QUARK_URL"
    timeout_s = 60.0
    homepage = "https://github.com/quark-engine/quark-engine"


class ClamAVStub(_DockerStub):
    name = "clamav"
    description = ("ClamAV — signature + heuristic AV scan. Returns matched "
                   "signature name + severity. Requires clamd sidecar with "
                   "the daily freshclam update task.")
    supported_file_types = ["any"]
    service_env_var = "RECON_CLAMAV_URL"
    timeout_s = 30.0
    homepage = "https://www.clamav.net/"


class SuricataStub(_DockerStub):
    name = "suricata"
    description = ("Suricata PCAP analysis — IDS alerts + protocol parse "
                   "over a captured pcap. Returns alert list + flow "
                   "summaries.")
    supported_file_types = ["pcap"]
    service_env_var = "RECON_SURICATA_URL"
    timeout_s = 120.0
    homepage = "https://suricata.io/"


class HfingerStub(_DockerStub):
    name = "hfinger"
    description = ("Hfinger — HTTP request fingerprinting from PCAP for "
                   "malware traffic identification.")
    supported_file_types = ["pcap"]
    service_env_var = "RECON_HFINGER_URL"
    timeout_s = 60.0
    homepage = "https://github.com/CERT-Polska/hfinger"


class StringsifterStub(_DockerStub):
    name = "stringsifter"
    description = ("Stringsifter — ML-ranked strings extraction, surfacing "
                   "the most malware-relevant strings in a sample.")
    supported_file_types = ["pe", "elf"]
    service_env_var = "RECON_STRINGSIFTER_URL"
    timeout_s = 60.0
    homepage = "https://github.com/mandiant/stringsifter"


for cls in (QilingStub, SpeakeasyStub, ThugStub, BoxJsStub, MobsfStub,
             QuarkStub, ClamAVStub, SuricataStub, HfingerStub,
             StringsifterStub):
    register(cls)
