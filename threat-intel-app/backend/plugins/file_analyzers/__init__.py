"""File-sample analyzers.

Covers the IntelOwl inbuilt file-analysis matrix as RECON plugins.
Easy pure-Python wrappers (YARA, CAPA, Blint, FLOSS, Androguard, PE
metadata, PDF/Office/ELF) land here directly.

Docker-/daemon-required ones (Qiling, Speakeasy, Thug, Mobsf, ClamAV,
Suricata, Box-js) register with requires_docker=True — the registry
lists them so users see what's coming, but analyze_file returns a
soft error_type='unavailable' until the service is wired.
"""
