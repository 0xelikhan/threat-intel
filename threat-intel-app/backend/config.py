"""
Config Manager
Reads and writes API keys to a local config.json file.
Keys never leave the user's machine — no telemetry, no cloud sync.
"""

import json
import os
from pathlib import Path

DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))
CONFIG_FILE = DATA_DIR / "config.json"

# All supported API keys with metadata for the settings UI
API_KEY_DEFINITIONS = {
    "OPENAI_API_KEY": {
        "label": "OpenAI / Azure OpenAI Key",
        "description": "AI threat assessment, Sigma/KQL generation. Use your Azure OpenAI Key 1 if on Azure.",
        "required": True,
        "url": "https://platform.openai.com/api-keys",
        "placeholder": "sk-... or Azure OpenAI Key 1",
        "group": "API Keys"
    },
    "OPENAI_BASE_URL": {
        "label": "OpenAI Base URL",
        "description": "Leave default for OpenAI. For Azure: https://YOUR-RESOURCE.openai.azure.com/openai/deployments/MODEL/chat/completions?api-version=2024-02-01",
        "required": False,
        "default": "https://api.openai.com/v1",
        "placeholder": "https://api.openai.com/v1",
        "group": "API Keys"
    },
    "AI_MODEL": {
        "label": "AI Model (deep reasoning)",
        "description": "Smart model for the deep analyst + investigation. gpt-4o for best results. On Azure, this is your deployment name.",
        "required": False,
        "default": "gpt-4o-mini",
        "placeholder": "gpt-4o",
        "group": "API Keys"
    },
    "FAST_AI_MODEL": {
        "label": "Fast AI Model (light tasks)",
        "description": "Optional speed boost. Faster/cheaper model for latency-sensitive calls: triage classification, file summaries, chat, and Sigma/YARA/KQL generation. On Azure, deploy gpt-4o-mini and put its deployment name here. Leave blank to use the main AI Model for everything.",
        "required": False,
        "default": "",
        "placeholder": "gpt-4o-mini",
        "group": "API Keys"
    },
    "LLM_PROVIDER": {
        "label": "LLM Provider",
        "description": "Which provider every AI call routes through. openai (default, also covers Azure OpenAI when OPENAI_BASE_URL is set), anthropic, or ollama.",
        "required": False,
        "default": "openai",
        "placeholder": "openai | anthropic | ollama",
        "group": "API Keys"
    },
    "ANTHROPIC_API_KEY": {
        "label": "Anthropic API Key",
        "description": "Required when LLM_PROVIDER=anthropic. Claude Sonnet 4 by default.",
        "required": False,
        "url": "https://console.anthropic.com",
        "placeholder": "sk-ant-...",
        "group": "API Keys"
    },
    "OLLAMA_BASE_URL": {
        "label": "Ollama Base URL",
        "description": "Local Ollama endpoint when LLM_PROVIDER=ollama. Default http://localhost:11434.",
        "required": False,
        "default": "http://localhost:11434",
        "placeholder": "http://localhost:11434",
        "group": "API Keys"
    },
    "VIRUSTOTAL_KEY": {
        "label": "VirusTotal API Key",
        "description": "IP, domain, URL, hash reputation. Free: 500 req/day.",
        "required": True,
        "url": "https://virustotal.com",
        "placeholder": "64-character hex key",
        "group": "API Keys"
    },
    "ABUSEIPDB_KEY": {
        "label": "AbuseIPDB API Key",
        "description": "IP abuse confidence scores. Free: 1,000 checks/day.",
        "required": True,
        "url": "https://abuseipdb.com",
        "placeholder": "AbuseIPDB API key",
        "group": "API Keys"
    },
    "MALWAREBAZAAR_API_KEY": {
        "label": "MalwareBazaar Auth-Key",
        "description": "abuse.ch MalwareBazaar requires authentication for "
                       "every API call (since Nov 2023). Free, takes a "
                       "minute to provision. Drives the attribution chip's "
                       "malware-hash pivot.",
        "required": False,
        "url": "https://auth.abuse.ch",
        "placeholder": "MalwareBazaar Auth-Key",
        "group": "API Keys"
    },
    "IPINFO_TOKEN": {
        "label": "ipinfo.io Token",
        "description": "IP geolocation, ASN. Required for Geo Map. Free: 50,000/month.",
        "required": True,
        "url": "https://ipinfo.io",
        "placeholder": "ipinfo token",
        "group": "API Keys"
    },
    "GREYNOISE_KEY": {
        "label": "GreyNoise API Key",
        "description": "Internet noise vs targeted attack classification.",
        "required": False,
        "url": "https://greynoise.io",
        "placeholder": "GreyNoise API key",
        "group": "API Keys"
    },
    "OTX_KEY": {
        "label": "AlienVault OTX Key",
        "description": "Community threat pulses, IOC feeds.",
        "required": False,
        "url": "https://otx.alienvault.com",
        "placeholder": "OTX API key",
        "group": "API Keys"
    },
    "URLSCAN_KEY": {
        "label": "URLScan.io API Key",
        "description": "URL and domain scanning, screenshots.",
        "required": False,
        "url": "https://urlscan.io",
        "placeholder": "URLScan API key",
        "group": "API Keys"
    },
    "CROWDSEC_KEY": {
        "label": "CrowdSec CTI Key",
        "description": "Crowd-sourced IP threat intelligence.",
        "required": False,
        "url": "https://app.crowdsec.net",
        "placeholder": "CrowdSec CTI key",
        "group": "API Keys"
    },
    "PULSEDIVE_KEY": {
        "label": "Pulsedive API Key",
        "description": "Risk scoring and threat feed context.",
        "required": False,
        "url": "https://pulsedive.com",
        "placeholder": "Pulsedive API key",
        "group": "API Keys"
    },
    "PHISHTANK_KEY": {
        "label": "PhishTank App Key",
        "description": "Phishing URL database lookup.",
        "required": False,
        "url": "https://phishtank.org",
        "placeholder": "PhishTank app key",
        "group": "API Keys"
    },
    # ── Paste-site / asset enrichment sources ────────────────────────────────
    "CRIMINAL_IP_KEY": {
        "label": "Criminal IP API Key",
        "description": "IP threat scoring (inbound / outbound) + VPN / proxy / Tor / scanner classification.",
        "required": False,
        "url": "https://www.criminalip.io",
        "placeholder": "Criminal IP API key",
        "group": "API Keys"
    },
    "ABUSECH_AUTH_KEY": {
        "label": "abuse.ch API Key",
        "description": "abuse.ch API key — free at auth.abuse.ch, unlocks MalwareBazaar, "
                       "ThreatFox, and URLhaus. Required since mid-2024; anonymous calls "
                       "are heavily rate-limited.",
        "required": False,
        "url": "https://auth.abuse.ch",
        "placeholder": "abuse.ch Auth-Key",
        "group": "API Keys"
    },
    "WHOISXML_KEY": {
        "label": "Whois XML API Key",
        "description": "Domain WHOIS lookup: registrar, creation date, registrant. Strong FP signal for newly-registered domains.",
        "required": False,
        "url": "https://whoisxmlapi.com",
        "placeholder": "at_... key",
        "group": "API Keys"
    },
    "CENSYS_API_KEY": {
        "label": "Censys API Key (Personal Access Token)",
        "description": "Censys v2 Personal Access Token — single token sent "
                       "as a Bearer header. Replaces the legacy API ID + "
                       "Secret pair. Free tier: 250 queries/month. Generate "
                       "at https://search.censys.io/account/api.",
        "required": False,
        "url": "https://search.censys.io/account/api",
        "placeholder": "Censys Personal Access Token",
        "group": "API Keys"
    },
    "HYBRID_ANALYSIS_KEY": {
        "label": "Hybrid Analysis API Key",
        "description": "Sandboxed malware behavior reports. Free tier.",
        "required": False,
        "url": "https://hybrid-analysis.com",
        "placeholder": "Hybrid Analysis API key",
        "group": "API Keys"
    },
    "FULLHUNT_KEY": {
        "label": "FullHunt API Key",
        "description": "Attack surface and exposed service discovery. Free: 100/day.",
        "required": False,
        "url": "https://fullhunt.io",
        "placeholder": "FullHunt API key",
        "group": "API Keys"
    },
    "POLYSWARM_KEY": {
        "label": "Polyswarm API Key",
        "description": "Decentralized malware scanning network.",
        "required": False,
        "url": "https://polyswarm.io",
        "placeholder": "Polyswarm API key",
        "group": "API Keys"
    },
    "PROXYCHECK_KEY": {
        "label": "Proxycheck API Key",
        "description": "VPN, proxy, and Tor exit node detection. Free: 1,000/day.",
        "required": False,
        "url": "https://proxycheck.io",
        "placeholder": "Proxycheck API key",
        "group": "API Keys"
    },
    # ─── Email Composer (RECON port of the MDR email tool) ───────────────────
    "EMAIL_FROM_NAME": {
        "label": "Email · Analyst Display Name",
        "description": "Shown in the email signature block as the sender name.",
        "required": False,
        "url": "",
        "placeholder": "Jane Analyst",
        "group": "API Keys"
    },
    "EMAIL_FROM_ADDRESS": {
        "label": "Email · From Address",
        "description": "Sender address that appears in composed emails and SMTP envelope.",
        "required": False,
        "url": "",
        "placeholder": "analyst@example.com",
        "group": "API Keys"
    },
    "EMAIL_SIGNATURE": {
        "label": "Email · Custom Signature",
        "description": "Plain text or full HTML signature block. Leave blank to use the default.",
        "required": False,
        "url": "",
        "placeholder": "Best regards,\\nJane Analyst\\nMDR Team",
        "group": "API Keys"
    },
    "EMAIL_TEAM_NAME": {
        "label": "Email · Team Name",
        "description": "Used wherever templates say 'reach out to the MDR team'.",
        "required": False,
        "url": "",
        "placeholder": "the MDR analyst team",
        "group": "API Keys"
    },
    "EMAIL_SMTP_HOST": {
        "label": "Email · SMTP Host",
        "description": "Optional — if set, enables Send via SMTP from the composer.",
        "required": False,
        "url": "",
        "placeholder": "smtp.office365.com",
        "group": "API Keys"
    },
    "EMAIL_SMTP_PORT": {
        "label": "Email · SMTP Port",
        "description": "Common values: 587 (STARTTLS), 465 (SSL).",
        "required": False,
        "url": "",
        "placeholder": "587",
        "group": "API Keys"
    },
    "EMAIL_SMTP_USER": {
        "label": "Email · SMTP Username",
        "description": "Used for authenticating to the SMTP server.",
        "required": False,
        "url": "",
        "placeholder": "analyst@example.com",
        "group": "API Keys"
    },
    "EMAIL_SMTP_PASSWORD": {
        "label": "Email · SMTP Password / App Password",
        "description": "Use an app password if your provider requires one.",
        "required": False,
        "url": "",
        "placeholder": "••••••••",
        "group": "API Keys"
    },
    "EMAIL_COPY_TO": {
        "label": "Email · Default CC",
        "description": "Comma-separated addresses to CC on every sent email. Optional.",
        "required": False,
        "url": "",
        "placeholder": "team-inbox@example.com",
        "group": "API Keys"
    },
}

# Keys that work with no API key at all
FREE_APIS = [
    "MalwareBazaar (abuse.ch)",
    "ThreatFox (abuse.ch)",
    "URLHaus (abuse.ch)",
    "Feodo Tracker (abuse.ch)",
    "SSL Blacklist (abuse.ch)",
    "crt.sh (certificate transparency)",
    "WHOIS (who-dat.as93.net)",
    "BGP Ranking (CIRCL)",
    "CIRCL Passive DNS",
    "Robtex",
    "Tor exit node list (torproject.org)",
    "CIRCL Hashlookup",
    "HackerTarget",
    "Maltiverse",
]


class ConfigManager:
    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._config: dict = {}
        self._mtime: float = 0.0
        self._load()

    def _load(self):
        """Load config from file, fall back to environment variables."""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    self._config = json.load(f)
                self._mtime = CONFIG_FILE.stat().st_mtime
            except Exception:
                self._config = {}

        # Merge in environment variables (env vars take precedence for Docker/CI)
        for key in API_KEY_DEFINITIONS:
            if key in os.environ and os.environ[key]:
                self._config[key] = os.environ[key]

    def _maybe_reload(self):
        """Re-read config.json when the file's mtime advances. Lets the
        operator edit data/config.json with the backend running and have
        new keys (MalwareBazaar Auth-Key, etc.) picked up immediately
        without a restart. Cheap — one stat() call per get()."""
        if not CONFIG_FILE.exists():
            return
        try:
            mtime = CONFIG_FILE.stat().st_mtime
        except OSError:
            return
        if mtime > self._mtime:
            self._load()

    def _save(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            json.dump(self._config, f, indent=2)
        try:
            self._mtime = CONFIG_FILE.stat().st_mtime
        except OSError:
            pass

    def get(self, key: str, default: str = "") -> str:
        self._maybe_reload()
        defn = API_KEY_DEFINITIONS.get(key, {})
        return self._config.get(key) or defn.get("default") or default

    def set(self, key: str, value: str):
        self._config[key] = value
        self._save()

    def set_many(self, updates: dict):
        for k, v in updates.items():
            if k in API_KEY_DEFINITIONS:
                self._config[k] = v
        self._save()

    def is_configured(self) -> bool:
        required = [k for k, v in API_KEY_DEFINITIONS.items() if v.get("required")]
        return all(self.get(k) for k in required)

    def get_model(self, fast: bool = False) -> str:
        """Pick the model/deployment for a call. `fast=True` returns the
        lightweight model (FAST_AI_MODEL) for latency-sensitive tasks; otherwise
        the smart model (AI_MODEL) for deep reasoning. Falls back to the smart
        model if no fast model is configured."""
        if fast:
            return self.get("FAST_AI_MODEL") or self.get("AI_MODEL", "gpt-4o-mini")
        return self.get("AI_MODEL", "gpt-4o-mini")

    def get_ai_provider(self) -> str:
        return "azure" if "openai.azure.com" in self.get("OPENAI_BASE_URL", "") else "openai"

    def is_azure_openai(self) -> bool:
        return "openai.azure.com" in self.get("OPENAI_BASE_URL", "")

    def get_status(self) -> dict:
        """Return key status for health/settings UI (never returns actual key values)."""
        status = {}
        for key, defn in API_KEY_DEFINITIONS.items():
            val = self.get(key)
            status[key] = {
                "configured": bool(val),
                "required": defn.get("required", False),
                "label": defn["label"],
                "description": defn["description"],
                "url": defn.get("url"),
                "group": defn.get("group", "Other"),
                "placeholder": defn.get("placeholder", ""),
                "isDefault": val == defn.get("default", ""),
            }
        return status

    def get_settings_response(self) -> dict:
        """For the settings page — returns masked key values."""
        result = {}
        for key, defn in API_KEY_DEFINITIONS.items():
            val = self.get(key)
            default = defn.get("default", "")
            result[key] = {
                "value": val if (val == default or not val) else "•" * min(len(val), 20),
                "rawValue": val,  # sent only to settings page, masked in display
                "configured": bool(val and val != default),
                "label": defn["label"],
                "description": defn["description"],
                "required": defn.get("required", False),
                "url": defn.get("url"),
                "group": defn.get("group", "Other"),
                "placeholder": defn.get("placeholder", ""),
                "default": default,
            }
        return result


# Global singleton
config = ConfigManager()