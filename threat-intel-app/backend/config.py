"""
Config Manager
Reads and writes API keys to a local config.json file.
Keys never leave the user's machine — no telemetry, no cloud sync.
"""

import json
import os
from pathlib import Path
from typing import Optional

DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))
CONFIG_FILE = DATA_DIR / "config.json"

# All supported API keys with metadata for the settings UI
API_KEY_DEFINITIONS = {
    # Required for core functionality
    "OPENAI_API_KEY": {
        "label": "OpenAI API Key",
        "description": "Used for AI threat assessment, Sigma rule generation, and KQL query building.",
        "required": True,
        "url": "https://platform.openai.com/api-keys",
        "placeholder": "sk-...",
        "group": "AI"
    },
    "OPENAI_BASE_URL": {
        "label": "OpenAI Base URL",
        "description": "Leave default for OpenAI. Change for Azure OpenAI or local models (e.g. Ollama).",
        "required": False,
        "default": "https://api.openai.com/v1",
        "placeholder": "https://api.openai.com/v1",
        "group": "AI"
    },
    "AI_MODEL": {
        "label": "AI Model",
        "description": "Which model to use for analysis. gpt-4o-mini is recommended for cost efficiency.",
        "required": False,
        "default": "gpt-4o-mini",
        "placeholder": "gpt-4o-mini",
        "group": "AI"
    },
    "VIRUSTOTAL_KEY": {
        "label": "VirusTotal API Key",
        "description": "IP, domain, URL, and hash reputation. Free tier: 500 requests/day.",
        "required": True,
        "url": "https://virustotal.com",
        "placeholder": "64-character hex key",
        "group": "Core TI"
    },
    "ABUSEIPDB_KEY": {
        "label": "AbuseIPDB API Key",
        "description": "IP abuse confidence scores and reports. Free tier: 1,000 checks/day.",
        "required": True,
        "url": "https://abuseipdb.com",
        "placeholder": "API key from abuseipdb.com",
        "group": "Core TI"
    },
    "IPINFO_TOKEN": {
        "label": "ipinfo.io Token",
        "description": "IP geolocation, org, ASN. Required for the Geo Map tab. Free: 50,000/month.",
        "required": True,
        "url": "https://ipinfo.io",
        "placeholder": "Token from ipinfo.io",
        "group": "Core TI"
    },
    "SHODAN_KEY": {
        "label": "Shodan API Key",
        "description": "Open ports, services, banners, known CVEs. Free tier available.",
        "required": False,
        "url": "https://shodan.io",
        "placeholder": "Shodan API key",
        "group": "Core TI"
    },
    "GREYNOISE_KEY": {
        "label": "GreyNoise API Key",
        "description": "Identifies internet noise vs targeted activity. Free community tier.",
        "required": False,
        "url": "https://greynoise.io",
        "placeholder": "GreyNoise API key",
        "group": "Core TI"
    },
    "OTX_KEY": {
        "label": "AlienVault OTX Key",
        "description": "Community threat pulse database. Free — sign up at otx.alienvault.com.",
        "required": False,
        "url": "https://otx.alienvault.com",
        "placeholder": "OTX API key",
        "group": "Core TI"
    },
    "URLSCAN_KEY": {
        "label": "URLScan.io API Key",
        "description": "URL and domain scanning. Free tier: 1,000 scans/day.",
        "required": False,
        "url": "https://urlscan.io",
        "placeholder": "URLScan API key",
        "group": "Core TI"
    },
    "PHISHTANK_KEY": {
        "label": "PhishTank App Key",
        "description": "Phishing URL database lookup. Free with registration.",
        "required": False,
        "url": "https://phishtank.org",
        "placeholder": "PhishTank app key",
        "group": "Extended TI"
    },
    "PULSEDIVE_KEY": {
        "label": "Pulsedive API Key",
        "description": "Risk scoring and threat feed context for domains. Free tier available.",
        "required": False,
        "url": "https://pulsedive.com",
        "placeholder": "Pulsedive API key",
        "group": "Extended TI"
    },
}

# Keys that work with no API key at all
FREE_APIS = [
    "MalwareBazaar (abuse.ch)",
    "ThreatFox (abuse.ch)",
    "URLHaus (abuse.ch)",
    "crt.sh (certificate transparency)",
    "WHOIS (who-dat.as93.net)",
    "BGP Ranking (CIRCL)",
    "Tor exit node list (torproject.org)",
]


class ConfigManager:
    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._config: dict = {}
        self._load()

    def _load(self):
        """Load config from file, fall back to environment variables."""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    self._config = json.load(f)
            except Exception:
                self._config = {}

        # Merge in environment variables (env vars take precedence for Docker/CI)
        for key in API_KEY_DEFINITIONS:
            if key in os.environ and os.environ[key]:
                self._config[key] = os.environ[key]

    def _save(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            json.dump(self._config, f, indent=2)

    def get(self, key: str, default: str = "") -> str:
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
        """True if minimum required keys are present."""
        required = [k for k, v in API_KEY_DEFINITIONS.items() if v.get("required")]
        return all(self.get(k) for k in required)

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
