"""
Error message registry — every analyst-facing error in one place with a
plain-English explanation and an actionable fix hint.

Usage:
    from intel.error_messages import lookup, lookup_for_exception
    msg = lookup("OPENAI_API_KEY_MISSING")
    # → {"detail": "...", "error_code": "openai_key_missing",
    #    "fix_hint": "Open Settings and add your Azure OpenAI key..."}

The keys are stable string identifiers. Call sites pass them by name
rather than re-spelling the message — adds one place to update wording
across the platform.

For raw exceptions, `lookup_for_exception(exc)` walks the registry and
returns the first match by exception class name + message substring,
falling back to `INTERNAL_ERROR` when nothing matches.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


# ─── registry ─────────────────────────────────────────────────────────────────
# Each entry: detail (analyst-facing), error_code (machine slug),
# fix_hint (specific instruction the analyst can act on right now).
_REGISTRY: Dict[str, Dict[str, str]] = {

    # ── LLM provider configuration ────────────────────────────────────────────
    "OPENAI_API_KEY_MISSING": {
        "detail":    "Azure OpenAI key is not configured.",
        "error_code": "openai_key_missing",
        "fix_hint":  ("Open Settings and add your Azure OpenAI key from the "
                      "Azure Portal → your OpenAI resource → Keys and Endpoint."),
    },
    "OPENAI_BASE_URL_MISSING": {
        "detail":    "Azure OpenAI endpoint is not configured.",
        "error_code": "openai_base_url_missing",
        "fix_hint":  ("Open Settings and add OPENAI_BASE_URL — the endpoint URL "
                      "from the Azure Portal → your OpenAI resource → Keys and "
                      "Endpoint (looks like https://<name>.openai.azure.com/)."),
    },
    "OPENAI_AUTH_FAILED": {
        "detail":    "Azure OpenAI rejected your key (authentication failed).",
        "error_code": "openai_auth_failed",
        "fix_hint":  ("Your AI key is invalid or expired. Check that you copied "
                      "the full key from the Azure Portal and that it hasn't been "
                      "rotated. Open Settings to paste the current key."),
    },
    "OPENAI_RATE_LIMITED": {
        "detail":    "Azure OpenAI rate-limited the request.",
        "error_code": "openai_rate_limited",
        "fix_hint":  ("Your deployment has reached its TPM (tokens-per-minute) "
                      "quota. Wait 60 seconds and try again, or increase the TPM "
                      "quota in the Azure Portal → your deployment → Manage."),
    },
    "OPENAI_TIMEOUT": {
        "detail":    "Azure OpenAI did not respond in time.",
        "error_code": "openai_timeout",
        "fix_hint":  ("The AI service is slow or unreachable. Retry the request. "
                      "If this persists, check the Azure status page and your "
                      "deployment's current capacity in the Azure Portal."),
    },
    "OPENAI_BAD_JSON": {
        "detail":    "AI returned a response that couldn't be parsed as JSON.",
        "error_code": "openai_bad_json",
        "fix_hint":  ("The AI produced an unstructured response. RECON retried "
                      "once with a corrected instruction. If this keeps happening "
                      "try a shorter input or check your model deployment."),
    },

    # ── Enrichment sources ────────────────────────────────────────────────────
    "SOURCE_TIMEOUT": {
        "detail":    "Enrichment source did not respond within 12 seconds.",
        "error_code": "source_timeout",
        "fix_hint":  ("The source may be temporarily down. Your result will not "
                      "include data from this source. Other sources are unaffected."),
    },
    "SOURCE_AUTH_FAILED": {
        "detail":    "Enrichment source rejected your API key.",
        "error_code": "source_auth_failed",
        "fix_hint":  ("The API key for this source is invalid or expired. Open "
                      "Settings and refresh the key from your account at the "
                      "source's provider portal."),
    },
    "SOURCE_RATE_LIMITED": {
        "detail":    "Enrichment source rate-limited the request.",
        "error_code": "source_rate_limited",
        "fix_hint":  ("You've hit the source's request quota. Wait for the limit "
                      "to reset, or upgrade your plan with the source provider."),
    },
    "SOURCE_CIRCUIT_OPEN": {
        "detail":    "Enrichment source is currently being skipped (circuit breaker open).",
        "error_code": "source_circuit_open",
        "fix_hint":  ("The source failed three times in a row, so RECON is "
                      "skipping it for 5 minutes. It will be retried automatically."),
    },

    # ── Per-source key configuration ──────────────────────────────────────────
    "CENSYS_INCOMPLETE": {
        "detail":    "Censys requires both an API ID and a secret.",
        "error_code": "censys_incomplete",
        "fix_hint":  ("Open Settings and add BOTH the CENSYS_ID and CENSYS_SECRET "
                      "from your Censys account → API page. One without the other "
                      "won't authenticate."),
    },
    "VT_KEY_MISSING": {
        "detail":    "VirusTotal API key is not configured.",
        "error_code": "virustotal_key_missing",
        "fix_hint":  ("Open Settings and add VIRUSTOTAL_KEY from your VirusTotal "
                      "account → API key page. A free key is sufficient for low "
                      "volume; paid is needed for sustained use."),
    },
    "ABUSEIPDB_KEY_MISSING": {
        "detail":    "AbuseIPDB API key is not configured.",
        "error_code": "abuseipdb_key_missing",
        "fix_hint":  ("Open Settings and add ABUSEIPDB_KEY from your AbuseIPDB "
                      "account → API page (1,000 free checks per day)."),
    },
    "OTX_KEY_MISSING": {
        "detail":    "AlienVault OTX API key is not configured.",
        "error_code": "otx_key_missing",
        "fix_hint":  ("Open Settings and add OTX_KEY from your OTX profile → "
                      "API integration page. Free for community use."),
    },
    "GREYNOISE_KEY_MISSING": {
        "detail":    "GreyNoise API key is not configured.",
        "error_code": "greynoise_key_missing",
        "fix_hint":  ("Open Settings and add GREYNOISE_KEY from your GreyNoise "
                      "Community account → API page."),
    },

    # ── Static datasets ───────────────────────────────────────────────────────
    "MITRE_DATASET_MISSING": {
        "detail":    "MITRE ATT&CK dataset (enterprise-attack.json) is missing.",
        "error_code": "mitre_dataset_missing",
        "fix_hint":  ("Run this from the project root to download it:\n"
                      "  curl -L -o threat-intel-app/backend/intel/mitre/enterprise-attack.json "
                      "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json\n"
                      "Then restart the backend."),
    },
    "WARNINGLISTS_MISSING": {
        "detail":    "MISP warninglists are not installed.",
        "error_code": "warninglists_missing",
        "fix_hint":  ("False-positive filtering is disabled. Run "
                      "`scripts/setup_vendor.sh` from the project root to download "
                      "the MISP warninglists vendor pack."),
    },

    # ── Detection generation ──────────────────────────────────────────────────
    "SIGMA_VALIDATION_FAILED": {
        "detail":    "Generated Sigma rule has a syntax error.",
        "error_code": "sigma_validation_failed",
        "fix_hint":  ("The AI will retry automatically. If this keeps happening "
                      "try a more specific log input — sparse alerts produce "
                      "rules that sigma-cli rejects."),
    },
    "SIGMA_CLI_MISSING": {
        "detail":    "sigma-cli is not installed; rule was generated but not validated.",
        "error_code": "sigma_cli_missing",
        "fix_hint":  ("Install sigma-cli with `pip install sigma-cli` in the "
                      "backend venv to enable validation. The generated rule is "
                      "still usable as-is."),
    },
    "YARA_COMPILATION_FAILED": {
        "detail":    "Generated YARA rule failed to compile.",
        "error_code": "yara_compilation_failed",
        "fix_hint":  ("The compilation error is included in the response. Edit "
                      "the rule to fix the reported syntax issue or regenerate "
                      "with more specific file context."),
    },

    # ── File analysis ─────────────────────────────────────────────────────────
    "UNSUPPORTED_FILE_TYPE": {
        "detail":    "RECON doesn't have a format-specific parser for this file type.",
        "error_code": "unsupported_file_type",
        "fix_hint":  ("Basic hashes, entropy, and string extraction still ran — "
                      "format-specific (PE / Office / PDF / archive) checks were "
                      "skipped because this format isn't supported."),
    },
    "SANDBOX_UNAVAILABLE": {
        "detail":    "Sandbox APIs are unavailable.",
        "error_code": "sandbox_unavailable",
        "fix_hint":  ("Hybrid Analysis or URLScan didn't respond. Static analysis "
                      "completed normally; dynamic / sandbox analysis is missing "
                      "from this scan."),
    },
    "FILE_TOO_LARGE": {
        "detail":    "File exceeds the 50 MB scan size limit.",
        "error_code": "file_too_large",
        "fix_hint":  ("Trim or chunk the file before scanning, or run YARA "
                      "against it directly outside RECON."),
    },

    # ── Generic / fallback ────────────────────────────────────────────────────
    "INTERNAL_ERROR": {
        "detail":    "Unexpected backend error.",
        "error_code": "internal_error",
        "fix_hint":  ("Check the X-Request-ID header on the response and search "
                      "the backend logs for that ID for the full stack trace."),
    },
    "NOT_CONFIGURED": {
        "detail":    "RECON is not fully configured.",
        "error_code": "not_configured",
        "fix_hint":  "Open Settings to configure the required keys.",
    },
    "AUTH_REQUIRED": {
        "detail":    "You need to sign in to access this resource.",
        "error_code": "auth_required",
        "fix_hint":  "Sign in via /login and retry.",
    },
}


# ─── lookup helpers ───────────────────────────────────────────────────────────
def lookup(key: str, **fmt: Any) -> Dict[str, str]:
    """Return the registry entry for `key`, applying str.format to every
    field with the supplied kwargs. Unknown keys return INTERNAL_ERROR
    so the call site stays branch-free."""
    entry = _REGISTRY.get(key) or _REGISTRY["INTERNAL_ERROR"]
    if not fmt:
        return dict(entry)
    return {k: (v.format(**fmt) if isinstance(v, str) else v) for k, v in entry.items()}


# Exception-class-name + message-substring matchers, evaluated in order.
# The first match wins; falls back to INTERNAL_ERROR when nothing matches.
_EXC_PATTERNS = (
    # OpenAI / Anthropic / Azure errors
    (("AuthenticationError",),       ("",),                      "OPENAI_AUTH_FAILED"),
    (("RateLimitError",),            ("",),                      "OPENAI_RATE_LIMITED"),
    (("APITimeoutError", "TimeoutError"), ("",),                 "OPENAI_TIMEOUT"),
    # JSON parse failures from the LLM
    (("JSONDecodeError", "ValueError"), ("json",),               "OPENAI_BAD_JSON"),
    # Aiohttp HTTP failures — mapped by status text
    (("ClientError",),               ("401", "403", "unauthorized", "forbidden"), "SOURCE_AUTH_FAILED"),
    (("ClientError",),               ("429", "rate limit"),                       "SOURCE_RATE_LIMITED"),
    (("ClientError", "TimeoutError"), ("timeout", "timed out"),                   "SOURCE_TIMEOUT"),
    # Filesystem
    (("FileNotFoundError",),         ("mitre", "enterprise-attack.json"),         "MITRE_DATASET_MISSING"),
    (("FileNotFoundError",),         ("warninglists",),                           "WARNINGLISTS_MISSING"),
)


def lookup_for_exception(exc: BaseException) -> Dict[str, str]:
    """Best-effort mapping from a raw exception to a registry entry.
    Matches on class name + lower-cased message substring; falls back
    to INTERNAL_ERROR."""
    cls = type(exc).__name__
    msg = str(exc).lower()
    for class_names, needles, key in _EXC_PATTERNS:
        if cls in class_names and any(n in msg for n in needles):
            return lookup(key)
    return lookup("INTERNAL_ERROR")


def all_keys() -> Dict[str, Dict[str, str]]:
    """Return the full registry — used by the /api/diagnose endpoint to
    enumerate every well-known error code."""
    return {k: dict(v) for k, v in _REGISTRY.items()}
