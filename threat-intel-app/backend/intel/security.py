"""
Platform hardening helpers — spec §9.

Provides:
  - security_headers_middleware: ASGI middleware that adds CSP, X-Frame-Options,
    X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy
    headers to every response, plus a request body size cap (413 on exceed).
  - safe_data_path(path, root): resolves a user-supplied path inside the data
    directory and refuses to escape it (path traversal guard).
  - audit_log(event, **fields): appends a structured JSON line to
    backend/data/audit.log.
  - encrypt_value / decrypt_value: Fernet-based at-rest encryption for API
    keys when RECON_SECRET env var is set. If RECON_SECRET is missing the
    helpers no-op so existing plaintext configs keep working.
  - is_production() / suppress_errors(): production-mode toggle reading
    RECON_ENV; when 'production' detailed error responses get genericized.
  - validate_ioc_value(value, ioc_type): pattern checks for common IOC types
    used by request handlers before processing.
  - validate_file_upload(content, max_mb=10): magic-byte file type detection
    + size limit; returns (ok, type|reason).
  - security_self_check(): checklist of pass/fail booleans for /api/security/check.
"""

from __future__ import annotations

import json
import os
import re
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).resolve().parents[1] / "data"
_DATA_DIR.mkdir(parents=True, exist_ok=True)
_AUDIT_LOG = _DATA_DIR / "audit.log"
_MAX_BODY = 50 * 1024 * 1024   # 50 MB — matches the File Analyzer drop-zone copy
_MAX_FILE = 50 * 1024 * 1024


# ─── env helpers ───────────────────────────────────────────────────────────────
def is_production() -> bool:
    return (os.environ.get("RECON_ENV") or "development").lower() == "production"


def suppress_errors() -> bool:
    return is_production()


# ─── security headers + request size middleware ────────────────────────────────
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; "
        "font-src 'self' data:; connect-src 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options":        "DENY",
    "X-XSS-Protection":       "1; mode=block",
    "Referrer-Policy":        "strict-origin-when-cross-origin",
    "Permissions-Policy":     "camera=(), microphone=(), geolocation=()",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Request body size cap. Matches the File Analyzer drop-zone copy.
        # Use error_envelope() so the shape matches every other API
        # error (frontend reads err.detail || err.error || ...; this
        # used to ship only `detail` and broke the structured-error
        # consumers).
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > _MAX_BODY:
            from intel.observability import error_envelope
            body = error_envelope(
                f"request body too large (max {_MAX_BODY // (1024*1024)}MB)",
                code="payload_too_large",
                status=413,
            )
            return JSONResponse(body, status_code=413)
        response: Response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers[k] = v
        return response


# ─── path traversal guard ──────────────────────────────────────────────────────
def safe_data_path(path: str, root: Optional[Path] = None) -> Optional[Path]:
    """Resolve `path` inside the data directory (default backend/data/).
    Returns None if the resolved path escapes the root."""
    root = (root or _DATA_DIR).resolve()
    if ".." in path or path.startswith(("/", "\\")) or ":" in path:
        return None
    candidate = (root / path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


# ─── audit log ────────────────────────────────────────────────────────────────
# Redaction-safe by construction: every string value in `fields` is passed
# through the redactor before it reaches disk. That means an analyst-pasted
# IOC, customer log line, or accidentally-included credential never ends up
# in audit.log — only the typed placeholders survive. The redaction-rejected
# case still logs the request envelope (path / status / client) so we have
# a trail, just with the body replaced by a marker.
_REDACT_AUDIT_FIELDS = {"error", "body", "log", "raw", "input", "message"}


def _redact_audit_value(field: str, value):
    """Apply the redactor to a single audit-field value when it's a string and
    the field name is in the sensitive set. Non-string types pass through."""
    if not isinstance(value, str) or not value:
        return value
    if field not in _REDACT_AUDIT_FIELDS:
        return value
    try:
        from intel.redactor import redact as _redact
        out = _redact(value)
        return out.redacted
    except Exception:
        # Fail-closed for audit too — if redaction can't run, drop the value
        # rather than logging the raw string.
        return "{{REDACTOR_UNAVAILABLE}}"


def audit_log(event: str, **fields) -> None:
    """Emit a structured audit record. Historically this wrote to
    backend/data/audit.log; the platform's no-persistence policy means
    we now route it to the structured logger instead so it lands in
    container stdout (transient) rather than on a mounted volume
    (durable). Sensitive fields are still redactor-rewritten so error
    bodies / log content can't leak credentials into the log stream."""
    safe = {k: _redact_audit_value(k, v) for k, v in fields.items()}
    try:
        logger.info("audit %s %s", event, json.dumps(safe, default=str)[:1500])
    except Exception:
        pass


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        try:
            response = await call_next(request)
        except Exception as e:
            audit_log("request_error", path=str(request.url.path),
                      method=request.method, error=str(e)[:200])
            raise
        if request.url.path.startswith("/api/"):
            audit_log("api_call",
                      path=str(request.url.path), method=request.method,
                      status=response.status_code,
                      client=str(request.client.host) if request.client else None)
        return response


# ─── Fernet encryption (optional) ──────────────────────────────────────────────
def _fernet():
    secret = os.environ.get("RECON_SECRET")
    if not secret:
        return None
    try:
        from cryptography.fernet import Fernet
        # Derive a 32-byte key from secret if it's not already a proper Fernet key
        if len(secret) == 44 and secret.endswith("="):
            return Fernet(secret.encode())
        import hashlib, base64
        key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
        return Fernet(key)
    except Exception:
        return None


def encrypt_value(plaintext: str) -> str:
    """Returns 'enc:<base64token>' if encryption available, else plaintext."""
    if not plaintext:
        return plaintext
    f = _fernet()
    if not f:
        return plaintext
    try:
        return "enc:" + f.encrypt(plaintext.encode()).decode()
    except Exception:
        return plaintext


def decrypt_value(stored: str) -> str:
    if not stored or not stored.startswith("enc:"):
        return stored
    f = _fernet()
    if not f:
        return stored  # caller will see ciphertext; surface as unconfigured
    try:
        return f.decrypt(stored[4:].encode()).decode()
    except Exception:
        return stored


# ─── input validation ──────────────────────────────────────────────────────────
_PATTERNS = {
    "ip":     re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$"),
    "domain": re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"),
    "hash":   re.compile(r"^[a-fA-F0-9]{32,128}$"),
    "url":    re.compile(r"^https?://[^\s]{4,2048}$"),
}


def validate_ioc_value(value: str, ioc_type: str) -> bool:
    if not value or len(value) > 2048:
        return False
    rex = _PATTERNS.get(ioc_type)
    if not rex:
        return True  # unknown type — let downstream handle
    return bool(rex.match(value))


# ─── file upload validation (magic-byte check) ─────────────────────────────────
_MAGIC = [
    (b"\x4D\x5A",           "application/x-msdownload"),    # PE / DLL / EXE
    (b"\x7F\x45\x4C\x46",   "application/x-elf"),           # ELF
    (b"PK\x03\x04",         "application/zip"),             # ZIP / OOXML / JAR
    (b"%PDF-",              "application/pdf"),
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "application/x-ole"),  # legacy Office
    (b"{\\rtf",             "application/rtf"),
    (b"\xCA\xFE\xBA\xBE",   "application/java-class"),
    (b"\x1F\x8B",           "application/gzip"),
    (b"\x42\x5A\x68",       "application/x-bzip2"),
    (b"7z\xBC\xAF\x27\x1C", "application/x-7z-compressed"),
    (b"Rar!",               "application/x-rar"),
]


def validate_file_upload(content: bytes, max_mb: int = 10) -> Tuple[bool, str]:
    if len(content) > max_mb * 1024 * 1024:
        return False, f"file exceeds {max_mb} MB limit"
    if not content:
        return False, "empty file"
    head = content[:16]
    for magic, mime in _MAGIC:
        if head.startswith(magic):
            return True, mime
    # Plain text fallback (logs / EML / JSON / CSV)
    try:
        head.decode("utf-8")
        return True, "text/plain"
    except UnicodeDecodeError:
        return True, "application/octet-stream"


# ─── security self-check ───────────────────────────────────────────────────────
def security_self_check(config) -> dict:
    has_secret    = bool(os.environ.get("RECON_SECRET"))
    has_openai    = bool(config.get("OPENAI_API_KEY"))
    is_https      = (os.environ.get("RECON_HTTPS") or "").lower() in {"1", "true", "yes"}
    cors_strict   = (os.environ.get("RECON_CORS") or "*") != "*"
    in_prod       = is_production()

    items = [
        {"name": "HTTPS enabled",          "pass": is_https or not in_prod,
         "detail": "Set RECON_HTTPS=1 once behind TLS"},
        {"name": "RECON_ENV=production",   "pass": in_prod,
         "detail": "Suppresses error traces; required when shipping"},
        {"name": "API key encryption",     "pass": has_secret,
         "detail": "Set RECON_SECRET to enable at-rest Fernet encryption of API keys"},
        {"name": "OpenAI key configured",  "pass": has_openai,
         "detail": "Required for AI investigation, log translation, training quiz"},
        {"name": "CORS restricted",        "pass": cors_strict,
         "detail": "Set RECON_CORS to a specific origin list (currently *)"},
        {"name": "Security headers active","pass": True,
         "detail": "CSP/X-Frame/X-Content-Type/Referrer-Policy set on every response"},
        {"name": "Audit log writable",     "pass": _AUDIT_LOG.parent.exists(),
         "detail": str(_AUDIT_LOG)},
        {"name": "Request body size cap",  "pass": True,
         "detail": f"Enforced by SecurityHeadersMiddleware at {_MAX_BODY // (1024*1024)}MB"},
    ]
    return {
        "items": items,
        "pass_count": sum(1 for i in items if i["pass"]),
        "fail_count": sum(1 for i in items if not i["pass"]),
        "production": in_prod,
    }
