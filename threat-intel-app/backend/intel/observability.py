"""
Observability primitives — request IDs, structured logging, error envelope.

Three concerns, all additive:

  1. `RequestIDMiddleware` attaches a UUID to every incoming request,
     stashes it in a contextvar, and echoes it back as `X-Request-ID`.
     Existing clients ignore the header; tooling that grep s logs by
     request ID gets a stable correlation key for free.

  2. `configure_logging()` installs a single JSON-ish formatter on the
     root logger that includes the timestamp, level, component name,
     message, and (when present) the current request ID. Callers obtain
     loggers via `logging.getLogger("recon.<subsystem>")` and stop
     worrying about format. Idempotent — re-calling is a no-op.

  3. `error_envelope(detail, code=None, extras=None)` builds the
     additive error body served by main.py's global HTTPException
     handler. The existing `detail` key is preserved so the React
     frontend's `err.detail || err.error || HTTP <status>` fallback
     keeps working; new clients can read `error_code` and `details`.

Nothing in this module mutates global state at import time except for
defining the contextvar. `configure_logging()` is called from main.py
during app construction.
"""

from __future__ import annotations

import contextvars
import logging
import os
import re
import sys
import time
import uuid
from typing import Any, Dict, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


# ─── per-request context ──────────────────────────────────────────────────────
request_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "recon_request_id", default=None,
)


def current_request_id() -> Optional[str]:
    """Return the request ID for the currently-handling task, or None
    when called outside a request scope (background jobs, tests, etc.)."""
    return request_id_var.get()


# ─── request ID middleware ────────────────────────────────────────────────────
_HEADER_NAME = "X-Request-ID"
# Accept only canonical UUIDv4-ish strings (32 hex + 4 hyphens, length 36).
# Anything else gets a fresh UUID so an attacker can't smuggle arbitrary text
# into the log stream by setting X-Request-ID, can't blend traffic with a
# pre-existing rid to confuse forensics, and can't pollute the response
# header echoed back to other tooling.
_RID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Stamp every request with a UUID. Reuses an inbound `X-Request-ID`
    header ONLY when it parses as a UUID (so a trusted reverse proxy can
    propagate its own trace ID without giving an untrusted client a slot
    to inject arbitrary text into our logs) and falls back to a fresh
    UUID otherwise."""

    async def dispatch(self, request: Request, call_next):
        inbound = request.headers.get(_HEADER_NAME)
        rid = inbound if inbound and _RID_RE.match(inbound) else str(uuid.uuid4())
        token = request_id_var.set(rid)
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)
        # Echo back so the client sees what to grep logs for.
        response.headers[_HEADER_NAME] = rid
        return response


# ─── logging configuration ────────────────────────────────────────────────────
class _ReconFormatter(logging.Formatter):
    """`level | timestamp | component | request_id | message`. The
    request_id slot stays empty when not in a request scope so background
    tasks don't print a misleading id."""

    _BASE_FMT = "%(asctime)s.%(msecs)03d  %(levelname)-7s  %(name)-22s  rid=%(request_id)-12s  %(message)s"

    def __init__(self) -> None:
        super().__init__(fmt=self._BASE_FMT, datefmt="%Y-%m-%dT%H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        rid = current_request_id() or "-"
        record.request_id = (rid[:8] if rid != "-" else "-")
        return super().format(record)


_CONFIGURED = False


def configure_logging(level: Optional[str] = None) -> None:
    """Install the root formatter once. Honours LOG_LEVEL env override;
    safe to call multiple times."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    lvl_name = (level or os.environ.get("LOG_LEVEL") or "INFO").upper()
    lvl = getattr(logging, lvl_name, logging.INFO)

    # Windows consoles default to cp1252, which rejects the Unicode
    # glyphs some modules use in log messages (✓ / ✗ / ↔ / —). Reconfigure
    # stdout to UTF-8 up-front so no log line can crash the handler with
    # UnicodeEncodeError. No-op on platforms where stdout is already UTF-8.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        # Older Python or already-detached stream — fall back to
        # errors="replace" via the handler so glyphs render as '?'
        # instead of raising.
        pass

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_ReconFormatter())

    root = logging.getLogger()
    # Drop existing handlers so we don't double-log in places that
    # called logging.basicConfig() earlier (e.g. taxii_poller's
    # `if __name__ == "__main__"` block).
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(lvl)

    # The noisy ones — quiet them so DEBUG doesn't drown out the real
    # signal. Tune via LOG_LEVEL=DEBUG when actively debugging.
    for noisy in ("asyncio", "aiohttp.access", "urllib3.connectionpool",
                  "uvicorn.access", "watchfiles", "openai", "httpx"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _CONFIGURED = True


# ─── error envelope ───────────────────────────────────────────────────────────
def error_envelope(
    detail:  str,
    *,
    code:    Optional[str] = None,
    extras:  Optional[Dict[str, Any]] = None,
    status:  Optional[int] = None,
) -> Dict[str, Any]:
    """Build the JSON body for an error response. Always returns the
    same shape so log scrapers and tests have one structure to match.

    Compatibility notes:
      * `detail` is what FastAPI emits by default and what the React
        frontend already reads — preserved as-is so existing clients
        don't break.
      * `error` mirrors `detail` for callers that read `err.error`
        (e.g. AgentPipeline.jsx).
      * `error_code` is a stable machine-readable slug for new clients.
      * `details` carries optional structured context (the offending
        field, an upstream error, etc.).
      * `request_id` lets the user paste a single string into a bug
        report and have the operator find the matching log line.
      * `status` echoes the HTTP code in the body for log enrichers
        that can't see the response status separately.
    """
    body: Dict[str, Any] = {
        "detail":     detail,
        "error":      detail,
        "error_code": code or "internal_error",
        "details":    extras or {},
        "request_id": current_request_id(),
        "ts":         int(time.time() * 1000),
    }
    if status is not None:
        body["status"] = status
    return body
