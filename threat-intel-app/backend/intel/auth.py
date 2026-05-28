"""
Single-user app authentication.

Why this lives in `intel/`: the existing security middleware (SecurityHeaders,
Audit) already sits in `intel/security.py`, so login is in the same neighborhood.

Storage model: zero database. The username, a bcrypt hash of the password, and
the cookie-signing secret all come from environment variables that are bound
to Container App secrets in Azure (never committed). To rotate the password
locally:

    python -c "import bcrypt; print(bcrypt.hashpw(b'<new-password>', bcrypt.gensalt(rounds=12)).decode())"

then `az containerapp secret set --name threat-intel-platform --resource-group
threat-intel-rg --secrets auth-password-hash=<paste-hash>` and restart the
revision.

Session model: signed HTTP-only cookie via Starlette's SessionMiddleware
(secret = AUTH_SESSION_SECRET). SameSite=Strict + HttpOnly + Secure (in prod)
covers XSS cookie theft and basic CSRF. Cookie lifetime defaults to 12 hours.
"""
from __future__ import annotations

import os
from typing import Optional

import bcrypt


# Read once at import — env vars are baked into the container at startup.
# When unset (e.g. running locally without secrets), auth is treated as
# misconfigured and every login attempt fails closed.
_USERNAME      = (os.environ.get("AUTH_USERNAME") or "").strip()
_PASSWORD_HASH = (os.environ.get("AUTH_PASSWORD_HASH") or "").encode("utf-8")


def auth_configured() -> bool:
    """True when both the username and a non-empty hash are wired up. Used by
    the login endpoint to return a clear 503 instead of an opaque 401 when the
    operator forgot to bind the Container App secrets."""
    return bool(_USERNAME and _PASSWORD_HASH)


def verify_credentials(username: str, password: str) -> bool:
    """Constant-time check: returns True only when the supplied username
    matches AUTH_USERNAME *and* bcrypt verifies the supplied password against
    AUTH_PASSWORD_HASH. Returns False on any error so a bad/corrupt hash can't
    leak a 500 with a stack trace.

    Note: we still call bcrypt.checkpw even on a username mismatch so the
    response time doesn't reveal whether the username was wrong vs the
    password — both paths pay the bcrypt cost."""
    if not auth_configured():
        return False
    try:
        ok_user = (username or "").strip() == _USERNAME
        # checkpw is constant-time per char; passing a dummy hash on user
        # mismatch keeps timing identical to the genuine-user-wrong-pw path.
        ok_pass = bcrypt.checkpw((password or "").encode("utf-8"), _PASSWORD_HASH)
        return ok_user and ok_pass
    except Exception:
        return False


def current_user(session: dict) -> Optional[str]:
    """Read the logged-in username off the Starlette session dict. Returns
    None when the session is empty or doesn't have our marker key."""
    if not isinstance(session, dict):
        return None
    return session.get("auth_user") or None
