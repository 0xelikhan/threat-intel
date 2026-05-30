"""
Tenant-scoped HMAC hashing for identifiers.

When the platform persists or correlates anything tied to a sensitive value
(user UPN, email, hostname, IOC), it stores HMAC(key, tenant || normalized)
instead of the raw value. That gives:
  * Cross-tenant isolation: the same email hashes to a different value
    per tenant, so a leaked hash from tenant A cannot be correlated
    against tenant B's data.
  * Irreversibility: a leaked hash by itself can't be inverted to the
    original; you'd need both the per-tenant key and a brute-force.
  * Stable equality: the same value inside the same tenant always hashes
    to the same output, so correlation/dedup still works.

Key sourcing:
  * Production reads HMAC_HASH_KEY (preferred — single 32+ byte secret
    rotated centrally) OR HMAC_HASH_KEY_<TENANT_ID> for per-tenant keys
    when each tenant gets its own rotation cadence.
  * If neither is set, the module derives an ephemeral key from RECON's
    SESSION secret + a salt and warns once. This keeps single-tenant
    dev usable without an explicit secret, but the warning makes it
    obvious to ship a real key before production.

Normalization rules per input type (so trivial casing/space differences
don't produce different hashes for the same value):
  * email     -> lowercase, trim
  * upn       -> lowercase, trim
  * hostname  -> lowercase, trim, strip trailing dot
  * ip        -> trim, IPv6 normalized to compressed form
  * domain    -> lowercase, trim, strip trailing dot
  * default   -> trim
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import warnings
from typing import Optional


_DEFAULT_TENANT = "_global_"


def _key_for_tenant(tenant_id: str) -> bytes:
    """Resolve the HMAC key. Per-tenant override beats the global, both beat
    the dev-only derived fallback."""
    if tenant_id:
        per = os.environ.get(f"HMAC_HASH_KEY_{tenant_id.upper().replace('-', '_')}")
        if per:
            return per.encode("utf-8")
    glob = os.environ.get("HMAC_HASH_KEY")
    if glob:
        return glob.encode("utf-8")
    # Dev fallback: derive from the session secret so the same dev install
    # produces stable hashes across restarts, but it's clearly NOT what
    # production should run with.
    sess = os.environ.get("AUTH_SESSION_SECRET", "")
    if sess:
        _warn_once()
        return hashlib.sha256(b"recon-hmac-derived||" + sess.encode("utf-8")).digest()
    _warn_once()
    return b"recon-dev-only-hmac-key-please-rotate-me"


_warned = {"x": False}
def _warn_once():
    if _warned["x"]:
        return
    _warned["x"] = True
    warnings.warn(
        "intel.identity_hash: no HMAC_HASH_KEY set; using a derived dev key. "
        "Set HMAC_HASH_KEY (or HMAC_HASH_KEY_<TENANT_ID>) before production.",
        stacklevel=2,
    )


def _normalize(value: str, kind: str) -> str:
    if value is None:
        return ""
    v = str(value).strip()
    kind = (kind or "").lower()
    if kind in ("email", "upn"):
        return v.lower()
    if kind == "hostname":
        return v.lower().rstrip(".")
    if kind == "domain":
        return v.lower().rstrip(".")
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            return v
    return v


def hash_id(value: str, tenant_id: str = "", kind: str = "") -> str:
    """Return the hex-encoded HMAC-SHA256 of (tenant || normalized value).
    Same value within the same tenant -> stable hash; same value across
    tenants -> different hashes. Returns "" for empty input."""
    norm = _normalize(value, kind)
    if not norm:
        return ""
    key = _key_for_tenant(tenant_id)
    msg = f"{tenant_id or _DEFAULT_TENANT}||{kind or 'raw'}||{norm}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def hash_many(values, tenant_id: str = "", kind: str = "") -> list[str]:
    """Bulk-hash an iterable of values. Empty values produce empty strings
    (so the index alignment with the caller's input list is preserved)."""
    return [hash_id(v, tenant_id, kind) for v in (values or [])]


def short_hash(value: str, tenant_id: str = "", kind: str = "", chars: int = 12) -> str:
    """Display-friendly truncated form. NEVER use for equality/dedup —
    truncated hashes have collision risk; this is for human-readable logs."""
    h = hash_id(value, tenant_id, kind)
    return h[:chars] if h else ""
