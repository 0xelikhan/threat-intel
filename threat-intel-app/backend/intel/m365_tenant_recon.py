"""
Microsoft 365 / Entra tenant recon.

Unauthenticated fingerprinting of M365-hosted domains. Adapted from
cti-expert (MIT, Hieu Ngo, chongluadao.vn) techniques/microsoft-tenant-recon.md
— our value-add is a pure-Python implementation that lives in the same
async aiohttp session as the rest of enrichment (no msftrecon subprocess
required) and a fail-open gate that skips the work entirely when the
domain isn't M365.

Endpoints probed (zero auth required, all read-only):
  1. login.microsoftonline.com/getuserrealm.srf — federation type +
     brand name + federation provider (AD FS / Okta / Ping / …)
  2. login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration
     — tenant ID (GUID via `issuer` field), cloud instance
  3. {tenant}.sharepoint.com — SharePoint tenant existence
  4. {tenant}.azurewebsites.net — Azure App Service tenant existence

Output shape lines up with every other RECON enrichment source so it
drops into per-source rendering without special casing:

  {
    "is_m365":         bool,
    "tenant_id":       "...uuid..." | None,
    "tenant_name":     str | None,        # prefix like "contoso"
    "brand_name":      str | None,
    "federation_type": "Managed" | "Federated" | "Unknown",
    "federation_provider": str | None,    # AD FS / Okta / Ping / …
    "cloud_instance":  "commercial" | "usgov" | "china" | None,
    "sharepoint":      bool,
    "azure_app_service": bool,
    "endpoints_checked": list[dict],      # for the evidence chain
    "verdict":         "CLEAN" | "SUSPICIOUS",
    "summary":         str,
    "source":          "m365_tenant_recon",
  }

This is INFRA intel, not a malice verdict. `verdict` defaults to CLEAN;
we tag SUSPICIOUS only when something points to a misconfiguration
worth flagging (e.g. federation provider is EOL, tenant lacks MDI
presence indicators). Most callers will just read the structured fields.

Latency budget: 4 concurrent HTTPS GETs to MS-owned endpoints. Per-host
caps in agents.enrichment._SLOW_HOSTS already cover these.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.intel.m365_tenant_recon")


_GUID_RE = re.compile(
    r"\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b",
    re.IGNORECASE,
)
_TENANT_NAME_RE = re.compile(
    r"^https?://login\.microsoftonline\.([a-z]+)/([^/]+)/", re.IGNORECASE,
)


def _detect_cloud(issuer: str) -> Optional[str]:
    """Map the OIDC `issuer` URL host to one of the three M365 clouds."""
    if not issuer:
        return None
    lower = issuer.lower()
    if "microsoftonline.us" in lower or "login.microsoftonline.us" in lower:
        return "usgov"
    if "microsoftonline.cn" in lower or "partner.microsoftonline.cn" in lower:
        return "china"
    if "microsoftonline.com" in lower or "sts.windows.net" in lower:
        return "commercial"
    return None


def _tenant_prefix(domain: str) -> str:
    """Best-effort guess of the SharePoint / Azure tenant slug. M365
    tenants default to the SLD label (`contoso.onmicrosoft.com` →
    `contoso`); some orgs customise but the default catches the vast
    majority and a 404 on the probe is a clean negative either way."""
    if not domain:
        return ""
    parts = domain.lower().strip(".").split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


async def _probe_openid_config(session, domain: str) -> Dict[str, Any]:
    """Pull the tenant's openid-configuration. The `issuer` field
    contains the tenant ID as a GUID (https://sts.windows.net/{GUID}/)
    and the cloud instance. 200 = M365 tenant exists, 400 = domain
    not on M365."""
    url = (f"https://login.microsoftonline.com/{domain}"
           f"/v2.0/.well-known/openid-configuration")
    try:
        async with session.get(url, timeout=8) as r:
            if r.status != 200:
                return {"ok": False, "status": r.status, "endpoint": url}
            data = await r.json(content_type=None)
            issuer = (data.get("issuer") or "").strip()
            guid_m = _GUID_RE.search(issuer)
            return {
                "ok":        True,
                "status":    200,
                "endpoint":  url,
                "issuer":    issuer,
                "tenant_id": guid_m.group(1).lower() if guid_m else None,
                "cloud":     _detect_cloud(issuer),
            }
    except Exception as e:
        return {"ok": False, "error": str(e)[:120], "endpoint": url}


async def _probe_userrealm(session, domain: str) -> Dict[str, Any]:
    """getuserrealm.srf returns federation posture for an arbitrary
    user@domain. We use a dummy localpart since we only care about the
    domain-level fields."""
    url = (f"https://login.microsoftonline.com/getuserrealm.srf"
           f"?login=test@{domain}&json=1")
    try:
        async with session.get(url, timeout=8) as r:
            if r.status != 200:
                return {"ok": False, "status": r.status, "endpoint": url}
            data = await r.json(content_type=None)
            return {
                "ok":               True,
                "status":           200,
                "endpoint":         url,
                "federation_type":  data.get("NameSpaceType"),
                "brand":            data.get("FederationBrandName"),
                "federation_url":   data.get("AuthURL"),
                "domain_name":      data.get("DomainName"),
            }
    except Exception as e:
        return {"ok": False, "error": str(e)[:120], "endpoint": url}


async def _probe_sharepoint(session, tenant: str) -> Dict[str, Any]:
    """SharePoint tenant existence — HEAD to {tenant}.sharepoint.com.
    401/403 = exists (auth required to read), 404 = no such tenant."""
    if not tenant:
        return {"ok": False, "endpoint": ""}
    url = f"https://{tenant}.sharepoint.com"
    try:
        async with session.head(url, timeout=8, allow_redirects=False) as r:
            return {
                "ok":       True,
                "status":   r.status,
                "endpoint": url,
                "exists":   r.status in (401, 403, 200, 301, 302),
            }
    except Exception as e:
        return {"ok": False, "error": str(e)[:120], "endpoint": url}


async def _probe_azure_app(session, tenant: str) -> Dict[str, Any]:
    """Azure App Service tenant — {tenant}.azurewebsites.net. 404 means
    no app, 403 / 200 / 502 means the slug is taken."""
    if not tenant:
        return {"ok": False, "endpoint": ""}
    url = f"https://{tenant}.azurewebsites.net"
    try:
        async with session.head(url, timeout=8, allow_redirects=False) as r:
            return {
                "ok":       True,
                "status":   r.status,
                "endpoint": url,
                "exists":   r.status not in (404,),
            }
    except Exception as e:
        return {"ok": False, "error": str(e)[:120], "endpoint": url}


def _derive_federation_provider(federation_url: str) -> Optional[str]:
    """Best-effort: read the AuthURL host and label common IdPs."""
    if not isinstance(federation_url, str) or not federation_url:
        return None
    h = federation_url.lower()
    if "adfs" in h or "/adfs/" in h:
        return "AD FS"
    if "okta.com" in h:
        return "Okta"
    if "ping" in h:
        return "Ping Identity"
    if "onelogin.com" in h:
        return "OneLogin"
    if "duosecurity.com" in h:
        return "Duo"
    if "auth0.com" in h:
        return "Auth0"
    return None


async def enrich(session, domain: str) -> Dict[str, Any]:
    """Run the full 4-probe pass against a domain. Caller is expected
    to gate the call — see `is_m365_candidate` below."""
    if not isinstance(domain, str) or not domain.strip():
        return {"is_m365": False, "source": "m365_tenant_recon",
                "verdict": "CLEAN", "summary": "empty domain"}

    domain = domain.strip().lower().rstrip(".")
    tenant = _tenant_prefix(domain)

    oidc_task   = _probe_openid_config(session, domain)
    realm_task  = _probe_userrealm(session, domain)
    sp_task     = _probe_sharepoint(session, tenant)
    azure_task  = _probe_azure_app(session, tenant)

    oidc, realm, sp, azure = await asyncio.gather(
        oidc_task, realm_task, sp_task, azure_task,
        return_exceptions=True,
    )

    def _safe(x):
        return x if isinstance(x, dict) else {"ok": False, "error": str(x)[:120]}

    oidc, realm, sp, azure = _safe(oidc), _safe(realm), _safe(sp), _safe(azure)

    # No openid-config + no realm response → domain isn't on M365.
    if not oidc.get("ok") and not realm.get("ok"):
        return {
            "is_m365":  False,
            "verdict":  "CLEAN",
            "summary":  f"{domain} does not appear to be a Microsoft 365 tenant.",
            "source":   "m365_tenant_recon",
            "endpoints_checked": [oidc, realm, sp, azure],
        }

    tenant_id  = oidc.get("tenant_id")
    cloud      = oidc.get("cloud")
    fed_type   = realm.get("federation_type")
    brand      = realm.get("brand")
    fed_url    = realm.get("federation_url")
    fed_prov   = _derive_federation_provider(fed_url or "")
    sp_exists  = bool(sp.get("exists"))
    az_exists  = bool(azure.get("exists"))

    bits: List[str] = []
    if tenant_id:
        bits.append(f"tenant_id={tenant_id}")
    if cloud:
        bits.append(f"cloud={cloud}")
    if fed_type:
        bits.append(f"federation={fed_type}")
    if fed_prov:
        bits.append(f"idp={fed_prov}")
    if brand:
        bits.append(f"brand={brand!r}")
    if sp_exists:
        bits.append("sharepoint=yes")
    if az_exists:
        bits.append("azure_app_service=yes")

    verdict = "CLEAN"
    # Federated tenants are higher-attack-surface (SAML/IdP layer).
    # We surface that as SUSPICIOUS so the analyst pivots to the IdP,
    # not because the tenant itself is malicious.
    if fed_type and fed_type.lower() == "federated":
        verdict = "SUSPICIOUS"

    summary = (
        f"Microsoft 365 tenant fingerprinted ({domain}). "
        + " · ".join(bits)
        + (". Federated tenants share trust with the IdP — extend the "
           "investigation to that provider." if verdict == "SUSPICIOUS" else ".")
    )

    return {
        "is_m365":              True,
        "tenant_id":            tenant_id,
        "tenant_name":          tenant or None,
        "brand_name":           brand,
        "federation_type":      fed_type,
        "federation_provider":  fed_prov,
        "cloud_instance":       cloud,
        "sharepoint":           sp_exists,
        "azure_app_service":    az_exists,
        "endpoints_checked":    [oidc, realm, sp, azure],
        "verdict":              verdict,
        "summary":              summary,
        "source":               "m365_tenant_recon",
    }


def is_m365_candidate(per_source_enrichment: Dict[str, Any]) -> bool:
    """Cheap pre-check the caller runs against the rest of the domain's
    enrichment payload to decide whether to fire the 4-probe pass.
    Inspects WHOIS / MX / SPF fields for the M365 indicators called out
    in the cti-expert technique doc. Returns True when at least one
    Microsoft-hosted signal is present."""
    if not isinstance(per_source_enrichment, dict):
        return False

    # Look at WHOIS / DNS-style fields that the existing enrichment
    # already populates. Field names vary by source; check several.
    pools: List[str] = []
    for key in ("whois", "wayback", "shodan", "ipinfo"):
        v = per_source_enrichment.get(key)
        if isinstance(v, dict):
            for sub in v.values():
                if isinstance(sub, (str, int, float)):
                    pools.append(str(sub))
                elif isinstance(sub, (list, tuple)):
                    pools.extend(str(x) for x in sub if isinstance(x, (str, int, float)))

    hay = " ".join(pools).lower()
    return any(needle in hay for needle in (
        "protection.outlook.com",
        "spf.protection.outlook.com",
        "outlook.office",
        "onmicrosoft.com",
        "microsoft.com",
        "office365",
        "exchange online",
    ))


def stats() -> Dict[str, Any]:
    """Available for /api/status. No persistent index — every call is
    a live network probe."""
    return {
        "loaded":           True,
        "endpoints_probed": 4,
        "note":             "Live probe, no cache — caller should respect breaker.",
    }
