"""
OpenCTI bidirectional sync.

PUSH  — after an analysis completes, optionally push the findings as a
        STIX 2.1 Report linked to Observable objects for every extracted IOC.

PULL  — during enrichment, optionally query OpenCTI for existing context on
        each IOC (labels, score, related entities, prior reports).

Configured via config.json:
  OPENCTI_URL   — e.g. https://opencti.example.com
  OPENCTI_TOKEN — API token from the user's profile page

PUSH happens in a background task so it never blocks the analyst's view.
PULL is a single batched query at enrichment time.
"""
import asyncio
from datetime import datetime, timezone


# Map our IOC type names to OpenCTI/STIX observable types + simple-observable keys
_TYPE_MAP = {
    "ips":     ("IPv4-Addr",    "IPv4-Addr.value"),
    "domains": ("Domain-Name",  "Domain-Name.value"),
    "urls":    ("Url",          "Url.value"),
    "emails":  ("Email-Addr",   "Email-Addr.value"),
}


def _hash_key(h: str) -> str | None:
    """Return STIX simple-observable key for a hash based on its length."""
    if len(h) == 32:
        return "File.hashes.MD5"
    if len(h) == 40:
        return "File.hashes.SHA-1"
    if len(h) == 64:
        return "File.hashes.SHA-256"
    return None


def _level_to_score(threat_level: str) -> int:
    return {"CRITICAL": 95, "HIGH": 80, "MEDIUM": 55, "LOW": 25, "INFORMATIONAL": 10}.get(
        (threat_level or "").upper(), 30,
    )


def _client(url: str, token: str):
    """Return a configured OpenCTIApiClient or raise. TLS verification is on
    by default; operators with a self-hosted OpenCTI behind a private CA can
    set OPENCTI_INSECURE_TLS=1 to fall back to ssl_verify=False."""
    from pycti import OpenCTIApiClient
    import os as _os
    verify = (_os.environ.get("OPENCTI_INSECURE_TLS") or "").lower() not in {"1", "true", "yes"}
    return OpenCTIApiClient(url, token, log_level="error", ssl_verify=verify)


async def push_result(result: dict, opencti_url: str, opencti_token: str) -> dict:
    """Push a RECON analysis result to OpenCTI as a Report + linked Observables.
    Runs the synchronous pycti operations in a thread so we don't block the event loop."""
    if not (opencti_url and opencti_token):
        return {"ok": False, "error": "OPENCTI_URL / OPENCTI_TOKEN not configured"}
    return await asyncio.to_thread(_sync_push_result, result, opencti_url, opencti_token)


def _sync_push_result(result: dict, opencti_url: str, opencti_token: str) -> dict:
    try:
        client = _client(opencti_url, opencti_token)
    except ImportError:
        return {"ok": False, "error": "pycti library not installed"}
    except Exception as e:
        return {"ok": False, "error": f"OpenCTI connection failed: {e}"}

    rs = result.get("response_summary") or {}
    iocs = result.get("iocs") or {}
    threat_level = rs.get("threat_level", "INFORMATIONAL")
    score = _level_to_score(threat_level)

    # Ensure a stable RECON identity exists in this OpenCTI instance
    identity_id = None
    try:
        identity = client.identity.create(
            type="Organization",
            name="RECON Threat Intelligence Platform",
            description="Automated MDR/SOC investigation pipeline",
        )
        identity_id = identity.get("id")
    except Exception:
        pass

    observable_refs = []
    errors = []

    # ── Create observables ───────────────────────────────────────────────
    for ioc_type, items in iocs.items():
        if not items:
            continue
        if ioc_type == "hashes":
            for h in items[:50]:
                key = _hash_key(h)
                if not key:
                    continue
                try:
                    obs = client.stix_cyber_observable.create(
                        simple_observable_key=key,
                        simple_observable_value=h,
                        x_opencti_score=score,
                        x_opencti_description=f"From RECON run · threat level {threat_level}",
                        createdBy=identity_id,
                    )
                    if obs and obs.get("id"):
                        observable_refs.append(obs["id"])
                except Exception as e:
                    errors.append(f"hash {h[:12]}…: {e}")
            continue

        stix_type_pair = _TYPE_MAP.get(ioc_type)
        if not stix_type_pair:
            continue
        _, key = stix_type_pair
        for v in items[:50]:
            try:
                obs = client.stix_cyber_observable.create(
                    simple_observable_key=key,
                    simple_observable_value=v,
                    x_opencti_score=score,
                    x_opencti_description=f"From RECON run · threat level {threat_level}",
                    createdBy=identity_id,
                )
                if obs and obs.get("id"):
                    observable_refs.append(obs["id"])
            except Exception as e:
                errors.append(f"{ioc_type[:-1]} {str(v)[:60]}: {e}")

    # ── Create a Report linking the observables ──────────────────────────
    report_id, report_url = None, None
    try:
        name = f"RECON · {threat_level} · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
        body_parts = [rs.get("summary", "")]
        if (rs.get("analyst_summary") or {}).get("disposition_reason"):
            body_parts.append("Disposition: " + rs["analyst_summary"]["disposition_reason"])
        if rs.get("mitre_techniques"):
            body_parts.append("MITRE: " + ", ".join(rs["mitre_techniques"][:10]))
        labels = []
        for t_ in (rs.get("mitre_techniques") or [])[:8]:
            labels.append("attack-" + t_.split(" ")[0].lower())
        if threat_level:
            labels.append(f"recon-{threat_level.lower()}")
        report = client.report.create(
            name=name,
            description="\n\n".join([p for p in body_parts if p])[:5000],
            published=datetime.now(timezone.utc).isoformat(),
            report_types=["threat-report"],
            createdBy=identity_id,
            objects=observable_refs,
            x_opencti_score=score,
            labels=labels,
            confidence=int((rs.get("confidence") or 0.5) * 100),
        )
        if report:
            report_id  = report.get("id")
            report_url = f"{opencti_url.rstrip('/')}/dashboard/analyses/reports/{report_id}"
    except Exception as e:
        return {"ok": False, "error": str(e),
                "observables_pushed": len(observable_refs), "errors": errors[:5]}

    return {"ok": True,
            "report_id":          report_id,
            "report_url":         report_url,
            "observables_pushed": len(observable_refs),
            "errors":             errors[:5]}


# ─── PULL ─────────────────────────────────────────────────────────────────────────
async def lookup_observable(value: str, opencti_url: str, opencti_token: str) -> dict | None:
    """Look up an existing observable in OpenCTI. Returns context if found."""
    if not (value and opencti_url and opencti_token):
        return None
    return await asyncio.to_thread(_sync_lookup, value, opencti_url, opencti_token)


def _sync_lookup(value: str, opencti_url: str, opencti_token: str) -> dict | None:
    try:
        client = _client(opencti_url, opencti_token)
    except Exception:
        return None
    try:
        obs = client.stix_cyber_observable.read(
            filters={"mode": "and",
                     "filters": [{"key": "value", "values": [value]}],
                     "filterGroups": []},
        )
    except Exception:
        return None
    if not obs:
        return None
    return {
        "found":       True,
        "score":       obs.get("x_opencti_score"),
        "labels":      [l.get("value") for l in (obs.get("objectLabel") or [])][:8],
        "description": (obs.get("x_opencti_description") or "")[:280],
        "created":     obs.get("created"),
        "report_url":  f"{opencti_url.rstrip('/')}/dashboard/observations/observables/{obs.get('id')}",
    }


def is_configured(config) -> bool:
    return bool(config.get("OPENCTI_URL") and config.get("OPENCTI_TOKEN"))
