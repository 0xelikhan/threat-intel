"""
MISP push adapter — create an Event in an operator-configured MISP
instance from a RECON investigation result.

PyMISP is already in requirements.txt (for the read-side galaxy
loaders). This module uses the same dependency to PUSH IOCs out as a
new MISP event — closes the loop so RECON findings can flow into the
operator's shared threat-intel platform.

Operator configuration via env or settings:
  MISP_URL          — https://misp.example.org
  MISP_KEY          — PyMISP automation key
  MISP_VERIFYCERT   — 1 / 0 (default 1)

When unset, the push endpoint returns 503 with a clear "configure MISP
in Settings" message.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.intel.misp_push")


# Map RECON IOC types → MISP attribute types. MISP uses very granular
# naming (ip-src vs ip-dst, etc.) — we default to ip-dst (outbound) for
# IPs since RECON's reactive triage usually surfaces C2 / attacker IPs.
_IOC_TYPE_TO_MISP = {
    "ips":     ("Network activity",  "ip-dst"),
    "domains": ("Network activity",  "domain"),
    "urls":    ("Network activity",  "url"),
    "hashes":  ("Payload delivery",  "_HASH_"),
    "emails":  ("Payload delivery",  "email-src"),
    "cves":    ("External analysis", "vulnerability"),
}


def _config_or_none(config: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, str]]:
    """Resolve MISP config from the supplied dict, the ConfigManager
    singleton, or env vars (in that order)."""
    cfg: Dict[str, str] = {}
    if isinstance(config, dict):
        for k in ("MISP_URL", "MISP_KEY", "MISP_VERIFYCERT"):
            v = config.get(k)
            if v:
                cfg[k] = str(v)
    if not cfg.get("MISP_URL"):
        try:
            from config import config as _cm
            for k in ("MISP_URL", "MISP_KEY", "MISP_VERIFYCERT"):
                v = _cm.get(k)
                if v and not cfg.get(k):
                    cfg[k] = str(v)
        except Exception:
            pass
    for k in ("MISP_URL", "MISP_KEY", "MISP_VERIFYCERT"):
        if not cfg.get(k):
            v = os.environ.get(k)
            if v:
                cfg[k] = v
    if not cfg.get("MISP_URL") or not cfg.get("MISP_KEY"):
        return None
    cfg.setdefault("MISP_VERIFYCERT", "1")
    return cfg


def _build_misp_attributes(iocs: Dict[str, List[str]],
                           investigation: Dict[str, Any]) -> List[Dict[str, str]]:
    """Build the MISP attributes list from RECON's IOC dict."""
    attrs: List[Dict[str, str]] = []
    actor_label = ""
    actor = (investigation or {}).get("threat_actor")
    if isinstance(actor, dict):
        actor_label = actor.get("name") or actor.get("group") or ""
    elif isinstance(actor, str):
        actor_label = actor

    for ioc_type, values in (iocs or {}).items():
        spec = _IOC_TYPE_TO_MISP.get(ioc_type)
        if not spec or not isinstance(values, list):
            continue
        category, misp_type = spec
        for v in values[:50]:
            if not isinstance(v, str) or not v:
                continue
            if misp_type == "_HASH_":
                length = len(v)
                if   length == 32: misp_type_resolved = "md5"
                elif length == 40: misp_type_resolved = "sha1"
                elif length == 64: misp_type_resolved = "sha256"
                else: continue
            else:
                misp_type_resolved = misp_type
            comment_bits = ["from RECON"]
            if actor_label:
                comment_bits.append(f"actor: {actor_label}")
            attrs.append({
                "type":       misp_type_resolved,
                "category":   category,
                "value":      v,
                "to_ids":     True,
                "comment":    "; ".join(comment_bits)[:160],
            })
    return attrs


def push_event(iocs: Dict[str, List[str]],
               investigation: Dict[str, Any],
               response_summary: Optional[Dict[str, Any]] = None,
               distribution: int = 0,
               threat_level_id: int = 3,
               analysis: int = 1,
               config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Push a single Event with all IOCs as attributes. Returns
    {ok, event_id, url, error}. Synchronous PyMISP call; runs from
    a worker thread (asyncio.to_thread) when called from FastAPI.

    distribution / threat_level_id / analysis are MISP standard enums:
      distribution     : 0=org-only, 1=community, 2=connected, 3=all
      threat_level_id  : 1=high, 2=medium, 3=low, 4=undefined
      analysis         : 0=initial, 1=ongoing, 2=completed
    """
    cfg = _config_or_none(config)
    if not cfg:
        return {"ok": False, "error": "MISP not configured",
                "error_code": "not_configured"}

    try:
        from pymisp import PyMISP, MISPEvent, MISPAttribute
    except Exception as e:
        return {"ok": False, "error": f"pymisp unavailable: {e}",
                "error_code": "pymisp_missing"}

    verify_cert = cfg.get("MISP_VERIFYCERT", "1") not in ("0", "false", "False")
    try:
        misp = PyMISP(cfg["MISP_URL"], cfg["MISP_KEY"], ssl=verify_cert)
    except Exception as e:
        return {"ok": False, "error": f"MISP connect failed: {e}",
                "error_code": "connect_failed"}

    inv = investigation or {}
    rs  = response_summary or {}
    verdict = (rs.get("threat_level") or inv.get("verdict")
                or "UNKNOWN").upper()
    actor   = ""
    raw_actor = inv.get("threat_actor")
    if isinstance(raw_actor, dict):
        actor = raw_actor.get("name") or raw_actor.get("group") or ""
    elif isinstance(raw_actor, str):
        actor = raw_actor

    event = MISPEvent()
    event.info = (f"RECON {verdict} — {actor}" if actor
                  else f"RECON {verdict} investigation")[:240]
    event.distribution     = distribution
    event.threat_level_id  = threat_level_id
    event.analysis         = analysis

    # Add MITRE technique tags + a "recon:auto-pushed" tag for upstream
    # filtering / sharing-policy decisions.
    techniques: List[str] = []
    for t in (inv.get("mitre_techniques") or []):
        if isinstance(t, str):
            tid = t.split(" ", 1)[0].strip()
            if tid.upper().startswith("T"):
                techniques.append(tid)
    for tag_name in {
        "tlp:amber",
        "recon:auto-pushed",
        *[f"mitre-attack:{tid}" for tid in techniques[:10]],
    }:
        try:
            event.add_tag(tag_name)
        except Exception:
            pass

    for attr in _build_misp_attributes(iocs, inv):
        try:
            event.add_attribute(**attr)
        except Exception as e:
            _log.debug("misp_push: skipping bad attribute %s: %s", attr, e)

    if not event.attributes:
        return {"ok": False, "error": "no IOCs to push",
                "error_code": "empty"}

    try:
        result = misp.add_event(event, pythonify=True)
    except Exception as e:
        return {"ok": False, "error": f"MISP add_event failed: {e}",
                "error_code": "push_failed"}

    if hasattr(result, "uuid"):
        return {
            "ok":       True,
            "event_id": str(getattr(result, "id", "")),
            "uuid":     str(getattr(result, "uuid", "")),
            "url":      f"{cfg['MISP_URL'].rstrip('/')}/events/view/"
                         f"{getattr(result, 'id', '')}",
            "attribute_count": len(event.attributes),
        }
    if isinstance(result, dict) and result.get("errors"):
        return {"ok": False, "error": str(result["errors"])[:240],
                "error_code": "misp_error"}
    return {"ok": False, "error": f"unexpected MISP response: {result!r}",
            "error_code": "unknown"}
