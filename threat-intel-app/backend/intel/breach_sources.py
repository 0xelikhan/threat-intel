"""
Paste-site / asset enrichment sources.

Adds to the IOC enrichment pipeline:
  * Criminal IP — IP threat scoring + asset detail
  * URLScan screenshot retrieval — fetch the screenshot UUID for a previously
    scanned URL so analysts can preview the page without visiting it

Every function:
  * accepts an aiohttp ClientSession + the IOC value + a `keys` dict
  * returns a flat dict with a `source` key + optional `verdict` field
  * NEVER raises — failures return {"error": ..., "source": ..., "error_type": ...}
  * uses the shared _get / _post wrappers from agents.enrichment so circuit
    breaker + semaphore + per-source timeout apply uniformly
"""

from __future__ import annotations

from typing import Any, Dict, Optional

# Imported lazily inside functions to avoid a circular import — these
# helpers live in agents.enrichment which imports nothing from this module.


# ─── Criminal IP ─────────────────────────────────────────────────────────────
async def criminal_ip(session, ip: str, criminal_ip_key: Optional[str]) -> Dict[str, Any]:
    """Criminal IP threat scoring for a given IP. Returns inbound /
    outbound score + abuse-record summary."""
    from agents.enrichment import _get
    if not criminal_ip_key:
        return {"error": "CRIMINAL_IP_KEY not configured",
                "error_type": "not_configured", "source": "criminal_ip"}
    r = await _get(
        session,
        f"https://api.criminalip.io/v1/asset/ip/report?ip={ip}",
        headers={"x-api-key": criminal_ip_key},
    )
    return _parse_criminal_ip(r, ip)


def _parse_criminal_ip(r: Any, ip: str) -> Dict[str, Any]:
    if isinstance(r, dict) and "error" in r and "status" not in r:
        return {"source": "criminal_ip", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    if not isinstance(r, dict):
        return {"source": "criminal_ip", "error": "unexpected response shape"}

    score = (r.get("score") or {})
    inbound = (score.get("inbound") or "").lower()
    outbound = (score.get("outbound") or "").lower()
    issues = r.get("issues") or {}
    # Criminal IP score values: safe / low / moderate / dangerous / critical
    _BAD = {"dangerous", "critical"}
    _SUS = {"moderate"}

    if inbound in _BAD or outbound in _BAD:
        verdict = "MALICIOUS"
    elif inbound in _SUS or outbound in _SUS:
        verdict = "SUSPICIOUS"
    elif inbound == "safe" and outbound == "safe":
        verdict = "CLEAN"
    else:
        verdict = "UNKNOWN"

    return {
        "source":        "criminal_ip",
        "ip":            ip,
        "inbound_score":  inbound,
        "outbound_score": outbound,
        "is_vpn":         bool(issues.get("is_vpn")),
        "is_proxy":       bool(issues.get("is_proxy")),
        "is_tor":         bool(issues.get("is_tor")),
        "is_hosting":     bool(issues.get("is_hosting")),
        "is_scanner":     bool(issues.get("is_scanner")),
        "is_anonymous_vpn": bool(issues.get("is_anonymous_vpn")),
        "open_ports":     (r.get("port") or {}).get("count"),
        "country":        (r.get("whois") or {}).get("data", [{}])[0].get("org_country_code"),
        "summary":        (f"Criminal IP: inbound={inbound or 'unknown'}, "
                           f"outbound={outbound or 'unknown'}"),
        "verdict":        verdict,
    }


# ─── URLScan screenshot retrieval ────────────────────────────────────────────
async def urlscan_screenshot(session, url: str,
                             urlscan_key: Optional[str]) -> Dict[str, Any]:
    """Look up the URL on urlscan.io's search index. When a previous public
    scan exists, return the screenshot URL + scan UUID so the frontend can
    display the thumbnail inline. URLScan's search endpoint works without
    a key (rate-limited) but a key raises the limit considerably."""
    from agents.enrichment import _get
    # Search for the most-recent scan of this URL.
    headers = {"Accept": "application/json"}
    if urlscan_key:
        headers["API-Key"] = urlscan_key
    # Quote-wrap the URL for the search query. The page.url field is the
    # canonical match.
    import urllib.parse as _up
    q = _up.quote(f'page.url:"{url}"')
    r = await _get(
        session, f"https://urlscan.io/api/v1/search/?q={q}&size=1",
        headers=headers,
    )
    return _parse_urlscan_screenshot(r, url)


def _parse_urlscan_screenshot(r: Any, url: str) -> Dict[str, Any]:
    if isinstance(r, dict) and "error" in r:
        return {"source": "urlscan_screenshot", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    if not isinstance(r, dict):
        return {"source": "urlscan_screenshot",
                "error": "unexpected response shape"}

    results = r.get("results") or []
    if not results:
        return {
            "source":   "urlscan_screenshot",
            "url":      url,
            "found":    False,
            "summary":  "No prior URLScan scan found for this URL.",
        }
    first = results[0] if isinstance(results[0], dict) else {}
    uuid = first.get("_id") or (first.get("task") or {}).get("uuid")
    if not uuid:
        return {
            "source":   "urlscan_screenshot",
            "url":      url,
            "found":    False,
            "summary":  "Scan exists but UUID missing.",
        }
    verdict_data = first.get("verdicts") or {}
    overall = (verdict_data.get("overall") or {})
    malicious = bool(overall.get("malicious"))
    score = overall.get("score") or 0

    return {
        "source":         "urlscan_screenshot",
        "url":            url,
        "found":          True,
        "uuid":           uuid,
        "scan_date":      first.get("task", {}).get("time"),
        "scan_country":   first.get("page", {}).get("country"),
        "scan_ip":        first.get("page", {}).get("ip"),
        "screenshot_url": f"https://urlscan.io/screenshots/{uuid}.png",
        "scan_url":       f"https://urlscan.io/result/{uuid}/",
        "malicious":      malicious,
        "score":          score,
        "verdict":        "MALICIOUS" if malicious else ("SUSPICIOUS" if score >= 50 else "CLEAN"),
        "summary":        (f"URLScan previously scanned this URL on "
                           f"{first.get('task', {}).get('time') or 'unknown date'}; "
                           f"verdict score {score}"
                           + (" (malicious)" if malicious else "")),
    }
