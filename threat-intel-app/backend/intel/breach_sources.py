"""
Breach-database and paste-site enrichment sources.

Adds to the IOC enrichment pipeline:
  * HaveIBeenPwned (HIBP) — email breach history (requires HIBP_KEY since 2019)
  * Dehashed — email + username search across leaked credential databases
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

import base64
from typing import Any, Dict, Optional

# Imported lazily inside functions to avoid a circular import — these
# helpers live in agents.enrichment which imports nothing from this module.


# ─── HaveIBeenPwned ──────────────────────────────────────────────────────────
async def hibp_email(session, email: str, hibp_key: Optional[str]) -> Dict[str, Any]:
    """Look up an email address against HIBP's breach database. HIBP requires
    a paid API key for /breachedaccount; returns a clear "key not configured"
    error when missing (frontend tags it as auth_failed and prompts the
    analyst to add a key in Settings)."""
    from agents.enrichment import _get
    if not hibp_key:
        return {"error": "HIBP_KEY not configured", "error_type": "auth_failed",
                "source": "hibp"}
    url = (f"https://haveibeenpwned.com/api/v3/breachedaccount/"
           f"{email}?truncateResponse=false&includeUnverified=false")
    r = await _get(
        session, url,
        headers={"hibp-api-key": hibp_key,
                 "user-agent": "RECON-MDR-Platform/1.0"},
    )
    return _parse_hibp(r, email)


def _parse_hibp(r: Any, email: str) -> Dict[str, Any]:
    """HIBP returns a 404 (we get {"error": ...}) when the email has no
    breaches; 200 with a list when it does. Normalize either case."""
    if isinstance(r, dict) and "error" in r:
        # 404 means "no breaches found" — that's a CLEAN verdict.
        if "404" in str(r.get("error", "")) or "Not Found" in str(r.get("error", "")):
            return {
                "source":       "hibp",
                "email":        email,
                "breach_count": 0,
                "breaches":     [],
                "verdict":      "CLEAN",
                "summary":      "No breaches found in HIBP for this email.",
            }
        return {"source": "hibp", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    if not isinstance(r, list):
        return {"source": "hibp", "error": "unexpected response shape"}

    breaches = []
    total_pwned = 0
    all_classes: set = set()
    for b in r:
        if not isinstance(b, dict):
            continue
        classes = b.get("DataClasses") or []
        total_pwned += int(b.get("PwnCount") or 0)
        for c in classes:
            all_classes.add(c)
        breaches.append({
            "name":          b.get("Name"),
            "title":         b.get("Title"),
            "domain":        b.get("Domain"),
            "breach_date":   b.get("BreachDate"),
            "added_date":    b.get("AddedDate"),
            "pwn_count":     b.get("PwnCount"),
            "data_classes":  classes,
            "verified":      b.get("IsVerified", False),
            "sensitive":     b.get("IsSensitive", False),
            "fabricated":    b.get("IsFabricated", False),
        })

    n = len(breaches)
    # Verdict scaling — credential breach exposure is a real compromised-
    # account signal. Threshold tuned to match user spec: "an email
    # appearing in 15 data breaches is a strong indicator of compromise".
    if n >= 10:
        verdict = "MALICIOUS"
    elif n >= 3:
        verdict = "SUSPICIOUS"
    elif n >= 1:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "source":           "hibp",
        "email":            email,
        "breach_count":     n,
        "breaches":         breaches[:20],     # cap UI render size
        "total_pwn_count":  total_pwned,
        "data_classes":     sorted(all_classes)[:20],
        "verdict":          verdict,
        "summary":          (f"{n} breach{'es' if n != 1 else ''} exposed this "
                             f"email; {total_pwned:,} total records affected; "
                             f"exposed data types: "
                             f"{', '.join(sorted(all_classes)[:8])}"
                             if n else "No breaches found in HIBP."),
    }


# ─── Dehashed ────────────────────────────────────────────────────────────────
async def dehashed_search(session, identifier: str, kind: str,
                          dehashed_email: Optional[str],
                          dehashed_key: Optional[str]) -> Dict[str, Any]:
    """Search Dehashed for an email or username. Dehashed uses HTTP Basic
    auth with the account-email + API-key pair. `kind` controls the
    Dehashed query operator ('email:foo' / 'username:bar')."""
    from agents.enrichment import _get
    if not (dehashed_email and dehashed_key):
        return {"error": "DEHASHED_EMAIL + DEHASHED_KEY not configured",
                "error_type": "auth_failed", "source": "dehashed"}
    query_field = {"email": "email", "username": "username"}.get(kind, "email")
    auth_token = base64.b64encode(
        f"{dehashed_email}:{dehashed_key}".encode()
    ).decode()
    r = await _get(
        session,
        f"https://api.dehashed.com/search?query={query_field}:{identifier}",
        headers={"Accept": "application/json",
                 "Authorization": f"Basic {auth_token}"},
    )
    return _parse_dehashed(r, identifier)


def _parse_dehashed(r: Any, identifier: str) -> Dict[str, Any]:
    if isinstance(r, dict) and "error" in r:
        return {"source": "dehashed", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    if not isinstance(r, dict):
        return {"source": "dehashed", "error": "unexpected response shape"}

    total = int(r.get("total") or 0)
    entries = r.get("entries") or []
    # Surface a curated subset of fields (Dehashed returns everything
    # including plaintext passwords which we never want in the UI).
    hits = []
    for e in entries[:20]:
        if not isinstance(e, dict):
            continue
        hits.append({
            "database":    e.get("database_name"),
            "email":       e.get("email"),
            "username":    e.get("username"),
            "has_password":  bool(e.get("password")),
            "has_hash":      bool(e.get("hashed_password")),
            "ip_address":  e.get("ip_address"),
            "phone":       e.get("phone"),
            "name":        e.get("name"),
        })

    if total >= 10:
        verdict = "MALICIOUS"
    elif total >= 3:
        verdict = "SUSPICIOUS"
    elif total >= 1:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "source":     "dehashed",
        "identifier": identifier,
        "total":      total,
        "hits":       hits,
        "verdict":    verdict,
        "summary":    (f"{total} record{'s' if total != 1 else ''} found in "
                       f"Dehashed breach databases."
                       if total else "No records in Dehashed."),
    }


# ─── Criminal IP ─────────────────────────────────────────────────────────────
async def criminal_ip(session, ip: str, criminal_ip_key: Optional[str]) -> Dict[str, Any]:
    """Criminal IP threat scoring for a given IP. Returns inbound /
    outbound score + abuse-record summary."""
    from agents.enrichment import _get
    if not criminal_ip_key:
        return {"error": "CRIMINAL_IP_KEY not configured",
                "error_type": "auth_failed", "source": "criminal_ip"}
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
