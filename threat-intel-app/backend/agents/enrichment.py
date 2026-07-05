"""
Enrichment Agent — all API keys read from config at call time.
Zero AI tokens — pure parallel HTTP calls.

Concurrency model:
* `_SEMAPHORE` caps the number of in-flight HTTP requests across the
  whole process. Default 10; tunable via ENRICH_CONCURRENCY env var.
  Prevents the fan-out from saturating downstream rate limits when
  several investigations run in parallel.
* `_get_connector()` returns a single process-wide TCPConnector. Every
  ClientSession we open passes connector_owner=False so they share the
  TCP/DNS pool but don't close the connector when the session exits.
  ttl_dns_cache=300 saves a DNS round trip per source on repeat calls.
* `_TIMEOUT` (aiohttp.ClientTimeout) is the *transport* timeout —
  protects against slow body reads. `_PER_SOURCE_TIMEOUT` wraps the
  whole `_get`/`_post` with asyncio.wait_for so a hung TLS handshake
  or parser deadlock also returns rather than stalling the gather.
* MISP warninglist filtering happens in triage (agents/triage.py) BEFORE
  this module is called, so known-clean IOCs never reach enrichment.
"""

import asyncio
import hashlib
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import aiohttp

from intel.circuit_breaker import get_breaker, host_of

_log = logging.getLogger("recon.enrichment")


def _humanise_exc(e: BaseException) -> str:
    """aiohttp's default str() leaks `0, message='', url=URL(...)` which is
    meaningless in a user-visible 'error' field. Map common exception
    types to a short phrase, fall back to the exception class name."""
    if isinstance(e, asyncio.TimeoutError):
        return "request timed out"
    if isinstance(e, getattr(aiohttp, "TooManyRedirects", ())):
        return "too many redirects"
    if isinstance(e, getattr(aiohttp, "InvalidURL", ())):
        return "URL is malformed"
    if isinstance(e, getattr(aiohttp, "ClientConnectorError", ())):
        return "could not connect (DNS or refused)"
    if isinstance(e, getattr(aiohttp, "ServerDisconnectedError", ())):
        return "server closed the connection"
    if isinstance(e, getattr(aiohttp, "ClientPayloadError", ())):
        return "malformed response body"
    if isinstance(e, getattr(aiohttp, "ClientResponseError", ())):
        s = getattr(e, "status", 0) or 0
        m = getattr(e, "message", "") or ""
        if s > 0:
            return f"HTTP {s}" + (f" ({m})" if m else "")
        return "server returned an empty or malformed response"
    msg = str(e).strip()
    if (not msg
            or msg.startswith("0, message=")
            or "message='', url=URL(" in msg):
        cls = type(e).__name__
        return (cls.replace("Error", " error")
                   .replace("Exception", " exception")
                   .strip().lower()) or "unknown error"
    return msg[:200]

# Transport timeout (aiohttp-internal — covers connect + read body).
# This is the INNER timeout — fires before the wait_for safety net if
# the upstream is slow. Default 10 s is fine for most sources; slow
# hosts get a per-host override (see _SLOW_HOSTS) that bumps BOTH
# the inner aiohttp timeout AND the outer wait_for cap. Previously
# only wait_for was bumped, which meant OTX's 12-second body still
# tripped the 10 s aiohttp timeout first — the visible "timed out"
# wasn't from our safety net, it was from aiohttp internal.
_TIMEOUT = aiohttp.ClientTimeout(total=10)
# Outer safety-net timeout (wraps the whole call, including parsing).
_PER_SOURCE_TIMEOUT = float(os.getenv("ENRICH_SOURCE_TIMEOUT_S", "12"))
# Slow hosts: per-host (transport, safety) tuple. Transport must be
# the aiohttp.ClientTimeout the session.get gets; safety is the outer
# wait_for cap. Both have to grow together — bumping only the outer
# one (what we did before) doesn't help because aiohttp fires first.
_SLOW_HOSTS: "dict[str, tuple[aiohttp.ClientTimeout, float]]" = {
    # OTX's /general endpoint takes 11-15 s anonymously and longer
    # with an API key because pulse aggregation expands. The user
    # was hitting "timed out" because of the 10 s inner aiohttp
    # timeout, not the outer safety. Both bumped.
    "otx.alienvault.com":      (aiohttp.ClientTimeout(total=90),  90.0),
    "www.virustotal.com":      (aiohttp.ClientTimeout(total=20),  20.0),
    "www.hybrid-analysis.com": (aiohttp.ClientTimeout(total=20),  20.0),
}


def _timeouts_for(host: str | None) -> "tuple[aiohttp.ClientTimeout, float]":
    """Return (aiohttp transport timeout, outer wait_for cap) for a host."""
    return _SLOW_HOSTS.get(host or "", (_TIMEOUT, _PER_SOURCE_TIMEOUT))
# Cap on in-flight HTTP fan-out — protects downstream rate limits and
# our own event loop from a thousand simultaneous sockets. Bumped from
# 10 → 16 → 24 (successive perf passes): the per-host cap in
# _get_connector (ENRICH_POOL_PER_HOST=10) independently bounds traffic
# to any single TI source, so this only adds cross-host parallelism.
# With 18 IP + 21 domain sources fanning out concurrently per IOC,
# raising the global cap meaningfully reduces tail latency on the
# enrichment node.
_SEMAPHORE = asyncio.Semaphore(int(os.getenv("ENRICH_CONCURRENCY", "24")))
# Backwards-compat alias — older code in this module imports TIMEOUT.
TIMEOUT = _TIMEOUT

# Per-pipeline-run dedup cache. The full /api/analyze flow clears this
# at the top of run_enrichment(), but skill-registry / MCP / direct
# enrich_* callers never go through run_enrichment, so the dict would
# grow linearly forever as Claude Desktop / Cursor users hit the MCP
# lookup tools. BoundedDict gives FIFO eviction at 1000 entries — much
# larger than any single analysis needs but still capped, so MCP usage
# can't drain memory over a multi-day container lifetime.
from bg_utils import BoundedDict as _BoundedDict
_cache: dict = _BoundedDict(cap=1000)
_tor_nodes: set = set()
_tor_fetched: float = 0.0

# Process-wide connector singleton — see module docstring.
_CONNECTOR: "aiohttp.TCPConnector | None" = None


def _get_connector() -> aiohttp.TCPConnector:
    """Lazy-create the shared TCPConnector. Recreated if the previous
    one was closed (e.g. after a Hot reload in dev)."""
    global _CONNECTOR
    if _CONNECTOR is None or _CONNECTOR.closed:
        _CONNECTOR = aiohttp.TCPConnector(
            limit=int(os.getenv("ENRICH_POOL_LIMIT", "100")),
            limit_per_host=int(os.getenv("ENRICH_POOL_PER_HOST", "10")),
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
        )
    return _CONNECTOR


async def close_connector() -> None:
    """Close the shared connector. Called from the FastAPI lifespan
    shutdown hook so we don't leak sockets on graceful exit."""
    global _CONNECTOR
    if _CONNECTOR is not None and not _CONNECTOR.closed:
        await _CONNECTOR.close()
    _CONNECTOR = None


def _ck(ioc_type: str, value: str) -> str:
    return f"{ioc_type}:{hashlib.md5(value.encode()).hexdigest()}"


# ─── Per-host network timing histogram ──────────────────────────────────────
# Lightweight bookkeeping so the operator can spot slow / failing TI
# sources via /api/status without reaching for a profiler. The dict is
# bounded (max ~100 hosts) — anything beyond that gets a "..." bucket.
# Reset on demand via reset_network_timings() so an analyst can scope
# a measurement to a single analyze run.
_TIMING_MAX_HOSTS = 100
_network_timings: Dict[str, Dict[str, float]] = {}


def _record_timing(host: Optional[str], elapsed_ms: float, *,
                   ok: bool, status: int = 0) -> None:
    """Record one HTTP call. Cheap — single dict lookup, no locks."""
    h = host or "?unknown"
    bucket = _network_timings.get(h)
    if bucket is None:
        if len(_network_timings) >= _TIMING_MAX_HOSTS:
            h = "?overflow"
            bucket = _network_timings.get(h)
        if bucket is None:
            bucket = {"count": 0, "ok_count": 0, "err_count": 0,
                      "total_ms": 0.0, "max_ms": 0.0, "last_status": 0}
            _network_timings[h] = bucket
    bucket["count"]     += 1
    bucket["total_ms"]  += elapsed_ms
    bucket["max_ms"]    = max(bucket["max_ms"], elapsed_ms)
    bucket["last_status"] = status or bucket.get("last_status", 0)
    if ok:
        bucket["ok_count"] += 1
    else:
        bucket["err_count"] += 1


def network_timings_snapshot(top: int = 25) -> List[Dict[str, Any]]:
    """Return a top-N-by-mean-ms snapshot for /api/status. Includes
    ok/error counts so the operator can see whether a slow source is
    actually serving traffic or just timing out."""
    rows: List[Dict[str, Any]] = []
    for host, b in _network_timings.items():
        count = max(1, int(b.get("count") or 1))
        rows.append({
            "host":       host,
            "count":      count,
            "ok":         int(b.get("ok_count")  or 0),
            "errors":     int(b.get("err_count") or 0),
            "mean_ms":    round(float(b.get("total_ms") or 0.0) / count, 1),
            "max_ms":     round(float(b.get("max_ms") or 0.0), 1),
            "last_status": int(b.get("last_status") or 0),
        })
    rows.sort(key=lambda r: -r["mean_ms"])
    return rows[:top]


def reset_network_timings() -> None:
    """Clear the histogram — used by /api/status?reset=1 or tests."""
    _network_timings.clear()


async def _get(session, url, **kw):
    """Issue one GET inside the global semaphore, bounded by the per-source
    safety timeout, gated by the per-host circuit breaker. Never raises —
    always returns a dict (with `error` + `error_type` keys on failure) so
    callers + the frontend can categorise the failure without parsing the
    message string.

    error_type values: timed_out | circuit_open | auth_failed |
    rate_limited | unreachable | http_error"""
    breaker = get_breaker()
    host = host_of(url)
    if host and breaker.is_open(host):
        _log.debug("circuit open — skipping %s", host)
        return {"error": f"circuit open for {host}", "error_type": "circuit_open",
                "skipped": True}
    transport_to, safety = _timeouts_for(host)

    async def _do():
        async with session.get(url, timeout=transport_to, **kw) as r:
            status = r.status
            payload = await r.json() if "json" in r.content_type else {"raw": await r.text()}
            return status, payload
    _t0 = time.perf_counter()
    try:
        async with _SEMAPHORE:
            status, payload = await asyncio.wait_for(_do(), timeout=safety)
        _record_timing(host, (time.perf_counter() - _t0) * 1000.0,
                        ok=True, status=status)
        # Tag categorical failures so the frontend can render them
        # consistently (auth → "check your key", rate-limit → "wait n s").
        if status in (401, 403):
            if host: breaker.record_failure(host)
            return {"error": f"auth failed (HTTP {status})", "error_type": "auth_failed"}
        if status == 429:
            if host: breaker.record_failure(host)
            return {"error": "rate limited (HTTP 429)", "error_type": "rate_limited"}
        if status >= 500:
            if host: breaker.record_failure(host)
            return {"error": f"server error (HTTP {status})", "error_type": "http_error"}
        # Successful response. Some APIs return 200 with a JSON error
        # body — treat that as a soft failure for breaker accounting.
        if isinstance(payload, dict) and "error" in payload and not isinstance(payload.get("error"), bool):
            if host: breaker.record_failure(host)
        else:
            if host: breaker.record_success(host)
        return payload
    except asyncio.TimeoutError:
        if host: breaker.record_failure(host)
        _record_timing(host, (time.perf_counter() - _t0) * 1000.0,
                        ok=False, status=0)
        return {"error": f"source timed out after {safety:.0f}s",
                "error_type": "timed_out"}
    except Exception as e:
        if host: breaker.record_failure(host)
        _record_timing(host, (time.perf_counter() - _t0) * 1000.0,
                        ok=False, status=0)
        return {"error": _humanise_exc(e), "error_type": "unreachable"}


async def _post(session, url, **kw):
    """POST variant of `_get` — same semaphore, same timeout discipline,
    same circuit breaker, same never-raise contract, same error_type tags."""
    breaker = get_breaker()
    host = host_of(url)
    if host and breaker.is_open(host):
        _log.debug("circuit open — skipping %s", host)
        return {"error": f"circuit open for {host}", "error_type": "circuit_open",
                "skipped": True}
    transport_to, safety = _timeouts_for(host)

    async def _do():
        async with session.post(url, timeout=transport_to, **kw) as r:
            status = r.status
            payload = await r.json() if "json" in r.content_type else {"raw": await r.text()}
            return status, payload
    try:
        async with _SEMAPHORE:
            status, payload = await asyncio.wait_for(_do(), timeout=safety)
        if status in (401, 403):
            if host: breaker.record_failure(host)
            return {"error": f"auth failed (HTTP {status})", "error_type": "auth_failed"}
        if status == 429:
            if host: breaker.record_failure(host)
            return {"error": "rate limited (HTTP 429)", "error_type": "rate_limited"}
        if status >= 500:
            if host: breaker.record_failure(host)
            return {"error": f"server error (HTTP {status})", "error_type": "http_error"}
        if isinstance(payload, dict) and "error" in payload and not isinstance(payload.get("error"), bool):
            if host: breaker.record_failure(host)
        else:
            if host: breaker.record_success(host)
        return payload
    except asyncio.TimeoutError:
        if host: breaker.record_failure(host)
        return {"error": f"source timed out after {safety:.0f}s",
                "error_type": "timed_out"}
    except Exception as e:
        if host: breaker.record_failure(host)
        return {"error": _humanise_exc(e), "error_type": "unreachable"}


async def _noop():
    """Placeholder coroutine for conditionally-disabled sources — returns sentinel."""
    return {"error": "source not configured", "skipped": True}


async def _tor(session):
    global _tor_nodes, _tor_fetched
    import time
    if _tor_nodes and time.time() - _tor_fetched < 3600:
        return _tor_nodes
    try:
        async with session.get("https://check.torproject.org/torbulkexitlist", timeout=TIMEOUT) as r:
            text = await r.text()
            _tor_nodes = {l.strip() for l in text.splitlines() if l.strip() and not l.startswith("#")}
            _tor_fetched = time.time()
    except Exception:
        pass
    return _tor_nodes


def _safe(d, *keys, default=None):
    try:
        for k in keys:
            d = d[k]
        return d
    except Exception:
        return default


# ─── PARSERS ──────────────────────────────────────────────────────────────────────
#
# Every parser:
#   - accepts an HTTP response (dict / list / Exception)
#   - returns a flat human-readable dict
#   - on failure returns {"error": "<reason>", "source": "<name>"}
#   - adds a "verdict" field on data-bearing results when the source signal is strong
#     enough to call it (MALICIOUS / SUSPICIOUS / CLEAN / UNKNOWN)
#
def _err(source: str, reason) -> dict:
    # Plain `str(None)` produces the literal 'None' which the frontend
    # renders as "error: None" — meaningless to an analyst. When the
    # source returned no data at all (reason is None), report it that
    # way so the source card can show the right empty state.
    if reason is None:
        return {"error": "no data", "source": source}
    if isinstance(reason, Exception):
        return {"error": _humanise_exc(reason), "source": source}
    # When the parser received a categorical-error dict from _get / _post
    # (circuit_open, auth_failed, rate_limited, timed_out, http_error,
    # unreachable), preserve BOTH the human-readable message AND the
    # error_type so the frontend can render the right translated phrasing
    # instead of stringifying the whole dict via Python repr (which
    # surfaces to the analyst as "{'error': 'circuit open...', 'error_type':
    # 'circuit_open', 'skipped': True}" — looks like a stack trace leak).
    if isinstance(reason, dict):
        inner_err = reason.get("error")
        out = {"source": source}
        if isinstance(inner_err, str) and inner_err.strip():
            out["error"] = inner_err.strip()
        else:
            out["error"] = "no data"
        if reason.get("error_type"):
            out["error_type"] = reason["error_type"]
        if reason.get("skipped"):
            out["skipped"] = True
        return out
    s = str(reason).strip()
    msg = s if s and s.lower() != "none" else "no data"
    return {"error": msg, "source": source}

def _is_fail(r) -> bool:
    return isinstance(r, Exception) or not isinstance(r, (dict, list)) or (
        isinstance(r, dict) and "error" in r and "source" not in r
    )


def _p_abuse(r):
    if _is_fail(r):
        return _err("abuseipdb", r)
    d = _safe(r, "data", default={}) or {}
    score = d.get("abuseConfidenceScore") or 0
    out = {
        "abuseScore":     score,
        "totalReports":   d.get("totalReports"),
        "country":        d.get("countryCode"),
        "isp":            d.get("isp"),
        "usageType":      d.get("usageType"),
        "lastReportedAt": d.get("lastReportedAt"),
        "isWhitelisted":  d.get("isWhitelisted"),
        "domain":         d.get("domain"),
        "hostnames":      (d.get("hostnames") or [])[:5],
    }
    # Recent 5 reports — categories + reporter country (per spec §3)
    reports = (d.get("reports") or [])[:5]
    if reports:
        out["recent_reports"] = [
            {
                "reportedAt":      x.get("reportedAt"),
                "categories":      x.get("categories"),
                "reporterCountry": x.get("reporterCountryCode"),
                "comment":         (x.get("comment") or "")[:140],
            }
            for x in reports
        ]
    # Flag same-day IP activity (first/last reported within 24 h is high signal)
    last = d.get("lastReportedAt")
    if last:
        try:
            ts = datetime.fromisoformat(str(last).replace("Z", "+00:00"))
            hours = (datetime.now(timezone.utc) - ts).total_seconds() / 3600
            if hours < 24:
                out["recent_activity"] = {"hours_since_last_report": round(hours, 1),
                                          "is_active_today": True}
            elif hours < 168:
                out["recent_activity"] = {"hours_since_last_report": round(hours, 1),
                                          "is_active_this_week": True}
        except Exception:
            pass
    # Source-level verdict — aligned with AbuseIPDB's own published
    # guidance so the verdict we show matches the colour / severity the
    # AbuseIPDB site uses for the same score:
    #
    #   >= 75  -> MALICIOUS    (AbuseIPDB: "high confidence" — red on
    #                           their site, "this IP is reported as
    #                           highly abusive")
    #   25-74  -> SUSPICIOUS   (AbuseIPDB: "potentially malicious" /
    #                           "investigate" — yellow/orange on their
    #                           site; their API docs explicitly call
    #                           this the floor for actionable signal)
    #   1-24   -> UNKNOWN      (low-confidence reports; AbuseIPDB
    #                           doesn't recommend action at this level)
    #   0 + reports = 0 -> CLEAN (no reports, nothing observed)
    #   0 + any reports -> UNKNOWN  (reports filed but they don't
    #                           confidence-score them — informational
    #                           only)
    reports = d.get("totalReports") or 0
    if score >= 75:
        out["verdict"] = "MALICIOUS"
    elif score >= 25:
        out["verdict"] = "SUSPICIOUS"
    elif score == 0 and reports == 0:
        out["verdict"] = "CLEAN"
    else:
        out["verdict"] = "UNKNOWN"
    return out


def _p_ipinfo(r):
    if _is_fail(r):
        return _err("ipinfo", r)
    return {"org": r.get("org"), "country": r.get("country"), "city": r.get("city"),
            "region": r.get("region"), "loc": r.get("loc"), "hostname": r.get("hostname"),
            "asn": (r.get("org") or "").split(" ")[0] if (r.get("org") or "").startswith("AS") else None}



def _vt_top_labels(attrs: dict) -> list:
    """Pull the most specific detection labels from VT analysis results."""
    results = (attrs.get("last_analysis_results") or {})
    labels = []
    for engine, info in results.items():
        if isinstance(info, dict) and info.get("category") == "malicious":
            lbl = info.get("result")
            if lbl and lbl not in labels:
                labels.append(lbl)
        if len(labels) >= 5:
            break
    return labels


def _p_vt_ip(r):
    if _is_fail(r):
        return _err("virustotal", r)
    attrs = _safe(r, "data", "attributes", default={}) or {}
    s = attrs.get("last_analysis_stats") or {}
    mal = s.get("malicious") or 0
    out = {
        "malicious":      mal,
        "suspicious":     s.get("suspicious"),
        "harmless":       s.get("harmless"),
        "undetected":     s.get("undetected"),
        "reputation":     attrs.get("reputation"),
        "country":        attrs.get("country"),
        "as_owner":       attrs.get("as_owner"),
        "asn":            attrs.get("asn"),
        "network":        attrs.get("network"),
        "last_analysis":  attrs.get("last_analysis_date"),
        "top_labels":     _vt_top_labels(attrs),
    }
    out["verdict"] = "MALICIOUS" if mal > 5 else "SUSPICIOUS" if mal >= 1 else "CLEAN" if (s.get("harmless") or 0) > 0 else "UNKNOWN"
    return out


def _p_vt_domain(r):
    if _is_fail(r):
        return _err("virustotal", r)
    attrs = _safe(r, "data", "attributes", default={}) or {}
    s = attrs.get("last_analysis_stats") or {}
    mal = s.get("malicious") or 0
    out = {
        "malicious":         mal,
        "suspicious":        s.get("suspicious"),
        "harmless":          s.get("harmless"),
        "undetected":        s.get("undetected"),
        "reputation":        attrs.get("reputation"),
        "categories":        attrs.get("categories"),
        "creation_date":     attrs.get("creation_date"),
        "last_modification": attrs.get("last_modification_date"),
        "last_dns_records":  [d.get("value") for d in (attrs.get("last_dns_records") or [])[:5]],
        "top_labels":        _vt_top_labels(attrs),
    }
    out["verdict"] = "MALICIOUS" if mal > 5 else "SUSPICIOUS" if mal >= 1 else "UNKNOWN"
    return out


def _p_vt_file(r):
    if _is_fail(r):
        return _err("virustotal", r)
    attrs = _safe(r, "data", "attributes", default={}) or {}
    s = attrs.get("last_analysis_stats") or {}
    mal = s.get("malicious") or 0
    families = attrs.get("popular_threat_classification") or {}
    out = {
        "malicious":           mal,
        "suspicious":          s.get("suspicious"),
        "harmless":            s.get("harmless"),
        "undetected":          s.get("undetected"),
        "name":                attrs.get("meaningful_name"),
        "type":                attrs.get("type_description"),
        "size":                attrs.get("size"),
        "first_submission":    attrs.get("first_submission_date"),
        "last_analysis":       attrs.get("last_analysis_date"),
        "reputation":          attrs.get("reputation"),
        "malware_family":      families.get("suggested_threat_label"),
        "family_categories":   [c.get("value") for c in (families.get("popular_threat_category") or [])][:3],
        "names":               (attrs.get("names") or [])[:5],
        "tags":                attrs.get("tags") or [],
        "top_labels":          _vt_top_labels(attrs),
    }
    out["verdict"] = "MALICIOUS" if mal > 5 else "SUSPICIOUS" if mal >= 1 else "UNKNOWN"
    return out


def _p_vt_url(r):
    if _is_fail(r):
        return _err("virustotal", r)
    attrs = _safe(r, "data", "attributes", default={}) or {}
    s = attrs.get("last_analysis_stats") or {}
    mal = s.get("malicious") or 0
    out = {
        "malicious":   mal,
        "suspicious":  s.get("suspicious"),
        "harmless":    s.get("harmless"),
        "undetected":  s.get("undetected"),
        "categories":  attrs.get("categories"),
        "last_analysis": attrs.get("last_analysis_date"),
        "title":       attrs.get("title"),
        "top_labels":  _vt_top_labels(attrs),
    }
    out["verdict"] = "MALICIOUS" if mal > 5 else "SUSPICIOUS" if mal >= 1 else "UNKNOWN"
    return out


async def _shodan_internetdb(session, ip: str) -> dict:
    """Shodan's free InternetDB endpoint (no key required).
    Endpoint: https://internetdb.shodan.io/<ip>  -> JSON of:
      ip, ports[], cpes[], hostnames[], tags[], vulns[]
    Empty 404 means no observed data — return {found:False}."""
    try:
        r = await _get(
            session, f"https://internetdb.shodan.io/{ip}",
            headers={"User-Agent": "RECON-ThreatIntel/1.0",
                     "Accept": "application/json"},
            timeout=6,
        )
    except Exception as e:
        return {"source": "shodan_internetdb", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "shodan_internetdb", "error": "unexpected shape",
                "error_type": "unreachable"}
    if "error" in r:
        # Shodan returns {"detail": "No information available"} for
        # unknown IPs — treat as not-found rather than an error.
        msg = (r.get("error") or "").lower()
        if "no information" in msg or "404" in msg or "not_found" in msg:
            return {"source": "shodan_internetdb", "found": False,
                    "summary": f"Shodan has no observed services on {ip}."}
        return {"source": "shodan_internetdb", "error": r.get("error"),
                "error_type": r.get("error_type", "unreachable")}
    if "ip" not in r and "ports" not in r and "vulns" not in r:
        return {"source": "shodan_internetdb", "found": False,
                "summary": f"Shodan has no observed services on {ip}."}

    ports     = list(r.get("ports") or [])[:30]
    hostnames = [str(h)[:120] for h in (r.get("hostnames") or [])][:8]
    cpes      = [str(c)[:160] for c in (r.get("cpes") or [])][:12]
    tags      = [str(t)[:40] for t in (r.get("tags") or [])][:10]
    vulns     = [str(v)[:24] for v in (r.get("vulns") or [])][:25]

    risky_tags = {"vpn", "tor", "cdn", "anonymous", "proxy",
                   "compromised", "honeypot", "malware"}
    risky_present = [t for t in tags if t.lower() in risky_tags]

    summary_bits = []
    if ports:
        summary_bits.append(f"{len(ports)} exposed port"
                            f"{'s' if len(ports) != 1 else ''}")
    if vulns:
        summary_bits.append(f"{len(vulns)} known CVE"
                            f"{'s' if len(vulns) != 1 else ''}")
    if risky_present:
        summary_bits.append(f"tags: {', '.join(risky_present)}")
    summary = "Shodan InternetDB: " + (", ".join(summary_bits) if summary_bits
                                       else "host visible to Shodan with no notable signals.")

    verdict = "UNKNOWN"
    if vulns and len(vulns) >= 3:
        verdict = "SUSPICIOUS"
    if risky_present:
        verdict = "SUSPICIOUS"

    return {
        "source":     "shodan_internetdb",
        "found":      True,
        "ports":      ports,
        "hostnames":  hostnames,
        "cpes":       cpes,
        "tags":       tags,
        "vulns":      vulns,
        "vuln_count": len(vulns),
        "verdict":    verdict,
        "summary":    summary,
    }


async def _malware_bazaar(session, hash_val: str) -> dict:
    """abuse.ch MalwareBazaar hash lookup. POST form-encoded query=get_info
    + hash. Returns named-family + tags + first-seen + YARA rule names.
    Free + unauthenticated; same operator as Feodo / ThreatFox / URLhaus."""
    if not hash_val or len(hash_val) not in (32, 40, 64):
        return {"source": "malware_bazaar", "error": "invalid hash length",
                "error_type": "skipped"}
    try:
        r = await _post(
            session,
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": hash_val},
            headers={"User-Agent": "RECON-ThreatIntel/1.0"},
            timeout=10,
        )
    except Exception as e:
        return {"source": "malware_bazaar", "error": str(e)[:120],
                "error_type": "unreachable"}
    if not isinstance(r, dict):
        return {"source": "malware_bazaar", "error": "unexpected shape",
                "error_type": "unreachable"}
    status = (r.get("query_status") or "").lower()
    if status in ("hash_not_found", "no_results", "no_hash"):
        return {"source": "malware_bazaar", "found": False,
                "summary": f"MalwareBazaar has no record for {hash_val}."}
    if status != "ok":
        return {"source": "malware_bazaar", "found": False,
                "error_type": "not_found", "summary": status or "no data"}
    rows = r.get("data") or []
    if not isinstance(rows, list) or not rows:
        return {"source": "malware_bazaar", "found": False,
                "summary": "MalwareBazaar returned no data rows."}
    row = rows[0] if isinstance(rows[0], dict) else {}
    family   = row.get("signature") or ""
    tags     = row.get("tags") or []
    yara     = row.get("yara_rules") or []
    yara_names = [(y.get("rule_name") or "")[:80]
                   for y in yara if isinstance(y, dict)]
    return {
        "source":          "malware_bazaar",
        "found":           True,
        "family":          family,
        "file_name":       (row.get("file_name") or "")[:160],
        "file_type":       (row.get("file_type") or "")[:40],
        "first_seen":      row.get("first_seen"),
        "last_seen":       row.get("last_seen"),
        "tags":            [str(t)[:40] for t in tags][:12],
        "yara_rule_names": yara_names[:8],
        "verdict":         "MALICIOUS" if family else "SUSPICIOUS",
        "summary":         (f"MalwareBazaar: {family}" if family
                            else "MalwareBazaar: sample present without family attribution"),
    }


def _p_otx(r):
    """Pulses + tags + adversaries + linked hashes from related malware samples."""
    if _is_fail(r):
        return _err("otx", r)
    pulses = (_safe(r, "pulse_info", "pulses") or [])
    tags = set()
    adversaries = set()
    related_hashes = set()
    for p in pulses[:10]:
        for t in (p.get("tags") or []):
            tags.add(t.lower())
        if p.get("adversary"):
            adversaries.add(p["adversary"])
        for h in (p.get("indicators") or [])[:5]:
            v = h.get("indicator") if isinstance(h, dict) else None
            t_ = h.get("type") if isinstance(h, dict) else None
            if v and t_ in ("FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256"):
                related_hashes.add(v)
    out = {
        "pulseCount":     _safe(r, "pulse_info", "count") or len(pulses),
        "relatedPulses":  [p.get("name") for p in pulses[:5]],
        "tags":           sorted(tags)[:15],
        "adversaries":    sorted(adversaries),
        "related_hashes": sorted(related_hashes)[:10],
    }
    if out["pulseCount"] >= 5 or adversaries:
        out["verdict"] = "SUSPICIOUS"
    return out

def _p_whois(r):
    if _is_fail(r):
        return _err("whois", r)
    # who-dat.as93.net response shape — pull the fields the frontend
    # source-card actually renders. age_days is derived here so the
    # WHOIS card and the URL-identity banner can both show domain age
    # without re-parsing the date string client-side.
    created = _safe(r, "domain", "created_date") or ""
    age_days = None
    if created:
        try:
            from datetime import datetime as _dt, timezone as _tz
            _s = created.replace("Z", "+00:00")
            _d = _dt.fromisoformat(_s)
            if _d.tzinfo is None:
                _d = _d.replace(tzinfo=_tz.utc)
            age_days = max(0, (_dt.now(_tz.utc) - _d).days)
        except Exception:
            age_days = None
    registrant_country = _safe(r, "registrant", "country") or _safe(r, "registrant", "country_code") or ""
    registrant_org = _safe(r, "registrant", "organization") or ""
    return {
        "registrar":          _safe(r, "registrar", "name"),
        "registrar_iana_id":  _safe(r, "registrar", "iana_id"),
        "registrant_org":     registrant_org,
        "registrant_country": registrant_country,
        "registrant_email":   _safe(r, "registrant", "email"),
        "created":            created,
        "updated":            _safe(r, "domain", "updated_date"),
        "expires":            _safe(r, "domain", "expiration_date"),
        "age_days":           age_days,
        "name_servers":       (r.get("nameservers") or _safe(r, "domain", "name_servers") or [])[:6],
        "status":             (_safe(r, "domain", "status") or [])[:5] if isinstance(_safe(r, "domain", "status"), list) else [],
        "privacy_protected":  bool(registrant_org.lower().startswith(
            ("privacy", "redacted", "withheld", "domains by proxy",
             "whoisguard", "data redacted"))),
    }


def _p_pd(r):
    # Pulsedive returns 200 OK with {"error": "Indicator not found."} when
    # the IOC isn't in their DB. That's a clean miss, not a source failure.
    if isinstance(r, dict) and isinstance(r.get("error"), str) \
            and "not found" in r["error"].lower() and "source" not in r:
        return {"risk": None, "verdict": "CLEAN",
                "note": "Not in Pulsedive database"}
    if _is_fail(r):
        return _err("pulsedive", r)
    risk = (r.get("risk") or "").lower()
    out = {
        "risk":         r.get("risk"),
        "risk_factor":  r.get("riskfactor"),
        "threats":      [t.get("name") for t in (r.get("threats") or [])[:5]],
        "feeds":        [f.get("name") for f in (r.get("feeds") or [])[:10]],
        "links":        [l.get("indicator") for l in (r.get("links") or [])[:8]],
        "manualrisk":   r.get("manualrisk"),
    }
    if risk in {"critical", "high"}:
        out["verdict"] = "MALICIOUS"
    elif risk in {"medium", "low"}:
        out["verdict"] = "SUSPICIOUS"
    return out


def _p_wayback(r):
    if _is_fail(r):
        return _err("wayback", "no wayback")
    snap = (r.get("archived_snapshots") or {}).get("closest") or {}
    if not snap.get("available"):
        return {"has_snapshots": False,
                "note": "Domain not in Wayback Machine — no history at all"}
    ts = snap.get("timestamp", "")
    formatted = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts
    return {"has_snapshots":   True,
            "closest_snapshot": formatted,
            "snapshot_url":    snap.get("url"),
            "status":          snap.get("status")}


def _p_urlscan(r):
    if _is_fail(r):
        return _err("urlscan", r)
    hits = r.get("results") or []
    if not hits:
        return _err("urlscan", "No scans found")
    top = hits[0]
    v = (top.get("verdicts") or {}).get("overall") or {}
    page = top.get("page") or {}
    task = top.get("task") or {}
    out = {
        "malicious":     v.get("malicious"),
        "score":         v.get("score"),
        "tags":          v.get("tags") or [],
        "categories":    v.get("categories") or [],
        "screenshot":    task.get("screenshotURL"),
        "report_url":    task.get("reportURL"),
        "page_title":    page.get("title"),
        "page_url":      page.get("url"),
        "page_server":   page.get("server"),
        "page_country":  page.get("country"),
        "technologies":  [t.get("name") for t in (top.get("stats") or {}).get("technologies", [])][:8]
                          if isinstance((top.get("stats") or {}).get("technologies"), list) else [],
    }
    if v.get("malicious"):
        out["verdict"] = "MALICIOUS"
    elif (v.get("score") or 0) >= 50:
        out["verdict"] = "SUSPICIOUS"
    return out


def _p_mb(r):
    """MalwareBazaar — match = MALICIOUS per spec §3."""
    if _is_fail(r):
        return _err("malwarebazaar", r)
    if r.get("query_status") != "ok":
        return {"queryStatus": r.get("query_status")}
    d = (r.get("data") or [{}])[0]
    return {
        "malwareName":    d.get("signature"),
        "malware_family": d.get("signature"),
        "tags":           d.get("tags"),
        "fileType":       d.get("file_type"),
        "fileSize":       d.get("file_size"),
        "firstSeen":      d.get("first_seen"),
        "lastSeen":       d.get("last_seen"),
        "delivery_method": d.get("delivery_method"),
        "yara_rules":     [y.get("rule_name") for y in (d.get("yara_rules") or [])][:5],
        "verdict":        "MALICIOUS",
    }


def _p_tf(r):
    """ThreatFox — match = MALICIOUS per spec §3."""
    if _is_fail(r):
        return _err("threatfox", r)
    if r.get("query_status") != "ok":
        return {"queryStatus": r.get("query_status")}
    d = (r.get("data") or [{}])[0]
    return {
        "malware":        d.get("malware_printable"),
        "malware_family": d.get("malware_printable"),
        "ioc_type":       d.get("ioc_type"),
        "threat_type":    d.get("threat_type"),
        "confidence":     d.get("confidence_level"),
        "first_seen":     d.get("first_seen"),
        "last_seen":      d.get("last_seen"),
        "tags":           d.get("tags") or [],
        "verdict":        "MALICIOUS",
    }


# ─── Free no-key sources (per spec §3) ─────────────────────────────────────────
def _p_robtex(r):
    """Robtex free IP/domain lookup — passive DNS + ASN."""
    if _is_fail(r):
        return _err("robtex", r)
    out = {
        "asn":        r.get("as"),
        "asnName":    r.get("asname"),
        "country":    r.get("country"),
        "bgproute":   r.get("bgproute"),
        "active_dns": [d.get("o") for d in (r.get("act") or [])[:10]],
        "passive_dns": [d.get("o") for d in (r.get("pas") or [])[:10]],
    }
    return out


def _p_hackertarget(r):
    """HackerTarget reverse IP / ASN lookup — plain text lines."""
    if isinstance(r, Exception):
        return _err("hackertarget", r)
    if isinstance(r, dict) and "raw" in r:
        text = r["raw"]
    elif isinstance(r, str):
        text = r
    else:
        return _err("hackertarget", "unexpected format")
    if "API count exceeded" in text or "error" in text.lower()[:60]:
        return _err("hackertarget", text[:120])
    rows = [l.strip() for l in text.splitlines() if l.strip()]
    return {"record_count": len(rows), "rows": rows[:25]}


# Module-level import — feeds_loader is part of our own backend, so a
# missing import is a hard bug, not a runtime degradation case. Importing
# inside the function silently masked the historical case where
# check_feodo didn't exist; now-fixed but moved out so a future regression
# fails loudly at startup instead of one analysis at a time.
from intel.feeds_loader import check_feodo as _check_feodo


def _p_feodo(ip: str) -> dict:
    """Local Feodo Tracker match. Match = MALICIOUS."""
    try:
        hit = _check_feodo(ip)
        if hit:
            return {**hit, "verdict": "MALICIOUS"}
    except Exception as _e:
        _log.debug("feodo lookup failed for %s: %s", ip, _e)
    return {}


# ─── Authenticated sources (Censys / Hybrid Analysis) ─────────────────────────
def _p_censys(r):
    """Censys host view — handles BOTH the legacy search.censys.io/v2
    response shape and the new api.platform.censys.io/v3 shape.
    The v2 response puts host fields at `result.<field>`; the v3
    Platform response wraps them one deeper at `result.resource.<field>`.
    Field names are the same once you reach the resource level."""
    if _is_fail(r):
        return _err("censys", r)
    res = (r.get("result") or {})
    # Platform v3 wraps the host data under 'resource'; legacy v2 puts
    # the fields directly on result. Detect and unwrap.
    if isinstance(res.get("resource"), dict):
        res = res["resource"]
    services = []
    for s in (res.get("services") or [])[:15]:
        services.append({
            "port":     s.get("port"),
            "transport": s.get("transport_protocol"),
            "service":  s.get("service_name"),
            "product":  _safe(s, "software", 0, "product") or _safe(s, "_decoded"),
            "banner":   (s.get("banner") or "")[:160] or None,
        })
    cert = None
    tls = next((s.get("tls") for s in (res.get("services") or []) if s.get("tls")), None)
    if tls:
        leaf = (tls.get("certificates") or {}).get("leaf_data") or {}
        cert = {
            "subject": _safe(leaf, "subject_dn"),
            "issuer":  _safe(leaf, "issuer_dn"),
            "sha256":  leaf.get("fingerprint_sha256"),
            "expires": _safe(leaf, "validity", "end"),
        }
    asys = res.get("autonomous_system") or {}
    loc = res.get("location") or {}
    out = {
        "services":    services,
        "ssl_cert":    cert,
        "asn":         asys.get("asn"),
        "asn_name":    asys.get("name"),
        "bgp_prefix":  asys.get("bgp_prefix"),
        "country":     loc.get("country") or loc.get("country_code"),
        "city":        loc.get("city"),
        "last_updated": res.get("last_updated_at") or res.get("last_observed_at"),
        "os":          _safe(res, "operating_system", "product"),
    }
    return out


def _p_hybrid(r):
    """Hybrid Analysis sandbox report (search by hash) → behavioral summary.

    Verdict mapping respects HA's own taxonomy — they distinguish
    'malicious' from 'suspicious' deliberately, and collapsing the two
    into MALICIOUS amplifies severity beyond what the source said. HA
    verdicts in the wild: 'no_specific_threat' / 'no specific threat'
    (clean enough), 'suspicious', 'malicious', 'unknown', or empty.

    Response shape: HA v2 /search/hash used to return a bare list of
    reports. Sometime before 2026-06-19 they wrapped it in
    {"sha256s": [...], "reports": [...]}. Handle both. Prefer the
    most recent report in state=SUCCESS over any older/errored one.
    """
    if _is_fail(r):
        return _err("hybrid_analysis", r)
    # Unwrap the new shape (object with `reports` key) or accept the
    # legacy bare list.
    if isinstance(r, dict):
        reports = r.get("reports") or []
    elif isinstance(r, list):
        reports = r
    else:
        reports = []
    if not reports:
        return _err("hybrid_analysis", "no reports")
    # Prefer SUCCESS state over any other (ERROR / IN_PROGRESS / IN_QUEUE).
    top = next((rep for rep in reports if (rep or {}).get("state") == "SUCCESS"), None)
    if not top:
        top = reports[0]
    raw = (top.get("verdict") or "").lower().strip()
    if raw == "malicious":
        verdict = "MALICIOUS"
    elif raw == "suspicious":
        verdict = "SUSPICIOUS"
    elif raw in ("no specific threat", "no_specific_threat", "whitelisted"):
        verdict = "CLEAN"
    else:
        verdict = "UNKNOWN"
    return {
        "verdict_raw":     top.get("verdict"),
        "threat_score":    top.get("threat_score"),
        "av_detect":       top.get("av_detect"),
        "malware_family":  top.get("vx_family"),
        "type":            top.get("type"),
        "submit_name":     top.get("submit_name"),
        "environment":     top.get("environment_description"),
        "mitre":           [t.get("technique") + " " + t.get("name", "") for t in (top.get("mitre_attcks") or [])][:6],
        "tags":            top.get("tags") or [],
        "processes":       [p.get("name") for p in (top.get("processes") or [])][:8],
        "network_hosts":   [(h.get("address") or h.get("name")) for h in (top.get("hosts") or [])][:8],
        "dropped_count":   len(top.get("extracted_files") or []),
        "report_url":      f"https://www.hybrid-analysis.com/sample/{top.get('sha256')}" if top.get("sha256") else None,
        "verdict":         verdict,
    }


# ─── ENRICHMENT FUNCTIONS ─────────────────────────────────────────────────────────
def _local_ip_check(ip: str) -> dict:
    try:
        from intel.feeds_loader import check_ip
        hit = check_ip(ip)
        return hit or {}
    except Exception:
        return {}


def _local_domain_check(domain: str) -> dict:
    try:
        from intel.feeds_loader import check_domain
        hit = check_domain(domain)
        return hit or {}
    except Exception:
        return {}


def _typosquat_check(domain: str) -> dict:
    try:
        from intel.typosquat import check_domain as twist
        hit = twist(domain)
        return hit or {}
    except Exception:
        return {}


async def _opencti_lookup(value: str, cfg) -> dict:
    try:
        from intel.opencti import is_configured, lookup_observable
        if not is_configured(cfg):
            return {}
        r = await lookup_observable(value, cfg.get("OPENCTI_URL", ""),
                                    cfg.get("OPENCTI_TOKEN", ""))
        return r or {}
    except Exception:
        return {}


async def _maltiverse_lookup(ioc_type: str, value: str, cfg) -> dict:
    try:
        from intel.maltiverse import lookup
        r = await lookup(ioc_type, value, cfg.get("MALTIVERSE_KEY", ""))
        return r or {}
    except Exception:
        return {}


def _ok_dict(r):
    """A gathered result that's usable as enrichment data: a dict that isn't an
    exception. Filters out exceptions (return_exceptions=True) and None so the
    concurrent secondary-lookup blocks read just like the old sequential ones."""
    return r if isinstance(r, dict) else None


async def _skip():
    """Falsy placeholder for a disabled/unavailable concurrent lookup — returns
    an empty dict so `if result:` checks treat it as 'nothing found'. (Unlike
    _noop(), which is a truthy sentinel for the keyed-source parsers.)"""
    return {}


async def enrich_ip(session, ip: str, keys: dict) -> dict:
    ck = _ck("ip", ip)
    if ck in _cache:
        return {**_cache[ck], "cached": True}

    # Built-in known-good baseline short-circuit. When the IOC maps to
    # a stable benign service (public DNS, Microsoft endpoint, etc.) we
    # skip the entire enrichment fan-out and return a synthetic CLEAN
    # verdict. Saves ~10 API calls and a couple seconds per analysis on
    # the common false-positive sources that slip past warninglists.
    try:
        from intel.known_good_baseline import lookup_ip as _kg_ip
        kg = _kg_ip(ip)
        if kg:
            data = {"known_good_baseline": kg, "_short_circuited": True}
            _cache[ck] = data
            return data
    except Exception as _e:
        # When the short-circuit lookup fails we drop straight into the
        # paid TI fan-out for every known-good IP (public DNS resolvers,
        # MS endpoints, …) — surface it so the cost shows up in logs.
        _log.warning("known_good_baseline IP lookup failed for %s: %s", ip, _e)

    tor_nodes = await _tor(session)

    # Censys auth — two paths:
    #   • New Platform API (PAT): CENSYS_API_KEY starts with 'censys_',
    #     used as a Bearer token against api.platform.censys.io. This is
    #     the actively-supported v3 surface.
    #   • Legacy search.censys.io/v2 API ID + Secret pair, kept as a
    #     fallback for older deployments that haven't rotated yet.
    # The two endpoints return different response shapes; _p_censys
    # handles both.
    censys_token = keys.get("CENSYS_API_KEY", "")
    censys_url = None
    censys_auth = None
    if censys_token:
        censys_url  = f"https://api.platform.censys.io/v3/global/asset/host/{ip}"
        censys_auth = f"Bearer {censys_token}"
    else:
        censys_id     = keys.get("CENSYS_ID", "")
        censys_secret = keys.get("CENSYS_SECRET", "")
        if censys_id and censys_secret:
            import base64 as _b64
            censys_url  = f"https://search.censys.io/api/v2/hosts/{ip}"
            censys_auth = "Basic " + _b64.b64encode(
                f"{censys_id}:{censys_secret}".encode()).decode()

    tasks = [
        # ── keyed sources (existing) ───────────────────────────────────────────
        _get(session, "https://api.abuseipdb.com/api/v2/check",
             params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"},
             headers={"Key": keys.get("ABUSEIPDB_KEY", ""), "Accept": "application/json"}),
        _get(session, f"https://ipinfo.io/{ip}/json",
             params={"token": keys.get("IPINFO_TOKEN", "")}),
        _get(session, f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
             headers={"x-apikey": keys.get("VIRUSTOTAL_KEY", "")}),
        _get(session, f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
             headers={"X-OTX-API-KEY": keys.get("OTX_KEY", "")}),
        # ── free no-key sources (spec §3) ──────────────────────────────────────
        _get(session, f"https://freeapi.robtex.com/ipquery/{ip}"),
        _get(session, f"https://api.hackertarget.com/reverseiplookup/?q={ip}"),
        # ── conditional authenticated sources ──────────────────────────────────
        _get(session, censys_url,
             headers={"Authorization": censys_auth}) if censys_auth else _noop(),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    abuse_data  = _p_abuse(results[0])
    ipinfo_data = _p_ipinfo(results[1])
    data = {
        "tor":         {"isExitNode": ip in tor_nodes},
        "abuseipdb":   abuse_data,
        "ipinfo":      ipinfo_data,
        "virustotal":  _p_vt_ip(results[2]),
        "otx":         _p_otx(results[3]),
        "robtex":      _p_robtex(results[4]),
        "hackertarget": _p_hackertarget(results[5]),
        "local_feeds": _local_ip_check(ip),
    }
    # Censys (optional)
    if censys_auth and not isinstance(results[6], Exception):
        cs = _p_censys(results[6])
        if "error" not in cs:
            data["censys"] = cs
    # Feodo Tracker (offline list)
    feodo = _p_feodo(ip)
    if feodo:
        data["feodo_tracker"] = feodo

    # Shodan InternetDB — free, no-key IP service inventory. Returns
    # observed ports, CPEs, hostnames, tags, and CVEs. ON by default
    # (free + reasonably fast); operator can disable in Settings when
    # processing very large IP batches.
    from config import config as _cfg_sdb
    if (_cfg_sdb.get("RECON_ENABLE_SHODAN_INTERNETDB", "1") or "1") not in ("0","false","False"):
        try:
            idb = await _shodan_internetdb(session, ip)
            if idb and not idb.get("error"):
                data["shodan_internetdb"] = idb
        except Exception:
            pass

    # Cloud provider IP ranges — AWS/Azure/GCP/Cloudflare/Fastly/GitHub.
    # Strong trust signal: an IP belonging to AWS CloudFront is almost
    # certainly NOT the attacker, just the CDN edge. Synchronous lookup
    # against the in-memory CIDR list warmed by the lifespan handler.
    try:
        from intel.cloud_ip_ranges import lookup as _cloud_lookup
        cl = _cloud_lookup(ip)
        if cl:
            data["cloud_provider"] = {
                "source":   "cloud-provider IP ranges",
                "provider": cl.get("provider"),
                "region":   cl.get("region"),
                "service":  cl.get("service"),
                "cidr":     cl.get("cidr"),
                "verdict":  "CLEAN_INFRA",
                "summary":  (f"{ip} belongs to {cl.get('provider')}"
                              + (f" ({cl.get('service')})" if cl.get("service") else "")
                              + (f" in {cl.get('region')}" if cl.get("region") else "")
                              + " — likely CDN/cloud infra, not attacker-controlled."),
            }
    except Exception:
        pass

    # DataPlane.org honeypot feeds — daily-refreshed CSV from a global
    # mesh of volunteer sensors. Hits here indicate the IP has been
    # caught actively brute-forcing or scanning a specific service.
    try:
        from intel.dataplane import lookup as _dp_lookup
        dp_hits = _dp_lookup(ip)
        if dp_hits:
            feeds = sorted({h["feed"] for h in dp_hits})
            data["dataplane"] = {
                "source":     "DataPlane.org",
                "feeds":      feeds,
                "hit_count":  len(dp_hits),
                "last_seen":  max((h["last_seen"] for h in dp_hits
                                    if h.get("last_seen")), default=""),
                "verdict":    "MALICIOUS" if len(feeds) >= 2 else "SUSPICIOUS",
                "summary":    (f"{ip} active on {len(feeds)} DataPlane honeypot "
                                f"feed{'s' if len(feeds) != 1 else ''}: {', '.join(feeds[:4])}"
                                f"{'…' if len(feeds) > 4 else ''}."),
            }
    except Exception:
        pass

    # SANS DShield — volunteer-firewall sensor network. Live API, no key.
    try:
        from intel.dshield import lookup as _dshield_lookup
        ds = await _dshield_lookup(session, ip)
        if ds and ds.get("found"):
            data["dshield"] = ds
    except Exception:
        pass

    # Spamhaus DROP/EDROP — canonical hijacked-netblock list.
    try:
        from intel.spamhaus_drop import lookup as _shaus_lookup
        sh = _shaus_lookup(ip)
        if sh:
            data["spamhaus_drop"] = {
                "source":  "Spamhaus DROP/EDROP",
                "feed":    sh["feed"],
                "sbl":     sh.get("sbl"),
                "cidr":    sh["cidr"],
                "verdict": "MALICIOUS",
                "summary": (f"{ip} is on the Spamhaus {sh['feed']} list "
                              f"(netblock {sh['cidr']}"
                              + (f", SBL {sh['sbl']}" if sh.get("sbl") else "")
                              + ") - hijacked or criminal infrastructure."),
            }
    except Exception:
        pass

    # FireHOL — 400+ curated IP blocklists. Synchronous in-memory lookup
    # over the vendored blocklist-ipsets repo. Each hit reports which
    # named blocklist matched (firehol_level1, blocklist_de_ssh, ...).
    try:
        from intel.firehol import lookup as _firehol_lookup
        fh_hits = _firehol_lookup(ip)
        if fh_hits:
            data["firehol"] = {
                "source":     "FireHOL blocklist-ipsets",
                "blocklists": fh_hits,
                "list_count": len(fh_hits),
                "verdict":    "MALICIOUS" if len(fh_hits) >= 3 else "SUSPICIOUS",
                "summary":    (f"{ip} is on {len(fh_hits)} FireHOL blocklist"
                                f"{'s' if len(fh_hits) != 1 else ''}: "
                                f"{', '.join(fh_hits[:4])}"
                                f"{'…' if len(fh_hits) > 4 else ''}"),
            }
    except Exception:
        pass

    # ── Secondary lookups — all independent, so fire them concurrently instead
    #    of one await after another (BGP, Safe Browsing, deception, Maltiverse,
    #    OpenCTI). Each helper already fails soft; return_exceptions keeps one
    #    slow/broken source from sinking the rest. ────────────────────────────
    from config import config as _cfg
    gsb_key = keys.get("GOOGLE_API_KEY", "")
    try:
        from intel.osint_extra import bgp_ranking, google_safe_browsing
        _bgp_co = bgp_ranking(session, ip)
        _gsb_co = google_safe_browsing(session, ip, "ip", gsb_key) if gsb_key else _skip()
    except Exception:
        _bgp_co, _gsb_co = _skip(), _skip()
    try:
        from intel.deception_intel import enrich_deception
        _dec_co = enrich_deception(session, ip, keys)
    except Exception:
        _dec_co = _skip()

    # ── New IP enrichment source (Criminal IP) ──
    # Criminal IP returns inbound/outbound threat scores + VPN/proxy/Tor
    # classification flags.
    try:
        from intel.breach_sources import criminal_ip as _crimip
        _crimip_co = _crimip(session, ip, keys.get("CRIMINAL_IP_KEY", ""))
    except Exception:
        _crimip_co = _skip()

    bgp_r, gsb_r, dec_r, mv_r, oc_r, crimip_r = await asyncio.gather(
        _bgp_co, _gsb_co, _dec_co,
        _maltiverse_lookup("ip", ip, _cfg),
        _opencti_lookup(ip, _cfg),
        _crimip_co,
        return_exceptions=True,
    )

    osint: dict = {}
    bgp = _ok_dict(bgp_r)
    if bgp and "error" not in bgp:
        osint["bgp_ranking"] = bgp
    gsb = _ok_dict(gsb_r)
    if gsb and "error" not in gsb and "skipped" not in gsb:
        osint["google_safebrowsing"] = gsb
    if osint:
        data["osint"] = osint
    dec = _ok_dict(dec_r)
    if dec:
        data["deception"] = dec
    mv = _ok_dict(mv_r)
    if mv:
        data["maltiverse"] = mv
    oc = _ok_dict(oc_r)
    if oc:
        data["opencti"] = oc
    # New sources — attach only when they returned real data (auth-failed /
    # not-configured results carry an error key + error_type and are
    # surfaced as a separate source-status row by the frontend).
    crimip = _ok_dict(crimip_r)
    if crimip:
        data["criminal_ip"] = crimip

    # ASN reputation — offline, uses ISP/org strings we already have, no API call
    try:
        from intel.asn_reputation import check as asn_check
        asn = asn_check(
            isp=(abuse_data or {}).get("isp", ""),
            org=(ipinfo_data or {}).get("org", ""),
            usage_type=(abuse_data or {}).get("usageType", ""),
        )
        if asn:
            data["asn_reputation"] = asn
    except Exception:
        pass

    # ProxyCheck — VPN / proxy / Tor / residential-proxy classification.
    # Configured via PROXYCHECK_KEY; free tier supports 1000 daily checks
    # without a key but rate-limits aggressively. Returns proxy/VPN/Tor
    # flags + ISP + country + ASN.
    proxycheck_key = keys.get("PROXYCHECK_KEY", "")
    if proxycheck_key:
        try:
            pc = await _get(
                session, f"https://proxycheck.io/v2/{ip}",
                params={"key": proxycheck_key, "vpn": "1", "asn": "1", "risk": "1"},
            )
            if isinstance(pc, dict) and not pc.get("error"):
                row = pc.get(ip) or {}
                if row:
                    data["proxycheck"] = {
                        "proxy":     (row.get("proxy") or "").lower() == "yes",
                        "type":      row.get("type"),       # VPN / TOR / public / etc.
                        "provider":  row.get("provider"),
                        "country":   row.get("country"),
                        "isp":       row.get("isocode"),
                        "asn":       row.get("asn"),
                        "risk":      row.get("risk"),       # 0-100
                    }
                else:
                    data["proxycheck"] = {"error": "no data", "error_type": "no_data"}
            elif isinstance(pc, dict):
                data["proxycheck"] = pc
        except Exception as e:
            data["proxycheck"] = {"error": _humanise_exc(e), "error_type": "unreachable"}
    _cache[ck] = data
    return data


async def enrich_domain(session, domain: str, keys: dict) -> dict:
    ck = _ck("domain", domain)
    if ck in _cache:
        return {**_cache[ck], "cached": True}

    # Known-good baseline short-circuit (see enrich_ip for the rationale).
    try:
        from intel.known_good_baseline import lookup_domain as _kg_dom
        kg = _kg_dom(domain)
        if kg:
            data = {"known_good_baseline": kg, "_short_circuited": True}
            _cache[ck] = data
            return data
    except Exception as _e:
        # Same cost concern as enrich_ip — surface so a wedged baseline
        # shows up in operator logs instead of just inflating TI usage.
        _log.warning("known_good_baseline domain lookup failed for %s: %s",
                     domain, _e)

    # WhoisXML API runs in parallel with the rest when the paid key is set.
    # When it's not, we fall back to the free who-dat.as93.net endpoint at the
    # same index. Whichever responds gets normalised into the `whois` slot.
    _whoisxml_key = keys.get("WHOISXML_KEY", "")
    if _whoisxml_key:
        from intel.whois_lookup import lookup as _whoisxml_lookup
        async def _whois_call():
            return await _whoisxml_lookup(domain, _whoisxml_key, session)
        _whois_coro = _whois_call()
    else:
        _whois_coro = _get(session, f"https://who-dat.as93.net/{domain}")

    results = await asyncio.gather(
        _get(session, f"https://www.virustotal.com/api/v3/domains/{domain}",
             headers={"x-apikey": keys.get("VIRUSTOTAL_KEY", "")}),
        _get(session, "https://urlscan.io/api/v1/search/",
             params={"q": f"domain:{domain}", "size": 1},
             headers={"API-Key": keys.get("URLSCAN_KEY", "")}),
        _get(session, f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
             headers={"X-OTX-API-KEY": keys.get("OTX_KEY", "")}),
        _whois_coro,
        _get(session, "https://pulsedive.com/api/info.php",
             params={"indicator": domain, "pretty": 1, "key": keys.get("PULSEDIVE_KEY", "")}),
        # Wayback Machine — free, no key, indicates if the domain ever had snapshots
        _get(session, "https://archive.org/wayback/available",
             params={"url": domain}),
        return_exceptions=True,
    )

    # WhoisXML returns its own normalised dict; who-dat passes through _p_whois.
    raw_whois = results[3]
    whois_data = raw_whois if (_whoisxml_key and isinstance(raw_whois, dict)) else _p_whois(raw_whois)
    data = {
        "virustotal":      _p_vt_domain(results[0]),
        "urlscan":         _p_urlscan(results[1]),
        "otx":             _p_otx(results[2]),
        "whois":           whois_data,
        "pulsedive":       _p_pd(results[4]),
        "wayback":         _p_wayback(results[5]),
        "local_feeds":     _local_domain_check(domain),
        "typosquat":       _typosquat_check(domain),
    }
    # DGA classifier (sklearn LogisticRegression over char-bigram TF-IDF
    # + structural features). Synchronous, ~1 ms post-train. Falls back
    # to the heuristic when sklearn isn't installed.
    try:
        from intel.dga_classifier import classify as _dga_classify
        data["dga_classifier"] = _dga_classify(domain)
    except Exception:
        pass

    # Microsoft 365 / Entra tenant recon (4 parallel probes against
    # login.microsoftonline.com + SharePoint + Azure App Service). Only
    # fires when the existing enrichment evidence indicates the domain
    # IS on M365 — skip otherwise so non-M365 domains don't pay the
    # network cost. Adapted from cti-expert (MIT).
    try:
        from intel.m365_tenant_recon import enrich as _m365_enrich, is_m365_candidate
        if is_m365_candidate(data):
            m365 = await _m365_enrich(session, domain)
            if m365 and m365.get("is_m365"):
                data["m365_tenant"] = m365
    except Exception as _e:
        _log.debug("m365 tenant recon failed for %s: %s", domain, _e)
    # Phishing.Database — synchronous in-memory lookup against the hourly
    # active feed warmed by the lifespan handler. Adds {"hit": True, ...}
    # when the domain is on the active phishing list.
    try:
        from intel.phishing_db import is_known_phish
        if is_known_phish(domain):
            data["phishing_db"] = {
                "source":  "mitchellkrogza/Phishing.Database",
                "hit":     True,
                "summary": (f"{domain} is on the active phishing-domains "
                            "feed (validated by PyFunceble)."),
            }
    except Exception:
        pass

    # MVT mobile-spyware IOCs — domain hits (Pegasus, Predator, etc.).
    try:
        from intel.mvt_iocs import lookup_domain as _mvt_domain
        mvt = _mvt_domain(domain)
        if mvt:
            data["mvt_mobile"] = {
                "source":  "MVT (Mobile Verification Toolkit)",
                "family":  mvt.get("family"),
                "ref":     mvt.get("ref"),
                "verdict": "MALICIOUS",
                "summary": (f"MVT spyware hit: {mvt.get('family')}"
                            " — mobile-targeted infrastructure."),
            }
    except Exception:
        pass

    # OFAC SDN — sanctioned domain. Legally material.
    try:
        from intel.ofac_sdn import lookup_domain as _ofac_domain
        ofac = _ofac_domain(domain)
        if ofac:
            data["ofac_sdn"] = {
                "source":   "US Treasury OFAC SDN",
                "entity":   ofac.get("entity"),
                "programs": ofac.get("programs") or [],
                "verdict":  "MALICIOUS",
                "summary":  (f"{domain} is OFAC SDN-sanctioned "
                              f"(entity: {ofac.get('entity')}, programs: "
                              f"{', '.join(ofac.get('programs') or [])})."),
            }
    except Exception:
        pass

    # Chrome HSTS preload — major org's hardcoded must-be-HTTPS domain.
    try:
        from intel.hsts_preload import is_preloaded
        if is_preloaded(domain):
            data["hsts_preload"] = {
                "source":    "Chrome HSTS preload",
                "preloaded": True,
                "summary":   (f"{domain} is on the Chromium HSTS preload "
                                "list — major org with hardcoded HTTPS-only enforcement."),
            }
    except Exception:
        pass

    # Mozilla Observatory — web-security posture grade. Opt-in because
    # the v2 API can take 3+ seconds per domain to respond — slows
    # every multi-domain analyze. Set RECON_ENABLE_MOZILLA_OBSERVATORY=1
    # in Settings for deep-dive analysis.
    from config import config as _cfg_obs
    if (_cfg_obs.get("RECON_ENABLE_MOZILLA_OBSERVATORY", "0") or "0") not in ("0","false","False"):
        try:
            from intel.mozilla_observatory import scan as _obs_scan
            obs = await _obs_scan(session, domain)
            if obs and obs.get("found"):
                data["mozilla_observatory"] = obs
        except Exception:
            pass

    # Tranco top-1M ranking — strong "this is a legitimate brand, not the
    # attacker" signal. We surface the rank verbatim and a tier bucket so
    # the analyst can see the popularity context at a glance.
    try:
        from intel.tranco import rank as _tr_rank
        tr = _tr_rank(domain)
        if tr is not None:
            tier = ("top-100" if tr <= 100
                    else "top-1k" if tr <= 1000
                    else "top-10k" if tr <= 10000
                    else "top-100k" if tr <= 100000
                    else "top-1M")
            data["tranco"] = {
                "source":  "Tranco-list",
                "rank":    tr,
                "tier":    tier,
                "summary": (f"{domain} is ranked #{tr} on the Tranco top-1M "
                            f"({tier}); a popular brand or service. Treat as "
                            f"impersonation target rather than attacker infra "
                            f"unless other signals contradict."),
            }
    except Exception:
        pass
    # Domain heuristics: NRD age, DGA score, IDN/homoglyph — all offline
    try:
        from intel.domain_analysis import analyze_domain
        heuristics = analyze_domain(domain, (whois_data or {}).get("created"))
        if heuristics:
            data["heuristics"] = heuristics
    except Exception:
        pass
    # ── Secondary lookups — independent, so run them concurrently (Spamhaus DBL,
    #    Maltiverse, OpenCTI, passive DNS, Safe Browsing). ──────────────────────
    from config import config as _cfg
    gsb_key = keys.get("GOOGLE_API_KEY", "")
    try:
        from intel.spamhaus_dbl import lookup as dbl_lookup
        _dbl_co = dbl_lookup(domain)
    except Exception:
        _dbl_co = _skip()
    try:
        from intel.osint_extra import dns_records, google_safe_browsing
        _dns_co = dns_records(session, domain)
        _gsb_co = google_safe_browsing(session, f"http://{domain}/", "domain", gsb_key) if gsb_key else _skip()
    except Exception:
        _dns_co, _gsb_co = _skip(), _skip()

    dbl_r, mv_r, oc_r, dns_r, gsb_r = await asyncio.gather(
        _dbl_co,
        _maltiverse_lookup("hostname", domain, _cfg),
        _opencti_lookup(domain, _cfg),
        _dns_co, _gsb_co,
        return_exceptions=True,
    )

    dbl = _ok_dict(dbl_r)
    if dbl and dbl.get("hit"):
        data["spamhaus_dbl"] = dbl
    mv = _ok_dict(mv_r)
    if mv:
        data["maltiverse"] = mv
    oc = _ok_dict(oc_r)
    if oc:
        data["opencti"] = oc
    osint: dict = {}
    dns = _ok_dict(dns_r)
    if dns and "error" not in dns:
        osint["dns_records"] = dns
    gsb = _ok_dict(gsb_r)
    if gsb and "error" not in gsb and "skipped" not in gsb:
        osint["google_safebrowsing"] = gsb
    if osint:
        data["osint"] = osint

    _cache[ck] = data
    return data


async def enrich_hash(session, hash_val: str, keys: dict) -> dict:
    ck = _ck("hash", hash_val)
    if ck in _cache:
        return {**_cache[ck], "cached": True}

    hybrid_key = keys.get("HYBRID_ANALYSIS_KEY", "")
    abusech_key = keys.get("ABUSECH_AUTH_KEY", "") or keys.get("MALWAREBAZAAR_API_KEY", "")
    is_sha256 = len(hash_val) == 64

    # ── CIRCL hashlookup SHORT-CIRCUIT ────────────────────────────────────────
    # Run CIRCL FIRST as a single synchronous-ish step. If it returns a
    # known-good (NIST NSRL / trusted-software) match we short-circuit
    # the rest of the hash fan-out: no need to spend API quota on VT /
    # MB / ThreatFox / etc. for a file CIRCL has already vouched for.
    hl_url = (f"https://hashlookup.circl.lu/lookup/sha256/{hash_val}" if is_sha256
              else f"https://hashlookup.circl.lu/lookup/md5/{hash_val}")
    hl = await _get(session, hl_url)
    known_good = (
        isinstance(hl, dict) and not hl.get("error")
        and bool(hl.get("hashlookup:trust"))
        and not (hl.get("KnownMalicious") or hl.get("hashlookup:malicious"))
    )
    if known_good:
        data = {"circl_hashlookup": {
            "FileName":     hl.get("FileName"),
            "FileSize":     hl.get("FileSize"),
            "ProductName":  hl.get("ProductName"),
            "ProductCode":  hl.get("ProductCode"),
            "OpSystemCode": hl.get("OpSystemCode"),
            "trust":        hl.get("hashlookup:trust"),
            "verdict":      "CLEAN",
            "summary":      (f"Known-good file: {hl.get('FileName') or '?'}"
                             + (f" ({hl.get('ProductName')})"
                                if hl.get("ProductName") else "")),
        }, "_short_circuited": True}
        _cache[ck] = data
        return data

    # abuse.ch endpoints — pass the Auth-Key header when configured.
    # MalwareBazaar / ThreatFox / URLhaus all use the same key. Anonymous
    # requests have been rate-limited / soft-blocked since mid-2024.
    _ac_headers = {"Auth-Key": abusech_key} if abusech_key else {}

    tasks = [
        _post(session, "https://mb-api.abuse.ch/api/v1/",
              data=f"query=get_info&hash={hash_val}",
              headers={"Content-Type": "application/x-www-form-urlencoded",
                       **_ac_headers}),
        _post(session, "https://threatfox-api.abuse.ch/api/v1/",
              json={"query": "search_hash", "hash": hash_val},
              headers=_ac_headers),
        _get(session, f"https://www.virustotal.com/api/v3/files/{hash_val}",
             headers={"x-apikey": keys.get("VIRUSTOTAL_KEY", "")}),
        _get(session, f"https://otx.alienvault.com/api/v1/indicators/file/{hash_val}/general",
             headers={"X-OTX-API-KEY": keys.get("OTX_KEY", "")}),
        # URLhaus payload lookup — confirms whether the hash is on the
        # URLhaus malware-distribution payload database. Returns malware
        # family + first seen.
        _post(session, "https://urlhaus-api.abuse.ch/v1/payload/",
              data=f"sha256_hash={hash_val}" if is_sha256 else f"md5_hash={hash_val}",
              headers={"Content-Type": "application/x-www-form-urlencoded",
                       **_ac_headers}),
        # Hybrid Analysis — search by hash for prior sandbox detonations.
        # HA's v2 /search/hash requires the hash as a QUERY STRING param
        # (was body-form). Live audit 2026-06-19 confirmed body-form now
        # returns HTTP 400 "value should not be blank". Also the response
        # shape changed from a bare list to {"sha256s": [...],
        # "reports": [...]}. Fix applied in file_correlation.py + sandbox.py
        # by commit d7dd6b6 but this third call site was missed.
        _post(session, "https://www.hybrid-analysis.com/api/v2/search/hash",
              params={"hash": hash_val},
              headers={"api-key": hybrid_key, "user-agent": "Falcon Sandbox",
                       "accept": "application/json"}) if hybrid_key
            else _noop(),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    data = {
        "malwarebazaar": _p_mb(results[0]),
        "threatfox":     _p_tf(results[1]),
        "virustotal":    _p_vt_file(results[2]),
        "otx":           _p_otx(results[3]),
    }
    # URLhaus payload — surface only when the hash actually appears in
    # the database; the "not found" response is informational, not bad.
    uh = results[4]
    if isinstance(uh, dict) and not uh.get("error"):
        query_status = (uh.get("query_status") or "").lower()
        if query_status == "ok":
            data["urlhaus_payload"] = {
                "file_type":      uh.get("file_type"),
                "signature":      uh.get("signature"),
                "first_seen":     uh.get("firstseen"),
                "last_seen":      uh.get("lastseen"),
                "url_count":      uh.get("url_count"),
                "verdict":        "MALICIOUS",
                "summary":        (f"URLhaus payload hit: {uh.get('signature') or 'unknown family'}, "
                                   f"distributed across {uh.get('url_count') or '?'} URLs"),
            }
    # CIRCL hashlookup — we already ran it above. Re-record the data here
    # so the per-source UI shows it alongside everything else. We're past
    # the known-good short-circuit, so this branch covers two cases:
    # (a) CIRCL explicitly flags the hash as KnownMalicious (EICAR,
    #     widely-tracked malware samples) — surface that signal, don't
    #     bury it under generic "below threshold" text.
    # (b) CIRCL has SOME metadata but neither known-good nor known-bad
    #     (UNKNOWN verdict; trust score is just provenance confidence).
    if isinstance(hl, dict) and not hl.get("error"):
        known_malicious = bool(hl.get("KnownMalicious") or hl.get("hashlookup:malicious"))
        data["circl_hashlookup"] = {
            "FileName":        hl.get("FileName"),
            "FileSize":        hl.get("FileSize"),
            "ProductName":     hl.get("ProductName"),
            "trust":           hl.get("hashlookup:trust"),
            "known_malicious": known_malicious,
            "verdict":         "MALICIOUS" if known_malicious else None,
        }
    # Hybrid Analysis (index shifted to 5 after URLhaus payload insertion)
    if hybrid_key and not isinstance(results[5], Exception):
        ha = _p_hybrid(results[5])
        if "error" not in ha:
            data["hybrid_analysis"] = ha

    # MalwareBazaar (abuse.ch) — free hash-to-family lookup. Same
    # operator (abuse.ch) as Feodo/ThreatFox/URLhaus, so the access
    # pattern + reliability are the same. Returns named family, tags,
    # YARA rule names, first/last seen.
    try:
        mb = await _malware_bazaar(session, hash_val)
        if mb and not mb.get("error"):
            data["malware_bazaar"] = mb
    except Exception:
        pass

    # HIBP Pwned Passwords — k-anonymity API for SHA-1 input. We never
    # send the password / full hash; only the first 5 chars of the SHA-1
    # prefix leave the box. RECON's hash IOC extractor surfaces SHA-1s
    # too, and analysts often paste a leaked credential's SHA-1 — when
    # they do, HIBP can confirm "this hash is in 4M breaches."
    if len(hash_val) == 40:
        try:
            from intel.hibp import check_sha1 as _hibp_check
            hp = await _hibp_check(session, hash_val)
            if hp and hp.get("found"):
                data["hibp_passwords"] = hp
        except Exception:
            pass

    # MVT mobile-spyware IOCs — Pegasus / Predator / RCS Lab / BadBazaar.
    # Synchronous in-memory lookup. Hits here are extremely high-signal:
    # MVT only ships IOCs after the threat is named and confirmed.
    try:
        from intel.mvt_iocs import lookup_hash as _mvt_hash
        mvt = _mvt_hash(hash_val)
        if mvt:
            data["mvt_mobile"] = {
                "source":  "MVT (Mobile Verification Toolkit)",
                "family":  mvt.get("family"),
                "ref":     mvt.get("ref"),
                "verdict": "MALICIOUS",
                "summary": (f"MVT spyware hit: {mvt.get('family')}"
                            " — mobile-targeted threat."),
            }
    except Exception:
        pass

    # MISP feeds — flat hashes.csv dump from CIRCL OSINT / DigitalSide /
    # Botvrij. Free, no key, refreshed every 6h. Hits here are strong
    # corroborating evidence (community-curated event with a UUID + a
    # filename context).
    try:
        from intel.misp_feeds import lookup_hash as _misp_lookup
        _misp_hits = await _misp_lookup(hash_val)
        if _misp_hits:
            data["misp_feeds"] = {
                "matched_feeds": [h["feed"] for h in _misp_hits],
                "hits":          _misp_hits[:5],
                "verdict":       "MALICIOUS",
                "summary":       (f"Hash matched in {len(_misp_hits)} MISP feed"
                                  f"{'s' if len(_misp_hits) != 1 else ''}: "
                                  + ", ".join(h["feed"] for h in _misp_hits)),
            }
    except Exception as _e:
        _log.debug("misp_feeds hash lookup failed: %s", _e)
    # ── Secondary lookups — independent, run concurrently (Team Cymru MHR,
    #    Maltiverse, OpenCTI, VT graph, MalwareBazaar pivot, deep sandbox). The
    #    family pivot + deep sandbox depend only on data already collected above. ─
    from config import config as _cfg
    try:
        from intel.team_cymru import lookup as cymru_lookup
        _cy_co = cymru_lookup(hash_val)
    except Exception:
        _cy_co = _skip()
    try:
        from intel.osint_extra import vt_hash_relationships, malwarebazaar_similar
        _vt_co = vt_hash_relationships(session, hash_val, keys.get("VIRUSTOTAL_KEY", ""))
        family = ((data.get("malwarebazaar") or {}).get("malware_family") or
                  (data.get("threatfox") or {}).get("malware_family"))
        _mb_co = malwarebazaar_similar(session, family, abusech_key) if family else _skip()
    except Exception:
        _vt_co, _mb_co = _skip(), _skip()
    if len(hash_val) == 64:
        try:
            from intel.sandbox_deep import fetch_deep_report
            _deep_co = fetch_deep_report(hash_val,
                                         hybrid_key=keys.get("HYBRID_ANALYSIS_KEY", ""))
        except Exception:
            _deep_co = _skip()
    else:
        _deep_co = _skip()

    cy_r, mv_r, oc_r, vt_r, mb_r, deep_r = await asyncio.gather(
        _cy_co,
        _maltiverse_lookup("hash", hash_val, _cfg),
        _opencti_lookup(hash_val, _cfg),
        _vt_co, _mb_co, _deep_co,
        return_exceptions=True,
    )

    cy = _ok_dict(cy_r)
    if cy:
        data["team_cymru_mhr"] = cy
    mv = _ok_dict(mv_r)
    if mv:
        data["maltiverse"] = mv
    oc = _ok_dict(oc_r)
    if oc:
        data["opencti"] = oc
    osint: dict = {}
    vt_rel = _ok_dict(vt_r)
    if vt_rel and "error" not in vt_rel:
        osint["vt_graph"] = vt_rel
    sim = _ok_dict(mb_r)
    if sim and "error" not in sim:
        osint["mb_similar"] = sim
    if osint:
        data["osint"] = osint
    deep = _ok_dict(deep_r)
    if deep:
        data["sandbox_deep"] = deep
    _cache[ck] = data
    return data


# ─── CVE enrichment (per-CVE NVD + EPSS + live CISA KEV) ─────────────────────
async def enrich_cve(session, cve_id: str, keys: dict) -> dict:
    """Per-CVE live API enrichment. Runs NVD + EPSS + CISA KEV concurrently;
    KEV uses the once-per-investigation in-memory cache so the catalog is
    only downloaded once per run no matter how many CVEs are in the alert."""
    ck = _ck("cve", cve_id.upper())
    if ck in _cache:
        return {**_cache[ck], "cached": True}

    try:
        from intel.cve_enrichment import (
            nvd_cve, epss, cisa_kev_check, osv, rhsa, msrc,
        )
    except Exception as e:
        return {"error": f"cve_enrichment unavailable: {e}"}

    # Speed gate — slow/heavy CVE sources are opt-in via Settings.
    # NVD + EPSS + KEV are ALWAYS ON because they're the verdict-driving
    # signals the analyst report cites by default. OSV / RHSA stay on by
    # default (~0.5-1s each). MSRC is OFF by default because the
    # Microsoft Security Update Guide endpoint regularly takes 3-5s
    # per CVE and most analysts don't need it on every analyze.
    from config import config as _cfg
    enable_osv  = (_cfg.get("RECON_ENABLE_OSV", "1") or "1") not in ("0","false","False")
    enable_rhsa = (_cfg.get("RECON_ENABLE_RHSA", "1") or "1") not in ("0","false","False")
    enable_msrc = (_cfg.get("RECON_ENABLE_MSRC", "0") or "0") not in ("0","false","False")
    _tasks = [
        nvd_cve(session, cve_id),
        epss(session, cve_id),
        cisa_kev_check(session, cve_id),
    ]
    _keys = ["nvd", "epss", "kev"]
    if enable_osv:  _tasks.append(osv(session, cve_id));  _keys.append("osv")
    if enable_rhsa: _tasks.append(rhsa(session, cve_id)); _keys.append("rhsa")
    if enable_msrc: _tasks.append(msrc(session, cve_id)); _keys.append("msrc")
    _r = await asyncio.gather(*_tasks, return_exceptions=True)
    _by_key = dict(zip(_keys, _r))
    nvd_r  = _by_key.get("nvd")
    epss_r = _by_key.get("epss")
    kev_r  = _by_key.get("kev")
    osv_r  = _by_key.get("osv")
    rhsa_r = _by_key.get("rhsa")
    msrc_r = _by_key.get("msrc")

    data: dict = {}
    nvd = _ok_dict(nvd_r)
    if nvd:
        data["nvd"] = nvd
    ep = _ok_dict(epss_r)
    if ep:
        data["epss"] = ep
    kev = _ok_dict(kev_r)
    if kev:
        data["cisa_kev"] = kev
    osv_d = _ok_dict(osv_r)
    if osv_d:
        data["osv"] = osv_d
    rh = _ok_dict(rhsa_r)
    if rh:
        data["rhsa"] = rh
    ms = _ok_dict(msrc_r)
    if ms:
        data["msrc"] = ms

    # ProjectDiscovery nuclei-templates: how many public detection
    # templates target this CVE. "X templates exist" is a more concrete
    # exploitation-tooling signal than CVSS alone — closes the gap
    # between EPSS (probability) and KEV (in-the-wild) with active
    # community detection coverage.
    try:
        from intel.nuclei_index import lookup as _nuclei_lookup
        templates = _nuclei_lookup(cve_id, max_results=8)
        if templates:
            data["nuclei"] = {
                "source":         "nuclei-templates",
                "template_count": len(templates),
                "templates":      templates,
                "summary":        (f"{len(templates)} public nuclei detection "
                                   "templates target this CVE."),
            }
    except Exception:
        # Nuclei lookup is additive — never break CVE enrichment.
        pass

    # GitHub Security Advisories — editorial-curated package-ecosystem
    # advisories. Same upstream as OSV.dev but with cleaner summaries +
    # per-ecosystem context.
    try:
        from intel.ghsa import lookup_cve as _ghsa_lookup
        ghsa_rows = _ghsa_lookup(cve_id, max_results=6)
        if ghsa_rows:
            ecosystems: list = []
            for g in ghsa_rows:
                ecosystems.extend(g.get("ecosystems") or [])
            data["ghsa"] = {
                "source":      "GitHub Security Advisories",
                "advisories":  ghsa_rows,
                "ecosystems":  list(dict.fromkeys(ecosystems))[:6],
                "summary":     (f"{len(ghsa_rows)} GitHub Security Advisor"
                                f"{'ies' if len(ghsa_rows) != 1 else 'y'} "
                                f"reference this CVE."),
            }
    except Exception:
        pass

    # Vendor advisory RSS — Apple / Adobe / Oracle. Daily-refreshed
    # via lifespan task. Cross-references against the in-memory CVE
    # index to surface advisory titles + links.
    try:
        from intel.vendor_advisories import lookup_cve as _va_lookup
        va = _va_lookup(cve_id, max_results=6)
        if va:
            vendors_hit = sorted({r.get("vendor_name") for r in va
                                   if r.get("vendor_name")})
            data["vendor_advisories"] = {
                "source":     "Apple/Adobe/Oracle RSS",
                "advisories": va,
                "vendors":    vendors_hit,
                "summary":    (f"{len(va)} vendor advisor"
                                f"{'ies' if len(va) != 1 else 'y'} "
                                f"({', '.join(vendors_hit[:3])})."),
            }
    except Exception:
        pass

    # CSAF — vendor-specific advisories (Cisco, Red Hat, Siemens, SAP,
    # Schneider, Bosch). Synchronous in-memory lookup over the bundled
    # CSAF JSON tree at vendor/csaf/<vendor>/*.json.
    try:
        from intel.csaf import lookup_cve as _csaf_lookup
        csaf_rows = _csaf_lookup(cve_id, max_results=6)
        if csaf_rows:
            vendors_hit = sorted({r.get("vendor") for r in csaf_rows
                                   if r.get("vendor")})
            data["csaf"] = {
                "source":   "OASIS CSAF",
                "advisories": csaf_rows,
                "vendors":  vendors_hit,
                "summary":  (f"{len(csaf_rows)} vendor advisor"
                              f"{'ies' if len(csaf_rows) != 1 else 'y'}"
                              f" via CSAF ({', '.join(vendors_hit[:4])}"
                              f"{'…' if len(vendors_hit) > 4 else ''})."),
            }
    except Exception:
        pass

    # Emerging Threats Open + Snort Community IDS rules. Synchronous
    # in-memory lookup over the bundled .rules trees at
    # vendor/emerging-threats-open / vendor/snort-community.
    try:
        from intel.ids_rules import match_by_cve as _ids_lookup
        ids_rows = _ids_lookup(cve_id, max_results=8)
        if ids_rows:
            data["ids_rules"] = {
                "source":     "ET Open + Snort Community",
                "rules":      ids_rows,
                "rule_count": len(ids_rows),
                "summary":    (f"{len(ids_rows)} IDS rule"
                                f"{'s' if len(ids_rows) != 1 else ''} "
                                f"target this CVE (Suricata/Snort)."),
            }
    except Exception:
        pass

    # trickest/cve PoC catalog — public proof-of-concept exploit links
    # mined from GitHub / gist / exploit-db. "5 PoCs exist" is a sharper
    # weaponisation signal than EPSS-probability alone.
    try:
        from intel.cve_pocs import lookup as _poc_lookup
        pocs = _poc_lookup(cve_id, max_results=10)
        if pocs:
            github_pocs = [p for p in pocs if p["source"] == "github"]
            data["public_pocs"] = {
                "source":      "trickest/cve",
                "pocs":        pocs,
                "poc_count":   len(pocs),
                "github_count": len(github_pocs),
                "summary":     (f"{len(pocs)} public PoC reference"
                                f"{'s' if len(pocs) != 1 else ''} "
                                f"({len(github_pocs)} on GitHub)."),
            }
    except Exception:
        pass

    # SSVC — Stakeholder-Specific Vulnerability Categorization. Synthesises
    # the assembled CVE data into a decision-tree action (Act / Attend /
    # Track* / Track). Sits at the bottom of the gather so every upstream
    # signal (KEV / nuclei / PoCs / NVD) has populated by the time it runs.
    try:
        from intel.ssvc import assess as _ssvc_assess
        data["ssvc"] = _ssvc_assess(data)
    except Exception:
        pass

    _cache[ck] = data
    return data


async def enrich_url(session, url: str, keys: dict) -> dict:
    ck = _ck("url", url)
    if ck in _cache:
        return {**_cache[ck], "cached": True}

    import base64
    url_b64 = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    # URLScan screenshot lookup — finds any previous public scan for this
    # URL and returns the screenshot UUID so the frontend can render the
    # thumbnail inline. Works without an API key (rate-limited) but a key
    # raises the limit considerably.
    try:
        from intel.breach_sources import urlscan_screenshot as _us
        _us_co = _us(session, url, keys.get("URLSCAN_KEY", ""))
    except Exception:
        _us_co = _skip()

    abusech_key = keys.get("ABUSECH_AUTH_KEY", "") or keys.get("MALWAREBAZAAR_API_KEY", "")
    _ac_headers = {"Auth-Key": abusech_key} if abusech_key else {}

    results = await asyncio.gather(
        _get(session, f"https://www.virustotal.com/api/v3/urls/{url_b64}",
             headers={"x-apikey": keys.get("VIRUSTOTAL_KEY", "")}),
        _us_co,
        # URLhaus URL endpoint
        _post(session, "https://urlhaus-api.abuse.ch/v1/url/",
              data=f"url={url}",
              headers={"Content-Type": "application/x-www-form-urlencoded",
                       **_ac_headers}),
        # ThreatFox URL search
        _post(session, "https://threatfox-api.abuse.ch/api/v1/",
              json={"query": "search_ioc", "search_term": url},
              headers=_ac_headers),
        # OTX URL indicator — pulse count + tags for the URL itself
        _get(session,
             f"https://otx.alienvault.com/api/v1/indicators/url/{url}/general",
             headers={"X-OTX-API-KEY": keys.get("OTX_KEY", "")}),
        return_exceptions=True,
    )

    data = {
        "virustotal": _p_vt_url(results[0]),
    }
    us = _ok_dict(results[1])
    if us:
        data["urlscan_screenshot"] = us
    uh = results[2]
    if isinstance(uh, dict) and not uh.get("error") and \
            (uh.get("query_status") or "").lower() == "ok":
        data["urlhaus_url"] = {
            "url_status":   uh.get("url_status"),
            "threat":       uh.get("threat"),
            "tags":         (uh.get("tags") or [])[:8],
            "first_seen":   uh.get("date_added"),
            "last_seen":    uh.get("last_online"),
            "host":         uh.get("host"),
            "payload_count": len(uh.get("payloads") or []),
            "verdict":      "MALICIOUS",
            "summary":      (f"URLhaus hit: {uh.get('threat') or 'malware-distribution'}"
                             + (f" ({uh.get('url_status')})" if uh.get("url_status") else "")),
        }
    tf_url = results[3]
    if isinstance(tf_url, dict) and not tf_url.get("error"):
        tf_parsed = _p_tf(tf_url)
        if not tf_parsed.get("error"):
            data["threatfox"] = tf_parsed
    # OTX URL pulses
    otx_url = _ok_dict(results[4])
    if otx_url and not otx_url.get("error"):
        data["otx"] = _p_otx(otx_url)

    # Phishing URL classifier (sklearn GradientBoosting over URL-structural
    # features). Purely local — string analysis, no network I/O.
    try:
        from intel.phishing_url_classifier import classify as _phish_classify
        data["phishing_classifier"] = _phish_classify(url)
    except Exception:
        pass

    # Admin / sensitive-endpoint classifier (subdomain prefix + path
    # segment + localised keyword + scam-TLD amplifier). Purely string
    # analysis. Adapted from cti-expert (MIT) — surfaces actor admin
    # panels / back-office endpoints that DGA/phishing classifiers miss
    # because the URL is structurally "normal" but lexically suspicious.
    try:
        from intel.admin_endpoint_classifier import classify as _admin_classify
        admin_result = _admin_classify(url)
        if admin_result.get("is_admin") or admin_result.get("indicator"):
            data["admin_endpoint"] = admin_result
    except Exception:
        pass

    _cache[ck] = data
    return data


# ─── AGENT ENTRY POINT ────────────────────────────────────────────────────────────
def _summarize_ioc(per_source: dict) -> dict:
    """Count how many sources flagged this IOC as MALICIOUS / SUSPICIOUS / CLEAN."""
    counts = {"MALICIOUS": 0, "SUSPICIOUS": 0, "CLEAN": 0, "UNKNOWN": 0}
    sources = []
    for name, payload in per_source.items():
        if not isinstance(payload, dict):
            continue
        v = payload.get("verdict")
        if v in counts:
            counts[v] += 1
            sources.append({"source": name, "verdict": v})
    if counts["MALICIOUS"] >= 1:
        overall = "MALICIOUS"
    elif counts["SUSPICIOUS"] >= 1:
        # Used to be a two-branch ladder (>= 2 OR MALICIOUS, then == 1)
        # that collapsed to the same result; MALICIOUS was already
        # short-circuited above so the OR was dead. Single condition
        # now: any suspicious count beats clean.
        overall = "SUSPICIOUS"
    elif counts["CLEAN"] >= 1:
        # SUSPICIOUS is guaranteed 0 here (the elif above would have
        # caught any > 0), so the old `and counts["SUSPICIOUS"] == 0`
        # was a no-op.
        overall = "CLEAN"
    else:
        overall = "UNKNOWN"
    return {"overall": overall, "counts": counts, "sources": sources}


async def run_enrichment(state: dict, on_partial=None) -> dict:
    from config import config

    # No cross-investigation enrichment reuse: start every analysis with a clean
    # cache so each run fetches fresh intel and never serves data saved from a
    # previous investigation. (Within a single run, repeated IOCs still dedupe.)
    _cache.clear()

    keys = {
        "VIRUSTOTAL_KEY":      config.get("VIRUSTOTAL_KEY"),
        "ABUSEIPDB_KEY":       config.get("ABUSEIPDB_KEY"),
        "IPINFO_TOKEN":        config.get("IPINFO_TOKEN"),
        "URLSCAN_KEY":         config.get("URLSCAN_KEY"),
        "OTX_KEY":             config.get("OTX_KEY"),
        "PULSEDIVE_KEY":       config.get("PULSEDIVE_KEY"),
        "CENSYS_API_KEY":      config.get("CENSYS_API_KEY"),
        "CENSYS_ID":           config.get("CENSYS_ID"),
        "CENSYS_SECRET":       config.get("CENSYS_SECRET"),
        "HYBRID_ANALYSIS_KEY": config.get("HYBRID_ANALYSIS_KEY"),
        "GOOGLE_API_KEY":      config.get("GOOGLE_API_KEY"),
        "HONEYPOT_KEY":        config.get("HONEYPOT_KEY"),
        "CRIMINAL_IP_KEY":     config.get("CRIMINAL_IP_KEY"),
        # abuse.ch unified key — unlocks the authenticated endpoints for
        # MalwareBazaar, ThreatFox, and URLhaus (anonymous calls have
        # been rate-limited / soft-blocked since mid-2024).
        "ABUSECH_AUTH_KEY":    config.get("ABUSECH_AUTH_KEY"),
    }

    iocs = state.get("iocs", {})
    trace = state.get("agent_trace", [])
    iteration = state.get("iteration_count", 0)
    start = datetime.now(timezone.utc)

    # Each IOC type is enriched concurrently. We track them as separate tasks so
    # that — as each type finishes — we can stream a cumulative snapshot to the UI
    # (via on_partial) instead of waiting for the slowest type to land everything
    # at once. The final `enrichments` dict is identical either way.
    enrichments = {"ips": {}, "domains": {}, "hashes": {}, "urls": {},
                   "cves": {}}
    type_iocs = {
        "ips":     iocs.get("ips", [])[:10],
        "domains": iocs.get("domains", [])[:10],
        "hashes":  iocs.get("hashes", [])[:10],
        "urls":    iocs.get("urls", [])[:5],
        # CVE enrichment — NVD detail + EPSS exploitation probability +
        # live CISA KEV check. KEV catalog is downloaded once per run
        # via the cve_enrichment._kev_cache singleton.
        "cves":    iocs.get("cves", [])[:8],
    }
    _enrichers = {"ips": enrich_ip, "domains": enrich_domain,
                  "hashes": enrich_hash, "urls": enrich_url,
                  "cves": enrich_cve}

    # Share the process-wide TCP/DNS pool. connector_owner=False keeps the
    # connector alive after this session closes so the next investigation
    # reuses the same warm sockets.
    async with aiohttp.ClientSession(
        connector=_get_connector(), connector_owner=False
    ) as session:
        tasks = {
            cat: asyncio.ensure_future(
                asyncio.gather(*[_enrichers[cat](session, v, keys) for v in vals]))
            for cat, vals in type_iocs.items() if vals
        }
        task_to_cat = {t: cat for cat, t in tasks.items()}
        pending = set(tasks.values())
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                cat = task_to_cat[t]
                enrichments[cat] = {v: r for v, r in zip(type_iocs[cat], t.result())}
                if on_partial:
                    # Cumulative snapshot — the frontend merges this into the result,
                    # so each completed type fills its cards as soon as it's ready.
                    try:
                        await on_partial({"enrichments": {k: dict(v) for k, v in enrichments.items()}})
                    except Exception:
                        pass

    # ── Per-IOC verdict aggregation (spec §3 top-level summary) ────────────────
    # Derive the verdicts dict shape from enrichments.keys() so adding a
    # new IOC bucket (emails, cves, ...) above can't crash this loop with
    # KeyError on the new bucket name. Was hardcoded to the original four
    # buckets — broke every analysis whose log contained an email or CVE
    # IOC until this fix.
    verdicts = {cat: {} for cat in enrichments.keys()}
    overall = {"MALICIOUS": 0, "SUSPICIOUS": 0, "CLEAN": 0, "UNKNOWN": 0}
    for cat, items in enrichments.items():
        for ioc, payload in items.items():
            if not isinstance(payload, dict):
                continue
            s = _summarize_ioc(payload)
            verdicts[cat][ioc] = s
            overall[s["overall"]] = overall.get(s["overall"], 0) + 1
            payload["_summary"] = s  # also attach summary inline for the AI to consume

    summary = {
        "totals": {k: len(v) for k, v in enrichments.items()},
        "verdicts_per_ioc": verdicts,
        "verdict_counts":   overall,
        "any_malicious":    overall["MALICIOUS"] > 0,
        "any_suspicious":   overall["SUSPICIOUS"] > 0,
    }

    # Spec §2 — transparent confidence engine. Deterministic per-IOC score
    # independent of the AI assessment so the analyst can audit exactly why
    # each IOC scored where it did.
    confidence: dict = {}
    try:
        from intel.confidence_engine import score_all
        try:
            from intel.feed_aggregator import check_ioc as _feed_lookup
        except Exception:
            _feed_lookup = None
        confidence = score_all(enrichments,
                               behavioral=state.get("behavioral_indicators"),
                               feed_cache_lookup=_feed_lookup)
    except Exception as e:
        confidence = {"_error": str(e)}

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    trace.append({
        "agent": "enrichment",
        "status": "complete",
        "summary": (f"Enriched {summary['totals']['ips']} IPs, "
                    f"{summary['totals']['domains']} domains, "
                    f"{summary['totals']['hashes']} hashes, "
                    f"{summary['totals']['urls']} URLs in {elapsed:.1f}s. "
                    f"{overall['MALICIOUS']} malicious, {overall['SUSPICIOUS']} suspicious."),
        "iteration": iteration + 1,
        "elapsed_ms": int(elapsed * 1000),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    return {**state, "enrichments": enrichments,
            "enrichment_summary": summary,
            "confidence_scores": confidence,
            "iteration_count": iteration + 1, "agent_trace": trace}
