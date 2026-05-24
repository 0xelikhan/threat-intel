"""
Enrichment Agent — all API keys read from config at call time.
Zero AI tokens — pure parallel HTTP calls.
"""

import asyncio
import hashlib
from datetime import datetime, timezone

import aiohttp

TIMEOUT = aiohttp.ClientTimeout(total=10)
_cache: dict = {}
_tor_nodes: set = set()
_tor_fetched: float = 0.0


def _ck(ioc_type: str, value: str) -> str:
    return f"{ioc_type}:{hashlib.md5(value.encode()).hexdigest()}"


async def _get(session, url, **kw):
    try:
        async with session.get(url, timeout=TIMEOUT, **kw) as r:
            return await r.json() if "json" in r.content_type else {"raw": await r.text()}
    except Exception as e:
        return {"error": str(e)}


async def _post(session, url, **kw):
    try:
        async with session.post(url, timeout=TIMEOUT, **kw) as r:
            return await r.json() if "json" in r.content_type else {"raw": await r.text()}
    except Exception as e:
        return {"error": str(e)}


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
def _p_abuse(r):
    if isinstance(r, Exception) or not isinstance(r, dict) or "error" in r:
        return {"error": str(r)}
    d = _safe(r, "data", default={})
    out = {"abuseScore": d.get("abuseConfidenceScore"), "totalReports": d.get("totalReports"),
           "country": d.get("countryCode"), "isp": d.get("isp"), "usageType": d.get("usageType"),
           "lastReportedAt": d.get("lastReportedAt")}
    # Flag same-day IP activity (first/last reported within 24 h is high signal)
    try:
        from datetime import datetime, timezone
        last = d.get("lastReportedAt")
        if last:
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
    return out

def _p_ipinfo(r):
    if isinstance(r, Exception) or not isinstance(r, dict) or "error" in r:
        return {"error": str(r)}
    return {"org": r.get("org"), "country": r.get("country"), "city": r.get("city"),
            "region": r.get("region"), "loc": r.get("loc"), "hostname": r.get("hostname")}

def _p_gn(r):
    if isinstance(r, Exception) or not isinstance(r, dict):
        return {"error": "Not in GreyNoise"}
    return {"noise": r.get("noise"), "riot": r.get("riot"),
            "classification": r.get("classification"), "name": r.get("name")}

def _p_shodan(r):
    if isinstance(r, Exception) or not isinstance(r, dict) or "error" in r:
        return {"error": str(r)}
    return {"ports": r.get("ports"), "vulns": list((r.get("vulns") or {}).keys()),
            "os": r.get("os"), "tags": r.get("tags"),
            "services": [{"port": s.get("port"), "product": s.get("product")} for s in (r.get("data") or [])[:5]]}

def _p_vt_ip(r):
    if isinstance(r, Exception) or not isinstance(r, dict) or "error" in r:
        return {"error": str(r)}
    s = _safe(r, "data", "attributes", "last_analysis_stats", default={})
    return {"malicious": s.get("malicious"), "suspicious": s.get("suspicious"),
            "harmless": s.get("harmless"), "reputation": _safe(r, "data", "attributes", "reputation")}

def _p_vt_domain(r):
    if isinstance(r, Exception) or not isinstance(r, dict) or "error" in r:
        return {"error": str(r)}
    s = _safe(r, "data", "attributes", "last_analysis_stats", default={})
    return {"malicious": s.get("malicious"), "suspicious": s.get("suspicious"),
            "reputation": _safe(r, "data", "attributes", "reputation")}

def _p_vt_file(r):
    if isinstance(r, Exception) or not isinstance(r, dict) or "error" in r:
        return {"error": str(r)}
    s = _safe(r, "data", "attributes", "last_analysis_stats", default={})
    return {"malicious": s.get("malicious"), "suspicious": s.get("suspicious"),
            "name": _safe(r, "data", "attributes", "meaningful_name"),
            "type": _safe(r, "data", "attributes", "type_description")}

def _p_vt_url(r):
    if isinstance(r, Exception) or not isinstance(r, dict) or "error" in r:
        return {"error": str(r)}
    s = _safe(r, "data", "attributes", "last_analysis_stats", default={})
    return {"malicious": s.get("malicious"), "suspicious": s.get("suspicious")}

def _p_otx(r):
    if isinstance(r, Exception) or not isinstance(r, dict) or "error" in r:
        return {"error": str(r)}
    return {"pulseCount": _safe(r, "pulse_info", "count"),
            "relatedPulses": [p.get("name") for p in (_safe(r, "pulse_info", "pulses") or [])[:3]]}

def _p_crt(r):
    if isinstance(r, Exception) or not isinstance(r, list):
        return {"error": "No data"}
    return {"totalCerts": len(r), "subdomains": list({c.get("name_value") for c in r})[:20]}

def _p_whois(r):
    if isinstance(r, Exception) or not isinstance(r, dict) or "error" in r:
        return {"error": str(r)}
    return {"registrar": _safe(r, "registrar", "name"),
            "created": _safe(r, "domain", "created_date"),
            "expires": _safe(r, "domain", "expiration_date"),
            "nameservers": (r.get("nameservers") or [])[:4]}

def _p_pd(r):
    if isinstance(r, Exception) or not isinstance(r, dict) or "error" in r:
        return {"error": str(r)}
    return {"risk": r.get("risk"), "threats": [t.get("name") for t in (r.get("threats") or [])[:3]]}


def _p_wayback(r):
    if isinstance(r, Exception) or not isinstance(r, dict) or "error" in r:
        return {"error": "no wayback"}
    snap = (r.get("archived_snapshots") or {}).get("closest") or {}
    if not snap.get("available"):
        return {"has_snapshots": False, "note": "Domain not in Wayback Machine — no history at all"}
    ts = snap.get("timestamp", "")
    if len(ts) >= 8:
        formatted = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
    else:
        formatted = ts
    return {
        "has_snapshots":   True,
        "closest_snapshot":formatted,
        "snapshot_url":    snap.get("url"),
        "status":          snap.get("status"),
    }

def _p_urlscan(r):
    if isinstance(r, Exception) or not isinstance(r, dict) or "error" in r:
        return {"error": str(r)}
    hits = r.get("results") or []
    if not hits:
        return {"error": "No scans found"}
    v = hits[0].get("verdicts", {}).get("overall", {})
    return {"malicious": v.get("malicious"), "score": v.get("score"), "tags": v.get("tags")}

def _p_mb(r):
    if isinstance(r, Exception) or not isinstance(r, dict) or "error" in r:
        return {"error": str(r)}
    if r.get("query_status") != "ok":
        return {"queryStatus": r.get("query_status")}
    d = (r.get("data") or [{}])[0]
    return {"malwareName": d.get("signature"), "tags": d.get("tags"),
            "fileType": d.get("file_type"), "firstSeen": d.get("first_seen")}

def _p_tf(r):
    if isinstance(r, Exception) or not isinstance(r, dict) or "error" in r:
        return {"error": str(r)}
    if r.get("query_status") != "ok":
        return {"queryStatus": r.get("query_status")}
    d = (r.get("data") or [{}])[0]
    return {"malware": d.get("malware_printable"), "confidence": d.get("confidence_level")}


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


async def enrich_ip(session, ip: str, keys: dict) -> dict:
    ck = _ck("ip", ip)
    if ck in _cache:
        return {**_cache[ck], "cached": True}

    tor_nodes = await _tor(session)

    results = await asyncio.gather(
        _get(session, "https://api.abuseipdb.com/api/v2/check",
             params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
             headers={"Key": keys.get("ABUSEIPDB_KEY", ""), "Accept": "application/json"}),
        _get(session, f"https://ipinfo.io/{ip}/json",
             params={"token": keys.get("IPINFO_TOKEN", "")}),
        _get(session, f"https://api.greynoise.io/v3/community/{ip}",
             headers={"key": keys.get("GREYNOISE_KEY", "")}),
        _get(session, f"https://api.shodan.io/shodan/host/{ip}",
             params={"key": keys.get("SHODAN_KEY", "")}),
        _get(session, f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
             headers={"x-apikey": keys.get("VIRUSTOTAL_KEY", "")}),
        _get(session, f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
             headers={"X-OTX-API-KEY": keys.get("OTX_KEY", "")}),
        return_exceptions=True,
    )

    abuse_data  = _p_abuse(results[0])
    ipinfo_data = _p_ipinfo(results[1])
    data = {
        "tor":         {"isExitNode": ip in tor_nodes},
        "abuseipdb":   abuse_data,
        "ipinfo":      ipinfo_data,
        "greynoise":   _p_gn(results[2]),
        "shodan":      _p_shodan(results[3]),
        "virustotal":  _p_vt_ip(results[4]),
        "otx":         _p_otx(results[5]),
        "local_feeds": _local_ip_check(ip),
    }
    # ASN reputation — uses ISP/org strings we already have, no extra API call
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
    # Cortex-style ports: Maltiverse aggregator + OpenCTI prior-context lookup
    from config import config as _cfg
    try:
        mv = await _maltiverse_lookup("ip", ip, _cfg)
        if mv:
            data["maltiverse"] = mv
    except Exception:
        pass
    try:
        oc = await _opencti_lookup(ip, _cfg)
        if oc:
            data["opencti"] = oc
    except Exception:
        pass
    _cache[ck] = data
    return data


async def enrich_domain(session, domain: str, keys: dict) -> dict:
    ck = _ck("domain", domain)
    if ck in _cache:
        return {**_cache[ck], "cached": True}

    results = await asyncio.gather(
        _get(session, f"https://www.virustotal.com/api/v3/domains/{domain}",
             headers={"x-apikey": keys.get("VIRUSTOTAL_KEY", "")}),
        _get(session, "https://urlscan.io/api/v1/search/",
             params={"q": f"domain:{domain}", "size": 1},
             headers={"API-Key": keys.get("URLSCAN_KEY", "")}),
        _get(session, f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
             headers={"X-OTX-API-KEY": keys.get("OTX_KEY", "")}),
        _get(session, f"https://crt.sh/?q=%25.{domain}&output=json"),
        _get(session, f"https://who-dat.as93.net/{domain}"),
        _get(session, "https://pulsedive.com/api/info.php",
             params={"indicator": domain, "pretty": 1, "key": keys.get("PULSEDIVE_KEY", "")}),
        # Wayback Machine — free, no key, indicates if the domain ever had snapshots
        _get(session, "https://archive.org/wayback/available",
             params={"url": domain}),
        return_exceptions=True,
    )

    whois_data = _p_whois(results[4])
    data = {
        "virustotal":      _p_vt_domain(results[0]),
        "urlscan":         _p_urlscan(results[1]),
        "otx":             _p_otx(results[2]),
        "certTransparency":_p_crt(results[3]),
        "whois":           whois_data,
        "pulsedive":       _p_pd(results[5]),
        "wayback":         _p_wayback(results[6]),
        "local_feeds":     _local_domain_check(domain),
        "typosquat":       _typosquat_check(domain),
    }
    # Domain heuristics: NRD age, DGA score, IDN/homoglyph — all offline
    try:
        from intel.domain_analysis import analyze_domain
        heuristics = analyze_domain(domain, (whois_data or {}).get("created"))
        if heuristics:
            data["heuristics"] = heuristics
    except Exception:
        pass
    # Spamhaus DBL (free DNS-based domain blocklist)
    try:
        from intel.spamhaus_dbl import lookup as dbl_lookup
        dbl = await dbl_lookup(domain)
        if dbl and dbl.get("hit"):
            data["spamhaus_dbl"] = dbl
    except Exception:
        pass
    # Maltiverse + OpenCTI
    from config import config as _cfg
    try:
        mv = await _maltiverse_lookup("hostname", domain, _cfg)
        if mv:
            data["maltiverse"] = mv
    except Exception:
        pass
    try:
        oc = await _opencti_lookup(domain, _cfg)
        if oc:
            data["opencti"] = oc
    except Exception:
        pass
    _cache[ck] = data
    return data


async def enrich_hash(session, hash_val: str, keys: dict) -> dict:
    ck = _ck("hash", hash_val)
    if ck in _cache:
        return {**_cache[ck], "cached": True}

    results = await asyncio.gather(
        _post(session, "https://mb-api.abuse.ch/api/v1/",
              data=f"query=get_info&hash={hash_val}",
              headers={"Content-Type": "application/x-www-form-urlencoded"}),
        _post(session, "https://threatfox-api.abuse.ch/api/v1/",
              json={"query": "search_hash", "hash": hash_val}),
        _get(session, f"https://www.virustotal.com/api/v3/files/{hash_val}",
             headers={"x-apikey": keys.get("VIRUSTOTAL_KEY", "")}),
        _get(session, f"https://otx.alienvault.com/api/v1/indicators/file/{hash_val}/general",
             headers={"X-OTX-API-KEY": keys.get("OTX_KEY", "")}),
        return_exceptions=True,
    )

    data = {
        "malwarebazaar": _p_mb(results[0]),
        "threatfox":     _p_tf(results[1]),
        "virustotal":    _p_vt_file(results[2]),
        "otx":           _p_otx(results[3]),
    }
    # Team Cymru MHR (free DNS-based hash reputation) + Maltiverse + OpenCTI
    try:
        from intel.team_cymru import lookup as cymru_lookup
        cy = await cymru_lookup(hash_val)
        if cy:
            data["team_cymru_mhr"] = cy
    except Exception:
        pass
    from config import config as _cfg
    try:
        mv = await _maltiverse_lookup("hash", hash_val, _cfg)
        if mv:
            data["maltiverse"] = mv
    except Exception:
        pass
    try:
        oc = await _opencti_lookup(hash_val, _cfg)
        if oc:
            data["opencti"] = oc
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

    results = await asyncio.gather(
        _get(session, f"https://www.virustotal.com/api/v3/urls/{url_b64}",
             headers={"x-apikey": keys.get("VIRUSTOTAL_KEY", "")}),
        return_exceptions=True,
    )

    data = {
        "virustotal": _p_vt_url(results[0]),
    }
    _cache[ck] = data
    return data


# ─── AGENT ENTRY POINT ────────────────────────────────────────────────────────────
async def run_enrichment(state: dict) -> dict:
    from config import config

    keys = {
        "VIRUSTOTAL_KEY": config.get("VIRUSTOTAL_KEY"),
        "ABUSEIPDB_KEY":  config.get("ABUSEIPDB_KEY"),
        "IPINFO_TOKEN":   config.get("IPINFO_TOKEN"),
        "GREYNOISE_KEY":  config.get("GREYNOISE_KEY"),
        "SHODAN_KEY":     config.get("SHODAN_KEY"),
        "URLSCAN_KEY":    config.get("URLSCAN_KEY"),
        "OTX_KEY":        config.get("OTX_KEY"),
        "PULSEDIVE_KEY":  config.get("PULSEDIVE_KEY"),
    }

    iocs = state.get("iocs", {})
    trace = state.get("agent_trace", [])
    iteration = state.get("iteration_count", 0)
    start = datetime.now(timezone.utc)

    async with aiohttp.ClientSession() as session:
        ip_res, dom_res, hash_res, url_res = await asyncio.gather(
            asyncio.gather(*[enrich_ip(session, ip, keys)     for ip in iocs.get("ips", [])[:10]]),
            asyncio.gather(*[enrich_domain(session, d, keys)  for d  in iocs.get("domains", [])[:10]]),
            asyncio.gather(*[enrich_hash(session, h, keys)    for h  in iocs.get("hashes", [])[:10]]),
            asyncio.gather(*[enrich_url(session, u, keys)     for u  in iocs.get("urls", [])[:5]]),
        )

    enrichments = {
        "ips":     {ip: r for ip, r in zip(iocs.get("ips", []),     ip_res)},
        "domains": {d:  r for d,  r in zip(iocs.get("domains", []), dom_res)},
        "hashes":  {h:  r for h,  r in zip(iocs.get("hashes", []),  hash_res)},
        "urls":    {u:  r for u,  r in zip(iocs.get("urls", []),    url_res)},
    }

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    mal = sum(1 for d in enrichments.get("ips", {}).values()
              if (d.get("abuseipdb") or {}).get("abuseScore", 0) > 50
              or (d.get("virustotal") or {}).get("malicious", 0) > 3)
    mal += sum(1 for d in enrichments.get("hashes", {}).values()
               if (d.get("virustotal") or {}).get("malicious", 0) > 0
               or (d.get("malwarebazaar") or {}).get("malwareName"))

    trace.append({
        "agent": "enrichment",
        "status": "complete",
        "summary": (f"Enriched {len(iocs.get('ips',[]))} IPs, "
                    f"{len(iocs.get('domains',[]))} domains, "
                    f"{len(iocs.get('hashes',[]))} hashes, "
                    f"{len(iocs.get('urls',[]))} URLs in {elapsed:.1f}s. "
                    f"{mal} flagged by multiple sources."),
        "iteration": iteration + 1,
        "elapsed_ms": int(elapsed * 1000),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    return {**state, "enrichments": enrichments,
            "iteration_count": iteration + 1, "agent_trace": trace}
