"""
Extra free OSINT sources — spec §3.

Adds to enrichment.py: full DNS record enumeration (hackertarget), CIRCL BGP
ranking, VirusTotal graph relationships for hashes, MalwareBazaar similar
samples by family, Google Safe Browsing lookup when a key is configured.

The crt.sh / WHOIS / Wayback / Tor lookups already exist in enrichment.py and
are unchanged. These helpers are called from enrichment functions and merged
into a single `osint` section per IOC.
"""

from __future__ import annotations
import aiohttp
from typing import Dict, List

_TIMEOUT = aiohttp.ClientTimeout(total=10)


# ─── DNS record enumeration (hackertarget — no key) ─────────────────────────────
async def dns_records(session: aiohttp.ClientSession, domain: str) -> Dict:
    """Returns {records: {A:[…], AAAA:[…], MX:[…], NS:[…], TXT:[…], SOA:[…], CNAME:[…]}}."""
    records: Dict[str, List[str]] = {"A": [], "AAAA": [], "MX": [], "NS": [],
                                     "TXT": [], "SOA": [], "CNAME": []}
    try:
        async with session.get(
            "https://api.hackertarget.com/dnslookup/",
            params={"q": domain}, timeout=_TIMEOUT,
        ) as r:
            text = await r.text()
            if "API count exceeded" in text or "error" in text.lower()[:60]:
                return {"error": text[:120], "source": "hackertarget_dns"}
            for line in text.splitlines():
                line = line.strip()
                if " : " not in line:
                    continue
                left, val = line.split(" : ", 1)
                # HackerTarget's left side looks like:
                #   "example.com. 60 IN A" / "... 60 IN NS" / "... 60 IN SOA"
                # The record type is the LAST whitespace-separated token.
                # Previous logic used left.endswith(rec) which matched
                # 'SOA' against 'A' (suffix collision), polluting the A
                # record list with the SOA tuple. Comparing the last token
                # avoids that.
                toks = left.split()
                last_tok = toks[-1] if toks else ""
                if last_tok in records:
                    records[last_tok].append(val.strip())
    except Exception as e:
        return {"error": str(e), "source": "hackertarget_dns"}
    # Strip empty record types for compactness
    out = {k: v[:8] for k, v in records.items() if v}
    return {"records": out, "total_records": sum(len(v) for v in out.values())}


# ─── BGP ranking (CIRCL — no key) ──────────────────────────────────────────────
async def bgp_ranking(session: aiohttp.ClientSession, ip: str) -> Dict:
    """https://bgpranking.circl.lu/json?ip=IP — ASN reputation score."""
    try:
        async with session.get(
            "https://bgpranking-ng.circl.lu/json",
            params={"ip": ip}, timeout=_TIMEOUT,
        ) as r:
            if r.status != 200:
                return {"error": f"HTTP {r.status}", "source": "bgp_ranking"}
            d = await r.json()
            return {
                "asn":          d.get("asn"),
                "asn_description": d.get("asn_description"),
                "rank":         d.get("ranking"),  # smaller = worse
                "ranking_position": d.get("ranking_position"),
                "country":      d.get("country"),
            }
    except Exception as e:
        return {"error": str(e), "source": "bgp_ranking"}


# ─── VirusTotal graph relationships (for hashes) ───────────────────────────────
async def vt_hash_relationships(session: aiohttp.ClientSession, sha: str, key: str) -> Dict:
    """Look up files that contact the same C2 + drop the same children, etc.
    Uses the /relationships/{type} endpoint family on VT v3."""
    if not key:
        return {"error": "no VT key", "source": "vt_graph"}
    out: Dict[str, List] = {}
    for rel in ("contacted_domains", "contacted_ips", "contacted_urls",
                "dropped_files", "similar_files"):
        try:
            async with session.get(
                f"https://www.virustotal.com/api/v3/files/{sha}/{rel}",
                headers={"x-apikey": key}, timeout=_TIMEOUT, params={"limit": 5},
            ) as r:
                if r.status != 200:
                    continue
                d = await r.json()
                items = []
                for entry in (d.get("data") or [])[:5]:
                    items.append({
                        "id":   entry.get("id"),
                        "type": entry.get("type"),
                    })
                if items:
                    out[rel] = items
        except Exception:
            continue
    return out or {"error": "no relationships returned", "source": "vt_graph"}


# ─── MalwareBazaar similar samples by family ───────────────────────────────────
async def malwarebazaar_similar(session: aiohttp.ClientSession, family: str,
                                 abusech_key: str = "") -> Dict:
    """Pull recent samples tagged with the same family — useful for pivot."""
    if not family:
        return {}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if abusech_key:
        headers["Auth-Key"] = abusech_key
    try:
        async with session.post(
            "https://mb-api.abuse.ch/api/v1/",
            data=f"query=get_taginfo&tag={family}&limit=10",
            headers=headers,
            timeout=_TIMEOUT,
        ) as r:
            if r.status != 200:
                return {"error": f"HTTP {r.status}", "source": "mb_similar"}
            d = await r.json()
            if d.get("query_status") != "ok":
                return {"queryStatus": d.get("query_status")}
            samples = []
            for s in (d.get("data") or [])[:8]:
                samples.append({
                    "sha256":     s.get("sha256_hash"),
                    "file_type":  s.get("file_type"),
                    "first_seen": s.get("first_seen"),
                    "signature":  s.get("signature"),
                })
            return {"family": family, "samples": samples, "count": len(samples)}
    except Exception as e:
        return {"error": str(e), "source": "mb_similar"}


# ─── Google Safe Browsing (free, key required) ─────────────────────────────────
async def google_safe_browsing(session: aiohttp.ClientSession, value: str,
                                ioc_type: str, api_key: str) -> Dict:
    """If GOOGLE_API_KEY is configured query Safe Browsing v4. Otherwise skip."""
    if not api_key:
        return {"skipped": "no Google API key"}
    url_types = {"domain": "URL", "url": "URL", "ip": "IP_RANGE"}
    if ioc_type not in url_types:
        return {"skipped": f"unsupported type {ioc_type}"}
    body = {
        "client": {"clientId": "recon-platform", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": [url_types[ioc_type]],
            "threatEntries": [{"url": value} if ioc_type in ("domain", "url") else {"ip": value}],
        },
    }
    try:
        async with session.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=body, timeout=_TIMEOUT,
        ) as r:
            if r.status != 200:
                return {"error": f"HTTP {r.status}", "source": "google_safebrowsing"}
            d = await r.json()
            matches = d.get("matches") or []
            return {
                "match_count":  len(matches),
                "threat_types": sorted({m.get("threatType") for m in matches if m.get("threatType")}),
                "platform_types": sorted({m.get("platformType") for m in matches if m.get("platformType")}),
                "verdict":      "MALICIOUS" if matches else "CLEAN",
            }
    except Exception as e:
        return {"error": str(e), "source": "google_safebrowsing"}
