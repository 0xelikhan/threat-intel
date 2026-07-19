"""
Extra free OSINT sources — spec §3.

Adds to enrichment.py: full DNS record enumeration (hackertarget), CIRCL BGP
ranking, VirusTotal graph relationships for hashes, MalwareBazaar similar
samples by family, Google Safe Browsing lookup when a key is configured.

The WHOIS / Wayback / Tor lookups already exist in enrichment.py and are
unchanged. These helpers are called from enrichment functions and merged
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
    """CIRCL BGP Ranking — ASN reputation score. Two-call flow:
      1. POST /ipasn_history/  {"ip": X}  →  {"response": {"<ts>": {"asn": X, "prefix": X}}}
      2. POST /json/asn        {"asn": X} →  {"response": {"asn_description": X,
                                                            "ranking": {"rank": F, "position": N,
                                                                         "total_known_asns": N}}}

    CIRCL retired the old bgpranking-ng.circl.lu/json?ip=X endpoint. The
    module previously pointed there so this call had been silently 404ing
    on every enrich_ip run. Rank scoring: HIGHER rank = worse reputation
    (more indicators seen on that ASN). Position is where this ASN sits
    in a badness-sorted list, so position=1 is the single worst ASN."""
    try:
        async with session.post(
            "https://bgpranking.circl.lu/ipasn_history/",
            json={"ip": ip}, timeout=_TIMEOUT,
        ) as r:
            if r.status != 200:
                return {"error": f"HTTP {r.status} (ipasn_history)",
                        "source": "bgp_ranking"}
            step1 = await r.json()

        resp = step1.get("response") or {}
        # response is a dict keyed by timestamp. Take the most recent one.
        latest_ts = max(resp.keys()) if resp else ""
        latest    = resp.get(latest_ts) or {}
        asn       = str(latest.get("asn") or "")
        prefix    = latest.get("prefix") or ""
        if not asn:
            return {"error": "no ASN found for IP", "source": "bgp_ranking"}

        async with session.post(
            "https://bgpranking.circl.lu/json/asn",
            json={"asn": asn}, timeout=_TIMEOUT,
        ) as r:
            if r.status != 200:
                return {"error": f"HTTP {r.status} (asn rank)",
                        "source": "bgp_ranking"}
            step2 = await r.json()

        r2       = step2.get("response") or {}
        ranking  = r2.get("ranking") or {}
        rank     = ranking.get("rank")
        position = ranking.get("position")
        total    = ranking.get("total_known_asns")
        desc     = r2.get("asn_description") or ""

        # Derived verdict + human-readable summary. The AI analyst was
        # reading the raw `rank: 1.82e-06` and calling it "poor" — the
        # opposite of what a low rank actually means. Emitting a plain
        # verdict + summary makes the semantics impossible to invert.
        #
        # Position is the primary tier signal — it's normalised against
        # the total ASN count, so it survives CIRCL rebalancing better
        # than raw rank thresholds. Position=1 is the SINGLE WORST ASN
        # (most abuse indicators observed on it that day).
        verdict = "UNKNOWN"
        rep_word = "unranked"
        percentile_clean = None
        if isinstance(position, int) and isinstance(total, int) and total > 0:
            percentile_clean = round((position / total) * 100, 1)
            if position <= 200:
                verdict, rep_word = "MALICIOUS", "very poor"
            elif position <= 1000:
                verdict, rep_word = "SUSPICIOUS", "poor"
            elif position <= 4000:
                verdict, rep_word = "UNKNOWN", "mixed"
            else:
                verdict, rep_word = "CLEAN", "clean"

        summary_bits = [f"AS{asn}"]
        if desc: summary_bits.append(desc)
        summary_bits.append(f"{rep_word} reputation")
        if isinstance(position, int) and isinstance(total, int) and total > 0:
            summary_bits.append(f"position {position:,}/{total:,} in CIRCL badness index")
            summary_bits.append(f"cleaner than {percentile_clean}% of ASNs")
        summary = " · ".join(summary_bits)

        return {
            "source":            "CIRCL BGP Ranking",
            "asn":               asn,
            "asn_description":   desc,
            "prefix":            prefix,
            "rank":              rank,
            "ranking_position":  position,
            "total_known_asns":  total,
            "percentile_clean":  percentile_clean,
            "verdict":           verdict,
            "summary":           summary,
            "note":              ("CIRCL BGP Ranking: LOWER rank + HIGHER position = "
                                   "cleaner ASN. position=1 is the single worst ASN "
                                   "(most abuse indicators)."),
            "observed_at":       latest_ts,
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
