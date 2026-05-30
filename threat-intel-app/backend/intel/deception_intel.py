"""
Deception / honeypot intelligence — spec §5.

Free no-key sources (RIOT requires GREYNOISE_KEY which is already configured):

  GreyNoise RIOT       → /v3/riot/{ip} — is this a known safe service (Cloudflare,
                         Google, AWS)? If so we skip full enrichment.
  Shodan InternetDB    → https://internetdb.shodan.io/{ip} — completely free,
                         no key. Open ports + CPEs + CVEs + tags + hostnames in
                         <100ms. Pre-enrichment fast path.
  DShield (SANS ISC)   → https://isc.sans.edu/api/ip/{ip}?json — attack count,
                         report count, threat level, block list status.
  StopForumSpam        → https://api.stopforumspam.org/api?json&ip={ip} — spam
                         and abuse history.
  Emerging Threats     → cached download of compromised-ips.txt — checked as a
                         local set membership test.
  Project Honeypot     → https://www.projecthoneypot.org/api.php with HONEYPOT_KEY
                         — HTTP:BL data when configured.

Returns one combined dict per IP. Each subsection is `{flagged, …}` so the
confidence engine can wire any hit into a score factor.
"""

from __future__ import annotations
import asyncio
import aiohttp
import time
from typing import Dict, Set

_TIMEOUT = aiohttp.ClientTimeout(total=8)

# ── Emerging Threats compromised-IPs cache ────────────────────────────────────
_ET_CACHE: Set[str] = set()
_ET_FETCHED: float = 0.0
_ET_TTL = 6 * 3600  # refresh every 6 hours


async def _refresh_et(session: aiohttp.ClientSession) -> None:
    """Fetch ET compromised-ips list — only every 6h."""
    global _ET_CACHE, _ET_FETCHED
    if _ET_CACHE and (time.time() - _ET_FETCHED) < _ET_TTL:
        return
    try:
        async with session.get(
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            timeout=_TIMEOUT,
        ) as r:
            if r.status != 200:
                return
            text = await r.text()
            new_set = set()
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                new_set.add(line)
            _ET_CACHE = new_set
            _ET_FETCHED = time.time()
    except Exception:
        pass


# ─── per-IP enrichment ─────────────────────────────────────────────────────────
async def enrich_deception(session: aiohttp.ClientSession, ip: str, keys: Dict) -> Dict:
    """Run all deception-intel sources in parallel. Returns a combined dict."""
    await _refresh_et(session)
    gn_key = keys.get("GREYNOISE_KEY", "")
    hp_key = keys.get("HONEYPOT_KEY", "")

    tasks = [
        _riot(session, ip, gn_key),
        _internetdb(session, ip),
        _dshield(session, ip),
        _stopforumspam(session, ip),
        _project_honeypot(session, ip, hp_key),
    ]
    riot, internetdb, dshield, sfs, hp = await asyncio.gather(*tasks, return_exceptions=True)

    out: Dict = {}
    if isinstance(riot, dict) and "error" not in riot:
        out["greynoise_riot"] = riot
    if isinstance(internetdb, dict) and "error" not in internetdb:
        out["shodan_internetdb"] = internetdb
    if isinstance(dshield, dict) and "error" not in dshield:
        out["dshield"] = dshield
    if isinstance(sfs, dict) and "error" not in sfs:
        out["stopforumspam"] = sfs
    if isinstance(hp, dict) and "error" not in hp:
        out["project_honeypot"] = hp

    # Emerging Threats — local list lookup
    if ip in _ET_CACHE:
        out["emerging_threats"] = {
            "flagged":  True,
            "source":   "Emerging Threats compromised-ips",
            "summary":  "IP appears on the ET compromised-ips block list",
        }

    # Aggregated flagged count for quick frontend display
    flagged_count = sum(1 for v in out.values() if isinstance(v, dict) and v.get("flagged"))
    out["flagged_count"] = flagged_count
    out["sources_consulted"] = len(out) - 1  # minus flagged_count
    return out


# ─── individual probes ─────────────────────────────────────────────────────────
async def _riot(session, ip: str, key: str) -> Dict:
    """GreyNoise RIOT — known-good infrastructure (Cloudflare/Google/AWS etc.)."""
    if not key:
        return {"error": "no GREYNOISE_KEY", "source": "greynoise_riot"}
    try:
        async with session.get(
            f"https://api.greynoise.io/v3/riot/{ip}",
            headers={"key": key}, timeout=_TIMEOUT,
        ) as r:
            if r.status == 404:
                return {"riot": False, "is_known_good": False}
            if r.status != 200:
                return {"error": f"HTTP {r.status}", "source": "greynoise_riot"}
            d = await r.json()
            return {
                "riot":            d.get("riot", False),
                "is_known_good":   bool(d.get("riot")),
                "category":        d.get("category"),
                "name":            d.get("name"),
                "description":     (d.get("description") or "")[:200],
                "trust_level":     d.get("trust_level"),
                "last_updated":    d.get("last_updated"),
            }
    except Exception as e:
        return {"error": str(e), "source": "greynoise_riot"}


async def _internetdb(session, ip: str) -> Dict:
    """Shodan InternetDB — free, no key, <100ms response."""
    try:
        async with session.get(
            f"https://internetdb.shodan.io/{ip}", timeout=_TIMEOUT,
        ) as r:
            if r.status == 404:
                return {"in_dataset": False}
            if r.status != 200:
                return {"error": f"HTTP {r.status}", "source": "internetdb"}
            d = await r.json()
            cves = d.get("vulns") or []
            return {
                "in_dataset":  True,
                "ports":       (d.get("ports") or [])[:20],
                "cpes":        (d.get("cpes") or [])[:8],
                "vulns":       cves[:10],
                "vuln_count":  len(cves),
                "tags":        (d.get("tags") or [])[:8],
                "hostnames":   (d.get("hostnames") or [])[:5],
            }
    except Exception as e:
        return {"error": str(e), "source": "internetdb"}


async def _dshield(session, ip: str) -> Dict:
    """DShield / SANS Internet Storm Center."""
    try:
        async with session.get(
            f"https://isc.sans.edu/api/ip/{ip}?json", timeout=_TIMEOUT,
        ) as r:
            if r.status != 200:
                return {"error": f"HTTP {r.status}", "source": "dshield"}
            d = await r.json()
            ip_data = d.get("ip") or {}
            count   = ip_data.get("count") or 0
            attacks = ip_data.get("attacks") or 0
            threatlevel = ip_data.get("threatlevel") or ""
            return {
                "flagged":        count > 0 or attacks > 0,
                "attack_count":   attacks,
                "report_count":   count,
                "threat_level":   threatlevel,
                "comment":        ip_data.get("comment"),
                "summary":        f"{attacks} attacks / {count} reports — threat level {threatlevel or 'n/a'}",
                "source":         "DShield · SANS ISC",
            }
    except Exception as e:
        return {"error": str(e), "source": "dshield"}


async def _stopforumspam(session, ip: str) -> Dict:
    """StopForumSpam — spam / abuse history."""
    try:
        async with session.get(
            "https://api.stopforumspam.org/api",
            params={"json": "", "ip": ip}, timeout=_TIMEOUT,
        ) as r:
            if r.status != 200:
                return {"error": f"HTTP {r.status}", "source": "stopforumspam"}
            d = await r.json()
            ip_info = (d.get("ip") or {})
            appears = ip_info.get("appears") or 0
            return {
                "flagged":      appears > 0,
                "appears":      appears,
                "frequency":    ip_info.get("frequency"),
                "confidence":   ip_info.get("confidence"),
                "last_seen":    ip_info.get("lastseen"),
                "summary":      f"{appears} reports — frequency {ip_info.get('frequency') or 0}",
                "source":       "StopForumSpam",
            }
    except Exception as e:
        return {"error": str(e), "source": "stopforumspam"}


async def _project_honeypot(session, ip: str, key: str) -> Dict:
    """Project Honeypot HTTP:BL — requires HONEYPOT_KEY (free with registration)."""
    if not key:
        return {"error": "no HONEYPOT_KEY", "source": "project_honeypot"}
    # HTTP:BL uses reversed-octet DNS lookup format:  KEY.4.3.2.1.dnsbl.httpbl.org
    try:
        import socket as _s
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{key}.{reversed_ip}.dnsbl.httpbl.org"
        loop = asyncio.get_event_loop()
        try:
            res = await loop.run_in_executor(None, _s.gethostbyname, query)
        except _s.gaierror:
            return {"flagged": False, "in_blocklist": False, "source": "project_honeypot"}
        parts = res.split(".")
        if len(parts) == 4 and parts[0] == "127":
            days, threat, vtype = int(parts[1]), int(parts[2]), int(parts[3])
            type_map = {0: "Search Engine", 1: "Suspicious", 2: "Harvester",
                        3: "Suspicious + Harvester", 4: "Comment Spammer",
                        5: "Suspicious + Comment Spammer", 7: "Harvester + Comment Spammer"}
            return {
                "flagged":        True,
                "in_blocklist":   True,
                "last_seen_days": days,
                "threat_score":   threat,   # 0-255
                "visitor_type":   vtype,
                "classification": type_map.get(vtype, f"type_{vtype}"),
                "source":         "Project Honeypot HTTP:BL",
            }
        return {"flagged": False, "in_blocklist": False, "raw": res}
    except Exception as e:
        return {"error": str(e), "source": "project_honeypot"}
