"""
Tools the investigation AI can call iteratively to gather additional context.

Each tool wraps an existing intel module / enrichment function and returns a
compact JSON-serialisable dict (kept small to save tokens). The AI decides
which tools to call based on what it's seeing in the alert + the pre-enriched
baseline data — this lets investigations adapt instead of firing a fixed
enrichment pattern every time.
"""
import asyncio
import json


# ─── OpenAI function schemas (passed to the model via `tools=...`) ───────────────
TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "lookup_ip_reputation",
            "description": (
                "Get full reputation for an IP across all configured sources: VirusTotal, "
                "AbuseIPDB confidence score, GreyNoise classification (incl. RIOT), OTX "
                "pulse count, IPInfo geo+ASN, Tor exit status, offline blocklists (52K+ "
                "IPs), Censys open-ports + TLS cert, CrowdSec attack scenarios, Criminal "
                "IP inbound/outbound threat scoring, ProxyCheck VPN/proxy classification, "
                "Maltiverse, CIRCL passive DNS, Hackertarget reverse-IP, Feodo Tracker "
                "active-C2 list, Google Safe Browsing, BGP ranking, ASN reputation "
                "(bulletproof / VPN / anonymizer). Use when you have an IP and want to "
                "know whether it's malicious, what's hosted there, what country/ASN, or "
                "whether it's known anonymizer infrastructure."
            ),
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string", "description": "IPv4 or IPv6 address"}},
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_domain_reputation",
            "description": (
                "Get full reputation + heuristics for a domain: VirusTotal, OTX, URLScan, "
                "Pulsedive, Spamhaus DBL, certificate transparency subdomains (crt.sh), "
                "WHOIS (registration date), Wayback Machine snapshot history, NRD age, "
                "DGA score, IDN/punycode detection, typosquat brand matching, Maltiverse, "
                "OpenCTI, FullHunt subdomain inventory, Google Safe Browsing, DNS records, "
                "offline phishing-domain blocklists. Use when you have a domain and want "
                "to know if it's malicious, when it was registered, whether it impersonates "
                "a brand, or whether it's algorithmically generated."
            ),
            "parameters": {
                "type": "object",
                "properties": {"domain": {"type": "string"}},
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_hash_reputation",
            "description": (
                "Get full reputation for a file hash (MD5 / SHA-1 / SHA-256): VirusTotal, "
                "MalwareBazaar malware family + tags, ThreatFox malware/confidence, OTX, "
                "URLhaus payload tracking, CIRCL hashlookup (NSRL known-good vs known-bad), "
                "Team Cymru MHR (free DNS-based first-seen + detection %), Hybrid Analysis "
                "sandbox report (if SHA-256), Maltiverse, OpenCTI, MISP community feeds, "
                "LOLDrivers BYOVD catalog match. Use when you have a hash and want to know "
                "malware family, first-seen date, sandbox verdict, or BYOVD status."
            ),
            "parameters": {
                "type": "object",
                "properties": {"file_hash": {"type": "string"}},
                "required": ["file_hash"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_cve",
            "description": (
                "Combined CVE intelligence: CISA KEV (actively exploited) + EPSS (exploit "
                "probability percentile). Returns urgency tier and ransomware-use flag. Use "
                "when the alert mentions a CVE ID — you almost always want to call this."
            ),
            "parameters": {
                "type": "object",
                "properties": {"cve_id": {"type": "string", "description": "e.g. CVE-2024-3400"}},
                "required": ["cve_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_mitre",
            "description": (
                "Search the MITRE ATT&CK technique library (697 enterprise techniques). "
                "Query can be a technique ID like 'T1059' or a keyword like 'powershell', "
                "'wmi', 'kerberoasting'. Use when you suspect specific TTPs and want to "
                "map them to ATT&CK identifiers."
            ),
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_threat_actors_by_ttps",
            "description": (
                "Given a list of MITRE technique IDs, find threat-actor groups known to use "
                "them. Returns top groups ranked by TTP overlap, with aliases, country, and "
                "sponsor (from MISP galaxy + MITRE). Use when you've identified specific "
                "techniques and want to assess attribution."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "technique_ids": {
                        "type": "array", "items": {"type": "string"},
                        "description": "e.g. ['T1566', 'T1059.001', 'T1071']",
                    },
                },
                "required": ["technique_ids"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "threat_actor_profile",
            "description": (
                "Look up a threat actor by name, alias, or MITRE Group ID. Combines MISP "
                "galaxy (994 actors) with MITRE ATT&CK group data. Returns description, "
                "country, sponsor, victim sectors, common aliases, references. Use when "
                "you see a known actor name mentioned or want details on a group you "
                "identified via find_threat_actors_by_ttps."
            ),
            "parameters": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_phishing_kit",
            "description": (
                "Fingerprint a URL against 21+ known phishing kits: Tycoon 2FA, EvilProxy, "
                "Sneaky 2FA, Storm-1167, 16shop, Greatness, ClickFix, BitB, Quishing, "
                "generic AiTM lookalikes. Use when you have a suspicious URL and want to "
                "know which kit is behind it (huge attribution + campaign signal)."
            ),
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_lolbas",
            "description": (
                "Check whether a Windows binary is in the LOLBAS catalog (legitimate "
                "binaries adversaries abuse — certutil.exe, mshta.exe, regsvr32.exe, etc.). "
                "Returns categories and example abuse cases. Use when the alert mentions "
                "an executable and you want to know if it's commonly abused."
            ),
            "parameters": {
                "type": "object",
                "properties": {"binary_name": {"type": "string"}},
                "required": ["binary_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_rmm_tool",
            "description": (
                "Check whether a binary is a remote-management/monitoring tool known to be "
                "abused by ransomware affiliates (ScreenConnect, AnyDesk, TeamViewer, Atera, "
                "RustDesk, Splashtop, etc.). Returns vendor + list of threat groups that "
                "abuse it. Use when the alert mentions remote-access software."
            ),
            "parameters": {
                "type": "object",
                "properties": {"binary_name": {"type": "string"}},
                "required": ["binary_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "domain_heuristics",
            "description": (
                "Run offline heuristics on a domain without any API calls: NRD age (if "
                "WHOIS date given), DGA score, IDN/punycode attack detection, typosquat "
                "brand matching. Fast. Use when you want a quick offline read without "
                "burning lookup budget."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string"},
                    "whois_created": {"type": "string",
                                       "description": "Optional WHOIS created date (ISO)"}
                },
                "required": ["domain"],
            },
        },
    },
]


# ─── Tool implementations ───────────────────────────────────────────────────────
def _summarize_for_trace(name: str, result: dict) -> str:
    """One-liner version of a tool result, used in the agent trace UI."""
    if not isinstance(result, dict):
        return "no result"
    if "error" in result:
        return f"error: {str(result['error'])[:80]}"

    if name == "lookup_ip_reputation":
        abuse = (result.get("abuseipdb") or {}).get("abuseScore", "-")
        vt    = (result.get("virustotal") or {}).get("malicious", "-")
        gn    = (result.get("greynoise") or {}).get("classification", "-")
        local = (result.get("local_feeds") or {}).get("source")
        bits  = [f"AbuseIPDB {abuse}", f"VT {vt}", f"GreyNoise {gn}"]
        if local: bits.append(f"blocklist:{local}")
        return " · ".join(bits)
    if name == "lookup_domain_reputation":
        vt   = (result.get("virustotal") or {}).get("malicious", "-")
        nrd  = (result.get("heuristics") or {}).get("nrd", {}).get("is_same_day")
        dga  = (result.get("heuristics") or {}).get("dga", {}).get("flagged")
        dbl  = result.get("spamhaus_dbl", {}).get("hit")
        bits = [f"VT {vt}"]
        if nrd: bits.append("REGISTERED TODAY")
        if dga: bits.append("DGA flagged")
        if dbl: bits.append("Spamhaus DBL hit")
        return " · ".join(bits)
    if name == "lookup_hash_reputation":
        mb   = (result.get("malwarebazaar") or {}).get("malwareName")
        vt   = (result.get("virustotal") or {}).get("malicious", "-")
        cymru= (result.get("team_cymru_mhr") or {}).get("verdict")
        bits = [f"VT {vt}"]
        if mb:    bits.append(f"MalwareBazaar:{mb}")
        if cymru: bits.append(f"Cymru:{cymru}")
        return " · ".join(bits)
    if name == "check_cve":
        return f"{result.get('cve')} · {result.get('urgency','-')}"
    if name == "search_mitre":
        n = len(result.get("results", []))
        return f"{n} technique{'s' if n != 1 else ''} matched"
    if name == "find_threat_actors_by_ttps":
        actors = result.get("actors", [])
        top = ", ".join(f"{a['name']} ({a['score']}%)" for a in actors[:3])
        return f"{len(actors)} actor matches" + (f" — top: {top}" if top else "")
    if name == "threat_actor_profile":
        if result.get("found") is False:
            return f"not found: {result.get('query')}"
        return f"{result.get('name','-')} · {result.get('country','-')} · {result.get('sponsor','-')}"
    if name == "check_phishing_kit":
        if result.get("matched") is False:
            return "no kit match"
        return f"kit: {result.get('kit')}"
    if name == "check_lolbas":
        if not result.get("name"):
            return "not in LOLBAS"
        return f"LOLBAS · categories: {','.join(result.get('categories', [])[:3])}"
    if name == "check_rmm_tool":
        if not result.get("binary"):
            return "not a known RMM tool"
        groups = ", ".join(result.get("groups", [])[:3])
        return f"{result['binary']} · abused by: {groups}"
    if name == "domain_heuristics":
        return json.dumps(result)[:140]
    return json.dumps(result)[:140]


async def execute_tool(name: str, args: dict, config) -> dict:
    """Dispatch a tool call by name. Returns the result dict (capped in size)."""
    handlers = {
        "lookup_ip_reputation":       _t_lookup_ip,
        "lookup_domain_reputation":   _t_lookup_domain,
        "lookup_hash_reputation":     _t_lookup_hash,
        "check_cve":                  _t_check_cve,
        "search_mitre":               _t_search_mitre,
        "find_threat_actors_by_ttps": _t_actors_by_ttps,
        "threat_actor_profile":       _t_actor_profile,
        "check_phishing_kit":         _t_phishing_kit,
        "check_lolbas":               _t_lolbas,
        "check_rmm_tool":             _t_rmm,
        "domain_heuristics":          _t_domain_heur,
    }
    fn = handlers.get(name)
    if not fn:
        return {"error": f"unknown tool: {name}"}
    try:
        if asyncio.iscoroutinefunction(fn):
            return await fn(args, config)
        return fn(args, config)
    except Exception as e:
        return {"error": str(e)[:200]}


# Each enrich_* below internally cherry-picks the keys it needs, so we
# pass the FULL configured key set instead of a hand-curated subset.
# The earlier subset was missing ABUSECH_AUTH_KEY / HYBRID_ANALYSIS_KEY /
# CRIMINAL_IP / CENSYS / CROWDSEC / PROXYCHECK / URLSCAN / WHOISXML /
# GOOGLE / FULLHUNT etc., which meant the AI's tool calls during
# investigation got a substantially degraded enrichment vs. the main
# /api/analyze pipeline — abuse.ch endpoints in particular were hit
# anonymously and rate-limited.
def _all_keys(config) -> dict:
    return {k: config.get(k) for k in (
        "VIRUSTOTAL_KEY", "ABUSEIPDB_KEY", "IPINFO_TOKEN", "GREYNOISE_KEY",
        "OTX_KEY", "URLSCAN_KEY", "PULSEDIVE_KEY",
        "ABUSECH_AUTH_KEY", "MALWAREBAZAAR_API_KEY", "HYBRID_ANALYSIS_KEY",
        "CENSYS_API_ID", "CENSYS_API_SECRET", "CENSYS_PERSONAL_ACCESS_TOKEN",
        "CROWDSEC_KEY", "CRIMINAL_IP_KEY", "PROXYCHECK_KEY",
        "WHOISXML_KEY", "GOOGLE_API_KEY", "FULLHUNT_KEY",
        "MALTIVERSE_KEY", "OPENCTI_URL", "OPENCTI_TOKEN",
        "PHISHTANK_KEY",
    )}


# Individual tool implementations
async def _t_lookup_ip(args, config):
    from agents.enrichment import enrich_ip
    import aiohttp
    ip = args.get("ip", "").strip()
    if not ip:
        return {"error": "ip required"}
    async with aiohttp.ClientSession() as session:
        return await enrich_ip(session, ip, _all_keys(config))


async def _t_lookup_domain(args, config):
    from agents.enrichment import enrich_domain
    import aiohttp
    d = args.get("domain", "").strip()
    if not d:
        return {"error": "domain required"}
    async with aiohttp.ClientSession() as session:
        return await enrich_domain(session, d, _all_keys(config))


async def _t_lookup_hash(args, config):
    from agents.enrichment import enrich_hash
    from intel.loldrivers import lookup_hash as drv_lookup
    import aiohttp
    h = args.get("file_hash", "").strip()
    if not h:
        return {"error": "file_hash required"}
    async with aiohttp.ClientSession() as session:
        result = await enrich_hash(session, h, _all_keys(config))
    # NOTE: enrich_hash already runs the deep sandbox lookup for SHA-256, so we
    # don't make a second (slow) sandbox call here.
    drv = drv_lookup(h)
    if drv:
        result["loldrivers"] = drv
    return result


def _t_check_cve(args, config):
    from intel.kev import lookup as kev_lookup
    from intel.epss import get as epss_get
    cve = args.get("cve_id", "").strip().upper()
    if not cve:
        return {"error": "cve_id required"}
    kev = kev_lookup(cve)
    epss = epss_get(cve)
    pct = (epss or {}).get("epss_percent", 0)
    urgency = ("CRITICAL — actively exploited in ransomware"
               if kev and kev.get("ransomware_use")
               else "CRITICAL — confirmed exploited"      if kev and pct >= 70
               else "HIGH — in CISA KEV catalog"          if kev
               else "HIGH — high exploit probability"     if pct >= 70
               else "MEDIUM — moderate exploit probability" if pct >= 10
               else "LOW — no active exploitation observed")
    return {"cve": cve, "in_kev": bool(kev), "kev": kev, "epss": epss, "urgency": urgency}


def _t_search_mitre(args, config):
    from intel.mitre_data import search_techniques
    q = args.get("query", "").strip()
    if not q:
        return {"error": "query required"}
    return {"results": search_techniques(q)[:10]}


def _t_actors_by_ttps(args, config):
    from intel.actor_data import match_threat_actors
    ttps = args.get("technique_ids") or []
    if not ttps:
        return {"actors": []}
    return {"actors": match_threat_actors(ttps)[:5]}


def _t_actor_profile(args, config):
    from intel.actor_data import enrich_actor
    name = args.get("name", "").strip()
    if not name:
        return {"error": "name required"}
    return enrich_actor(name, name) or {"found": False, "query": name}


def _t_phishing_kit(args, config):
    from intel.phishing_kit import fingerprint
    url = args.get("url", "").strip()
    if not url:
        return {"error": "url required"}
    return fingerprint(url) or {"matched": False, "url": url}


def _t_lolbas(args, config):
    from intel.lolbas import lookup
    b = args.get("binary_name", "").strip()
    if not b:
        return {"error": "binary_name required"}
    return lookup(b) or {"matched": False, "binary": b}


def _t_rmm(args, config):
    from intel.rmm_abuse import lookup
    b = args.get("binary_name", "").strip()
    if not b:
        return {"error": "binary_name required"}
    return lookup(b) or {"matched": False, "binary": b}


def _t_domain_heur(args, config):
    from intel.domain_analysis import analyze_domain
    d = args.get("domain", "").strip()
    if not d:
        return {"error": "domain required"}
    return analyze_domain(d, args.get("whois_created"))
