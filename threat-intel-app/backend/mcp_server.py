"""
RECON Threat Intelligence — MCP Server (stdio)
================================================

Exposes RECON's analysis pipeline and intel modules as Model Context Protocol
tools so they can be called from Claude Desktop, Cursor, Continue, Zed, or any
MCP-compatible client.

Quick start
-----------
1. Edit your Claude Desktop config (location varies by OS):
     macOS / Linux : ~/Library/Application Support/Claude/claude_desktop_config.json
     Windows       : %APPDATA%\\Claude\\claude_desktop_config.json

2. Add the RECON server:

   {
     "mcpServers": {
       "recon": {
         "command": "C:\\\\Users\\\\elias\\\\Desktop\\\\threat-intel\\\\threat-intel-app\\\\backend\\\\venv\\\\Scripts\\\\python.exe",
         "args":    ["C:\\\\Users\\\\elias\\\\Desktop\\\\threat-intel\\\\threat-intel-app\\\\backend\\\\mcp_server.py"]
       }
     }
   }

3. Restart Claude Desktop. The RECON tools appear in the tool picker (paperclip menu).

Run directly for debugging:
   .\\venv\\Scripts\\python.exe mcp_server.py
"""
import sys
from pathlib import Path

# Make backend/ importable when launched from anywhere
sys.path.insert(0, str(Path(__file__).parent))

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("recon-threat-intel")


# ═══════════════════════════════════════════════════════════════════════════════
# Full pipeline
# ═══════════════════════════════════════════════════════════════════════════════
@mcp.tool()
async def analyze_log(log_text: str) -> dict:
    """Run RECON's full agentic threat-intel pipeline on a log, alert, or IOC list.

    The pipeline performs IOC extraction, multi-source enrichment, AI correlation,
    threat-actor attribution, MITRE mapping, multi-SIEM detection rule generation,
    and produces an analyst hand-off plus client notification email.

    Args:
        log_text: Raw log line, alert text, email source, or list of indicators.

    Returns:
        Threat verdict, disposition with reasoning, IOC assessments, MITRE coverage,
        attributed actors, recommended actions, client email, and Sigma/KQL rules.
    """
    from agents.orchestrator import run_pipeline
    state = await run_pipeline(log_text, "log")
    rs = state.get("response_summary") or {}
    asum = rs.get("analyst_summary") or {}
    return {
        "threat_level":         rs.get("threat_level"),
        "confidence":           rs.get("confidence"),
        "summary":              rs.get("summary"),
        "disposition":          asum.get("disposition"),
        "disposition_reason":   asum.get("disposition_reason"),
        "clear_justification":  asum.get("clear_justification"),
        "key_findings":         rs.get("key_findings", []),
        "ioc_assessments":      rs.get("ioc_assessments", []),
        "mitre_techniques":     rs.get("mitre_techniques", []),
        "matched_actors":       [{k: a.get(k) for k in ("name", "mitre_id", "origin", "sponsor", "score")}
                                  for a in rs.get("matched_actors", [])[:5]],
        "recommended_actions":  rs.get("recommended_actions", []),
        "cross_refs":           rs.get("cross_refs", {}),
        "client_email":         asum.get("client_email"),
        "sigma_rule":           state.get("sigma_rule"),
        "kql_query":            state.get("kql_query"),
        "extracted_iocs":       state.get("iocs", {}),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Individual IOC reputation
# ═══════════════════════════════════════════════════════════════════════════════
@mcp.tool()
async def lookup_ip(ip: str) -> dict:
    """Comprehensive IP reputation across all configured sources.

    Sources: offline blocklists (52K+ IPs), AbuseIPDB, VirusTotal, GreyNoise,
    Shodan, OTX, IPInfo geolocation, Tor exit list, ASN reputation (flags
    bulletproof hosters / VPNs / anonymizers).
    """
    from config import config as _cfg
    from agents.enrichment import enrich_ip
    import aiohttp
    keys = {k: _cfg.get(k) for k in (
        "VIRUSTOTAL_KEY", "ABUSEIPDB_KEY", "IPINFO_TOKEN",
        "GREYNOISE_KEY", "SHODAN_KEY", "URLSCAN_KEY", "OTX_KEY",
    )}
    async with aiohttp.ClientSession() as session:
        return await enrich_ip(session, ip, keys)


@mcp.tool()
async def lookup_domain(domain: str) -> dict:
    """Comprehensive domain reputation + heuristics.

    Sources: VirusTotal, URLScan, OTX, Pulsedive, certificate transparency,
    WHOIS, Wayback Machine, Spamhaus DBL, Maltiverse, OpenCTI (if configured),
    plus offline heuristics: NRD age, same-day registration flag, DGA score,
    IDN / punycode attack detection, typosquat brand matching.
    """
    from config import config as _cfg
    from agents.enrichment import enrich_domain
    import aiohttp
    keys = {k: _cfg.get(k) for k in ("VIRUSTOTAL_KEY", "URLSCAN_KEY", "OTX_KEY", "PULSEDIVE_KEY")}
    async with aiohttp.ClientSession() as session:
        return await enrich_domain(session, domain, keys)


@mcp.tool()
async def lookup_hash(file_hash: str) -> dict:
    """Comprehensive file-hash reputation + sandbox lookup.

    Accepts MD5, SHA-1, or SHA-256. Queries: VirusTotal, MalwareBazaar,
    ThreatFox, OTX, Team Cymru MHR (free, DNS-based), Maltiverse, Hybrid
    Analysis cloud sandbox (if SHA-256), LOLDrivers BYOVD catalog.
    """
    from config import config as _cfg
    from agents.enrichment import enrich_hash
    from intel.sandbox import lookup_all as sandbox_lookup
    from intel.loldrivers import lookup_hash as drv_lookup
    import aiohttp
    keys = {k: _cfg.get(k) for k in ("VIRUSTOTAL_KEY", "OTX_KEY")}
    async with aiohttp.ClientSession() as session:
        base = await enrich_hash(session, file_hash, keys)
    if len(file_hash) == 64:
        base["sandbox"] = await sandbox_lookup(file_hash, _cfg)
    base["loldrivers"] = drv_lookup(file_hash)
    return base


# ═══════════════════════════════════════════════════════════════════════════════
# Vulnerability intelligence
# ═══════════════════════════════════════════════════════════════════════════════
@mcp.tool()
def check_cve(cve_id: str) -> dict:
    """CVE intelligence: CISA KEV (actively exploited) + EPSS (exploit prediction).

    Returns urgency tier, KEV details (vendor / product / ransomware flag /
    required action), and EPSS exploit-probability percentage.
    """
    from intel.kev import lookup as kev_lookup
    from intel.epss import get as epss_get
    kev = kev_lookup(cve_id)
    epss = epss_get(cve_id)
    pct = (epss or {}).get("epss_percent", 0)
    urgency = ("CRITICAL — actively exploited in ransomware"
               if kev and kev.get("ransomware_use")
               else "CRITICAL — confirmed exploited" if kev and pct >= 70
               else "HIGH — in CISA KEV catalog"      if kev
               else "HIGH — high exploit probability" if pct >= 70
               else "MEDIUM — moderate exploit probability" if pct >= 10
               else "LOW — no active exploitation observed")
    return {"cve": cve_id.upper().strip(),
            "in_kev": bool(kev),
            "kev":    kev,
            "epss":   epss,
            "urgency": urgency}


# ═══════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK
# ═══════════════════════════════════════════════════════════════════════════════
@mcp.tool()
def search_mitre(query: str) -> list:
    """Search MITRE ATT&CK technique library (697 enterprise techniques).
    Query can be a technique ID ('T1059') or keyword ('powershell')."""
    from intel.mitre_data import search_techniques
    return search_techniques(query)[:20]


@mcp.tool()
def mitre_groups_for_techniques(technique_ids: list) -> list:
    """Find MITRE threat-actor groups known to use a set of techniques.
    Cross-references with MISP galaxy for aliases, country, and victim sectors.
    Example: ['T1566', 'T1059.001']"""
    from intel.mitre_data import get_groups_by_techniques
    from intel.actor_data import enrich_actor
    groups = get_groups_by_techniques(technique_ids)[:10]
    for g in groups:
        misp = enrich_actor(g.get("name", ""), g.get("id", ""))
        if misp:
            g["aliases"] = misp.get("synonyms", [])[:5]
            g["country"] = misp.get("country", "")
            g["sponsor"] = misp.get("sponsor", "")
    return groups


@mcp.tool()
def threat_actor_profile(name_or_id: str) -> dict:
    """Look up a threat actor by name, alias, or MITRE Group ID.
    Combines MISP galaxy (994 actors) with MITRE ATT&CK group data."""
    from intel.actor_data import enrich_actor
    return enrich_actor(name_or_id, name_or_id) or {"found": False, "query": name_or_id}


# ═══════════════════════════════════════════════════════════════════════════════
# Phishing / URL analysis
# ═══════════════════════════════════════════════════════════════════════════════
@mcp.tool()
def detect_phishing_kit(url: str) -> dict:
    """Fingerprint a URL against 21+ known phishing kits.
    Catches: Tycoon 2FA, Sneaky 2FA, EvilProxy, Storm-1167, W3LL, Greatness,
    Caffeine, 16shop, NakedPages, Browser-in-Browser, Quishing, ClickFix,
    SocGholish fake-update, generic AiTM lookalikes, OAuth abuse patterns."""
    from intel.phishing_kit import fingerprint
    return fingerprint(url) or {"matched": False, "url": url}


@mcp.tool()
async def scan_url_live(url: str) -> dict:
    """Submit a URL to URLScan.io for live detonation. Returns the submission UUID
    and a result-page URL where the screenshot / verdicts appear after ~30-60 seconds."""
    from config import config as _cfg
    from intel.urlscan import submit_url
    return await submit_url(url, _cfg.get("URLSCAN_KEY", ""), visibility="unlisted")


# ═══════════════════════════════════════════════════════════════════════════════
# File / sandbox
# ═══════════════════════════════════════════════════════════════════════════════
@mcp.tool()
async def sandbox_hash_lookup(sha256: str) -> dict:
    """Query Hybrid Analysis cloud sandbox for an existing detonation report
    on this SHA-256 hash. Returns verdict, threat score, malware family,
    MITRE techniques observed in sandbox, and a link to the full report."""
    from config import config as _cfg
    from intel.sandbox import lookup_all
    return {"sha256": sha256, "sandbox": await lookup_all(sha256, _cfg)}


# ═══════════════════════════════════════════════════════════════════════════════
# Status / inventory
# ═══════════════════════════════════════════════════════════════════════════════
@mcp.tool()
def recon_intel_inventory() -> dict:
    """Report what offline intelligence RECON has loaded and what integrations
    are configured. Useful for confirming readiness before an analysis."""
    out = {}
    try:
        from intel.feeds_loader  import stats as f; out.update(f())
    except Exception: pass
    try:
        from intel.actor_data    import stats as a; out.update(a())
    except Exception: pass
    try:
        from intel.kev           import stats as k; out.update(k())
    except Exception: pass
    try:
        from intel.epss          import stats as e; out.update(e())
    except Exception: pass
    try:
        from intel.lolbas        import stats as l; out.update(l())
    except Exception: pass
    try:
        from intel.loldrivers    import stats as d; out.update(d())
    except Exception: pass
    try:
        from intel.atomic_red_team import stats as t; out.update(t())
    except Exception: pass
    try:
        from intel.phishing_kit  import stats as pk; out.update(pk())
    except Exception: pass
    try:
        from intel.ja_fingerprints import stats as ja; out.update(ja())
    except Exception: pass
    try:
        from intel.rmm_abuse     import stats as r; out.update(r())
    except Exception: pass
    try:
        from intel.yara_scanner  import stats as y; out.update(y())
    except Exception: pass
    return out


# ═══════════════════════════════════════════════════════════════════════════════
# Resources — let MCP clients browse RECON's reference data
# ═══════════════════════════════════════════════════════════════════════════════
@mcp.resource("recon://about")
def about() -> str:
    """Description of RECON's capabilities."""
    return ("RECON is an autonomous threat-intelligence platform for SOC / MDR "
            "analysts. It combines a multi-agent AI pipeline (Triage → Enrichment "
            "→ Investigation → Response) with offline intelligence including CISA "
            "KEV, EPSS, MITRE ATT&CK, MISP galaxy, LOLBAS, LOLDrivers, Atomic Red "
            "Team, 21+ phishing kits, JA3/JA4 C2 fingerprints, and ASN reputation. "
            "Detection content is auto-generated for Sigma, KQL/Sentinel, Splunk "
            "SPL, Elastic EQL, Chronicle YARA-L, and CrowdStrike Falcon.")


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    mcp.run(transport="stdio")
