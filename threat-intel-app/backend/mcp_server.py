"""
Threat Intel Platform — MCP Server
Exposes platform capabilities as tools that Claude (or any MCP client) can call natively.
Run: python mcp_server.py
Then connect in Claude Desktop: add to claude_desktop_config.json
"""

import asyncio
import json
import os
import sys
import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent, CallToolResult

PLATFORM_URL = os.getenv("PLATFORM_URL", "http://localhost:8000")

server = Server("threat-intel-platform")


# ─── TOOL DEFINITIONS ────────────────────────────────────────────────────────────
@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="analyze_threat",
            description=(
                "Analyze a security log, alert, or IOC list through a multi-agent threat intelligence pipeline. "
                "Extracts IOCs, enriches against 10+ threat intel APIs, performs chain-of-thought investigation, "
                "generates MITRE ATT&CK mapping, and produces Sigma and KQL detection rules. "
                "Use this when an analyst pastes a log, mentions suspicious IPs/domains/hashes, or asks to investigate an alert."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "log_text": {
                        "type": "string",
                        "description": "The raw log content, alert text, or IOC list to analyze"
                    },
                    "input_type": {
                        "type": "string",
                        "enum": ["log", "alert", "misp", "stix"],
                        "description": "Type of input",
                        "default": "log"
                    }
                },
                "required": ["log_text"]
            }
        ),
        Tool(
            name="enrich_ioc",
            description=(
                "Quickly enrich a single IOC (IP address, domain, file hash, or URL) against threat intel APIs "
                "without running a full investigation. Returns abuse scores, geolocation, VirusTotal results, "
                "Shodan data, OTX pulses, and more. Faster and cheaper than a full analysis."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "ioc": {
                        "type": "string",
                        "description": "The IOC to enrich (IP, domain, SHA256 hash, or URL)"
                    }
                },
                "required": ["ioc"]
            }
        ),
        Tool(
            name="poll_taxii_feeds",
            description=(
                "Pull fresh IOCs from configured TAXII threat intelligence feeds. "
                "Returns newly observed IPs, domains, hashes, and URLs from public threat feeds. "
                "Use to check if new threats have been published since last poll."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "since_hours": {
                        "type": "integer",
                        "description": "How many hours back to pull data from",
                        "default": 24
                    }
                }
            }
        ),
        Tool(
            name="generate_sigma_rule",
            description=(
                "Generate a production-ready Sigma detection rule from a threat description, "
                "IOC list, or MITRE technique. Returns valid YAML that can be deployed to any "
                "SIEM supporting Sigma (Splunk, Sentinel, Elastic, QRadar)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "threat_description": {
                        "type": "string",
                        "description": "Description of the threat, attack pattern, or IOCs to detect"
                    },
                    "mitre_techniques": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "MITRE ATT&CK technique IDs (e.g. T1566, T1059.001)"
                    }
                },
                "required": ["threat_description"]
            }
        ),
        Tool(
            name="generate_kql_rule",
            description=(
                "Generate a Microsoft Sentinel KQL analytics rule from a threat description or IOC list. "
                "Returns query with entity mapping, let statements for IOC lists, and rule metadata comments. "
                "Ready to paste into Sentinel Analytics."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "threat_description": {
                        "type": "string",
                        "description": "Description of the threat or IOCs to detect"
                    },
                    "mitre_techniques": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "MITRE ATT&CK technique IDs"
                    }
                },
                "required": ["threat_description"]
            }
        ),
        Tool(
            name="check_platform_health",
            description="Check which threat intel APIs are configured and the platform status.",
            inputSchema={"type": "object", "properties": {}}
        ),
    ]


# ─── TOOL HANDLERS ───────────────────────────────────────────────────────────────
@server.call_tool()
async def call_tool(name: str, arguments: dict) -> CallToolResult:
    async with httpx.AsyncClient(timeout=120) as client:

        if name == "analyze_threat":
            resp = await client.post(
                f"{PLATFORM_URL}/analyze/sync",
                json={
                    "logText": arguments["log_text"],
                    "inputType": arguments.get("input_type", "log")
                }
            )
            data = resp.json()

            # Format a clean summary for Claude to present
            summary = _format_analysis_summary(data)
            return CallToolResult(content=[TextContent(type="text", text=summary)])

        elif name == "enrich_ioc":
            ioc = arguments["ioc"].strip()
            ioc_type = _detect_ioc_type(ioc)

            # Call the appropriate enrichment endpoint
            resp = await client.post(
                f"{PLATFORM_URL}/analyze/sync",
                json={"logText": ioc, "inputType": "log"}
            )
            data = resp.json()
            enrichments = data.get("enrichments", {})

            result = _format_enrichment_summary(ioc, ioc_type, enrichments)
            return CallToolResult(content=[TextContent(type="text", text=result)])

        elif name == "poll_taxii_feeds":
            # Start poll
            resp = await client.post(
                f"{PLATFORM_URL}/taxii/poll",
                json={"sinceHours": arguments.get("since_hours", 24)}
            )
            poll_data = resp.json()
            poll_id = poll_data.get("pollId")

            # Wait for completion (up to 30s)
            for _ in range(15):
                await asyncio.sleep(2)
                result_resp = await client.get(f"{PLATFORM_URL}/taxii/results/{poll_id}")
                result = result_resp.json()
                if result.get("status") == "complete":
                    summary = _format_taxii_summary(result)
                    return CallToolResult(content=[TextContent(type="text", text=summary)])

            return CallToolResult(content=[TextContent(type="text", text="TAXII poll is still running. Check back shortly.")])

        elif name == "generate_sigma_rule":
            from openai import AsyncOpenAI
            ai_client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            prompt = f"""Generate a complete production-ready Sigma detection rule for:

Threat: {arguments['threat_description']}
MITRE Techniques: {', '.join(arguments.get('mitre_techniques', []))}

Output ONLY the YAML Sigma rule. No markdown fences, no explanation."""
            resp = await ai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1500,
                temperature=0.1
            )
            rule = resp.choices[0].message.content.strip()
            return CallToolResult(content=[TextContent(type="text", text=f"```yaml\n{rule}\n```")])

        elif name == "generate_kql_rule":
            from openai import AsyncOpenAI
            ai_client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            prompt = f"""Generate a complete Microsoft Sentinel KQL analytics rule for:

Threat: {arguments['threat_description']}
MITRE Techniques: {', '.join(arguments.get('mitre_techniques', []))}

Include: let statements for IOC lists, relevant Sentinel table queries, entity mapping fields, and // comments for rule metadata (name, severity, frequency). Output ONLY the KQL."""
            resp = await ai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1500,
                temperature=0.1
            )
            query = resp.choices[0].message.content.strip()
            return CallToolResult(content=[TextContent(type="text", text=f"```kql\n{query}\n```")])

        elif name == "check_platform_health":
            resp = await client.get(f"{PLATFORM_URL}/health")
            data = resp.json()
            lines = ["**Threat Intel Platform Health**\n"]
            lines.append(f"Status: {data.get('status', 'unknown').upper()}")
            lines.append(f"Version: {data.get('version')}")
            lines.append(f"Cached runs: {data.get('cached_runs', 0)}")
            lines.append("\n**API Key Status:**")
            for api, configured in data.get("env", {}).items():
                status = "✓ configured" if configured else "✗ missing"
                lines.append(f"  {api}: {status}")
            return CallToolResult(content=[TextContent(type="text", text="\n".join(lines))])

        else:
            raise ValueError(f"Unknown tool: {name}")


# ─── FORMATTERS ──────────────────────────────────────────────────────────────────
def _detect_ioc_type(ioc: str) -> str:
    import re
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ioc):
        return "IP"
    if len(ioc) in (32, 40, 64) and re.match(r"^[a-fA-F0-9]+$", ioc):
        return "Hash"
    if ioc.startswith("http"):
        return "URL"
    return "Domain"


def _format_analysis_summary(data: dict) -> str:
    response = data.get("response_summary", {})
    iocs = data.get("iocs", {})
    trace = data.get("agent_trace", [])

    lines = []
    threat_level = response.get("threat_level", "UNKNOWN")
    confidence = response.get("confidence", 0)

    lines.append(f"## Threat Intel Analysis")
    lines.append(f"**Threat Level:** {threat_level} | **Confidence:** {confidence:.0%}\n")
    lines.append(f"**Summary:** {response.get('summary', 'No summary available')}\n")

    total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
    if total_iocs:
        lines.append(f"**IOCs Analyzed:** {total_iocs} ({', '.join(f'{len(v)} {k}' for k,v in iocs.items() if v)})\n")

    if response.get("key_findings"):
        lines.append("**Key Findings:**")
        for f in response["key_findings"][:5]:
            lines.append(f"  - {f}")
        lines.append("")

    if response.get("mitre_techniques"):
        lines.append(f"**MITRE ATT&CK:** {', '.join(response['mitre_techniques'][:5])}\n")

    if response.get("matched_actors"):
        actors = response["matched_actors"][:3]
        lines.append(f"**Possible Attribution:** {', '.join(f\"{a['name']} ({a['score']}%)\" for a in actors)}\n")

    if response.get("recommended_actions"):
        lines.append("**Recommended Actions:**")
        for i, action in enumerate(response["recommended_actions"][:4], 1):
            lines.append(f"  {i}. {action}")
        lines.append("")

    # Pipeline trace summary
    lines.append("**Pipeline:** " + " → ".join(
        f"{t['agent'].upper()} ({'✓' if t['status'] == 'complete' else '✗ dropped'})"
        for t in trace
    ))

    run_id = data.get("runId", "")
    if run_id:
        lines.append(f"\n_STIX 2.1 bundle available at: GET /export/stix/{run_id}_")

    return "\n".join(lines)


def _format_enrichment_summary(ioc: str, ioc_type: str, enrichments: dict) -> str:
    lines = [f"## Enrichment: {ioc} ({ioc_type})\n"]

    all_data = {}
    if ioc_type == "IP" and ioc in enrichments.get("ips", {}):
        all_data = enrichments["ips"][ioc]
    elif ioc_type == "Domain" and ioc in enrichments.get("domains", {}):
        all_data = enrichments["domains"][ioc]
    elif ioc_type == "Hash" and ioc in enrichments.get("hashes", {}):
        all_data = enrichments["hashes"][ioc]

    if not all_data:
        return f"No enrichment data found for {ioc}"

    for source, data in all_data.items():
        if not isinstance(data, dict) or data.get("error"):
            continue
        lines.append(f"**{source.upper()}:**")
        for k, v in data.items():
            if v is not None and v != [] and v != {}:
                lines.append(f"  {k}: {v}")
    return "\n".join(lines)


def _format_taxii_summary(result: dict) -> str:
    lines = ["## TAXII Feed Poll Results\n"]
    lines.append(f"**Total unique IOCs:** {result.get('total', 0)}")
    lines.append(f"**Polled at:** {result.get('polled_at', '')}")
    lines.append(f"**Period:** Last {result.get('since', 'unknown')} to now\n")
    lines.append("**By type:**")
    for t, count in (result.get("by_type") or {}).items():
        lines.append(f"  {t}: {count}")
    lines.append("\n**By feed:**")
    for feed, count in (result.get("by_feed") or {}).items():
        lines.append(f"  {feed}: {count}")
    return "\n".join(lines)


# ─── ENTRY POINT ─────────────────────────────────────────────────────────────────
async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
