"""
Investigation Agent — chain-of-thought reasoning over enriched IOC data.
Reads AI config at call time from config manager.
"""

import json
from datetime import datetime, timezone


def _compress(enrichments: dict) -> dict:
    out = {}
    for ip, d in (enrichments.get("ips") or {}).items():
        out.setdefault("ips", {})[ip] = {
            "abuse_score":  (d.get("abuseipdb") or {}).get("abuseScore"),
            "vt_malicious": (d.get("virustotal") or {}).get("malicious"),
            "country":      (d.get("ipinfo") or {}).get("country"),
            "org":          (d.get("ipinfo") or {}).get("org"),
            "is_tor":       (d.get("tor") or {}).get("isExitNode"),
            "gn_class":     (d.get("greynoise") or {}).get("classification"),
            "shodan_ports": (d.get("shodan") or {}).get("ports"),
            "shodan_vulns": (d.get("shodan") or {}).get("vulns"),
            "otx_pulses":   (d.get("otx") or {}).get("pulseCount"),
        }
    for domain, d in (enrichments.get("domains") or {}).items():
        out.setdefault("domains", {})[domain] = {
            "vt_malicious":  (d.get("virustotal") or {}).get("malicious"),
            "otx_pulses":    (d.get("otx") or {}).get("pulseCount"),
            "pd_risk":       (d.get("pulsedive") or {}).get("risk"),
            "cert_count":    (d.get("certTransparency") or {}).get("totalCerts"),
            "whois_created": (d.get("whois") or {}).get("created"),
        }
    for h, d in (enrichments.get("hashes") or {}).items():
        out.setdefault("hashes", {})[h[:16] + "..."] = {
            "malware_name": (d.get("malwarebazaar") or {}).get("malwareName"),
            "vt_malicious": (d.get("virustotal") or {}).get("malicious"),
            "vt_name":      (d.get("virustotal") or {}).get("name"),
            "otx_pulses":   (d.get("otx") or {}).get("pulseCount"),
            "tf_malware":   (d.get("threatfox") or {}).get("malware"),
        }
    return out


PROMPT = """You are a senior threat intelligence analyst performing a chain-of-thought investigation.

CHARACTER: Senior TI analyst, GCIA certified, specializing in APT attribution.
CONTEXT: Investigation node in an automated multi-agent SOC pipeline.
CONSTRAINTS: Output ONLY valid JSON. Think step by step. Be precise about confidence.
COMMAND: Analyze the enriched IOC data and produce structured investigation findings.

Think step-by-step:
1. Which IOCs are most suspicious and why?
2. What attack pattern or type does this suggest?
3. What MITRE ATT&CK techniques does the evidence support?
4. Could this be a false positive? Confidence level?
5. Do you need additional data to raise confidence?

ENRICHED IOC DATA (compressed):
{enrichments}

ALERT TYPE: {alert_type}
TRIAGE SCORE: {triage_score}

Respond with exactly this JSON:
{{
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL",
  "confidence": <float 0.0-1.0>,
  "needs_more_enrichment": <true|false>,
  "summary": "<2-3 sentence executive summary>",
  "chain_of_thought": ["<step 1>", "<step 2>", "<step 3>"],
  "key_findings": ["<finding 1>", "<finding 2>", "<finding 3>"],
  "ioc_assessments": [
    {{"ioc": "<value>", "type": "IP|Domain|Hash|URL|Email", "verdict": "MALICIOUS|SUSPICIOUS|CLEAN|UNKNOWN", "reason": "<brief>"}}
  ],
  "mitre_techniques": ["T1566 - Phishing", "T1059.001 - PowerShell"],
  "attack_patterns": ["<pattern or campaign>"],
  "geo_highlights": ["<geolocation observation>"],
  "recommended_actions": ["<action 1>", "<action 2>", "<action 3>"],
  "tor_traffic": <true|false>,
  "attribution_hints": "<APT indicators or null>"
}}"""


async def run_investigation(state: dict) -> dict:
    from config import config
    from openai import AsyncOpenAI

    enrichments = state.get("enrichments", {})
    trace = state.get("agent_trace", [])
    triage_score = state.get("triage_score", 0.0)
    alert_type = next((t.get("alert_type", "unknown") for t in trace if t.get("agent") == "triage"), "unknown")

    compressed = _compress(enrichments)

    result = None
    openai_key = config.get("OPENAI_API_KEY")
    if openai_key:
        try:
            client = AsyncOpenAI(
                api_key=openai_key,
                base_url=config.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            )
            resp = await client.chat.completions.create(
                model=config.get("AI_MODEL", "gpt-4o-mini"),
                messages=[{"role": "user", "content": PROMPT.format(
                    enrichments=json.dumps(compressed, indent=2)[:5000],
                    alert_type=alert_type,
                    triage_score=round(triage_score, 2),
                )}],
                max_tokens=1200,
                temperature=0.1,
                response_format={"type": "json_object"},
            )
            result = json.loads(resp.choices[0].message.content)
        except Exception as e:
            result = None

    if result is None:
        result = {
            "threat_level": "MEDIUM",
            "confidence": 0.4,
            "needs_more_enrichment": False,
            "summary": "AI investigation unavailable — enrichment data collected. Manual review required.",
            "chain_of_thought": ["OpenAI key not configured or call failed. Review enrichment data manually."],
            "key_findings": ["Automated AI analysis unavailable. See enrichment data tab."],
            "ioc_assessments": [],
            "mitre_techniques": [],
            "attack_patterns": [],
            "geo_highlights": [],
            "recommended_actions": ["Review enrichment data manually.", "Configure OpenAI API key for AI analysis."],
            "tor_traffic": False,
            "attribution_hints": None,
        }

    trace.append({
        "agent": "investigation",
        "status": "complete",
        "summary": result.get("summary", ""),
        "threat_level": result.get("threat_level"),
        "confidence": result.get("confidence"),
        "mitre_count": len(result.get("mitre_techniques", [])),
        "needs_more": result.get("needs_more_enrichment", False),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    return {
        **state,
        "investigation": result,
        "mitre_techniques": result.get("mitre_techniques", []),
        "threat_level": result.get("threat_level", "MEDIUM"),
        "confidence": result.get("confidence", 0.5),
        "needs_more_enrichment": result.get("needs_more_enrichment", False),
        "agent_trace": trace,
    }
