"""
Triage Agent — reads API config at call time, not import time.
This allows keys entered in the Settings UI to take effect immediately.
"""

import re
import json
from datetime import datetime, timezone


BENIGN_IPS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "208.67.222.222", "169.254.169.254", "100.100.100.200",
}
PRIVATE_RANGES = [
    r"^10\.", r"^192\.168\.", r"^172\.(1[6-9]|2\d|3[01])\.",
    r"^127\.", r"^::1$", r"^fe80:",
]
BENIGN_DOMAINS = {
    "microsoft.com", "windows.com", "windowsupdate.com", "office.com",
    "office365.com", "live.com", "azure.com", "amazonaws.com",
    "google.com", "googleapis.com", "gstatic.com", "apple.com",
    "icloud.com", "cloudflare.com", "fastly.net", "akamai.net",
}


def extract_iocs(text: str) -> dict:
    text = (text
        .replace("[.]", ".").replace("(dot)", ".")
        .replace("[://]", "://").replace("hxxp", "http"))

    iocs = {"ips": set(), "domains": set(), "urls": set(), "hashes": set(), "emails": set()}

    url_re = re.compile(r"https?://[^\s\"'<>\]\),]+")
    for url in url_re.findall(text):
        iocs["urls"].add(url.rstrip(".,;)"))

    ip_re = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
    for ip in ip_re.findall(text):
        ip = ip.rstrip(".")
        if ip in BENIGN_IPS:
            continue
        if any(re.match(p, ip) for p in PRIVATE_RANGES):
            continue
        parts = ip.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            iocs["ips"].add(ip)

    stripped = url_re.sub("", text)
    domain_re = re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)"
        r"+(?:com|net|org|io|gov|edu|mil|co|uk|ru|cn|de|xyz|top|online|"
        r"site|app|dev|cloud|tech|store|live|icu|pw|cc|me|tv|ws|mobi)\b",
        re.IGNORECASE,
    )
    for d in domain_re.findall(stripped):
        d = d.lower()
        if not any(d == b or d.endswith("." + b) for b in BENIGN_DOMAINS):
            iocs["domains"].add(d)

    for pattern in [r"\b[a-fA-F0-9]{64}\b", r"\b[a-fA-F0-9]{40}\b", r"\b[a-fA-F0-9]{32}\b"]:
        for h in re.findall(pattern, text):
            iocs["hashes"].add(h.lower())

    for e in re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text):
        iocs["emails"].add(e.lower())

    return {k: list(v) for k, v in iocs.items()}


def score_iocs(iocs: dict) -> float:
    score = 0.0
    score += min(len(iocs.get("ips", [])) * 0.15, 0.45)
    score += min(len(iocs.get("hashes", [])) * 0.25, 0.50)
    score += min(len(iocs.get("domains", [])) * 0.10, 0.30)
    score += min(len(iocs.get("urls", [])) * 0.10, 0.20)
    score += min(len(iocs.get("emails", [])) * 0.05, 0.10)
    return min(score, 1.0)


TRIAGE_PROMPT = """You are a SOC triage analyst. Quickly assess this security alert.

CHARACTER: Senior SOC analyst, 10+ years experience.
CONTEXT: First agent in an automated pipeline. Your decision controls whether resources are spent.
CONSTRAINTS: Output ONLY valid JSON. When in doubt, proceed.
COMMAND: Score this alert and classify it.

RAW INPUT (first 800 chars):
{log_snippet}

EXTRACTED IOCs:
{ioc_summary}

Respond with exactly this JSON:
{{
  "triage_score": <float 0.0-1.0>,
  "should_proceed": <true|false>,
  "reasoning": "<one sentence>",
  "alert_type": "<phishing|malware|c2|recon|bruteforce|exfiltration|ransomware|unknown>",
  "urgency": "<immediate|high|medium|low>",
  "false_positive_indicators": [],
  "priority_iocs": []
}}"""


async def run_triage(state: dict) -> dict:
    from config import config
    from openai import AsyncOpenAI

    raw = state["raw_input"]
    iocs = extract_iocs(raw)
    heuristic_score = score_iocs(iocs)
    total_iocs = sum(len(v) for v in iocs.values())
    trace = state.get("agent_trace", [])
    ts = datetime.now(timezone.utc).isoformat()

    if total_iocs == 0:
        trace.append({
            "agent": "triage", "status": "dropped",
            "summary": "No IOCs detected in input.", "timestamp": ts,
        })
        return {**state, "iocs": iocs, "triage_score": 0.0,
                "should_proceed": False, "triage_reasoning": "No IOCs extracted.",
                "agent_trace": trace}

    ioc_summary = json.dumps({k: v[:5] for k, v in iocs.items() if v}, indent=2)

    ai_result = None
    openai_key = config.get("OPENAI_API_KEY")
    if openai_key:
        try:
            client = AsyncOpenAI(
                api_key=openai_key,
                base_url=config.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            )
            resp = await client.chat.completions.create(
                model=config.get("AI_MODEL", "gpt-4o-mini"),
                messages=[{"role": "user", "content": TRIAGE_PROMPT.format(
                    log_snippet=raw[:800], ioc_summary=ioc_summary,
                )}],
                max_tokens=400,
                temperature=0.1,
                response_format={"type": "json_object"},
            )
            ai_result = json.loads(resp.choices[0].message.content)
        except Exception as e:
            ai_result = None

    if ai_result is None:
        ai_result = {
            "triage_score": heuristic_score,
            "should_proceed": heuristic_score > 0.15,
            "reasoning": "Heuristic score (AI unavailable or key not configured).",
            "alert_type": "unknown",
            "urgency": "medium",
            "false_positive_indicators": [],
            "priority_iocs": [],
        }

    final_score = (ai_result.get("triage_score", heuristic_score) + heuristic_score) / 2

    trace.append({
        "agent": "triage",
        "status": "complete",
        "summary": ai_result.get("reasoning", ""),
        "score": round(final_score, 2),
        "alert_type": ai_result.get("alert_type", "unknown"),
        "urgency": ai_result.get("urgency", "medium"),
        "ioc_count": total_iocs,
        "timestamp": ts,
    })

    return {
        **state,
        "iocs": iocs,
        "triage_score": final_score,
        "should_proceed": ai_result.get("should_proceed", True) and final_score > 0.15,
        "triage_reasoning": ai_result.get("reasoning", ""),
        "agent_trace": trace,
    }
