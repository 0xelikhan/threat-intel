"""
Outbound webhook integrations for SOC team chat and case management.
Configured via config.json keys:
  - SLACK_WEBHOOK_URL
  - TEAMS_WEBHOOK_URL
  - THEHIVE_URL  + THEHIVE_TOKEN
  - WEBHOOK_GENERIC_URL  (raw POST of the analysis JSON)
"""
import aiohttp
from datetime import datetime, timezone

LEVEL_EMOJI = {
    "CRITICAL": ":rotating_light:", "HIGH": ":warning:", "MEDIUM": ":yellow_circle:",
    "LOW": ":large_blue_circle:", "INFORMATIONAL": ":white_circle:",
}

LEVEL_COLOR = {
    "CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308",
    "LOW": "#3b82f6", "INFORMATIONAL": "#6b7280",
}


def _short_text(result: dict, max_iocs: int = 5) -> dict:
    """Build a small, presentation-ready summary from a full result."""
    rs = result.get("response_summary", {}) or {}
    iocs = result.get("iocs", {}) or {}
    sample_iocs = []
    for k in ("ips", "domains", "hashes", "urls"):
        for v in (iocs.get(k) or [])[:max_iocs]:
            sample_iocs.append(f"{k[:-1].upper()}: {v}")
    return {
        "threat_level": rs.get("threat_level", "INFORMATIONAL"),
        "summary":      rs.get("summary", "(no summary)"),
        "confidence":   round((rs.get("confidence") or 0) * 100),
        "total_iocs":   sum(len(v or []) for v in iocs.values()),
        "mitre_count":  len(rs.get("mitre_techniques") or []),
        "actors":       [a.get("name", "") for a in (rs.get("matched_actors") or [])[:3]],
        "kev_count":    len((rs.get("cross_refs") or {}).get("kev") or []),
        "lolbas_count": len((rs.get("cross_refs") or {}).get("lolbas") or []),
        "sample_iocs":  sample_iocs[:8],
        "client_email_subject": ((rs.get("analyst_summary") or {}).get("client_email") or {}).get("subject", ""),
        "disposition":  (rs.get("analyst_summary") or {}).get("disposition", ""),
    }


# Slack mrkdwn requires &, <, > to be entity-escaped — otherwise an AI
# summary like "User <john> & admin" eats the angle-bracket spans and
# breaks the renderer. https://api.slack.com/reference/surfaces/formatting
def _slack_mrkdwn(text: str) -> str:
    if not text:
        return ""
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))


def _slack_code_safe(text: str) -> str:
    """Escape backticks inside text destined for a triple-backtick code
    block. A stray ``` would close the block early and break formatting
    for everything after it."""
    return str(text).replace("```", "ʼʼʼ")


# ─── SLACK ────────────────────────────────────────────────────────────────────────
def _build_slack_blocks(result: dict, run_url: str | None = None) -> dict:
    s = _short_text(result)
    emoji = LEVEL_EMOJI.get(s["threat_level"], ":grey_question:")
    fields = []
    if s["actors"]:
        fields.append({"type": "mrkdwn", "text": f"*Attribution*\n{_slack_mrkdwn(', '.join(s['actors']))}"})
    if s["kev_count"]:
        fields.append({"type": "mrkdwn", "text": f"*KEV CVEs*\n{s['kev_count']} actively exploited"})
    if s["lolbas_count"]:
        fields.append({"type": "mrkdwn", "text": f"*LOLBAS*\n{s['lolbas_count']} binaries"})

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": f"{emoji} RECON · {s['threat_level']}"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": _slack_mrkdwn(s["summary"])[:2900]}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Confidence*\n{s['confidence']}%"},
            {"type": "mrkdwn", "text": f"*Indicators*\n{s['total_iocs']}"},
            {"type": "mrkdwn", "text": f"*MITRE TTPs*\n{s['mitre_count']}"},
            {"type": "mrkdwn", "text": f"*Disposition*\n{_slack_mrkdwn(s['disposition'] or 'pending')}"},
        ] + fields},
    ]
    if s["sample_iocs"]:
        safe_iocs = "\n".join(_slack_code_safe(ioc) for ioc in s["sample_iocs"])
        blocks.append({"type": "section",
                       "text": {"type": "mrkdwn", "text": "*Sample indicators*\n```" + safe_iocs + "```"}})
    if run_url:
        blocks.append({"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "Open in RECON"},
             "url": run_url, "style": "primary"}
        ]})
    return {"blocks": blocks}


async def send_slack(url: str, result: dict, run_url: str | None = None) -> dict:
    payload = _build_slack_blocks(result, run_url)
    return await _post_json(url, payload)


# ─── TEAMS (MessageCard) ──────────────────────────────────────────────────────────
def _build_teams_card(result: dict, run_url: str | None = None) -> dict:
    s = _short_text(result)
    sections = [{
        "activityTitle": f"RECON Threat Intelligence · **{s['threat_level']}**",
        "activitySubtitle": f"{s['total_iocs']} indicators · {s['mitre_count']} MITRE TTPs · confidence {s['confidence']}%",
        "text": s["summary"],
        "facts": [
            {"name": "Disposition", "value": s["disposition"] or "pending"},
            {"name": "Attribution", "value": ", ".join(s["actors"]) or "—"},
            {"name": "KEV CVEs",    "value": str(s["kev_count"])},
            {"name": "LOLBAS hits", "value": str(s["lolbas_count"])},
        ],
    }]
    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": f"RECON {s['threat_level']}: {s['summary'][:80]}",
        "themeColor": LEVEL_COLOR.get(s["threat_level"], "#6b7280").lstrip("#"),
        "sections": sections,
    }
    if run_url:
        payload["potentialAction"] = [{
            "@type": "OpenUri", "name": "Open in RECON",
            "targets": [{"os": "default", "uri": run_url}],
        }]
    return payload


async def send_teams(url: str, result: dict, run_url: str | None = None) -> dict:
    return await _post_json(url, _build_teams_card(result, run_url))


# ─── TheHive 5 ────────────────────────────────────────────────────────────────────
async def send_thehive(base_url: str, token: str, result: dict, run_url: str | None = None) -> dict:
    """Create a TheHive 5 case + observables."""
    if not (base_url and token):
        return {"ok": False, "error": "TheHive URL/token not configured"}
    s = _short_text(result)
    rs = result.get("response_summary", {}) or {}
    # TheHive 5 severity is 1..4 (1=Low, 2=Medium, 3=High, 4=Critical).
    # The old map collapsed CRITICAL and HIGH both into 3, so every
    # critical-class case was filed at HIGH severity in TheHive and
    # never sorted to the top of the case queue.
    # Ref: https://docs.strangebee.com/thehive/api-docs/#tag/Case
    severity_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 1}
    case_payload = {
        "title": f"RECON: {s['threat_level']} — {s['summary'][:120]}",
        "description": s["summary"] + (f"\n\n[Open in RECON]({run_url})" if run_url else ""),
        "severity": severity_map.get(s["threat_level"], 2),
        "tlp": 2,
        "pap": 2,
        "tags": list({f"mitre:{t.split(' ')[0]}" for t in (rs.get("mitre_techniques") or [])[:8]}) + ["recon"],
    }
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    base = base_url.rstrip("/")
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(f"{base}/api/v1/case", json=case_payload, headers=headers,
                                    timeout=aiohttp.ClientTimeout(total=15)) as r:
                case = await r.json()
                if r.status >= 400:
                    return {"ok": False, "error": f"TheHive {r.status}: {case}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}
        # Add observables
        case_id = case.get("_id") or case.get("id")
        iocs = result.get("iocs", {}) or {}
        type_map = {"ips": "ip", "domains": "domain", "hashes": "hash", "urls": "url", "emails": "mail"}
        obs_count = 0
        for k, dataType in type_map.items():
            for v in (iocs.get(k) or [])[:20]:
                try:
                    async with session.post(
                        f"{base}/api/v1/case/{case_id}/observable",
                        json={"dataType": dataType, "data": v, "tlp": 2, "tags": ["recon"]},
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as r:
                        if r.status < 400:
                            obs_count += 1
                except Exception:
                    continue
        return {"ok": True, "case_id": case_id, "case_url": f"{base}/cases/{case_id}", "observables": obs_count}


# ─── Generic ──────────────────────────────────────────────────────────────────────
async def send_generic(url: str, result: dict) -> dict:
    """POST the full result JSON to a custom endpoint."""
    return await _post_json(url, {
        "platform": "RECON",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "result": _short_text(result),
        "full":   result,
    })


# ─── helpers ──────────────────────────────────────────────────────────────────────
async def _post_json(url: str, payload: dict) -> dict:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload,
                                    timeout=aiohttp.ClientTimeout(total=10)) as r:
                ok = r.status < 400
                body = await r.text()
                return {"ok": ok, "status": r.status, "body": body[:200]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def available(config) -> dict:
    """Return which destinations are configured (without exposing the secret values)."""
    return {
        "slack":   bool(config.get("SLACK_WEBHOOK_URL")),
        "teams":   bool(config.get("TEAMS_WEBHOOK_URL")),
        "thehive": bool(config.get("THEHIVE_URL")) and bool(config.get("THEHIVE_TOKEN")),
        "opencti": bool(config.get("OPENCTI_URL"))   and bool(config.get("OPENCTI_TOKEN")),
        "generic": bool(config.get("WEBHOOK_GENERIC_URL")),
    }
