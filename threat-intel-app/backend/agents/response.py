"""
Response Agent — generates Sigma rule, KQL query, STIX bundle, matches threat actors.
Reads AI config at call time.
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone


ACTORS = [
    {"name": "APT28 (Fancy Bear)",   "origin": "Russia",         "sponsor": "GRU",           "techniques": ["T1566","T1078","T1059.001","T1003","T1071.001","T1547","T1036"], "sectors": ["Government","Military","Media"],          "campaigns": ["Operation Pawn Storm","DNC Hack"]},
    {"name": "APT29 (Cozy Bear)",    "origin": "Russia",         "sponsor": "SVR",           "techniques": ["T1566","T1059.001","T1027","T1071","T1078","T1567","T1102"], "sectors": ["Government","Healthcare","Technology"],   "campaigns": ["SolarWinds","COVID-19 Vaccine Research"]},
    {"name": "APT41",                "origin": "China",          "sponsor": "MSS",           "techniques": ["T1190","T1133","T1059","T1505","T1078","T1486"], "sectors": ["Technology","Telecom","Finance"],          "campaigns": ["Operation Wicked Panda","ShadowPad"]},
    {"name": "Volt Typhoon",         "origin": "China",          "sponsor": "PLA",           "techniques": ["T1133","T1078","T1036","T1219","T1090","T1070"], "sectors": ["Critical Infrastructure","Energy"],      "campaigns": ["US Infrastructure Pre-positioning"]},
    {"name": "Salt Typhoon",         "origin": "China",          "sponsor": "MSS",           "techniques": ["T1190","T1078","T1071","T1040","T1114"], "sectors": ["Telecom","ISP"],                           "campaigns": ["US Telecom Breaches 2024"]},
    {"name": "Lazarus Group",        "origin": "North Korea",    "sponsor": "RGB",           "techniques": ["T1566","T1059","T1486","T1071","T1027","T1055","T1041"], "sectors": ["Finance","Crypto","Healthcare"],          "campaigns": ["WannaCry","Bangladesh Bank Heist","AppleJeus"]},
    {"name": "Kimsuky",              "origin": "North Korea",    "sponsor": "RGB",           "techniques": ["T1566","T1059.001","T1027","T1071","T1114","T1056"], "sectors": ["Government","Academic"],                 "campaigns": ["Operation Smoke Screen","AppleSeed"]},
    {"name": "FIN7",                 "origin": "Eastern Europe", "sponsor": "Criminal",      "techniques": ["T1566","T1059","T1055","T1486","T1041","T1027"], "sectors": ["Retail","Finance","Hospitality"],         "campaigns": ["CARBANAK","Black Basta affiliate"]},
    {"name": "Scattered Spider",     "origin": "US/UK",          "sponsor": "Criminal",      "techniques": ["T1078","T1566","T1539","T1219","T1486","T1110"], "sectors": ["Technology","Telecom","Finance"],         "campaigns": ["MGM Resorts","Caesars","Okta"]},
    {"name": "LockBit",              "origin": "Unknown",        "sponsor": "Criminal RaaS", "techniques": ["T1486","T1490","T1489","T1070","T1078","T1021"], "sectors": ["All Sectors"],                           "campaigns": ["LockBit 2.0","LockBit 3.0"]},
    {"name": "ALPHV/BlackCat",       "origin": "Eastern Europe", "sponsor": "Criminal RaaS", "techniques": ["T1486","T1490","T1041","T1078","T1021","T1003"], "sectors": ["Healthcare","Finance","Energy"],          "campaigns": ["Change Healthcare","MGM affiliate"]},
    {"name": "Cl0p",                 "origin": "Eastern Europe", "sponsor": "Criminal",      "techniques": ["T1190","T1486","T1041","T1567","T1078","T1070"], "sectors": ["Healthcare","Finance","Education"],       "campaigns": ["MOVEit","GoAnywhere MFT"]},
    {"name": "Evil Corp",            "origin": "Russia",         "sponsor": "Criminal",      "techniques": ["T1566","T1059","T1486","T1071","T1027","T1070"], "sectors": ["Finance","Insurance","Healthcare"],       "campaigns": ["Dridex","WastedLocker","Hades"]},
    {"name": "TA505",                "origin": "Eastern Europe", "sponsor": "Criminal",      "techniques": ["T1566","T1059","T1027","T1041","T1071"], "sectors": ["Finance","Retail","Healthcare"],          "campaigns": ["Dridex distribution","FlawedAmmyy"]},
]


def _match_actors(mitre_techniques: list) -> list:
    if not mitre_techniques:
        return []
    tech_ids = [t.split(" ")[0] for t in mitre_techniques]
    matched = []
    for actor in ACTORS:
        hits = [t for t in actor["techniques"] if t in tech_ids]
        if hits:
            score = round(len(hits) / max(len(tech_ids), len(actor["techniques"])) * 100)
            matched.append({**actor, "matchedTechniques": hits, "score": score})
    return sorted(matched, key=lambda x: x["score"], reverse=True)[:5]


def _build_stix(iocs: dict, investigation: dict) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    objects = []

    identity_id = f"identity--{uuid.uuid4()}"
    objects.append({"type": "identity", "spec_version": "2.1", "id": identity_id,
                    "created": now, "modified": now, "name": "Threat Intelligence Platform",
                    "identity_class": "system"})

    for ip in iocs.get("ips", [])[:10]:
        iid = f"indicator--{uuid.uuid4()}"
        objects.append({"type": "indicator", "spec_version": "2.1", "id": iid,
                        "created": now, "modified": now, "created_by_ref": identity_id,
                        "name": f"Malicious IP: {ip}", "indicator_types": ["malicious-activity"],
                        "pattern": f"[ipv4-addr:value = '{ip}']", "pattern_type": "stix",
                        "valid_from": now, "labels": ["automated-analysis"]})

    for domain in iocs.get("domains", [])[:10]:
        iid = f"indicator--{uuid.uuid4()}"
        objects.append({"type": "indicator", "spec_version": "2.1", "id": iid,
                        "created": now, "modified": now, "created_by_ref": identity_id,
                        "name": f"Suspicious domain: {domain}", "indicator_types": ["malicious-activity"],
                        "pattern": f"[domain-name:value = '{domain}']", "pattern_type": "stix",
                        "valid_from": now, "labels": ["automated-analysis"]})

    for h in iocs.get("hashes", [])[:10]:
        hash_type = "MD5" if len(h) == 32 else ("SHA-1" if len(h) == 40 else "SHA-256")
        field = {"MD5": "hashes.MD5", "SHA-1": "hashes.'SHA-1'", "SHA-256": "hashes.'SHA-256'"}[hash_type]
        iid = f"indicator--{uuid.uuid4()}"
        objects.append({"type": "indicator", "spec_version": "2.1", "id": iid,
                        "created": now, "modified": now, "created_by_ref": identity_id,
                        "name": f"Malicious hash ({hash_type})", "indicator_types": ["malicious-activity"],
                        "pattern": f"[file:{field} = '{h}']", "pattern_type": "stix",
                        "valid_from": now})

    for t in investigation.get("mitre_techniques", []):
        parts = t.split(" - ")
        tid = f"attack-pattern--{uuid.uuid4()}"
        objects.append({"type": "attack-pattern", "spec_version": "2.1", "id": tid,
                        "created": now, "modified": now,
                        "name": parts[1] if len(parts) > 1 else t,
                        "external_references": [{"source_name": "mitre-attack",
                                                 "external_id": parts[0],
                                                 "url": f"https://attack.mitre.org/techniques/{parts[0].replace('.', '/')}/"}]})

    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


async def _ai_call(prompt: str, config) -> str:
    from openai import AsyncOpenAI
    key = config.get("OPENAI_API_KEY")
    if not key:
        return "# OpenAI API key not configured"
    try:
        client = AsyncOpenAI(
            api_key=key,
            base_url=config.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        )
        resp = await client.chat.completions.create(
            model=config.get("AI_MODEL", "gpt-4o-mini"),
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1500,
            temperature=0.1,
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        return f"# AI generation failed: {e}"


async def run_response(state: dict) -> dict:
    from config import config

    investigation = state.get("investigation", {})
    iocs = state.get("iocs", {})
    threat_level = state.get("threat_level", "MEDIUM")
    mitre = state.get("mitre_techniques", [])
    trace = state.get("agent_trace", [])

    summary = investigation.get("summary", "")
    ioc_json = json.dumps({k: v[:5] for k, v in iocs.items() if v})
    mitre_str = ", ".join(mitre[:8])

    sigma_prompt = f"""Generate a complete production-ready Sigma detection rule.
Threat: {summary}
Threat Level: {threat_level}
MITRE Techniques: {mitre_str}
IOCs: {ioc_json}
Output ONLY the YAML Sigma rule. No markdown fences, no explanation."""

    kql_prompt = f"""Generate a complete Microsoft Sentinel KQL analytics rule.
Threat: {summary}
Threat Level: {threat_level}
MITRE Techniques: {mitre_str}
IOCs: {ioc_json}
Requirements: let statements for IOC lists, relevant Sentinel tables, entity mapping fields, inline // comments, rule metadata as comments at top.
Output ONLY the KQL. No markdown fences."""

    sigma_rule, kql_query = await asyncio.gather(
        _ai_call(sigma_prompt, config),
        _ai_call(kql_prompt, config),
    )

    stix_bundle = _build_stix(iocs, investigation)
    matched_actors = _match_actors(mitre)

    response_summary = {
        "threat_level":        threat_level,
        "confidence":          state.get("confidence", 0.0),
        "summary":             summary,
        "key_findings":        investigation.get("key_findings", []),
        "ioc_assessments":     investigation.get("ioc_assessments", []),
        "mitre_techniques":    mitre,
        "attack_patterns":     investigation.get("attack_patterns", []),
        "recommended_actions": investigation.get("recommended_actions", []),
        "geo_highlights":      investigation.get("geo_highlights", []),
        "tor_traffic":         investigation.get("tor_traffic", False),
        "attribution_hints":   investigation.get("attribution_hints"),
        "matched_actors":      matched_actors,
        "chain_of_thought":    investigation.get("chain_of_thought", []),
        "timestamp":           datetime.now(timezone.utc).isoformat(),
    }

    trace.append({
        "agent": "response",
        "status": "complete",
        "summary": (f"Generated Sigma rule, KQL query, STIX bundle "
                    f"({len(stix_bundle['objects'])} objects). "
                    f"Matched {len(matched_actors)} threat actor(s)."),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    return {
        **state,
        "sigma_rule":       sigma_rule,
        "kql_query":        kql_query,
        "response_summary": response_summary,
        "stix_bundle":      stix_bundle,
        "agent_trace":      trace,
    }
