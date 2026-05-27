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
    """Match threat actors using MITRE ATT&CK groups + MISP galaxy enrichment.
    Falls back to the hardcoded ACTORS list if neither external source is loaded."""
    if not mitre_techniques:
        return []
    try:
        from intel.actor_data import match_threat_actors
        rich = match_threat_actors(mitre_techniques)
        if rich:
            return rich[:5]
    except Exception:
        pass
    # Fallback: hardcoded list
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


import subprocess
import tempfile
import os as _os


def validate_sigma_rule(yaml_content: str) -> tuple[bool, str]:
    if not yaml_content or yaml_content.startswith("#"):
        return False, "Empty or error rule"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml",
                                     delete=False, encoding="utf-8") as f:
        f.write(yaml_content)
        tmp = f.name
    try:
        r = subprocess.run(["sigma", "check", tmp],
                           capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            return True, ""
        return False, r.stderr.strip() or r.stdout.strip()
    except FileNotFoundError:
        return True, "sigma-cli not installed — skipped"
    except subprocess.TimeoutExpired:
        return False, "Validation timed out"
    finally:
        _os.unlink(tmp)


def _make_client(config):
    from openai import AsyncAzureOpenAI, AsyncOpenAI
    key = config.get("OPENAI_API_KEY")
    base_url = config.get("OPENAI_BASE_URL", "")
    if not key:
        return None
    if "openai.azure.com" in base_url:
        return AsyncAzureOpenAI(
            api_key=key,
            azure_endpoint=base_url.rstrip("/"),
            api_version="2024-02-01",
        )
    return AsyncOpenAI(api_key=key, base_url=base_url or "https://api.openai.com/v1")


async def _ai_call(prompt: str, config, max_tokens: int = 1500) -> str:
    client = _make_client(config)
    if not client:
        return "# OpenAI API key not configured"
    try:
        resp = await client.chat.completions.create(
            # Detection-content generation (Sigma/KQL) + templated hand-off →
            # fast model tier. The response stage runs these concurrently, so the
            # slowest call bounds the stage; keeping all of them fast is what
            # actually shortens it.
            model=config.get_model(fast=True),
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=0.1,
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        return f"# AI generation failed: {e}"


async def _ai_call_json(prompt: str, config, max_tokens: int = 1400) -> dict:
    client = _make_client(config)
    if not client:
        return {}
    try:
        resp = await client.chat.completions.create(
            model=config.get_model(fast=True),
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=0.1,
            response_format={"type": "json_object"},
        )
        # Truncation-tolerant parse so a capped response keeps its completed
        # fields instead of returning {} (lets us run a tighter token budget).
        from agents.investigation import _loads_lenient
        return _loads_lenient(resp.choices[0].message.content)
    except Exception:
        return {}


async def run_response(state: dict) -> dict:
    from config import config
    import time
    _t_start = time.perf_counter()

    investigation = state.get("investigation_result", {})
    iocs = state.get("iocs", {})
    threat_level = state.get("threat_level", "MEDIUM")
    mitre = state.get("mitre_techniques", [])
    trace = state.get("agent_trace", [])

    summary = investigation.get("summary", "")
    ioc_json = json.dumps({k: v[:5] for k, v in iocs.items() if v})
    mitre_str = ", ".join(mitre[:8])

    mitre_tags = " ".join(
        f"attack.{t.split(' ')[0].lower().replace('.','_')}" for t in mitre[:8]
    )

    sigma_prompt = f"""Generate a complete production-ready Sigma detection rule in YAML.
Threat: {summary}
Threat Level: {threat_level}
MITRE Techniques: {mitre_str}
IOCs: {ioc_json}

Requirements:
- title, id (uuid4), status: experimental, description
- author: RECON Platform
- tags section MUST include all MITRE IDs formatted as: attack.tXXXX or attack.tXXXX_XXX
  Tags for this rule: {mitre_tags}
- logsource with category and product
- detection section with keywords or field matching covering all IOCs
- falsepositives section
- level: {threat_level.lower()}
Output ONLY valid YAML. No markdown fences, no explanation."""

    kql_prompt = f"""Generate a complete Microsoft Sentinel KQL analytics rule.
Threat: {summary}
Threat Level: {threat_level}
MITRE ATT&CK: {mitre_str}
IOCs: {ioc_json}

Requirements:
- Comment block header with: rule name, MITRE techniques ({mitre_str}), severity, author: RECON Platform
- let statements defining IOC lists from the provided IOCs
- Query using relevant Sentinel tables (SecurityAlert, CommonSecurityLog, DeviceNetworkEvents, DnsEvents, etc.)
- extend or project to add ThreatLevel, MITRETechniques fields
- inline // comments explaining each section
Output ONLY valid KQL. No markdown fences, no explanation."""

    # Additional SIEM query languages
    siem_prompt = f"""Generate hunt queries in 4 SIEM languages for this threat.
Threat: {summary}
MITRE: {mitre_str}
IOCs: {ioc_json}

Output ONLY valid JSON with these exact keys (each value is a complete, runnable query string with inline comments):
{{
  "splunk_spl":      "<Splunk SPL query — index= ... | search ... | stats ...>",
  "elastic_eql":     "<Elastic EQL query — sequence by host.id ... or process where ...>",
  "chronicle_yara_l":"<Google Chronicle YARA-L 2.0 rule — rule {{...}}>",
  "crowdstrike_fql": "<CrowdStrike Falcon FQL/Event Search query>"
}}
Each query MUST reference at least one of the provided IOCs and use realistic field names for that platform."""

    # ── Actor attribution must happen BEFORE the evidence pack uses it ──
    matched_actors = _match_actors(mitre)

    # ── Build a rich evidence pack so the AI can cite specifics ──
    rs_cross = state.get("cross_refs", {})
    rs_email = state.get("email_analysis") or {}
    evidence_pack = {
        "alert_text_first_300": (state.get("raw_input") or "")[:300],
        "key_findings":         investigation.get("key_findings", [])[:6],
        "correlated_signals":   investigation.get("correlated_signals", [])[:5],
        "ioc_assessments":      investigation.get("ioc_assessments", [])[:8],
        "mitre_evidence":       investigation.get("mitre_evidence", [])[:6],
        "attack_chain":         investigation.get("attack_chain_hypothesis", ""),
        "confidence_basis":     investigation.get("confidence_basis", ""),
        "false_positive_check": investigation.get("false_positive_check", ""),
        "kev_hits":             [{"cve": k["cve"], "product": f"{k.get('vendor','')} {k.get('product','')}",
                                  "ransomware": k.get("ransomware_use", False),
                                  "epss_pct": (k.get("epss") or {}).get("epss_percent")}
                                 for k in (rs_cross.get("kev") or [])[:5]],
        "lolbas_hits":          [l.get("name") for l in (rs_cross.get("lolbas") or [])[:6]],
        "loldrivers_hits":      [{"name": d.get("value"), "category": d.get("category")}
                                 for d in (rs_cross.get("loldrivers") or [])[:3]],
        "phishing_kits":        [k.get("kit") for k in (rs_cross.get("phishing_kits") or [])[:3]],
        "matched_actors":       [{"name": a.get("name"), "score": a.get("score"),
                                  "origin": a.get("origin")} for a in matched_actors[:3]],
        "email_signals":        rs_email.get("phishing_signals", []) if rs_email else [],
        "email_auth":           rs_email.get("auth_results", {})    if rs_email else {},
    }

    analyst_prompt = f"""You are a senior MDR analyst (5+ years, T2/T3 escalation lead) writing the
final hand-off for a SOC investigation. Be CONCISE throughout — tight sentences, no
padding; keep each list to its most important 2-3 items. Two distinct outputs are required:

(A) INTERNAL DISPOSITION — for the next-tier analyst or shift lead
(B) CLIENT NOTIFICATION EMAIL — for a non-technical IT manager at the customer site

You must base every claim on SPECIFIC evidence from the investigation. Do not invent.
Do not be vague. "Suspicious activity detected" is FORBIDDEN — say what activity,
on what indicator, with what corroborating evidence.

═══════════════════════════════════════════════════════════════════════════════════
INPUT — investigation evidence pack
═══════════════════════════════════════════════════════════════════════════════════
Threat Level (AI verdict)  : {threat_level}
Confidence (0–1)           : {state.get('confidence', 0.0)}
One-line summary           : {summary}
MITRE techniques mapped    : {mitre_str}

Evidence pack:
{json.dumps(evidence_pack, indent=2)[:3500]}

═══════════════════════════════════════════════════════════════════════════════════
OUTPUT REQUIREMENTS
═══════════════════════════════════════════════════════════════════════════════════

(A) Disposition decision tree:
  • CLEAR    → only if you can cite a specific reason it's benign
                 (GreyNoise=benign, MISP warning list match, well-known infrastructure,
                  legitimate corporate service, etc.) AND confidence is high.
  • MONITOR  → suspicious but not actionable yet; specify the trigger that would escalate.
  • ESCALATE → real-world threat with corroborating evidence; give concrete next steps.

(B) Client email tone calibration:
  CRITICAL → urgent, plain "we observed an active attack", no hedging
  HIGH     → clear concern, recommended actions are time-sensitive
  MEDIUM   → professional caution, contextual, action recommended within business day
  LOW/INFO → informational only, no panic, often "we noticed but it appears benign"

  STRICT email rules:
  - No MITRE codes (no "T1566"), no raw hashes (refer to "a suspicious file")
  - No raw URLs in attack form; defang if mentioned ("a fake Microsoft login page on
    a newly registered domain")
  - Talk in terms of business impact ("could allow access to corporate email")
  - Specific recommendations ("please review sign-in logs in Entra ID for user X
    over the past 24 hours"), not vague ("please investigate")
  - 2-3 short paragraphs maximum. No bullet lists in the body — write prose.
  - Always end with a specific question/confirmation the client should reply with.

═══════════════════════════════════════════════════════════════════════════════════
RESPOND with this EXACT JSON (no markdown fences, no commentary):
═══════════════════════════════════════════════════════════════════════════════════
{{
  "disposition":        "ESCALATE|CLEAR|MONITOR",
  "disposition_reason": "<2-3 sentences. Cite at least TWO specific evidence items
                          from the pack (e.g. 'EPSS 94% on the matched KEV CVE',
                          'domain registered 4h ago + EvilProxy URL pattern',
                          'GreyNoise tags this IP as known benign scanner').
                          Must support the disposition choice.>",
  "clear_justification":"<If CLEAR: cite the specific signal that makes this benign.
                          If MONITOR/ESCALATE: state 'Not a false positive:' then explain
                          why benign-signal hypotheses were ruled out.>",
  "escalation_steps":   [
    "<concrete step — e.g. 'Query Entra ID sign-in logs for user X 24h back'>",
    "<another>",
    "<another>"
  ],
  "tier2_talking_points": [
    "<the one signal that most strongly drives your disposition>",
    "<the most important correlation between signals>",
    "<the biggest uncertainty / what to verify>"
  ],
  "client_email": {{
    "subject": "<plain-English subject line conveying severity. Examples:
                 CRITICAL → 'URGENT: Active credential phishing attempt detected'
                 HIGH     → 'Security alert: suspicious sign-in attempt on Acme account'
                 MEDIUM   → 'Notification: unusual activity observed on your network'
                 LOW      → 'Informational: routine threat-intel match'>",
    "body":    "<paragraph 1: WHAT WE OBSERVED in plain English — 'Earlier today we
                  detected an attempt to deliver a phishing email impersonating your
                  Microsoft 365 sign-in page from a domain that was registered just
                  hours before.' Reference the actual evidence from the pack but in
                  human terms.\\n\\nparagraph 2: WHAT THIS MEANS for them — connect to
                  their business risk ('If a user enters credentials, the attacker
                  would gain access to corporate email and any apps using SSO').\\n\\n
                  paragraph 3: WHAT WE'VE DONE and what we RECOMMEND they do —
                  specific actions ('We've blocked the source IP at our perimeter.
                  Please ask your IT team to review sign-in logs for any user that
                  received this email in the past 4 hours and confirm whether MFA
                  challenges were satisfied.').\\n\\nparagraph 4: HOW TO RESPOND —
                  'Please reply to confirm sign-in review is complete, or let us
                  know if you need our team to assist directly.'>"
  }},
  "ir_playbook": {{
    "phase_identification": ["<NIST 800-61 identification step — specific, evidence-tied>",
                              "<another>", "<another>"],
    "phase_containment":    ["<containment action targeting the specific IOCs/users at risk>",
                              "<another>", "<another>"],
    "phase_eradication":    ["<eradication step — e.g. revoke tokens for affected users>",
                              "<another>"],
    "phase_recovery":       ["<recovery step — restore service, validate access>",
                              "<another>"],
    "phase_lessons":        ["<post-incident lesson tied to this specific case>",
                              "<another>"]
  }}
}}

Remember: every disposition_reason and clear_justification claim must trace back to
the evidence pack. No generic phrasing."""

    # Detection content (Sigma/KQL/multi-SIEM) is generated ON DEMAND from the UI
    # via /api/detection — it's the slowest part of this stage and isn't needed on
    # every alert. Here we only generate the analyst Summary (the verdict hand-off),
    # which keeps the response stage to a single AI call. The prompts above are
    # still built so the on-demand path can reuse the same context.
    analyst_summary = await _ai_call_json(analyst_prompt, config)
    sigma_rule, kql_query, siem_queries = "", "", {}
    sigma_valid, sigma_error = False, "on-demand: generate from the Detection card"

    stix_bundle = _build_stix(iocs, investigation)
    # matched_actors already computed above (before evidence_pack was built)

    # Attach Atomic Red Team attack examples for each technique
    atomic_examples = []
    try:
        from intel.atomic_red_team import get_tests
        for t in (mitre or [])[:6]:
            tid = t.split(" ")[0]
            tests = get_tests(tid)
            if tests:
                atomic_examples.append({"technique": t, "tests": tests[:2]})
    except Exception:
        pass

    # Attach JA3/JA4 TLS fingerprints if this looks like C2 activity
    ja_fingerprints = []
    ja_sigma_snippet = ""
    ja_kql_snippet = ""
    try:
        from intel.ja_fingerprints import (
            get_for_alert_type, get_for_mitre,
            as_sigma_yaml_snippet, as_kql_snippet,
        )
        alert_type = next(
            (t.get("alert_type", "") for t in (state.get("agent_trace") or [])
             if t.get("agent") == "triage"),
            "",
        )
        ja_fingerprints = get_for_alert_type(alert_type) or get_for_mitre(mitre)
        if ja_fingerprints:
            ja_sigma_snippet = as_sigma_yaml_snippet(ja_fingerprints[:5])
            ja_kql_snippet   = as_kql_snippet(ja_fingerprints[:5])
    except Exception:
        pass

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
        # ─ CTI framework analysis (Diamond Model, Kill Chain, Pyramid of Pain, Admiralty) ─
        "diamond_model":       investigation.get("diamond_model", {}),
        "kill_chain":          investigation.get("kill_chain", {}),
        "pyramid_of_pain":     investigation.get("pyramid_of_pain", []),
        "evidence_ratings":    investigation.get("evidence_ratings", []),
        # ─ FP-vs-malicious assistant ─
        "verdict_classification": investigation.get("verdict_classification", ""),
        "probing_questions":   investigation.get("probing_questions", []),
        "attack_chain_hypothesis": investigation.get("attack_chain_hypothesis", ""),
        "confidence_basis":    investigation.get("confidence_basis", ""),
        "false_positive_check":investigation.get("false_positive_check", ""),
        "correlated_signals":  investigation.get("correlated_signals", []),
        "mitre_evidence":      investigation.get("mitre_evidence", []),
        "timestamp":           datetime.now(timezone.utc).isoformat(),
        "sigma_valid":         sigma_valid,
        "sigma_error":         sigma_error,
        "detections_on_demand": True,   # UI generates Sigma/KQL/SIEM via /api/detection
        "cross_refs":          state.get("cross_refs", {}),
        "atomic_examples":     atomic_examples,
        "siem_queries":        siem_queries or {},
        "analyst_summary":     analyst_summary or {},
        "ja_fingerprints":     ja_fingerprints,
        "ja_sigma_snippet":    ja_sigma_snippet,
        "ja_kql_snippet":      ja_kql_snippet,
    }

    trace.append({
        "agent": "response",
        "status": "complete",
        "summary": (f"Generated Sigma rule, KQL query, STIX bundle "
                    f"({len(stix_bundle['objects'])} objects). "
                    f"Matched {len(matched_actors)} threat actor(s)."),
        "elapsed_ms": int((time.perf_counter() - _t_start) * 1000),
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
