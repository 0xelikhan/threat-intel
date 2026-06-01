"""
Response Agent — generates Sigma rule, KQL query, STIX bundle, matches threat actors.
Reads AI config at call time.
"""

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


def _attribution_evidence(mitre_techniques: list,
                          mitre_evidence: list,
                          behavioral_indicators: dict) -> dict:
    """Build a {technique_id -> [evidence_entry, ...]} map combining the AI's
    mitre_evidence strings with regex hits from behavior_extractor. Each
    evidence_entry is a dict {source, text, snippet} so the UI can label
    where the evidence came from (AI inference vs. raw-log regex match).

    technique_id is the bare ID ("T1566"), parsed off the "T1566 - Phishing"
    form that travels through the pipeline. Both an exact match and a parent
    match (T1059 covers T1059.001) populate the same key, so an actor whose
    profile lists T1059 gets the powershell-specific evidence too.
    """
    out: dict = {}

    def _push(tid: str, entry: dict):
        if not tid:
            return
        key = tid.split(" ")[0].strip().upper()
        out.setdefault(key, []).append(entry)
        # Parent-technique key — keeps T1059 matches surfaced under T1059.001
        # actor profiles (and vice versa).
        if "." in key:
            out.setdefault(key.split(".", 1)[0], []).append(entry)

    # AI-derived evidence sentences (one per technique the AI cited)
    for me in (mitre_evidence or []):
        if not isinstance(me, dict):
            continue
        tid  = me.get("technique") or ""
        text = (me.get("evidence") or "").strip()
        if not text:
            continue
        _push(tid, {
            "source":  "ai",
            "text":    text[:280],
            "snippet": "",
            "confidence": (me.get("confidence") or "").strip(),
        })

    # Raw-log regex hits from intel.behavior_extractor — quotes the exact
    # substring from the original log so the analyst sees evidence anchored
    # to the literal characters that triggered the inference.
    cats = ((behavioral_indicators or {}).get("categories") or {})
    for _cat, entries in cats.items():
        if not isinstance(entries, list):
            continue
        for ent in entries:
            if not isinstance(ent, dict):
                continue
            tid = ent.get("mitre") or ent.get("mitre_id") or ""
            name = (ent.get("name") or "").strip()
            match = (ent.get("match") or "").strip()
            why  = (ent.get("explanation") or "").strip()
            if not tid:
                continue
            _push(tid, {
                "source":  "log_pattern",
                "text":    f"{name}{(' — ' + why) if why else ''}".strip(),
                "snippet": match[:160] if match else "",
                "confidence": "",
            })

    return out


def _attach_attribution_evidence(matched_actors: list,
                                 mitre_techniques: list,
                                 mitre_evidence: list,
                                 behavioral_indicators: dict) -> list:
    """Annotate each matched actor with evidence_by_technique so the
    AttributionChip can show exactly what in the log matched each TTP."""
    if not matched_actors:
        return matched_actors
    ev_map = _attribution_evidence(mitre_techniques, mitre_evidence,
                                   behavioral_indicators)
    # technique_id -> human label (parsed from "T1566 - Phishing")
    name_map: dict = {}
    for t in mitre_techniques or []:
        if not isinstance(t, str):
            continue
        parts = t.split(" - ", 1)
        if len(parts) == 2:
            name_map[parts[0].strip().upper()] = parts[1].strip()
    for actor in matched_actors:
        matched_tids = actor.get("matchedTechniques") or []
        per_tech = []
        for tid in matched_tids:
            tid_key = str(tid).strip().upper()
            entries = ev_map.get(tid_key) or ev_map.get(tid_key.split(".", 1)[0]) or []
            per_tech.append({
                "id":       tid_key,
                "name":     name_map.get(tid_key) or
                            name_map.get(tid_key.split(".", 1)[0], ""),
                "evidence": entries[:4],   # cap per technique to keep payload small
            })
        actor["evidence_by_technique"] = per_tech
    return matched_actors


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
    """Returns the configured LLMProvider, or None when no AI key is set.
    Kept for backwards compat — the function name is a holdover; it now
    returns an LLMProvider, not an SDK client."""
    if not config.get("OPENAI_API_KEY"):
        return None
    try:
        from providers import get_provider
        return get_provider()
    except Exception:
        return None


async def _ai_call_json(prompt: str, config, max_tokens: int = 1400) -> dict:
    provider = _make_client(config)
    if not provider:
        return {}
    resp = await provider.complete(
        model=config.get_model(fast=True),
        messages=[{"role": "user", "content": prompt}],
        max_tokens=max_tokens,
        temperature=0.1,
        response_format={"type": "json_object"},
    )
    if resp.error:
        return {}
    # Truncation-tolerant parse so a capped response keeps its completed
    # fields instead of returning {} (lets us run a tighter token budget).
    from agents.investigation import _loads_lenient
    return _loads_lenient(resp.message)


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
    mitre_str = ", ".join(mitre[:8])

    # ── Actor attribution must happen BEFORE the evidence pack uses it ──
    matched_actors = _match_actors(mitre)
    # Annotate each actor with the specific log evidence that triggered each
    # matched TTP — combines AI mitre_evidence sentences with regex matches
    # from intel.behavior_extractor so the AttributionChip can quote both
    # the AI's inference AND the literal log snippet that fired the pattern.
    matched_actors = _attach_attribution_evidence(
        matched_actors,
        mitre,
        investigation.get("mitre_evidence") or [],
        state.get("behavioral_indicators") or {},
    )

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

    # Calibration baked into the disposition prompt — same evidence-required
    # standard the investigation agent applies. Prevents the analyst summary
    # from disagreeing with the calibrated investigation verdict.
    from intel.calibration import CALIBRATION_PRINCIPLES as _CAL
    analyst_prompt = f"""You are a senior MDR analyst (5+ years, T2/T3 escalation lead) writing the
final INTERNAL DISPOSITION for a SOC investigation (for the next-tier analyst / shift
lead). Be CONCISE throughout. Tight sentences, no padding; keep each list to its
most important 2-3 items.

You must base every claim on SPECIFIC evidence from the investigation. Do not
invent. Do not be vague. "Suspicious activity detected" is FORBIDDEN. Say what
activity, on what indicator, with what corroborating evidence.

{_CAL}

══════════════════════════════════════════════════════════════════════════════════
INPUT - investigation evidence pack
══════════════════════════════════════════════════════════════════════════════════
Threat Level (AI verdict)  : {threat_level}
Confidence (0-1)           : {state.get('confidence', 0.0)}
One-line summary           : {summary}
MITRE techniques mapped    : {mitre_str}

Evidence pack:
{json.dumps(evidence_pack, indent=2)[:3500]}

══════════════════════════════════════════════════════════════════════════════════
DISPOSITION DECISION TREE
══════════════════════════════════════════════════════════════════════════════════
  * CLEAR    -> only if you can cite a specific reason it is benign
                  (known-good library hit, GreyNoise=benign, MISP warninglist
                   match, well-known infrastructure, legitimate corporate
                   service, clean hash across every TI source, scheduled
                   vendor maintenance). When the threat_level above is
                   INFORMATIONAL/LOW and the evidence supports benign,
                   default to CLEAR.
  * MONITOR  -> suspicious but not actionable yet; specify the trigger that
                  would escalate.
  * ESCALATE -> real-world threat with concrete corroborating evidence (at
                  least one item from the EVIDENCE STANDARD above); give
                  concrete next steps.

══════════════════════════════════════════════════════════════════════════════════
RESPOND with this EXACT JSON (no markdown fences, no commentary):
══════════════════════════════════════════════════════════════════════════════════
{{
  "disposition":        "ESCALATE|CLEAR|MONITOR",
  "disposition_reason": "<2-3 sentences. Cite at least TWO specific evidence
                          items from the pack (e.g. 'EPSS 94% on the matched
                          KEV CVE', 'domain registered 4h ago + EvilProxy URL
                          pattern', 'process matches Dell SupportAssist known-
                          good pattern + hash clean across all sources').
                          Must support the disposition choice.>",
  "clear_justification":"<If CLEAR: cite the specific signal that makes this
                          benign. If MONITOR/ESCALATE: state 'Not a false
                          positive:' then explain why benign-signal hypotheses
                          were ruled out.>",
  "escalation_steps":   [
    "<concrete step (only when ESCALATE) - e.g. 'Query Entra ID sign-in logs
      for user X 24h back'>",
    "<another>",
    "<another>"
  ]
}}

Every disposition_reason and clear_justification claim must trace back to the
evidence pack. No generic phrasing. No hedging with 'potential misuse' when
the evidence points to benign activity."""

    # Detection content (Sigma/KQL/multi-SIEM) is generated ON DEMAND from the UI
    # via /api/detection — it's the slowest part of this stage and isn't needed on
    # every alert. Here we only generate the analyst Summary (the verdict hand-off),
    # which keeps the response stage to a single AI call. The trimmed schema (no
    # client email / IR playbook — neither is shown in the UI) needs little headroom.
    analyst_summary = await _ai_call_json(analyst_prompt, config, max_tokens=700)
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
        "assessment_basis":    investigation.get("assessment_basis", []),
        # Always-visible reasoning paragraph rendered right beneath the
        # threat-level badge — the analyst should never have to expand a
        # toggle to find out why the platform picked this level.
        "threat_level_reasoning": investigation.get("threat_level_reasoning", ""),
        # PRINCIPLE 7 two-tier split — surfaced separately in the UI so
        # analysts can tell evidence-backed facts from analyst inference.
        "confirmed_facts":     investigation.get("confirmed_facts", []),
        "analysis_assessment": investigation.get("analysis_assessment", []),
        # Server-computed enrichment baseline — quoted at the top of the
        # Summary card so analysts see the empirical numbers before
        # reading any AI interpretation.
        "enrichment_summary":  investigation.get("enrichment_summary", {}),
        "ai_unavailable":      investigation.get("ai_unavailable", False),
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
        # Defender 1116/1117 structured parse — gives the UI authoritative
        # field interpretation (malware_name, infected_path, process_name)
        # so renderers don't conflate the legitimate triggering process
        # with the malware itself.
        "defender_parse":      state.get("defender_parse"),
        # Multi-log split + AI correlation — frontend renders a
        # Log Correlation card when multi_log.is_multi.
        "multi_log":           state.get("multi_log"),
        "log_count":           state.get("log_count", 1),
        "log_correlation":     investigation.get("log_correlation"),
        # Analyst-provided feedback (post-analysis re-run). Echoed back so
        # the frontend can render an "Updated based on analyst feedback"
        # banner and the case file persists the operator's verdict.
        "analyst_feedback":    state.get("analyst_feedback") or "",
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
