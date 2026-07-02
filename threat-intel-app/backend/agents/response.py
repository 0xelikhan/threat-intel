"""
Response Agent — generates Sigma rule, KQL query, STIX bundle, matches threat actors.
Reads AI config at call time.
"""

import json
import logging
import uuid
from datetime import datetime, timezone

_log = logging.getLogger("recon.response")


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


# Inverted index built once at module load — technique_id -> [actor, ...].
# Was O(N_actors * N_techniques_per_actor) per call before; now hash
# lookup per alert technique with O(matches) follow-up. Doesn't change
# behaviour, just lifts the inner loop out.
_ACTOR_BY_TECH: "dict[str, list[dict]]" = {}
for _a in ACTORS:
    for _tid in _a.get("techniques", []):
        _ACTOR_BY_TECH.setdefault(_tid, []).append(_a)


def _enrich_actor_with_cross_walk(actor: dict) -> dict:
    """Attach MISP-galaxy cross-walk metadata to a matched actor — sectors,
    cross-source confirmation, MITRE G####, Microsoft Storm-/Typhoon
    aliases — without touching the existing matchedTechniques + score.

    When cross_walk_actor confirms the actor in ≥2 of (community, MITRE,
    Microsoft), confidence='high' lights up the AttributionChip's
    'cross-confirmed' badge. The existing score (precision-style TTP
    overlap) remains the gate threshold; cross-walk is an additive
    confidence dimension."""
    try:
        from intel.misp_galaxies import cross_walk_actor
    except Exception:
        return actor
    name = actor.get("name") or actor.get("group") or ""
    if not name:
        return actor
    walk = cross_walk_actor(name)
    if not walk:
        return actor
    return {
        **actor,
        "cross_walk": {
            "confidence":       walk.get("confidence"),
            "tiers_hit":        walk.get("tiers_hit"),
            "mitre_id":         walk.get("mitre_id"),
            "microsoft_origin": walk.get("microsoft_origin"),
            "sectors":          walk.get("sectors"),
            "aliases":          walk.get("aliases", [])[:10],
        },
    }


def _match_actors(mitre_techniques: list) -> list:
    """Match threat actors using MITRE ATT&CK groups + MISP galaxy enrichment.
    Falls back to the hardcoded ACTORS list if neither external source is loaded.

    Round-16: every matched actor is post-processed through
    _enrich_actor_with_cross_walk which attaches a cross_walk dict
    pulling from MITRE-intrusion-set + Microsoft-activity-group +
    community threat-actor catalogues. Lights up the frontend
    AttributionChip with sectors + cross-confirmed badge."""
    if not mitre_techniques:
        return []
    try:
        from intel.actor_data import match_threat_actors
        rich = match_threat_actors(mitre_techniques)
        if rich:
            return [_enrich_actor_with_cross_walk(a) for a in rich[:5]]
    except Exception as _e:
        import logging
        logging.getLogger("recon.response").debug(
            "MISP actor match failed, falling back: %s", _e)
    # Fallback: hardcoded list. Same precision-style score as the
    # primary MITRE path — matches / N_alert_techniques * 100 — so the
    # gate threshold has consistent meaning regardless of which data
    # source produced the match.
    tech_ids = [t.split(" ")[0] for t in mitre_techniques]
    n_alert = len(tech_ids) or 1
    # Bucket matched-technique-ids per actor in a single pass over the
    # alert techniques using the precomputed index.
    actor_hits: "dict[int, list[str]]" = {}
    for tid in tech_ids:
        for actor in _ACTOR_BY_TECH.get(tid, ()):
            actor_hits.setdefault(id(actor), []).append(tid)
    matched = []
    for actor in ACTORS:
        hits = actor_hits.get(id(actor))
        if not hits:
            continue
        score = round(len(hits) / n_alert * 100)
        matched.append({**actor, "matchedTechniques": hits, "score": score})
    matched.sort(key=lambda x: x["score"], reverse=True)
    return [_enrich_actor_with_cross_walk(a) for a in matched[:5]]


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
    """Annotate each matched actor with:
      * evidence_by_technique — what in THIS log matched each TTP
      * ttps_to_look_for      — { before, after, all_count } showing this
        actor's full known TTP list bucketed by kill-chain position
        relative to the matched evidence. Lets the AttributionChip render
        "look for X before this alert" / "look for Y after this alert"
        hunt guidance specific to this actor's playbook.
    """
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
    # Lazy import — only loads the heavy MITRE STIX bundle when there are
    # actually matched actors to enrich.
    try:
        from intel.mitre_data import get_actor_ttps_by_phase
    except Exception:
        get_actor_ttps_by_phase = None  # type: ignore

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

        # Full TTP list bucketed by phase. mitre_id may be empty on the
        # hardcoded ACTORS fallback; the helper returns empty buckets in
        # that case and the UI just hides the section.
        actor_mid = actor.get("mitre_id") or actor.get("id") or ""
        if get_actor_ttps_by_phase and actor_mid:
            try:
                actor["ttps_to_look_for"] = get_actor_ttps_by_phase(
                    actor_mid, [str(t).strip().upper() for t in matched_tids],
                )
            except Exception:
                actor["ttps_to_look_for"] = {"before": [], "after": [],
                                              "matched": [], "all_count": 0}
        else:
            actor["ttps_to_look_for"] = {"before": [], "after": [],
                                          "matched": [], "all_count": 0}
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

    # Map of "T1059.001" -> "attack-pattern--<uuid>" so the Attack Flow
    # overlay below can link to the same attack-pattern objects instead
    # of duplicating them.
    attack_pattern_index: dict[str, str] = {}
    technique_labels = investigation.get("mitre_techniques", []) or []
    for t in technique_labels:
        parts = t.split(" - ")
        ap_id = f"attack-pattern--{uuid.uuid4()}"
        objects.append({"type": "attack-pattern", "spec_version": "2.1", "id": ap_id,
                        "created": now, "modified": now,
                        "name": parts[1] if len(parts) > 1 else t,
                        "external_references": [{"source_name": "mitre-attack",
                                                 "external_id": parts[0],
                                                 "url": f"https://attack.mitre.org/techniques/{parts[0].replace('.', '/')}/"}]})
        attack_pattern_index[parts[0]] = ap_id

    # Attack Flow overlay (CTID STIX 2.1 extension) — sequenced view of the
    # techniques, openable directly in the CTID Attack Flow Builder.
    if technique_labels:
        try:
            from intel.attack_flow import build_attack_flow_objects
            objects.extend(build_attack_flow_objects(
                identity_id=identity_id,
                technique_labels=technique_labels,
                attack_pattern_index=attack_pattern_index,
                investigation=investigation,
            ))
        except Exception as e:
            # The Attack Flow overlay is additive — never block the base
            # STIX export when the builder hiccups.
            import logging as _logging
            _logging.getLogger("recon.response").warning(
                "Attack Flow overlay skipped: %s", e)

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
    """Returns the configured LLMProvider, or None when the active
    provider doesn't have the credentials it needs. Kept for backwards
    compat — the function name is a holdover; it returns an LLMProvider,
    not an SDK client. Delegates the per-provider key check to the
    shared providers.provider_configured() helper."""
    try:
        from providers import get_provider, provider_configured
        if not provider_configured(config):
            return None
        return get_provider()
    except Exception:
        return None


async def _ai_call_json(prompt: str, config, max_tokens: int = 1400,
                         on_partial=None) -> dict:
    """Fast-tier JSON completion with optional streaming.

    When `on_partial` is provided, the call switches to streaming mode:
    each chunk arrival triggers a truncation-tolerant re-parse and calls
    on_partial(dict) with whatever fields are already complete. The
    frontend can render disposition + reason live as they arrive instead
    of waiting 5-10s for the full response.
    """
    provider = _make_client(config)
    if not provider:
        return {}
    from agents.investigation import _loads_lenient

    if on_partial is None:
        # Legacy non-streaming path — kept for callers that don't wire SSE.
        resp = await provider.complete(
            model=config.get_model(fast=True),
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=0.1,
            response_format={"type": "json_object"},
        )
        if resp.error:
            return {}
        return _loads_lenient(resp.message)

    # Streaming path — accumulate deltas, re-parse periodically, emit
    # partial dicts through on_partial. Throttle to at most one emit
    # every 6 chunks so we don't fire 500 partials for a 700-token
    # response.
    accumulated = []
    last_emit_at = 0
    try:
        async for chunk in provider.stream(
            model=config.get_model(fast=True),
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=0.1,
            response_format={"type": "json_object"},
        ):
            if chunk.error:
                break
            if chunk.delta_text:
                accumulated.append(chunk.delta_text)
                if len(accumulated) - last_emit_at >= 6:
                    last_emit_at = len(accumulated)
                    partial = _loads_lenient("".join(accumulated))
                    if isinstance(partial, dict) and partial:
                        try:
                            await on_partial(partial)
                        except Exception as _e:
                            _log.debug("analyst_summary on_partial failed: %s", _e)
    except Exception as _e:
        _log.warning("analyst_summary stream failed, falling back: %s", _e)
        # Streaming path failed — fall back to non-streaming completion
        # so the analysis still lands.
        resp = await provider.complete(
            model=config.get_model(fast=True),
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=0.1,
            response_format={"type": "json_object"},
        )
        if resp.error:
            return {}
        return _loads_lenient(resp.message)
    return _loads_lenient("".join(accumulated))


async def run_response(state: dict, on_event=None) -> dict:
    """Response synthesis stage.

    on_event(entry) — optional streaming callback the orchestrator wires
    into the SSE writer. Enables progressive rendering of the analyst
    summary (disposition + reason appear as the LLM emits them, rather
    than the analyst waiting 5-10s for the full JSON to land).
    """
    from config import config
    from gti_score import compute_gti_scores
    import time
    _t_start = time.perf_counter()

    investigation = state.get("investigation_result", {})
    iocs = state.get("iocs", {})
    threat_level = state.get("threat_level", "MEDIUM")
    mitre = state.get("mitre_techniques", [])
    trace = state.get("agent_trace", [])

    # GTI scores are a function of the enrichment data — compute them once
    # here so every caller of run_pipeline() (sync analyze, MCP, future
    # tests) gets the same shape on the returned state. The streaming
    # /api/analyze path computes a provisional gti_scores after enrichment
    # for the partial-result event; this is the final authoritative pass.
    gti_scores = compute_gti_scores(state.get("enrichments", {}))

    summary = investigation.get("summary", "")
    # Strip em / en dashes from the AI summary — the analyst-facing Summary
    # card renders this in plain prose alongside the disposition reason,
    # both of which look "AI-written" with em dashes scattered through.
    try:
        from intel.email_composer import _strip_em_dashes as _ed
        summary = _ed(summary) if isinstance(summary, str) else summary
    except Exception:
        pass
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

    # Pull any analyst commentary out of the raw input so the disposition
    # prompt can treat it as ground truth alongside the AI's own summary.
    # The analyze textarea now accepts logs + analyst notes interleaved; we
    # heuristically separate the operator's prose from the log payload by
    # looking for natural-language framing markers at the top of the input.
    _raw_full = (state.get("raw_input_clean") or state.get("raw_input") or "").strip()
    _operator_note = ""
    # Markers analysts commonly use to introduce commentary in the textbox.
    _marker = None
    for m in (
        "i think ", "i believe ", "we think ", "we believe ", "analyst note:",
        "analyst:", "context:", "fyi:", "note:", "this is ", "this looks like ",
        "we are ", "we're ", "this should be ",
    ):
        _idx = _raw_full.lower().find(m)
        if 0 <= _idx <= 300:   # only count framing in the FIRST 300 chars
            _marker = _idx
            break
    if _marker is not None:
        # Pull everything up to the first newline-after-log-keyword OR the
        # next obvious log line as the operator's commentary.
        _trailing = _raw_full[_marker:]
        # Stop at "User:" / "Date:" / "EventID" / "Process " / "Path " /
        # JSON brace / blank line — the first thing that looks like log
        # content terminates the commentary block.
        import re as _re
        _stop = _re.search(
            r"\n\s*("
            r"User\s*:|UserName\s*:|Date\s*[:=]|Event\s*ID|Policy\s+ID|"
            r"Process\s+(Path|Name|ID)|Path\s*:|Action\s+Type\s*:|"
            r"Full\s+Path\s*:|SHA256\s*:|TimeGenerated\b|\{|\["
            r")",
            _trailing,
            _re.IGNORECASE,
        )
        if _stop:
            _operator_note = _trailing[:_stop.start()].strip()
        else:
            # Bound to the first 600 chars to keep the prompt slot small.
            _operator_note = _trailing[:600].strip()

    # Ground-truth lookup of WHICH source flagged WHICH IOC — pulled from
    # the deterministic enrichment summary. The analyst_prompt cites these
    # verbatim so it cannot hallucinate "VirusTotal + MalwareBazaar
    # corroborated this hash" when actually only AbuseIPDB flagged the IP.
    _enr_sum = investigation.get("enrichment_summary") or {}
    _flagged_map = (_enr_sum.get("flagged_per_ioc") or {})
    _enr_line    = (_enr_sum.get("line") or "").strip()

    # Deterministic tier bucketing — computed BEFORE the LLM sees the
    # evidence pack so the model can't rationalise a CLEAR when a
    # TIER 1 signal is present. See intel/signal_priority.py.
    try:
        from intel.signal_priority import (
            extract_tier_signals as _extract_tiers,
            format_signal_correlation as _format_correlation,
        )
        _tier_signals = _extract_tiers({
            **state,
            "investigation_result": investigation,
            "response_summary": {  # partial — case_score not built yet
                "cross_refs":    rs_cross,
                "matched_actors": matched_actors,
                "malware_family": investigation.get("malware_family")
                                  or state.get("malware_family"),
            },
        })
        _correlation_prose = _format_correlation(state, _tier_signals)
    except Exception as _e:
        _log.warning("signal_priority extraction failed: %s", _e)
        _tier_signals = {"tier_1": [], "tier_2": [], "tier_3": [],
                         "downweight": [], "verdict_floor": threat_level,
                         "block_clear": False}
        _correlation_prose = ""

    evidence_pack = {
        "alert_text_first_300": (state.get("raw_input_clean") or state.get("raw_input") or "")[:300],
        # Analyst commentary the operator typed in the analyze textbox
        # (mixed inline with the log). Authoritative — the AI must respect
        # this when picking disposition.
        "operator_analyst_note": _operator_note,
        # AUTHORITATIVE source→IOC flag map. The ONLY pairs the AI is
        # allowed to cite as "<source> flagged <ioc>". If a pair isn't
        # in this dict it didn't happen.
        "ground_truth_flagged":  _flagged_map,
        "enrichment_summary":    _enr_line,
        # Signal tier framework — the LLM MUST read this first. If
        # tier_1 is non-empty, CLEAR is blocked deterministically.
        "signal_tier_1_present":  [s["signal"] for s in _tier_signals["tier_1"]],
        "signal_tier_2_present":  [s["signal"] for s in _tier_signals["tier_2"]],
        "signal_tier_3_present":  [s["signal"] for s in _tier_signals["tier_3"]],
        "signal_downweight":      [s["signal"] for s in _tier_signals["downweight"]],
        "signal_verdict_floor":   _tier_signals["verdict_floor"],
        "signal_block_clear":     _tier_signals["block_clear"],
        "key_findings":          investigation.get("key_findings", [])[:6],
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
    _note_block = (
        f"\nOPERATOR ANALYST NOTE (the analyst typed this in the input):\n"
        f"  \"{_operator_note}\"\n"
        f"\n"
        f"  How to handle this note:\n"
        f"   * ACKNOWLEDGE it in disposition_reason. Quote or paraphrase\n"
        f"     the analyst's framing so they can see you read it.\n"
        f"   * Factor it into your decision — the analyst usually has\n"
        f"     environmental context the enrichment data lacks (sanctioned\n"
        f"     tools, scheduled work, approved exceptions).\n"
        f"   * If you AGREE, lean toward CLEAR / lower disposition and\n"
        f"     cite the analyst's note as one of the reasons.\n"
        f"   * If you DISAGREE — i.e. the evidence still points to a real\n"
        f"     threat despite their framing — state that explicitly and\n"
        f"     name the SPECIFIC evidence that overrides the analyst's\n"
        f"     context (named-malware hit, KEV-listed CVE actively exploited,\n"
        f"     credential access, lateral movement, > 5 VT detections from\n"
        f"     independent reputable engines, etc.).\n"
        f"   * Do NOT silently ignore the note. Do NOT pick MONITOR just\n"
        f"     because 'context is unclear' — the analyst already gave it.\n"
        if _operator_note else ""
    )
    # Palantir Alerting and Detection Strategy (ADS) section outline —
    # injected as guardrails so the prose follows a recognisable industry
    # structure rather than ad-hoc paragraphs.
    try:
        from intel.ads_framework import ads_section_outline as _ads_outline
        _ads_block = "\n" + _ads_outline() + "\n"
    except Exception:
        _ads_block = ""

    analyst_prompt = f"""You are a senior MDR analyst (5+ years, T2/T3 escalation lead) writing the
final INTERNAL DISPOSITION for a SOC investigation (for the next-tier analyst / shift
lead). Be CONCISE throughout. Tight sentences, no padding; keep each list to its
most important 2-3 items.
{_ads_block}

You must base every claim on SPECIFIC evidence from the investigation. Do not
invent. Do not be vague. "Suspicious activity detected" is FORBIDDEN. Say what
activity, on what indicator, with what corroborating evidence.

{_CAL}
{_note_block}
══════════════════════════════════════════════════════════════════════════════════
INPUT - investigation evidence pack
══════════════════════════════════════════════════════════════════════════════════
Threat Level (AI verdict)  : {threat_level}
Confidence (0-1)           : {state.get('confidence', 0.0)}
One-line summary           : {summary}
MITRE techniques mapped    : {mitre_str}

══════════════════════════════════════════════════════════════════════════════════
SIGNAL PRIORITY LADDER — READ THIS BEFORE PICKING DISPOSITION
══════════════════════════════════════════════════════════════════════════════════
The tier framework below was computed DETERMINISTICALLY from the raw log +
enrichment data, BEFORE you saw the evidence. It represents the strongest
signals fired, ranked by their verdict weight. Your disposition MUST respect
the verdict floor and the block_clear flag — those are not suggestions, they
are the codified analyst calibration.

{_correlation_prose if _correlation_prose else "  (no significant signals fired — evidence is thin)"}

══════════════════════════════════════════════════════════════════════════════════
CORRELATION APPROACH (this is where bad dispositions come from — do this right)
══════════════════════════════════════════════════════════════════════════════════
Answer these questions IN ORDER before you write disposition_reason:

  1. Which TIER 1 signals fired?            → those set the verdict floor
  2. Which TIER 2 signals corroborate?      → those raise confidence
  3. Which DOWNWEIGHT signals fired?        → only relevant when no TIER 1/2
  4. Do the tiers align or conflict?
        * All point same direction → high-confidence verdict
        * TIER 1 fires + DOWNWEIGHT fires → TIER 1 WINS. The downweight
          reasons are not enough to overrule a nation-state / KEV /
          malware-family / cred-access / MFA-bypass finding.
        * No TIER 1/2, only DOWNWEIGHT → lean CLEAR/MONITOR
  5. Match your disposition to the strongest tier fired:
        * Any TIER 1     → ESCALATE (or MONITOR only if signal_block_clear
                            is False AND the log itself only marked
                            "Medium" risk)
        * ≥2 TIER 2      → ESCALATE
        * 1 TIER 2       → ESCALATE if no downweight; MONITOR otherwise
        * Only TIER 3    → MONITOR or CLEAR (context, not verdict)
        * DOWNWEIGHT only→ CLEAR

Evidence pack (raw JSON — refer to the tier ladder above for the correlated
view; use the JSON to pull specific evidence values to cite):
{json.dumps(evidence_pack, indent=2)[:3500]}

══════════════════════════════════════════════════════════════════════════════════
DISPOSITION DECISION TREE
══════════════════════════════════════════════════════════════════════════════════

HARD OVERRIDES — these BLOCK a CLEAR disposition regardless of anything else
in the evidence pack. Check them FIRST. If any fire, disposition MUST be
ESCALATE (or MONITOR when the log lists it as "medium risk"):

  1. LOG CONTENT NAMES A NATION-STATE OR TRACKED ACTOR
       Watch for: Storm-####, APT##, UNC####, TA####, FIN##, Lazarus,
       Sandworm, Cozy Bear, Midnight Blizzard, Fancy Bear, Turla,
       "nation-state", "state-sponsored", "state actor", "threat actor
       associated with…". These labels are the SIEM's or the source
       system's OWN attribution (Microsoft Storm-####, Mandiant APT##,
       etc.) — they represent PROPRIETARY threat intel the model has no
       basis to override with public TI (VirusTotal, AbuseIPDB, OTX).
       A "clean IP reputation" from VT/AbuseIPDB does NOT rebut a
       Storm-#### attribution — VT simply doesn't have Microsoft's
       tracking data. CLEAR is FORBIDDEN. Escalate.

  2. THE SOURCE LOG ITSELF MARKED THE RISK AS HIGH / CRITICAL
       Watch for: "High risk", "Critical risk", "Risk level: high",
       "High-severity alert", risk_score >= 8/10, MITRE Sentinel
       "Attempted / Successful atypical travel", Defender for Identity
       "High risk sign-in". The upstream detection engine already had
       information you don't (user's baseline, tenant-wide sign-in
       patterns, historical device/IP context). Do not downgrade a
       high-risk finding to CLEAR based on public IP reputation alone.
       CLEAR is FORBIDDEN. Escalate or Monitor.

  3. CONFIRMED IDENTITY-LAYER COMPROMISE INDICATORS
       Watch for: MFA bypass, session token replay, impossible travel,
       new device from an unusual country, atypical user-agent (empty
       UA, curl/PowerShell UA on a browser-only sign-in flow), atypical
       protocol (legacy auth on a modern tenant), password spray hits.
       These are attack primitives, not "just a login". Escalate.

If none of the above fire, use the normal decision tree:

  * CLEAR    -> only if you can cite a specific reason it is benign
                  (known-good library hit, MISP warninglist match,
                   well-known infrastructure, legitimate corporate
                   service, clean hash across every TI source, scheduled
                   vendor maintenance). When the threat_level above is
                   INFORMATIONAL/LOW and the evidence supports benign,
                   default to CLEAR. When the operator's note frames the
                   activity as routine / approved / a sanctioned tool AND
                   nothing in the enrichment contradicts that, lean CLEAR
                   and quote the analyst's framing in disposition_reason.
  * MONITOR  -> suspicious but not actionable yet; specify the trigger that
                  would escalate.
  * ESCALATE -> real-world threat with concrete corroborating evidence (at
                  least one item from the EVIDENCE STANDARD above); give
                  concrete next steps. When the operator's note disagreed
                  with this verdict, name the specific evidence that
                  overrides their framing.

COHERENCE RULES (this is where most bad dispositions come from):

  * Do not concatenate a "the log says X is bad" paragraph with a
    separate "the IOCs look clean" paragraph and then pick either
    conclusion. RESOLVE the conflict in ONE sentence. Rule of thumb:
    upstream detection wins over public IP/domain reputation, because
    public TI doesn't have the upstream system's private telemetry.

  * If your prose mentions "nation-state", "actor associated with",
    "high risk", "atypical", "unusual", "suspicious" — the disposition
    MUST be ESCALATE or MONITOR. It cannot be CLEAR while your own
    prose contradicts the verdict.

  * Do not write "clean reputation" or "no malicious activity" as a
    reason to CLEAR when the log content ITSELF flagged the event.
    Public TI sources not flagging an IP does not mean the log's
    detection was wrong; it means public TI didn't independently
    confirm it (which is normal and expected).

══════════════════════════════════════════════════════════════════════════════════
RESPOND with this EXACT JSON (no markdown fences, no commentary):
══════════════════════════════════════════════════════════════════════════════════
{{
  "disposition":        "ESCALATE|CLEAR|MONITOR",
  "disposition_reason": "<2-3 sentences of flowing prose. The Summary card
                          renders this DIRECTLY AFTER the AI's main summary
                          paragraph as part of one analyst-readable narrative —
                          so do NOT repeat what the summary already said, do
                          NOT lead with phrases like 'This alert is ESCALATE
                          because' (the disposition chip above the paragraph
                          already says that). Add NEW information beyond the
                          summary: cite at least TWO specific evidence items
                          from the pack ('EPSS 94% on the matched KEV CVE',
                          'domain registered 4h ago + EvilProxy URL pattern',
                          'process matches Dell SupportAssist known-good
                          pattern + hash clean across all sources') and weave
                          them into prose that naturally continues the
                          summary. Active voice, no em dashes, no
                          'Recommended action:' prefix.>",
  "clear_justification":"<If CLEAR: cite the specific signal that makes this
                          benign. If MONITOR/ESCALATE: state 'Not a false
                          positive:' then explain why benign-signal hypotheses
                          were ruled out.>",
  "escalation_steps":   [
    "<concrete step (only when ESCALATE) - e.g. 'Query Entra ID sign-in logs
      for user X 24h back'>",
    "<another>",
    "<another>"
  ],
  "intelligence_gaps": [
    "<one-line gap: what evidence you would need to make a higher-confidence
      verdict. e.g. 'No process-tree captured — would need EDR telemetry
      from the host to confirm whether powershell.exe spawned regsvr32.exe.'
      List 2-4 gaps. Empty list when the evidence is complete and you stand
      fully behind the verdict.>",
    "<another>"
  ],
  "analyst_caveats": [
    "<one-line methodology caveat: assumptions, source-reliability limits,
      time-bounded data freshness. e.g. 'OTX pulse count includes researcher
      pulses, not just confirmed compromises.' or 'AbuseIPDB scores are
      report-count-weighted and lag behind fresh campaigns by hours.' List
      1-3 caveats analysts should know about your reasoning. Empty list when
      the data is well-corroborated and no caveats apply.>",
    "<another>"
  ]
}}

Every disposition_reason and clear_justification claim must trace back to the
evidence pack. No generic phrasing. No hedging with 'potential misuse' when
the evidence points to benign activity.

SOURCE CITATION TRUTH RULES (read carefully — analysts catch this):
* "ground_truth_flagged" in the evidence pack is the ONLY authoritative
  source→IOC flag map. Each key is an IOC value; each value is the list
  of sources that flagged it. If you want to write "<Source> flagged
  <ioc>", the (source, ioc) pair MUST appear in that map.
* DO NOT write composite citations like "(MalwareBazaar, VirusTotal)"
  or "corroborated by multiple sources" unless ground_truth_flagged
  actually shows multiple sources for the same IOC.
* DO NOT name a hash as "flagged by X" when the only flagged IOC in the
  map is an IP or domain.
* If ground_truth_flagged is empty AND the threat_level is still
  HIGH/CRITICAL because of behavioural evidence (KEV CVE, named
  malware family in the AI summary, lateral movement pattern), CITE THAT
  evidence by name (e.g. "vssadmin shadow-copy deletion + ransom-note
  drop"). Don't fabricate TI sources to justify the verdict.

PROSE STYLE: do NOT use em dashes (—) or en dashes (–) anywhere in the
output. Use commas, periods, or restructure the sentence instead. The
analyst's UI strips them out, so writing them is wasted tokens."""

    # ── DETERMINISTIC CLEAR FAST-PATH ─────────────────────────────────────
    # When the tier framework says the alert is unambiguously benign, we
    # can skip the analyst_summary LLM call entirely (saves ~5-10s per
    # alert). Trigger conditions:
    #   * verdict_floor = INFORMATIONAL or LOW
    #   * threat_level  = INFORMATIONAL or LOW
    #   * no TIER 1 or TIER 2 signals fired
    #   * at least one DOWNWEIGHT signal fired
    #   * no operator analyst note (analyst text needs the LLM to ACK it)
    #   * no analyst feedback re-run (re-runs must respect analyst input)
    _floor_benign = (_tier_signals.get("verdict_floor") or "").upper() in ("INFORMATIONAL", "LOW")
    _tl_benign    = (threat_level or "").upper() in ("INFORMATIONAL", "LOW")
    _no_pos_sigs  = not _tier_signals.get("tier_1") and not _tier_signals.get("tier_2")
    _has_downwt   = bool(_tier_signals.get("downweight"))
    _no_notes     = not (_operator_note or state.get("analyst_feedback"))
    _fast_path    = (_floor_benign and _tl_benign and _no_pos_sigs
                     and _has_downwt and _no_notes)

    if _fast_path:
        _t_saved = time.perf_counter()
        _dw_reasons = "; ".join(
            (s.get("signal") if isinstance(s, dict) else str(s))
            for s in _tier_signals["downweight"][:2]
        )
        # Synthesised disposition mirrors the shape the LLM would have
        # returned so downstream defensive coercion + rendering paths
        # keep working identically.
        analyst_summary = {
            "disposition":         "CLEAR",
            "disposition_reason":  (
                f"Deterministic verdict: tier framework classified this as "
                f"informational activity. Downweight signals: {_dw_reasons}. "
                f"No verdict-determining or corroborating tier signals fired."
            ),
            "escalation_steps":    [],
            "intelligence_gaps":   [],
            "analyst_caveats":     [
                "Verdict produced by deterministic tier framework rather "
                "than LLM analysis. If this alert's context differs from a "
                "routine known-good pattern, re-analyze with an analyst note."
            ],
        }
        _log.info("response.fast_path skip: saved LLM call (%.2fs elapsed to gate)",
                  time.perf_counter() - _t_saved)
        # Emit the deterministic verdict immediately so the UI lands the
        # disposition without waiting for the remaining downstream work
        # (STIX build, JA3 lookup, GTI compute, etc.). Same channel the
        # streaming path uses, so the frontend needs no new event
        # handler.
        if on_event:
            try:
                await on_event({
                    "type":             "analyst_summary_partial",
                    "analyst_summary":  analyst_summary,
                })
            except Exception as _e:
                _log.debug("fast_path partial emit failed: %s", _e)
    else:
        # Detection content (Sigma/KQL/multi-SIEM) is generated ON DEMAND from the UI
        # via /api/detection — it's the slowest part of this stage and isn't needed on
        # every alert. Here we only generate the analyst Summary (the verdict hand-off),
        # which keeps the response stage to a single AI call. The trimmed schema (no
        # client email / IR playbook — neither is shown in the UI) needs little headroom.
        #
        # Streaming — when the orchestrator wired an on_event callback,
        # emit partial analyst_summary dicts as tokens arrive so the
        # frontend can render the disposition + reason live.
        _partial_cb = None
        if on_event:
            async def _emit_partial(partial: dict):
                await on_event({
                    "type":             "analyst_summary_partial",
                    "analyst_summary":  partial,
                })
            _partial_cb = _emit_partial
        analyst_summary = await _ai_call_json(
            analyst_prompt, config, max_tokens=700, on_partial=_partial_cb
        )

    # DISPOSITION SAFETY NET — the belt-and-braces enforcement of the
    # tier framework in intel/signal_priority.py. Even with the prompt-
    # level guardrails, LLMs sometimes still emit CLEAR when a TIER 1
    # signal fired. Force-upgrade CLEAR → ESCALATE and stamp a machine-
    # readable reason on override_reason so the analyst can see why.
    # This is what actually stops the "Storm-#### signed in, clean IP,
    # safe to clear" contradiction from reaching production.
    try:
        if isinstance(analyst_summary, dict) \
                and analyst_summary.get("disposition") == "CLEAR" \
                and _tier_signals.get("block_clear"):
            from intel.signal_priority import should_block_clear as _should_block
            _blocked, _reason = _should_block({
                **state,
                "investigation_result": investigation,
                "response_summary": {
                    "cross_refs":    rs_cross,
                    "matched_actors": matched_actors,
                    "malware_family": investigation.get("malware_family")
                                      or state.get("malware_family"),
                },
            })
            if _blocked:
                original_reason = analyst_summary.get("disposition_reason", "")
                analyst_summary["disposition"] = "ESCALATE"
                analyst_summary["disposition_reason"] = (
                    f"AUTO-OVERRIDE: model recommended CLEAR but "
                    f"{_reason} Upgraded to ESCALATE. "
                    f"Model's original reason: {original_reason[:400]}"
                )
                analyst_summary["safety_net_override"] = _reason
                _log.warning("disposition safety net fired: CLEAR → ESCALATE (%s)",
                             _reason)
    except Exception as _e:
        _log.debug("disposition safety net failed: %s", _e)

    # Strip em / en dashes from every prose field the analyst will read in
    # the Summary card. The AI tends to insert " — " between clauses; the
    # CLAUDE.md convention is to avoid em dashes in user-facing strings
    # because they signal "AI wrote this". Reuse the helper that already
    # handles this for email composer output.
    try:
        from intel.email_composer import _strip_em_dashes
        if isinstance(analyst_summary, dict):
            for _k in ("disposition_reason", "clear_justification"):
                _v = analyst_summary.get(_k)
                if isinstance(_v, str):
                    analyst_summary[_k] = _strip_em_dashes(_v)
            _steps = analyst_summary.get("escalation_steps")
            if isinstance(_steps, list):
                analyst_summary["escalation_steps"] = [
                    _strip_em_dashes(s) if isinstance(s, str) else s
                    for s in _steps
                ]
    except Exception:
        pass
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
    # Hoist alert_type out of the try block so it stays defined when the
    # ja_fingerprints import fails. response_summary below reads it and
    # we don't want a UnboundLocalError swallowing the whole stage.
    alert_type = next(
        (t.get("alert_type", "") for t in (state.get("agent_trace") or [])
         if t.get("agent") == "triage"),
        "",
    )
    ja_fingerprints = []
    ja_sigma_snippet = ""
    ja_kql_snippet = ""
    try:
        from intel.ja_fingerprints import (
            get_for_alert_type, get_for_mitre,
            as_sigma_yaml_snippet, as_kql_snippet,
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
        # analyst_notes is part of the AI investigation prompt output
        # (1-2 paragraphs of senior-analyst context). Was missing from
        # response_summary, so the UI block reading rs.analyst_notes
        # silently never rendered.
        "analyst_notes":       investigation.get("analyst_notes", ""),
        # alert_type lives in the triage trace entry; surface it on
        # response_summary so the frontend doesn't have to walk the
        # trace array to find it.
        "alert_type":          alert_type or "unknown",
        # malware_family lifted out of investigation.get so the frontend
        # can read rs.malware_family directly without falling back to
        # the top-level state field.
        "malware_family":      investigation.get("malware_family") or state.get("malware_family"),
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
        # Signal tier bucketing — deterministic reasoning surface. The
        # frontend renders a chip strip so the analyst sees the WHY
        # (named-actor + upstream high-risk vs. warninglist + signed
        # browser) in 2 seconds without reading the AI prose.
        "signal_tiers":        {
            "tier_1":        _tier_signals.get("tier_1")     or [],
            "tier_2":        _tier_signals.get("tier_2")     or [],
            "tier_3":        _tier_signals.get("tier_3")     or [],
            "downweight":    _tier_signals.get("downweight") or [],
            "verdict_floor": _tier_signals.get("verdict_floor") or threat_level,
            "block_clear":   bool(_tier_signals.get("block_clear")),
        },
    }

    # Case-level rollup score with letter grade + recency multipliers.
    # Lives alongside the per-IOC gti_scores so analysts can drill in
    # both ways — case-level grade for verdict-at-a-glance, per-IOC for
    # the drill-down. Adapted from cti-expert (MIT).
    try:
        from intel.case_score import compute as _compute_case_score
        # We DO have the {**state} dict by the time we land here; pass
        # it through. observation_ts defaults to "now" which means a
        # freshly analyzed alert gets the recency boost (intended for
        # live SOC traffic). Historical replay should override later.
        response_summary["case_score"] = _compute_case_score({
            **state,
            "response_summary": response_summary,
        })
    except Exception as _e:
        # Never let the rollup take down the whole response — the score
        # is a nice-to-have, not load-bearing.
        pass

    # Defensive coercion — every field below is LLM-emitted into the
    # `investigation` dict and the model occasionally ships them as a
    # string or dict instead of an array. The frontend's AnalystSummary
    # card does `.filter` on these and crashes when the shape is wrong.
    # `.get(..., [])` only protects against `None`; a returned string is
    # truthy and slips through. Force-coerce here so the SSE-streamed
    # payload always carries the expected shape.
    _ARRAY_FIELDS = (
        "key_findings", "ioc_assessments", "mitre_techniques",
        "attack_patterns", "recommended_actions", "geo_highlights",
        "chain_of_thought", "pyramid_of_pain", "evidence_ratings",
        "probing_questions", "assessment_basis", "confirmed_facts",
        "analysis_assessment", "matched_actors", "atomic_examples",
        "mitre_evidence",
    )
    # Round-15 — also coerce intelligence_gaps + analyst_caveats inside
    # the nested analyst_summary dict (adapted from cti-expert INTSUM
    # template). LLM occasionally returns them as a single string or
    # nested dict; the React renderer's `.map()` would crash.
    if isinstance(analyst_summary, dict):
        # escalation_steps added to this coercion — the frontend Next
        # Steps block calls .filter() on it, which crashes on non-array
        # values. LLM occasionally emits a single string here when the
        # model condenses the list.
        for _k in ("intelligence_gaps", "analyst_caveats", "escalation_steps"):
            _v = analyst_summary.get(_k)
            if isinstance(_v, list):
                continue
            if isinstance(_v, str) and _v.strip():
                analyst_summary[_k] = [_v.strip()]
            else:
                analyst_summary[_k] = []
    for _k in _ARRAY_FIELDS:
        _v = response_summary.get(_k)
        if isinstance(_v, list):
            continue
        if isinstance(_v, str):
            _trimmed = _v.strip()
            response_summary[_k] = [_trimmed] if _trimmed else []
        elif _v is None:
            response_summary[_k] = []
        else:
            # Dict / int / bool — drop to empty rather than crash the UI
            response_summary[_k] = []

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
        "gti_scores":       gti_scores,
        "agent_trace":      trace,
    }
