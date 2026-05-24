"""
Deep AI analysis engine for the file scanner — spec §1 of the deep-analyst plan.

Two phases per scan:
  1. triage_classify(analysis, config)  — fast classification into one of
     ~18 malware-family categories. Returns within ~3-5 seconds. Lets the
     UI render a verdict badge while the deep pass is still in flight.

  2. analyze_deep(analysis, config, comparative_context=None) — full
     senior-analyst structured assessment. Returns a 15-field JSON object
     with executive / technical / execution-narrative summaries, attribution,
     anomalies, evasion + persistence findings, C2 assessment, detection
     difficulty, recommended actions grouped by timeframe, hunting leads,
     clarifying questions, and an honest confidence statement.

Both use the Azure-aware OpenAI client pattern used everywhere else in the
codebase.  Both fail open — returning None / a sentinel error dict rather
than raising — so the scan still returns its other fields if the AI is
unavailable.

`gather_comparative_context` pulls related cases + similar fuzzy-hash
samples + the MITRE actor profile if a family was identified, and is
spliced into the deep-analysis prompt so the model has prior-history
context to reason against.
"""

from __future__ import annotations
import json
from typing import Optional, Dict, List


# ─── classification labels (kept in sync between prompts + UI badges) ──────────
CLASSIFICATIONS = [
    "Clean",
    "Potentially Unwanted Program",
    "Adware",
    "Dropper",
    "Downloader",
    "RAT or Backdoor",
    "Ransomware",
    "Keylogger",
    "Infostealer",
    "Worm",
    "Rootkit",
    "Bootkit",
    "Exploit",
    "Shellcode",
    "Packer or Crypter",
    "Lateral Movement Tool",
    "Credential Dumper",
    "Reconnaissance Tool",
    "Unknown Malware",
]

SOPHISTICATION_LEVELS = [
    "Script Kiddie",
    "Commodity Malware",
    "Capable Threat Actor",
    "Nation State Actor",
]

DETECTION_DIFFICULTY = ["Easy", "Moderate", "Difficult", "Very Difficult"]


# ─── OpenAI client (Azure-aware) ──────────────────────────────────────────────
def _client(config):
    key = config.get("OPENAI_API_KEY")
    if not key:
        return None, None
    try:
        from openai import AsyncAzureOpenAI, AsyncOpenAI
    except ImportError:
        return None, None
    base_url = config.get("OPENAI_BASE_URL", "")
    model    = config.get("AI_MODEL", "gpt-4o-mini")
    if "openai.azure.com" in base_url:
        return AsyncAzureOpenAI(api_key=key, azure_endpoint=base_url.rstrip("/"),
                                api_version="2024-02-01"), model
    return AsyncOpenAI(api_key=key, base_url=base_url or "https://api.openai.com/v1"), model


# ─── Phase 1 — rapid triage classification ─────────────────────────────────────
_TRIAGE_SYSTEM = f"""You are a senior malware triage analyst. You receive
high-signal indicators from a static file scan and must classify the sample
into exactly ONE category within seconds. Do not analyze deeply — that runs
separately. Output strict JSON only.

Categories (pick exactly one):
{', '.join(CLASSIFICATIONS)}

Output schema:
  {{
    "classification": "<one of the categories>",
    "confidence": <float 0.0-1.0>,
    "reasoning": "<one short sentence — the single strongest signal that drove this>"
  }}

No markdown. No commentary. JSON only."""


def _triage_context(analysis: Dict) -> Dict:
    """Smallest viable signal set for triage."""
    fs = analysis.get("format_specific") or {}
    pe = fs.get("pe") or {}
    yara = analysis.get("yara_matches") or []
    sus = [s.get("pattern") for s in (analysis.get("suspicious_strings") or [])][:10]
    iocs = analysis.get("iocs") or {}
    vt = ((analysis.get("threat_intel") or {}).get("virustotal") or {})
    return {
        "type":              (analysis.get("type") or {}).get("detected_mime"),
        "size":              analysis.get("size"),
        "entropy":           (analysis.get("entropy") or {}).get("overall"),
        "entropy_band":      (analysis.get("entropy") or {}).get("band"),
        "yara_match_names":  [m.get("rule") for m in yara if isinstance(m, dict)][:10],
        "yara_match_count":  len([m for m in yara if isinstance(m, dict) and not m.get("error")]),
        "suspicious_patterns": sus,
        "vt_detection_ratio": vt.get("detection_ratio"),
        "vt_malware_family":  vt.get("malware_family"),
        "vt_tags":            vt.get("tags"),
        "flagged_import_categories": list((pe.get("flagged_imports") or {}).keys()),
        "ioc_counts": {k: len(v) for k, v in iocs.items() if isinstance(v, list) and v},
        "static_verdict":    analysis.get("verdict"),
        "static_confidence": analysis.get("confidence"),
    }


async def triage_classify(analysis: Dict, config) -> Optional[Dict]:
    """Phase 1 — fast classification badge for the UI."""
    client, model = _client(config)
    if not client:
        return None
    try:
        resp = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": _TRIAGE_SYSTEM},
                {"role": "user",   "content": "Indicators:\n" +
                    json.dumps(_triage_context(analysis), indent=2)[:2500]},
            ],
            response_format={"type": "json_object"},
            temperature=0.0,
            max_tokens=200,
        )
        parsed = json.loads(resp.choices[0].message.content or "{}")
        cls = parsed.get("classification") or "Unknown Malware"
        # Defensive — coerce to a known label
        if cls not in CLASSIFICATIONS:
            for c in CLASSIFICATIONS:
                if c.lower() in cls.lower():
                    cls = c
                    break
            else:
                cls = "Unknown Malware"
        return {
            "classification": cls,
            "confidence":     float(parsed.get("confidence") or 0.5),
            "reasoning":      (parsed.get("reasoning") or "")[:240],
        }
    except Exception as e:
        return {"error": str(e)[:200]}


# ─── Phase 2 — deep analyst assessment ────────────────────────────────────────
_DEEP_SYSTEM = """You are a senior malware analyst and reverse engineer with 15
years of experience analyzing malware for a major antivirus vendor and government
CERT. You have analyzed hundreds of thousands of malware samples. You think like
a detective — you look for what is unusual, what does not fit, what the attacker
was trying to hide, and what the COMBINATION of indicators tells you that no
single indicator could reveal alone.

You have just received the complete static analysis, threat intelligence, and
behavioral assessment of a suspicious file. DO NOT simply restate what the tools
found. Synthesize the findings into insights. Explain what the combination of
indicators means. Identify what is unusual or notable about this specific sample.
Make definitive attributions when the evidence supports them and explain your
reasoning. Flag anything designed to mislead analysts.

Output STRICT JSON ONLY with this exact schema (every field present, no extras):
{
  "executive_summary":       "3-4 sentences for a CISO in plain English. No jargon. What is this file, what does it do, what risk does it pose, what should be done.",
  "technical_summary":       "2-3 paragraphs for a senior analyst. Architecture, how it achieves objectives, what makes this sample notable, comparison to similar known families.",
  "execution_narrative":     "3-4 paragraphs written like a story. Walk through what happens from execution to objective. Junior analyst should know what to look for in logs.",
  "malware_classification":  {"category": "<from the standard list>", "confidence": 0.0-1.0},
  "malware_family":          "<specific family name or null>",
  "variant":                 "<specific variant or null>",
  "threat_actor":            {"name": "<actor or null>", "confidence": 0.0-1.0} or null,
  "campaign":                "<campaign name or null>",
  "sophistication_level":    {"level": "<Script Kiddie|Commodity Malware|Capable Threat Actor|Nation State Actor>", "reasoning": "..."},
  "infection_vector":        "<most likely delivery mechanism>",
  "objectives":              [{"objective": "<plain English>", "evidence": "<what supports this>", "confidence": 0.0-1.0}, ...],
  "key_findings":            [{"title": "<short title>", "explanation": "<why this matters, what it reveals about attacker intent — NOT a restatement of tool output>"}, ...]  // 5-10 items
  "anomalies":               [{"observation": "<what's unusual>", "expected": "<what would normally be here>", "implication": "<what this tells us>"}, ...]
  "evasion_techniques":      [{"technique": "<specific name>", "explanation": "<plain English how it works>"}, ...]
  "persistence_mechanisms":  [{"mechanism": "<specific name>", "explanation": "..."}, ...]
  "c2_assessment":           {"protocol": "<HTTP|HTTPS|DNS|TCP raw|...>", "shared_or_dedicated": "shared|dedicated|unknown", "notes": "..."},
  "detection_difficulty":    {"level": "<Easy|Moderate|Difficult|Very Difficult>", "explanation": "..."},
  "false_positive_assessment":{"could_be_legitimate": true|false, "what_rules_it_out": "..."},
  "recommended_actions":     [{"action": "<full sentence with enough detail to execute>", "priority": "IMMEDIATE|SHORTTERM|LONGTERM"}, ...]
  "hunting_leads":           [{"hypothesis": "...", "data_source": "<e.g. DeviceProcessEvents>", "query_logic": "<plain English>"}, ...]
  "clarifying_questions":    ["..."]   // 0-3 questions whose answers would materially change classification or attribution
  "analyst_notes":           "<anything else a senior analyst would tell a junior analyst>",
  "confidence_assessment":   {"overall_confidence": 0.0-1.0, "what_would_help": "<what additional analysis would most strengthen this>"}
}

No markdown. No commentary outside the JSON object."""


def _deep_context(analysis: Dict, comparative: Optional[Dict] = None) -> Dict:
    """Full analysis package for the deep prompt — keeps the heaviest fields
    bounded so the prompt stays under model context."""
    fs = analysis.get("format_specific") or {}
    pe = fs.get("pe") or {}
    office = fs.get("office") or {}
    pdf = fs.get("pdf") or {}
    archive = fs.get("archive") or {}
    script = fs.get("script") or {}
    ti = analysis.get("threat_intel") or {}
    cap = analysis.get("capabilities") or {}

    return {
        "file": {
            "filename":   analysis.get("filename"),
            "size":       analysis.get("size"),
            "type":       analysis.get("type"),
            "entropy":    analysis.get("entropy"),
            "hashes":     analysis.get("hashes"),
            "static_verdict":    analysis.get("verdict"),
            "static_confidence": analysis.get("confidence"),
        },
        "iocs":              analysis.get("iocs"),
        "suspicious_strings": analysis.get("suspicious_strings"),
        "yara_matches":      [
            {k: v for k, v in (m or {}).items() if k != "matched_strings"}
            for m in (analysis.get("yara_matches") or [])[:15]
        ],
        "yara_top_matched_strings": [
            {"rule": m.get("rule"), "strings": m.get("matched_strings", [])[:3]}
            for m in (analysis.get("yara_matches") or [])
            if isinstance(m, dict) and m.get("matched_strings")
        ][:6],
        "format_specific": {
            "pe": ({
                "timestamp":         pe.get("timestamp"),
                "imphash":           pe.get("imphash"),
                "machine":           pe.get("machine_name"),
                "subsystem":         pe.get("subsystem"),
                "imports_count":     pe.get("import_count"),
                "flagged_imports":   pe.get("flagged_imports"),
                "exports":           (pe.get("exports") or [])[:30],
                "sections":          pe.get("sections"),
                "signature":         pe.get("signature"),
                "mitigations":       pe.get("mitigations"),
                "capabilities":      pe.get("capabilities"),
                "overlay":           pe.get("overlay"),
                "rich_header":       pe.get("rich_header"),
            } if pe else None),
            "office": ({
                "has_macros":          office.get("has_macros"),
                "auto_exec":           office.get("auto_exec"),
                "suspicious_patterns": office.get("suspicious_patterns"),
                "urls":                office.get("urls"),
                "unc_paths":           office.get("unc_paths"),
                "has_dde":             office.get("has_dde"),
                "embedded_objects":    office.get("embedded_objects"),
                "macro_preview":       (office.get("macros") or [{}])[0].get("code_preview")
                                       if office.get("macros") else None,
            } if office else None),
            "pdf":     pdf or None,
            "archive": archive or None,
            "script":  ({
                "language":          script.get("language"),
                "obfuscation_flags": script.get("obfuscation_flags"),
                "urls":              script.get("urls"),
                "ips":               script.get("ips"),
                "source_preview":    (script.get("source_preview") or "")[:1500],
            } if script else None),
        },
        "capabilities":     cap,
        "threat_intel":     ti,
        "comparative_context": comparative or {},
    }


def _safe_normalize_deep(out: Dict) -> Dict:
    """Make sure every field exists and is the right shape — tolerates a model
    that returns slightly off schema."""
    def _list(x): return x if isinstance(x, list) else ([] if x is None else [x])
    def _dict(x): return x if isinstance(x, dict) else {}
    cls = _dict(out.get("malware_classification"))
    soph = _dict(out.get("sophistication_level"))
    conf = _dict(out.get("confidence_assessment"))
    actor = out.get("threat_actor")
    if actor and not isinstance(actor, dict):
        actor = {"name": str(actor), "confidence": None}
    return {
        "executive_summary":      str(out.get("executive_summary") or ""),
        "technical_summary":      str(out.get("technical_summary") or ""),
        "execution_narrative":    str(out.get("execution_narrative") or ""),
        "malware_classification": {
            "category":   cls.get("category") or out.get("classification") or "Unknown Malware",
            "confidence": cls.get("confidence") or 0.5,
        },
        "malware_family":         out.get("malware_family"),
        "variant":                out.get("variant"),
        "threat_actor":           actor,
        "campaign":               out.get("campaign"),
        "sophistication_level": {
            "level":     soph.get("level") or "Commodity Malware",
            "reasoning": soph.get("reasoning") or "",
        },
        "infection_vector":       out.get("infection_vector"),
        "objectives":             _list(out.get("objectives")),
        "key_findings":           _list(out.get("key_findings")),
        "anomalies":              _list(out.get("anomalies")),
        "evasion_techniques":     _list(out.get("evasion_techniques")),
        "persistence_mechanisms": _list(out.get("persistence_mechanisms")),
        "c2_assessment":          _dict(out.get("c2_assessment")),
        "detection_difficulty":   _dict(out.get("detection_difficulty")),
        "false_positive_assessment": _dict(out.get("false_positive_assessment")),
        "recommended_actions":    _list(out.get("recommended_actions")),
        "hunting_leads":          _list(out.get("hunting_leads")),
        "clarifying_questions":   _list(out.get("clarifying_questions")),
        "analyst_notes":          str(out.get("analyst_notes") or ""),
        "confidence_assessment": {
            "overall_confidence": conf.get("overall_confidence") or 0.5,
            "what_would_help":    conf.get("what_would_help") or "",
        },
    }


async def analyze_deep(analysis: Dict, config,
                       comparative_context: Optional[Dict] = None,
                       extra_context: Optional[str] = None) -> Optional[Dict]:
    """Phase 2 — full structured assessment. Retries once on bad JSON."""
    client, model = _client(config)
    if not client:
        return None

    ctx = _deep_context(analysis, comparative_context)
    user_msg = "## Complete analysis package\n" + json.dumps(ctx, indent=2, default=str)[:10000]
    if extra_context:
        user_msg += "\n\n## Additional context\n" + extra_context[:2000]

    messages = [
        {"role": "system", "content": _DEEP_SYSTEM},
        {"role": "user",   "content": user_msg},
    ]

    for attempt in range(2):
        try:
            resp = await client.chat.completions.create(
                model=model,
                messages=messages,
                response_format={"type": "json_object"},
                temperature=0.15,
                max_tokens=2800,
            )
            text = resp.choices[0].message.content or "{}"
            parsed = json.loads(text)
            return _safe_normalize_deep(parsed)
        except json.JSONDecodeError as e:
            # Tell the model what broke and ask it to retry
            messages.append({"role": "assistant", "content": text})
            messages.append({"role": "user",
                "content": f"That response did not parse as JSON ({e}). Output the same "
                           f"assessment again as strict JSON only — no markdown, no commentary."})
            continue
        except Exception as e:
            return {"error": str(e)[:200]}
    return {"error": "AI failed to produce valid JSON after 2 attempts"}


# ─── Comparative context (case history + similar files + MITRE profile) ───────
def gather_comparative_context(analysis: Dict) -> Dict:
    """Synchronous — pulls related cases, similar fuzzy hashes, MITRE actor
    profile if a family was identified. Best-effort. Used as additional
    grounding for the deep AI prompt."""
    family  = (((analysis.get("threat_intel") or {}).get("virustotal") or {}).get("malware_family")
               or ((analysis.get("threat_intel") or {}).get("malwarebazaar") or {}).get("malware_family"))
    actor   = (((analysis.get("threat_intel") or {}).get("hybrid_analysis") or {}).get("malware_family"))

    similar_files = []
    sh = ((analysis.get("threat_intel") or {}).get("scan_history") or {})
    for kind in ("exact", "imphash", "tlsh_similar", "ssdeep_similar"):
        for entry in (sh.get(kind) or [])[:3]:
            similar_files.append({
                "match_type": kind,
                "sha256":     entry.get("sha256"),
                "filename":   entry.get("filename"),
                "verdict":    entry.get("verdict"),
                "tlsh_distance": entry.get("tlsh_distance"),
                "ssdeep_score":  entry.get("ssdeep_score"),
            })

    actor_profile = None
    if family or actor:
        try:
            from intel.threat_actors import get_all_groups, get_group_techniques
            needle = (family or actor or "").lower()
            for g in get_all_groups():
                if (g.get("name") or "").lower() == needle or any(
                    a.lower() == needle for a in (g.get("aliases") or [])
                ):
                    actor_profile = {
                        "id":             g.get("id"),
                        "name":           g.get("name"),
                        "aliases":        g.get("aliases"),
                        "country":        g.get("country"),
                        "description":    g.get("description"),
                        "top_techniques": [t.get("id") for t in
                                           (get_group_techniques(g.get("id")) or [])[:15]],
                    }
                    break
        except Exception:
            pass

    return {
        "similar_files":     similar_files,
        "actor_profile":     actor_profile,
        "family_hint":       family,
    }


# ─── Convenience: full AI pipeline in one call ────────────────────────────────
async def run_ai_pipeline(analysis: Dict, config,
                           extra_context: Optional[str] = None) -> Dict:
    """Runs triage + deep in parallel for the scan endpoint. Returns
    {triage, deep} where either may be None if no key is configured."""
    import asyncio
    comparative = gather_comparative_context(analysis)
    triage, deep = await asyncio.gather(
        triage_classify(analysis, config),
        analyze_deep(analysis, config, comparative_context=comparative,
                     extra_context=extra_context),
        return_exceptions=True,
    )
    return {
        "triage": triage if not isinstance(triage, Exception) else {"error": str(triage)[:200]},
        "deep":   deep   if not isinstance(deep,   Exception) else {"error": str(deep)[:200]},
        "comparative_context_keys": list(comparative.keys()),
    }
