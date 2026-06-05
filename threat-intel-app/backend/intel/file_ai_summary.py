"""
AI plain-English summary for a file analysis result.

Different from file_capability_map.plain_english_summary (which only describes
malicious capability). This describes what the file IS — works equally well
for "this is just a png of a sunset" as for "this is a stage-2 Cobalt Strike
beacon dropper". The analyst reads it before drilling into details.

Uses the same Azure-aware OpenAI client pattern as the rest of the codebase.
Fails open — returns None on missing key / model error so the caller falls
back to no summary rather than blocking the response.
"""

from __future__ import annotations
import json
import os
from typing import Optional, Dict


def _compress_for_prompt(analysis: Dict) -> Dict:
    """Pull just the high-signal fields — keeps prompt small and fast."""
    fs = analysis.get("format_specific") or {}
    pe = fs.get("pe") or {}
    office = fs.get("office") or {}
    pdf = fs.get("pdf") or {}
    archive = fs.get("archive") or {}
    script = fs.get("script") or {}
    iocs = analysis.get("iocs") or {}
    ti = analysis.get("threat_intel") or {}
    vt = ti.get("virustotal") or {}
    mb = ti.get("malwarebazaar") or {}

    return {
        "filename": analysis.get("filename"),
        "size":     analysis.get("size"),
        "type":     (analysis.get("type") or {}).get("detected_mime"),
        "type_desc": (analysis.get("type") or {}).get("detected_desc"),
        "category": (analysis.get("type") or {}).get("category"),
        "mismatch": (analysis.get("type") or {}).get("mismatch"),
        "entropy":  (analysis.get("entropy") or {}).get("overall"),
        "entropy_band": (analysis.get("entropy") or {}).get("band"),
        "verdict":  analysis.get("verdict"),
        "confidence": analysis.get("confidence"),
        "capabilities": (analysis.get("capabilities") or {}).get("tags") or [],
        "iocs": {k: len(v) for k, v in iocs.items() if isinstance(v, list) and v},
        "ioc_samples": {k: v[:3] for k, v in iocs.items() if isinstance(v, list) and v},
        "yara_matches": [m.get("rule") for m in (analysis.get("yara_matches") or [])
                         if isinstance(m, dict) and m.get("rule")][:8],
        "suspicious_strings": [s.get("pattern") for s in (analysis.get("suspicious_strings") or [])][:8],
        "pe": ({
            "imports_count":   pe.get("import_count"),
            "imphash":         pe.get("imphash"),
            "flagged_imports": list((pe.get("flagged_imports") or {}).keys()),
            "is_dll":          pe.get("is_dll"),
            "signed":          (pe.get("signature") or {}).get("present"),
        } if pe else None),
        "office": ({
            "has_macros":          office.get("has_macros"),
            "auto_exec":           office.get("auto_exec"),
            "suspicious_patterns": [p.get("pattern") for p in (office.get("suspicious_patterns") or [])],
            "urls":                office.get("urls"),
        } if office else None),
        "pdf": ({
            "pages":          pdf.get("pages"),
            "encrypted":      pdf.get("encrypted"),
            "javascript_blocks": len(pdf.get("javascript") or []),
            "launch_actions": len(pdf.get("launch_actions") or []),
            "embedded_count": pdf.get("embedded_count"),
        } if pdf else None),
        "archive": ({
            "member_count": archive.get("member_count"),
            "flags":        archive.get("flags"),
        } if archive else None),
        "script": ({
            "language":          script.get("language"),
            "line_count":        script.get("line_count"),
            "obfuscation_flags": script.get("obfuscation_flags"),
            "preview":           (script.get("source_preview") or "")[:400],
        } if script else None),
        "virustotal": ({
            "detection_ratio": vt.get("detection_ratio"),
            "malware_family":  vt.get("malware_family"),
            "tags":            vt.get("tags"),
        } if vt and vt.get("found") else None),
        "malwarebazaar": ({
            "family":     mb.get("malware_family"),
            "first_seen": mb.get("first_seen"),
        } if mb and mb.get("found") else None),
    }


SYSTEM_PROMPT = """OUTPUT STYLE (hard rule): Write in plain ASCII. NEVER use em-dashes (—), en-dashes (–), or curly quotes. Use hyphens (-), commas, or restructure the sentence.

You are a senior malware analyst writing for a colleague.
Given a file analysis result, write a SHORT plain-English summary (2-3 sentences,
~50-80 words) describing what this file actually IS and what it appears to do.

Tone: matter-of-fact, no fluff, no hedging. Lead with the file's nature, then
its purpose / behavior. If benign, say so plainly. If malicious, name the
family or capability directly. If just a picture / document / archive with
nothing notable, say that.

CALIBRATION — do not overstate:
* If the hash is clean across every TI source, no YARA rules matched, and
  no suspicious patterns were extracted, say "no malicious indicators" and
  treat the file as legitimate unless the type itself is suspect.
* Only call a file malicious when concrete evidence supports it: a non-zero
  VT detection ratio with a named family, a YARA match, a flagged import
  combination with corroborating signals, or a known-bad hash. Suspicious-
  LOOKING characteristics alone (high entropy, unsigned, etc.) without
  reputation backing should be described as "worth a closer look" rather
  than "likely malicious".
* Do NOT hedge with "could potentially be misused" when the evidence
  points to benign software.

Examples of the register:
  * "Standard 1.2 MB PNG image, looks like a photo. No embedded payloads,
    no anomalous metadata. Nothing to investigate."
  * "Python script (~400 lines) that fetches data from an HTTP API, parses
    JSON responses, and writes them to a local CSV. Reads credentials from
    environment variables. No malicious indicators."
  * "Windows PE executable, packed (entropy 7.8), signed by an unknown CA.
    Imports VirtualAllocEx, WriteProcessMemory, CreateRemoteThread — a
    textbook process injector. VirusTotal flags it as MALICIOUS (45/72)
    with the family 'CobaltStrike'."

Output ONLY the summary text. No markdown, no lists, no headers, no quotes
around it. No em dashes or en dashes — use commas or restructure.
"""


async def summarize_file(analysis: Dict, config) -> Optional[str]:
    """2-3 sentence file analysis summary. Provider-agnostic via providers/."""
    if not (config.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")):
        return None
    from providers import get_provider
    provider = get_provider()
    # Short 2-3 sentence summary — light, latency-sensitive → fast model tier.
    model = config.get_model(fast=True) if hasattr(config, "get_model") else None
    resp = await provider.complete(
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content":
                "## File analysis (compressed)\n"
                f"{json.dumps(_compress_for_prompt(analysis), indent=2)[:6000]}\n"
            },
        ],
        temperature=0.2,
        max_tokens=200,
        model=model,
    )
    if resp.error:
        return None
    text = (resp.message or "").strip()
    # Strip any stray quotation marks the model added despite instructions
    if text.startswith('"') and text.endswith('"') and len(text) > 2:
        text = text[1:-1].strip()
    return text or None
