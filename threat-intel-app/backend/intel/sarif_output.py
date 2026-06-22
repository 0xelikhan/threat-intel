"""
SARIF 2.1.0 output adapter.

Source: https://docs.oasis-open.org/sarif/sarif/v2.1.0/ (OASIS standard).
SARIF (Static Analysis Results Interchange Format) is the canonical
JSON interchange format for static-analysis tools. GitHub Code Scanning,
Azure DevOps Advanced Security, GitLab Vulnerability Reports, and most
modern code-scanning UIs accept SARIF directly.

This adapter converts RECON's file-scanner findings (YARA matches,
capa capabilities, suspicious-string hits, MITRE-mapped capabilities,
verdict) into a SARIF document that an analyst can attach to a GitHub
PR or upload to their CI.

Output is purely a serializer — no network IO, no LLM. Reads the
analyze_file() result dict; emits a SARIF dict the caller can
json.dumps() or stream to a downloadable response.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Map RECON verdict → SARIF level. SARIF levels are
# {"none", "note", "warning", "error"}.
_VERDICT_TO_LEVEL = {
    "CLEAN":         "none",
    "CLEAN_INFRA":   "note",
    "LOW":           "note",
    "SUSPICIOUS":    "warning",
    "MALICIOUS":     "error",
    "UNKNOWN":       "note",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sarif_rule(rule_id: str, name: str, description: str,
                attack_url: str = "") -> Dict[str, Any]:
    rule = {
        "id":   rule_id,
        "name": name[:200],
        "shortDescription": {"text": name[:200]},
        "fullDescription":  {"text": description[:600] or name[:200]},
        "defaultConfiguration": {"level": "warning"},
    }
    if attack_url:
        rule["helpUri"] = attack_url
    return rule


def _sarif_result(rule_id: str, level: str, message: str,
                  filename: str, locations_text: Optional[str] = None
                  ) -> Dict[str, Any]:
    result = {
        "ruleId":  rule_id,
        "level":   level,
        "message": {"text": message[:1000]},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": filename or "uploaded"},
            }
        }],
    }
    if locations_text:
        result["locations"][0]["physicalLocation"]["region"] = {
            "snippet": {"text": locations_text[:200]},
        }
    return result


def to_sarif(analyze_result: Dict[str, Any],
             filename: Optional[str] = None) -> Dict[str, Any]:
    """Convert a file_analyzer.analyze_file() result into SARIF 2.1.0.

    The output schema:
      {version, $schema, runs: [{tool, results, ...}]}
    Compatible with GitHub Code Scanning (upload as .sarif file).
    """
    if not isinstance(analyze_result, dict):
        analyze_result = {}
    fn = filename or analyze_result.get("filename") or "uploaded"
    verdict = (analyze_result.get("verdict") or "UNKNOWN").upper()
    default_level = _VERDICT_TO_LEVEL.get(verdict, "note")

    rules:   Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    # 1) YARA matches → one rule per matched YARA rule
    for m in (analyze_result.get("yara_matches") or [])[:60]:
        if not isinstance(m, dict):
            continue
        rule_name = m.get("rule") or m.get("namespace") or "yara"
        rule_id   = f"yara/{rule_name}"
        if rule_id not in rules:
            rules[rule_id] = _sarif_rule(
                rule_id=rule_id, name=rule_name,
                description=m.get("description") or
                            f"YARA rule {rule_name} matched.",
            )
        msg = (f"YARA rule {rule_name} matched"
                + (f" — {m['description']}" if m.get("description") else ""))
        # First matched string's snippet, if present
        snippet = ""
        for ms in (m.get("matched_strings") or [])[:1]:
            if isinstance(ms, dict) and ms.get("matched"):
                snippet = ms["matched"]
                break
        results.append(_sarif_result(rule_id, default_level, msg, fn, snippet))

    # 2) capa capabilities → one rule per capa rule
    capa_out = analyze_result.get("capa") or {}
    for cap in (capa_out.get("capabilities") or [])[:30]:
        if not isinstance(cap, dict):
            continue
        rule = cap.get("rule") or cap.get("name") or "capa"
        rule_id = f"capa/{rule}"
        if rule_id not in rules:
            rules[rule_id] = _sarif_rule(
                rule_id=rule_id, name=rule,
                description=cap.get("namespace") or
                            f"FLARE capa capability {rule}",
            )
        techs = cap.get("mitre_techniques") or []
        msg = (f"capa capability '{rule}' detected"
                + (f" (MITRE: {', '.join(techs[:4])})" if techs else ""))
        results.append(_sarif_result(rule_id, default_level, msg, fn))

    # 3) MITRE technique mappings from capability_map
    caps = analyze_result.get("capabilities") or {}
    if isinstance(caps, dict):
        for t in (caps.get("mitre_techniques") or [])[:20]:
            if isinstance(t, dict):
                tid  = t.get("id") or ""
                name = t.get("name") or tid
                url  = t.get("attack_url") or ""
                rule_id = f"mitre/{tid}"
                if rule_id not in rules:
                    rules[rule_id] = _sarif_rule(
                        rule_id=rule_id, name=f"{tid} - {name}",
                        description=(t.get("explanation") or
                                      f"MITRE ATT&CK technique {tid} inferred."),
                        attack_url=url,
                    )
                msg = (f"Technique {tid} ({name}) inferred from static "
                        f"analysis evidence")
                if t.get("evidence"):
                    msg += f": {t['evidence']}"
                results.append(_sarif_result(rule_id, default_level, msg, fn))

    # 4) Suspicious strings — surface only critical pattern hits, not every
    #    interesting string
    for s in (analyze_result.get("suspicious_strings") or [])[:25]:
        if not isinstance(s, dict):
            continue
        pat  = s.get("pattern") or s.get("name") or "suspicious-string"
        rule_id = f"static-string/{pat}"
        if rule_id not in rules:
            rules[rule_id] = _sarif_rule(
                rule_id=rule_id, name=pat,
                description=s.get("description") or
                            f"Suspicious pattern '{pat}' detected in strings.",
            )
        results.append(_sarif_result(
            rule_id, default_level,
            f"Suspicious string pattern: {pat}", fn,
            (s.get("matched") or s.get("hit") or "")[:120],
        ))

    sha256 = (analyze_result.get("hashes") or {}).get("sha256", "")
    invocation_meta = {
        "executionSuccessful": not bool(analyze_result.get("error")),
        "startTimeUtc": _now_iso(),
        "endTimeUtc":   _now_iso(),
    }
    if sha256:
        invocation_meta["properties"] = {"sha256": sha256}

    return {
        "version": "2.1.0",
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name":            "RECON",
                    "informationUri":  "https://0xrecon.com",
                    "version":         "1.0",
                    "rules":           list(rules.values()),
                },
            },
            "results":     results,
            "invocations": [invocation_meta],
            "properties":  {
                "recon_verdict":      verdict,
                "recon_filename":     fn,
                "recon_sha256":       sha256,
            },
        }],
    }
