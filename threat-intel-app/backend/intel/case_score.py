"""
Case-level rollup score with letter grade and recency multipliers.

Adapted from cti-expert (MIT) analysis/weight-engine.md +
analysis/exposure-model.md. The existing `gti_score.py` is per-IOC and
verdict×severity-driven, which is correct for triage. This module is
DIFFERENT — it produces ONE score for the whole investigation that
incorporates:

  * Recency multipliers — observations within 30 days count more,
    observations older than 730 days count less.
  * Active-compromise amplifier — when investigation_result flags an
    ongoing intrusion (KEV CVE actively exploited, named ransomware
    family, lateral movement signals), bump 1.35x.
  * Letter-grade subscale on top of the 0-100 number. Analysts read
    "D7" (case score 73) faster than "73/100" because the letter
    bands map to disposition (A=clear, B=monitor, C=investigate,
    D=escalate, F=critical).

The output rides alongside per-IOC `gti_scores` on `response_summary`
without replacing it — analysts can still drill in to per-IOC scores
when needed.

Shape:
  {
    "score":          int (0-100),
    "grade":          str ("A1" .. "F9"),
    "tier":           "CLEAR" | "MONITOR" | "INVESTIGATE" |
                       "ESCALATE" | "CRITICAL",
    "drivers":        list[dict] (which signals contributed, with weights),
    "multipliers":    dict (which amplifiers / decays applied),
    "summary":        one-line analyst-readable explanation,
  }
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_log = logging.getLogger("recon.intel.case_score")


# Driver weights — the BASE contributions before any multiplier. These
# track gut-feel triage importance: a confirmed KEV CVE is the biggest
# single signal; a single VT detection is a smaller signal; a benign
# warninglist hit subtracts. Tuned to land "typical malicious alert"
# in the 60-75 band so the grade letters track disposition tiers.
_DRIVERS: List[Dict[str, Any]] = [
    # (key, weight, label, finder function pulling value from state)
    {"key": "kev_active",    "weight": 30, "label": "Active-exploited CVE on KEV"},
    {"key": "named_malware", "weight": 25, "label": "Named malware family identified"},
    {"key": "ransomware",    "weight": 25, "label": "Ransomware behaviour observed"},
    {"key": "actor_match",   "weight": 18, "label": "Threat-actor attribution"},
    {"key": "vt_strong",     "weight": 15, "label": "≥5 VT engines flagged an IOC"},
    {"key": "vt_partial",    "weight": 8,  "label": "1–4 VT engines flagged an IOC"},
    {"key": "abuseipdb_high","weight": 10, "label": "AbuseIPDB ≥75 confidence"},
    {"key": "credential_access", "weight": 12, "label": "Credential access tactic present"},
    {"key": "lateral_movement",  "weight": 12, "label": "Lateral movement signal"},
    {"key": "c2_beacon",     "weight": 14, "label": "C2 beacon / known-bad infra hit"},
    {"key": "domain_dga",    "weight": 8,  "label": "Trained DGA classifier verdict"},
    {"key": "phish_url",     "weight": 8,  "label": "Trained phishing-URL verdict"},
    # Negative driver — warninglist match means a chunk of IOCs were
    # benign public infra (Cloudflare, MS, Google) and the case is
    # smaller than it looks.
    {"key": "warninglist",   "weight": -10, "label": "MISP warninglist hits"},
]


def _detect_drivers(state: Dict[str, Any]) -> Dict[str, bool]:
    """Walk a final pipeline `state` dict and decide which drivers fire."""
    inv = state.get("investigation_result") or {}
    rs  = state.get("response_summary") or {}
    cross = (rs.get("cross_refs")
             or state.get("cross_refs")
             or {})
    iocs = state.get("iocs") or {}
    enrichments = state.get("enrichments") or {}
    bi = state.get("behavioral_indicators") or {}

    out: Dict[str, bool] = {}

    # KEV active-exploited
    out["kev_active"] = any(
        bool(k.get("ransomware_use")) or bool(k.get("known_ransomware_campaigns"))
        for k in (cross.get("kev") or []) if isinstance(k, dict)
    ) or bool(cross.get("kev"))

    fam = (rs.get("malware_family") or state.get("malware_family") or "").strip()
    out["named_malware"] = bool(fam)
    out["ransomware"]    = bool(fam and re.search(r"ransom|crypt|locker|wiper", fam, re.I))

    actors = rs.get("matched_actors") or []
    out["actor_match"] = any(
        isinstance(a, dict) and (a.get("score") or 0) >= 0.4 for a in actors
    )

    vt_max = 0
    for per_type in (enrichments or {}).values():
        if not isinstance(per_type, dict):
            continue
        for per_source in per_type.values():
            if not isinstance(per_source, dict):
                continue
            vt = per_source.get("virustotal") or {}
            if isinstance(vt, dict) and not vt.get("error"):
                vt_max = max(vt_max, int(vt.get("malicious") or 0))
    out["vt_strong"]  = vt_max >= 5
    out["vt_partial"] = 1 <= vt_max < 5

    ai_max = 0
    for per_source in ((enrichments.get("ips") or {}).values() if isinstance(enrichments.get("ips"), dict) else []):
        ai = per_source.get("abuseipdb") if isinstance(per_source, dict) else None
        if isinstance(ai, dict) and not ai.get("error"):
            score = ai.get("abuseScore") or ai.get("abuse_confidence") or 0
            ai_max = max(ai_max, int(score or 0))
    out["abuseipdb_high"] = ai_max >= 75

    # Behavioural categories — read directly off the indicator dict.
    cats = (bi.get("categories") or {}) if isinstance(bi, dict) else {}
    out["credential_access"] = bool(cats.get("credential_access"))
    out["lateral_movement"]  = bool(cats.get("lateral_movement"))
    out["c2_beacon"] = bool(cats.get("c2") or cats.get("command_and_control"))

    # Round-14 classifiers — pick up the strongest signal across domains.
    dga_any = False
    phish_any = False
    for per_source in ((enrichments.get("domains") or {}).values() if isinstance(enrichments.get("domains"), dict) else []):
        d = per_source.get("dga_classifier") if isinstance(per_source, dict) else None
        if isinstance(d, dict) and d.get("is_dga"):
            dga_any = True
    for per_source in ((enrichments.get("urls") or {}).values() if isinstance(enrichments.get("urls"), dict) else []):
        p = per_source.get("phishing_classifier") if isinstance(per_source, dict) else None
        if isinstance(p, dict) and p.get("is_phish"):
            phish_any = True
    out["domain_dga"] = dga_any
    out["phish_url"]  = phish_any

    sup = state.get("suppressed_iocs") or {}
    out["warninglist"] = isinstance(sup, dict) and any(sup.values())

    return out


def _recency_multiplier(observation_ts: Optional[datetime]) -> float:
    """≤30 days → 1.25x; >730 days → 0.80x; everything in between scales
    linearly between the two anchors."""
    if observation_ts is None:
        return 1.0
    now = datetime.now(timezone.utc)
    if observation_ts.tzinfo is None:
        observation_ts = observation_ts.replace(tzinfo=timezone.utc)
    days = max(0.0, (now - observation_ts).total_seconds() / 86400.0)
    if days <= 30:
        return 1.25
    if days >= 730:
        return 0.80
    # Linear taper from 1.25 (30d) → 0.80 (730d)
    frac = (days - 30) / (730 - 30)
    return 1.25 - frac * (1.25 - 0.80)


def _grade(score: int) -> str:
    """Letter band A-F + 1-9 subscale. A=clear, F=critical."""
    s = max(0, min(100, int(score)))
    if s < 10:
        band = "A"
    elif s < 30:
        band = "B"
    elif s < 50:
        band = "C"
    elif s < 75:
        band = "D"
    else:
        band = "F"
    sub = (s % 10) or 1
    return f"{band}{sub}"


def _tier(score: int) -> str:
    s = max(0, min(100, int(score)))
    if s < 10:
        return "CLEAR"
    if s < 30:
        return "MONITOR"
    if s < 50:
        return "INVESTIGATE"
    if s < 75:
        return "ESCALATE"
    return "CRITICAL"


def compute(
    state: Dict[str, Any],
    observation_ts: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Roll up the case score for a final pipeline state.

    `observation_ts` is the timestamp the alert was generated (NOT
    when RECON analyzed it). Defaults to "now" when not supplied — that
    means newly-analyzed alerts get the recency boost, which is the
    right behaviour for live SOC traffic. Historical re-analysis passes
    should pass the original alert timestamp so old findings decay."""
    fired = _detect_drivers(state)
    raw_score = 0
    contributing: List[Dict[str, Any]] = []
    for d in _DRIVERS:
        if fired.get(d["key"]):
            raw_score += d["weight"]
            contributing.append({"driver": d["key"], "weight": d["weight"],
                                  "label": d["label"]})

    multipliers: Dict[str, float] = {}
    rec_mult = _recency_multiplier(observation_ts)
    multipliers["recency"] = round(rec_mult, 3)

    # Active-compromise amplifier (cti-expert's 1.35x) — only fires
    # when at least one of the high-signal drivers AND one of the
    # active-exploitation flags is present.
    high_signal = (
        fired.get("kev_active")
        or fired.get("named_malware")
        or fired.get("ransomware")
    )
    active = (
        fired.get("credential_access")
        or fired.get("lateral_movement")
        or fired.get("c2_beacon")
    )
    if high_signal and active:
        multipliers["active_compromise"] = 1.35
    else:
        multipliers["active_compromise"] = 1.0

    score = raw_score
    for v in multipliers.values():
        score = score * v
    score = max(0, min(100, int(round(score))))

    grade = _grade(score)
    tier = _tier(score)

    if score == 0:
        summary = "No significant signals — case score 0 / A1."
    else:
        top = sorted(contributing, key=lambda c: -c["weight"])[:3]
        top_str = ", ".join(c["label"] for c in top)
        summary = (
            f"Case score {score}/100 (grade {grade}, tier {tier}). "
            f"Top drivers: {top_str}."
            + (" Recency boost applied." if rec_mult > 1.0 else "")
            + (" Active-compromise multiplier applied."
               if multipliers["active_compromise"] > 1.0 else "")
        )

    return {
        "score":       score,
        "grade":       grade,
        "tier":        tier,
        "drivers":     contributing,
        "multipliers": multipliers,
        "summary":     summary,
    }


def stats() -> Dict[str, Any]:
    return {
        "loaded":         True,
        "drivers":        len(_DRIVERS),
        "max_raw_weight": sum(d["weight"] for d in _DRIVERS if d["weight"] > 0),
    }
