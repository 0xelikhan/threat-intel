"""
Scanner analyst feedback store + institutional-knowledge loop — spec §2.

  POST /api/scan/feedback  → record(scan_id, thumbs, correction, notes)
  When generating new AI analysis, similar-file lookups (by fuzzy hash)
  surface prior corrections so the model can be told 'last time you
  classified samples like this as X, the analyst corrected it to Y'.
"""

from __future__ import annotations
from collections import deque
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional


# In-memory feedback store. Analyst thumbs / corrections / notes are
# never persisted to disk (see platform no-persistence policy). The
# institutional-knowledge prompt still works within the lifetime of the
# same container.
_FEEDBACK: Deque[Dict] = deque(maxlen=1000)


def record(scan_id: str, thumbs: str, correction: Optional[Dict] = None,
           notes: Optional[str] = None, analyst: Optional[str] = None) -> Dict:
    """Append a single feedback entry to the in-memory ring buffer.
    Returns the stored record."""
    entry = {
        "scan_id":    scan_id,
        "thumbs":     thumbs,   # 'up' | 'down'
        "correction": correction or {},
        "notes":      (notes or "").strip()[:1500],
        "analyst":    (analyst or "").strip()[:80],
        "ts":         datetime.now(timezone.utc).isoformat(),
    }
    _FEEDBACK.appendleft(entry)
    return entry


def list_all(limit: int = 100) -> List[Dict]:
    return list(_FEEDBACK)[:limit]


def for_scan(scan_id: str) -> List[Dict]:
    return [e for e in _FEEDBACK if e.get("scan_id") == scan_id]


def institutional_knowledge_for(analysis: Dict, max_examples: int = 5) -> List[Dict]:
    """Return prior analyst corrections for samples similar to `analysis`.
    Similarity = exact SHA-256 match OR TLSH distance < 60 OR ssdeep > 50 OR
    same imphash. The matching uses the scan_history index to resolve sha256s
    referenced in feedback entries."""
    try:
        from intel.file_correlation import get_scan_history
    except Exception:
        return []

    target_sha = (analysis.get("hashes") or {}).get("sha256")
    target_tlsh = (analysis.get("hashes") or {}).get("tlsh")
    target_ssdeep = (analysis.get("hashes") or {}).get("ssdeep")
    target_imphash = ((analysis.get("format_specific") or {}).get("pe") or {}).get("imphash")
    if not any((target_sha, target_tlsh, target_ssdeep, target_imphash)):
        return []

    history = {e.get("sha256"): e for e in get_scan_history() if e.get("sha256")}
    fb = list(_FEEDBACK)
    out: List[Dict] = []

    for entry in fb:
        if len(out) >= max_examples:
            break
        sid = entry.get("scan_id")
        h = history.get(sid)
        if not h:
            continue
        similar = False
        match_kind = None
        if target_sha and h.get("sha256") == target_sha:
            similar, match_kind = True, "exact_sha256"
        elif target_imphash and h.get("imphash") and h["imphash"] == target_imphash:
            similar, match_kind = True, "same_imphash"
        elif target_tlsh and h.get("tlsh"):
            try:
                import tlsh
                d = tlsh.diff(target_tlsh, h["tlsh"])
                if d < 60:
                    similar, match_kind = True, f"tlsh_dist={d}"
            except Exception:
                pass
        elif target_ssdeep and h.get("ssdeep"):
            try:
                import ssdeep
                s = ssdeep.compare(target_ssdeep, h["ssdeep"])
                if s > 50:
                    similar, match_kind = True, f"ssdeep={s}%"
            except Exception:
                pass
        if not similar:
            continue
        out.append({
            "matched_sha256": h.get("sha256"),
            "match_kind":     match_kind,
            "filename":       h.get("filename"),
            "thumbs":         entry.get("thumbs"),
            "correction":     entry.get("correction"),
            "notes":          entry.get("notes"),
        })
    return out


def institutional_knowledge_prompt(analysis: Dict) -> Optional[str]:
    """Build a text block ready to drop into the AI prompt as extra_context."""
    examples = institutional_knowledge_for(analysis)
    if not examples:
        return None
    lines = ["Previous analyst corrections on samples similar to this one:"]
    for e in examples:
        corr = e.get("correction") or {}
        bits = []
        if corr.get("classification"):
            bits.append(f"reclassified as {corr['classification']}")
        if corr.get("family"):
            bits.append(f"family corrected to {corr['family']}")
        if corr.get("verdict"):
            bits.append(f"verdict corrected to {corr['verdict']}")
        thumb = e.get("thumbs")
        lines.append(
            f"  - {e['filename'] or e['matched_sha256'][:12]+'…'} "
            f"({e['match_kind']}) — analyst gave 👎: {', '.join(bits) or 'no specifics'}"
            if thumb == "down"
            else f"  - {e['filename'] or e['matched_sha256'][:12]+'…'} "
                 f"({e['match_kind']}) — analyst gave 👍 (your prior assessment was correct)"
        )
        if e.get("notes"):
            lines.append(f"    note: {e['notes'][:200]}")
    lines.append("Take this institutional knowledge into account in your assessment.")
    return "\n".join(lines)
