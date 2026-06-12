"""
Calibration routes — analyst-override recording + agreement-rate stats.

Extracted from main.py as the first router-split proof-of-concept. The
routes are self-contained (no shared globals, no cross-route helpers in
main.py), so moving them tests the pattern without risking the larger
analyze / detection / file-scan paths.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field


router = APIRouter(tags=["calibration"])


class CalibrationOverrideRequest(BaseModel):
    # raw_input is what the analyst originally pasted into /api/analyze; the
    # store-side input_hash() runs sha256 over its full bytes. Without a cap
    # an attacker could POST a 50 MB body (the audit middleware's max) and
    # make us spend real CPU on the hash + store the truncated summary.
    # Match /api/analyze's 1 MB cap so the two endpoints accept the same
    # universe of inputs.
    raw_input:            str           = Field(..., max_length=1_000_000)
    ai_threat_level:      str           = Field(..., max_length=64)
    ai_confidence:        Optional[float] = None
    # Summary and reason are truncated in the store; cap input too so we
    # don't allocate megabytes that get immediately sliced down to 240/600.
    ai_summary:           Optional[str] = Field(default="",   max_length=4_000)
    analyst_threat_level: str           = Field(..., max_length=64)
    analyst_reason:       Optional[str] = Field(default="",   max_length=4_000)
    alert_type:           Optional[str] = Field(default=None, max_length=128)


@router.post("/api/calibration/override")
async def calibration_override(req: CalibrationOverrideRequest):
    """Record an analyst override of the AI verdict. Returns the stored
    record (with computed input_hash + prompt_version) so the UI can
    confirm. The JSONL log is consumed by scripts/eval_prompts.py for
    A/B testing prompt changes against historical analyst judgement."""
    from intel.calibration_log import record_override
    rec = record_override(
        raw_input            = req.raw_input,
        ai_threat_level      = req.ai_threat_level,
        ai_confidence        = req.ai_confidence,
        ai_summary           = req.ai_summary or "",
        analyst_threat_level = req.analyst_threat_level,
        analyst_reason       = req.analyst_reason or "",
        alert_type           = req.alert_type,
    )
    return {"saved": True, "record": rec}
