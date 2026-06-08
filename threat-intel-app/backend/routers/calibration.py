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
from pydantic import BaseModel


router = APIRouter(tags=["calibration"])


class CalibrationOverrideRequest(BaseModel):
    raw_input:            str
    ai_threat_level:      str
    ai_confidence:        Optional[float] = None
    ai_summary:           Optional[str]   = ""
    analyst_threat_level: str
    analyst_reason:       Optional[str]   = ""
    alert_type:           Optional[str]   = None


@router.post("/api/calibration/override")
async def calibration_override(req: CalibrationOverrideRequest):
    """Record an analyst override of the AI verdict. Returns the stored
    record (with computed input_hash + prompt_version) so the UI can
    confirm. Eval data for spotting prompt regressions — see
    intel/calibration_log.py for the storage format."""
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


@router.get("/api/calibration/stats")
async def calibration_stats():
    """Aggregate override stats — agreement rate, per-prompt-version
    breakdown, level-pair counts (AI->Analyst), recent 20 overrides.
    Used to spot regressions: a sudden spike in the override rate after
    a prompt edit is a leading indicator."""
    from intel.calibration_log import stats
    return stats()
