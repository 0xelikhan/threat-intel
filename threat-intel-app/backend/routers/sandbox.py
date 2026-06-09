"""
Sandbox routes — auto-submission polling for Hybrid Analysis.

Extracted from main.py alongside calibration. The auto-submission
itself runs as a background task fired from intel/file_correlation.py
when sandbox_submission_eligible is True; this endpoint surfaces the
in-memory status the polling loop publishes via intel.sandbox._sandbox_set
(no on-disk persistence per the platform no-persistence policy — see
5a36e36).
"""

from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException


router = APIRouter(tags=["sandbox"])

# Local SHA-256 validator — kept here so the router has no main.py dep.
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@router.get("/api/sandbox/result/{sha256}")
async def sandbox_result(sha256: str):
    """Poll for the auto-submitted Hybrid Analysis detonation result.
    The file analyzer fires this submission in the background when HA
    has no prior report for the file — the analyst doesn't wait, this
    endpoint surfaces the eventual outcome (IN_PROGRESS / SUCCESS /
    ERROR / TIMEOUT) once it lands."""
    if not _SHA256_RE.match(sha256 or ""):
        raise HTTPException(400, "sha256 must be 64 hex characters")
    from intel.sandbox import load_sandbox_result
    result = load_sandbox_result(sha256.lower())
    if result is None:
        return {"sha256": sha256, "state": "NO_SUBMISSION",
                "note": "No auto-submission for this hash. The file analyzer "
                        "only auto-submits when HYBRID_ANALYSIS_KEY is set "
                        "and no prior report exists for the hash."}
    return result
