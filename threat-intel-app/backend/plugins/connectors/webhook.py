"""Webhook connector - POST investigation JSON to a configured URL.

The single most-general connector: covers Slack-via-webhook,
Teams-incoming-webhook, SIEM HTTP collectors, custom alert routers,
ngrok tunnels for local dev, Pipedream workflows, Zapier catches,
and anything else that accepts "a POST with some JSON".

Config shape (env-level or injected keys):

    RECON_WEBHOOK_URL       the destination URL (required)
    RECON_WEBHOOK_SECRET    optional - value for an X-Recon-Signature
                            header + HMAC-SHA256 of the body (lets the
                            receiver verify provenance)
    RECON_WEBHOOK_HEADERS   optional - JSON object of extra headers to
                            include on every request; useful for
                            provider auth tokens like
                            {"Authorization":"Bearer xyz"}
    RECON_WEBHOOK_MIN_VERDICT   optional - only POST when the worst
                            verdict reaches this level; one of
                            CLEAN|UNKNOWN|SUSPICIOUS|MALICIOUS. Default
                            SUSPICIOUS so CLEAN/UNKNOWN noise stays off
                            the receiver.

Payload the receiver gets:

    {
      "event": "recon.investigation_complete",
      "sent_at": "2026-11-25T18:30:00Z",
      "artifact": { "type": "ipv4", "value": "1.2.3.4", ... },
      "verdict": "MALICIOUS",
      "worst_score": 90,
      "sources_hit": ["abuseipdb", "otx", "virustotal"],
      "summary": "RECON: ...",
      "results": [...],
    }

Zero third-party deps; aiohttp is already in RECON's base install.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

import aiohttp

from plugins import AnalysisResult, Artifact, Connector, register

_log = logging.getLogger("recon.plugins.connectors.webhook")


_VERDICT_RANK = {"CLEAN": 0, "UNKNOWN": 1, "SUSPICIOUS": 2, "MALICIOUS": 3}

# Matches the OpenCTI connector's mapping so the two produce the same
# score for the same investigation. Duplicated rather than imported to
# keep the connectors fully independent.
_SCORE_FOR = {"CLEAN": 10, "UNKNOWN": 30, "SUSPICIOUS": 65, "MALICIOUS": 90}


class WebhookConnector(Connector):
    name = "webhook"
    description = ("POST the investigation JSON to a configured HTTP endpoint "
                   "(Slack / Teams / SIEM / custom). Optional HMAC-SHA256 "
                   "signature + per-request headers.")
    required_keys = ["RECON_WEBHOOK_URL"]
    optional_keys = ["RECON_WEBHOOK_SECRET", "RECON_WEBHOOK_HEADERS",
                     "RECON_WEBHOOK_MIN_VERDICT"]
    homepage = "https://en.wikipedia.org/wiki/Webhook"

    async def export(self, artifact: Artifact,
                      results: List[AnalysisResult],
                      keys: Dict[str, str]) -> Dict[str, Any]:
        url = (keys.get("RECON_WEBHOOK_URL")
               or os.environ.get("RECON_WEBHOOK_URL")
               or "").strip()
        if not url:
            return {"source": "webhook", "ok": False,
                    "error": "RECON_WEBHOOK_URL not configured",
                    "error_type": "missing_key"}

        found = [r for r in results if r.found and not r.error]
        verdict = _worst_verdict(found)

        # Threshold gate. Default SUSPICIOUS so analysts don't flood
        # the receiver with CLEAN/UNKNOWN pings on every search.
        min_verdict = (keys.get("RECON_WEBHOOK_MIN_VERDICT")
                       or "SUSPICIOUS").upper()
        if _VERDICT_RANK.get(verdict, 0) < _VERDICT_RANK.get(min_verdict, 2):
            return {"source": "webhook", "ok": True, "skipped": True,
                    "reason": f"verdict {verdict} below threshold {min_verdict}"}

        payload = _build_payload(artifact, results, found, verdict)
        body = json.dumps(payload, separators=(",", ":"),
                           sort_keys=True, default=str).encode("utf-8")

        # Build request headers. Default Content-Type + optional user-
        # supplied headers + optional HMAC signature (last so it can't
        # be overwritten by the extras).
        headers: Dict[str, str] = {"Content-Type": "application/json",
                                    "User-Agent": "RECON-Webhook/1.0"}
        raw_extra = (keys.get("RECON_WEBHOOK_HEADERS")
                     or os.environ.get("RECON_WEBHOOK_HEADERS") or "")
        if raw_extra:
            try:
                extras = json.loads(raw_extra)
                if isinstance(extras, dict):
                    headers.update({str(k): str(v) for k, v in extras.items()})
            except Exception:
                _log.warning("RECON_WEBHOOK_HEADERS is not valid JSON; ignoring")

        secret = (keys.get("RECON_WEBHOOK_SECRET")
                  or os.environ.get("RECON_WEBHOOK_SECRET") or "")
        if secret:
            sig = hmac.new(secret.encode("utf-8"), body,
                            hashlib.sha256).hexdigest()
            headers["X-Recon-Signature"] = f"sha256={sig}"

        # Issue the POST. 10s timeout - a stalled receiver should not
        # keep the investigation hanging. Timeout + 4xx/5xx are both
        # reported as `ok: false` with an `error_type` the frontend
        # can colour-code.
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(url, data=body, headers=headers) as r:
                    status = r.status
                    text = (await r.text())[:200] if r.status >= 400 else ""
        except Exception as e:
            return {"source": "webhook", "ok": False,
                    "error": str(e)[:200], "error_type": "unreachable"}

        if status >= 400:
            return {"source": "webhook", "ok": False,
                    "error": f"HTTP {status}: {text}",
                    "error_type": "http_error",
                    "http_status": status}
        return {"source": "webhook", "ok": True,
                "http_status": status,
                "bytes_sent": len(body),
                "verdict": verdict}


def _worst_verdict(results: List[AnalysisResult]) -> str:
    """Pick the single worst verdict across all result rows. UNKNOWN
    is the fallback when nothing fires - matches the frontend's
    threshold-gate behaviour."""
    worst = "UNKNOWN"
    for r in results:
        v = r.verdict or "UNKNOWN"
        if _VERDICT_RANK.get(v, 0) > _VERDICT_RANK.get(worst, 0):
            worst = v
    return worst


def _build_payload(artifact: Artifact,
                    all_results: List[AnalysisResult],
                    found: List[AnalysisResult],
                    verdict: str) -> Dict[str, Any]:
    """Shape the JSON payload. Kept deliberately flat + stable so
    downstream automations can parse by top-level keys."""
    return {
        "event":        "recon.investigation_complete",
        "sent_at":      datetime.now(timezone.utc).isoformat(),
        "artifact":     artifact.model_dump(),
        "verdict":      verdict,
        "worst_score":  _SCORE_FOR.get(verdict, 30),
        "sources_hit":  [r.source for r in found],
        "summary":      _rollup_summary(found, verdict),
        "results":      [r.model_dump() for r in all_results],
    }


def _rollup_summary(found: List[AnalysisResult], verdict: str) -> str:
    """Human-readable one-liner that fits in Slack/Teams fallback-text.
    Analysts eyeball this in the channel without clicking through."""
    n = len(found)
    sources = ", ".join(r.source for r in found[:5])
    tail = "..." if n > 5 else ""
    return f"RECON {verdict}: {n} source{'s' if n != 1 else ''} fired ({sources}{tail})"


register(WebhookConnector)
