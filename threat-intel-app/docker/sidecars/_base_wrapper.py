"""Shared Flask wrapper used by every RECON file-analyzer sidecar.

Each sidecar is a thin container that:
  1. Receives a POST /analyze with a multipart file upload
  2. Writes the file to a temp path
  3. Runs the actual tool (Qiling / Speakeasy / Mobsf / …) on it
  4. Returns a JSON report with { verdict, summary, …tool fields }

A single wrapper + overridable `analyze_bytes(data, filename)` keeps
the sidecar containers minimal — each service only ships the tool
install + a 10-line adapter function.
"""

from __future__ import annotations

import logging
import os
import tempfile
from typing import Any, Callable, Dict

from flask import Flask, jsonify, request

logging.basicConfig(level=logging.INFO)
_log = logging.getLogger("recon.sidecar")


def build_app(service_name: str,
               analyze_bytes: Callable[[bytes, str], Dict[str, Any]]) -> Flask:
    """Factory for a sidecar Flask app. `analyze_bytes` is the tool-
    specific adapter; it receives file bytes + filename and returns
    the JSON-serialisable report dict RECON's dispatcher expects."""
    app = Flask(service_name)

    @app.get("/health")
    def _health():
        return jsonify({"service": service_name, "ok": True})

    @app.post("/analyze")
    def _analyze():
        f = request.files.get("file")
        if not f:
            return jsonify({"error": "no file field",
                             "error_type": "invalid_request"}), 400
        filename = request.form.get("filename") or f.filename or "sample"
        data = f.read()
        if not data:
            return jsonify({"error": "empty file",
                             "error_type": "invalid_request"}), 400
        try:
            report = analyze_bytes(data, filename)
            if not isinstance(report, dict):
                return jsonify({"error": "adapter returned non-dict",
                                 "error_type": "adapter_error"}), 500
            return jsonify(report)
        except Exception as e:
            _log.exception("sidecar %s failed", service_name)
            return jsonify({"error": str(e)[:300],
                             "error_type": "runtime_error"}), 500

    @app.errorhandler(404)
    def _not_found(_e):
        return jsonify({"error": "unknown endpoint",
                         "error_type": "invalid_request"}), 404

    return app


def run(service_name: str,
         analyze_bytes: Callable[[bytes, str], Dict[str, Any]],
         default_port: int = 5000):
    """Entry point — each sidecar module calls this at `if __name__ == '__main__'`."""
    port = int(os.environ.get("PORT") or default_port)
    build_app(service_name, analyze_bytes).run(host="0.0.0.0", port=port)
