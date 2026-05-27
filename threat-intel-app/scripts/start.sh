#!/bin/sh
# Container entrypoint. main.py uses bare imports (from config import ...,
# from agents... , from intel...), so the backend/ directory must be the
# working directory / on sys.path. Bind to the platform-provided PORT
# (Azure Container Apps targetPort is 8000) and HOST.
set -e
cd /app/backend
exec uvicorn main:app --host "${HOST:-0.0.0.0}" --port "${PORT:-8000}"
