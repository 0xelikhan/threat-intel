# ─── Stage 1: Build React frontend ───────────────────────────────────────────────
FROM node:20-alpine AS frontend-build

WORKDIR /frontend

COPY frontend/package*.json ./
RUN npm ci --silent

COPY frontend/ ./
RUN npm run build

# ─── Stage 2: Python backend + built frontend ─────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Backend source
COPY backend/ ./backend/

# Built React frontend → served as static files by FastAPI
COPY --from=frontend-build /frontend/build ./frontend/build

# Data directory for config and history
RUN mkdir -p /app/data

# Startup script
COPY scripts/start.sh ./start.sh
RUN chmod +x ./start.sh

EXPOSE 8000

CMD ["./start.sh"]
