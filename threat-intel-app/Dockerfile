# Stage 1: Build React frontend
FROM node:20-alpine AS frontend-build

WORKDIR /frontend

COPY frontend/package*.json ./
RUN npm install --legacy-peer-deps

COPY frontend/ ./
RUN npm run build

# Stage 2: Python backend + built frontend
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/

# Fetch the MITRE ATT&CK STIX dataset at build time (~47 MB, not committed to
# git). Powers the Threat Actors browser + technique/group lookups. Parsed once
# at startup and cached, so no runtime cost. Non-fatal: if MITRE's host is down,
# remove any partial file and continue — the app falls back to its built-in
# actor list rather than failing the whole deploy.
RUN mkdir -p backend/intel/mitre \
    && (curl -fSL --retry 3 --retry-delay 2 \
         -o backend/intel/mitre/enterprise-attack.json \
         https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json \
        || (echo "WARNING: MITRE ATT&CK STIX download failed; Threat Actors browser will be empty this build" \
            && rm -f backend/intel/mitre/enterprise-attack.json))

COPY --from=frontend-build /frontend/build ./frontend/build

RUN mkdir -p /app/data

EXPOSE 8000

CMD ["python", "backend/main.py"]
