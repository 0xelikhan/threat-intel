# Stage 1: Build React frontend
FROM node:20-alpine AS frontend-build

WORKDIR /frontend

# Copy lockfile first so the slow `npm ci` step gets cached whenever only
# source changes (cache invalidates only when package*.json changes).
COPY frontend/package*.json ./
RUN npm ci --legacy-peer-deps --no-audit --no-fund

COPY frontend/ ./
RUN npm run build

# Stage 2: Python backend + built frontend
FROM python:3.11-slim AS runtime

WORKDIR /app

# curl is needed at build time for the MITRE STIX fetch + at runtime for the
# Dockerfile HEALTHCHECK. Both reasons → install once, keep installed.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps in their own layer so source edits don't bust the
# (slow) wheel-fetch cache.
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

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

# Drop root so the container can't write outside /app or escalate via package
# manager / SUID binaries if something goes sideways.
RUN useradd --create-home --shell /usr/sbin/nologin --uid 10001 recon \
    && chown -R recon:recon /app
USER recon

EXPOSE 8000

# Container Apps uses this for liveness/readiness when ingress probes aren't
# configured explicitly. Mirrors the post-deploy curl in the GH Actions
# workflow so a sick container can't stay in rotation.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/api/health || exit 1

CMD ["python", "backend/main.py"]
