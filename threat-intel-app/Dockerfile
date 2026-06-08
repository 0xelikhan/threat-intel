# Stage 1: Build React frontend
# Pull from AWS Public ECR's Docker Hub mirror to avoid the anonymous
# Docker Hub pull rate limit that bricks CI builds when many runs share
# the same egress IP. Image content is identical (the mirror is byte-for-
# byte from docker.io/library/node).
FROM public.ecr.aws/docker/library/node:20-alpine AS frontend-build

WORKDIR /frontend

# Copy lockfile first so the slow `npm ci` step gets cached whenever only
# source changes (cache invalidates only when package*.json changes).
COPY frontend/package*.json ./
RUN npm ci --legacy-peer-deps --no-audit --no-fund

COPY frontend/ ./
RUN npm run build

# Stage 2: Python backend + built frontend.
# Same Docker Hub mirror reason as above.
FROM public.ecr.aws/docker/library/python:3.11-slim AS runtime

WORKDIR /app

# curl is needed at build time for the MITRE STIX fetch + at runtime for the
# Dockerfile HEALTHCHECK. Both reasons → install once, keep installed.
# Drop root user creation into the same layer so we can use --chown on
# subsequent COPYs (avoids a separate chown -R layer that would duplicate
# every file's metadata and bloat the image by ~13 MB).
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin --uid 10001 recon

# Install Python deps in their own layer so source edits don't bust the
# (slow) wheel-fetch cache.
COPY --chown=recon:recon backend/requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY --chown=recon:recon backend/ ./backend/

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
            && rm -f backend/intel/mitre/enterprise-attack.json)) \
    && chown -R recon:recon backend/intel/mitre

# Fetch MISP galaxy clusters (~10 MB total) at build time. Same pattern as
# MITRE STIX above — bundled into the image, loaded lazily on first use.
# Augments AI-emitted threat_actor and malware_family fields with country,
# aliases, target sectors, and external refs. Non-fatal: missing clusters
# just mean lookup_actor / lookup_malware return None for that name.
RUN mkdir -p backend/intel/misp_galaxy \
    && for cluster in threat-actor malpedia ransomware rat tool; do \
         curl -fSL --retry 3 --retry-delay 2 \
           -o "backend/intel/misp_galaxy/${cluster}.json" \
           "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/${cluster}.json" \
         || (echo "WARNING: MISP galaxy ${cluster}.json download failed" \
             && rm -f "backend/intel/misp_galaxy/${cluster}.json"); \
       done \
    && chown -R recon:recon backend/intel/misp_galaxy

# Fetch offline IP/domain blocklists into vendor/ (the path
# intel/feeds_loader.py expects). Without these in the container,
# check_ip() / check_domain() / malicious_ips() / phishing_domains()
# silently return empty in prod, so the "blocklist" badge in the UI
# never fires and the confidence engine misses the 15-point blocklist
# boost. ~10 MB total - cheap. Same per-list || fallback pattern so a
# transient outage of any single source doesn't fail the whole deploy.
RUN mkdir -p vendor/firehol vendor/ipsum vendor/phishing-db \
    && for list in firehol_level1 firehol_level2 firehol_abusers_1d \
                   malware_filter dshield spamhaus_drop spamhaus_edrop; do \
         curl -fSL --retry 3 --retry-delay 2 \
           -o "vendor/firehol/${list}.netset" \
           "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/${list}.netset" \
         || (echo "WARNING: firehol ${list}.netset download failed" \
             && rm -f "vendor/firehol/${list}.netset"); \
       done \
    && (curl -fSL --retry 3 --retry-delay 2 \
          -o vendor/ipsum/ipsum.txt \
          https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt \
        || (echo "WARNING: ipsum.txt download failed" \
            && rm -f vendor/ipsum/ipsum.txt)) \
    && for list in ALL-phishing-domains phishing-domains-ACTIVE; do \
         curl -fSL --retry 3 --retry-delay 2 \
           -o "vendor/phishing-db/${list}.lst" \
           "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/${list}.lst" \
         || (echo "WARNING: phishing-db ${list}.lst download failed" \
             && rm -f "vendor/phishing-db/${list}.lst"); \
       done \
    && chown -R recon:recon vendor

COPY --from=frontend-build --chown=recon:recon /frontend/build ./frontend/build

RUN mkdir -p /app/data && chown recon:recon /app/data

USER recon

EXPOSE 8000

# Container Apps uses this for liveness/readiness when ingress probes aren't
# configured explicitly. Mirrors the post-deploy curl in the GH Actions
# workflow so a sick container can't stay in rotation.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/api/health || exit 1

CMD ["python", "backend/main.py"]
