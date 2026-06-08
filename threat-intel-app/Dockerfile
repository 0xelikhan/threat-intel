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

# ─── Build-time intel-data fetch ────────────────────────────────────────────
# Every dataset below uses the same shape:
#   1. curl with retries; on transport failure, rm the partial file
#   2. wc -l the result against a per-file minimum-lines floor
#   3. if under floor, treat it as a failed download (rm + warn)
#
# Failure handling at the bottom of each block:
#   - Critical datasets (MITRE STIX, any MISP galaxy) → fail the build if
#     missing/under-floor. These power core features; shipping a deploy
#     without them silently degrades the AI verdict quality.
#   - Optional datasets (firehol netsets, ipsum, phishing-db) → warn but
#     don't fail. They boost confidence-engine scoring but the platform
#     functions without them. A transient upstream outage shouldn't brick
#     a deploy.
#
# Helper: `_assert_min_lines <file> <min>` rms the file if it's under the
# floor (so caller can detect with `test -f`). Defined inline because
# Dockerfile RUN doesn't share state across instructions.

# MITRE ATT&CK STIX (~47 MB) — CRITICAL, powers Threat Actors browser +
# every group/technique lookup.
RUN mkdir -p backend/intel/mitre \
    && curl -fSL --retry 3 --retry-delay 2 \
         -o backend/intel/mitre/enterprise-attack.json \
         https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json \
       || (echo "WARNING: MITRE ATT&CK STIX download failed" \
           && rm -f backend/intel/mitre/enterprise-attack.json) \
    && if [ -f backend/intel/mitre/enterprise-attack.json ]; then \
         lines=$(wc -l < backend/intel/mitre/enterprise-attack.json); \
         if [ "$lines" -lt 100 ]; then \
           echo "ERROR: enterprise-attack.json is suspiciously small ($lines lines)"; \
           rm -f backend/intel/mitre/enterprise-attack.json; \
         else \
           echo "OK: MITRE STIX ($lines lines)"; \
         fi; \
       fi \
    && if [ ! -f backend/intel/mitre/enterprise-attack.json ]; then \
         echo "FATAL: MITRE STIX missing — refuse to ship a degraded image"; \
         exit 1; \
       fi \
    && chown -R recon:recon backend/intel/mitre

# MISP galaxy clusters (~10 MB) — CRITICAL. Augments AI-emitted threat
# actor / malware family with country, aliases, sectors, refs. Per-cluster
# minimum-line floor of 100 catches a corrupt download where the file
# exists but isn't valid JSON content.
RUN mkdir -p backend/intel/misp_galaxy \
    && failed_clusters="" \
    && for cluster in threat-actor malpedia ransomware rat tool; do \
         curl -fSL --retry 3 --retry-delay 2 \
           -o "backend/intel/misp_galaxy/${cluster}.json" \
           "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/${cluster}.json" \
         || (echo "WARNING: MISP galaxy ${cluster}.json download failed" \
             && rm -f "backend/intel/misp_galaxy/${cluster}.json"); \
         if [ -f "backend/intel/misp_galaxy/${cluster}.json" ]; then \
           lines=$(wc -l < "backend/intel/misp_galaxy/${cluster}.json"); \
           if [ "$lines" -lt 100 ]; then \
             echo "ERROR: MISP galaxy ${cluster} suspiciously small ($lines lines)"; \
             rm -f "backend/intel/misp_galaxy/${cluster}.json"; \
             failed_clusters="$failed_clusters $cluster"; \
           else \
             echo "OK: MISP galaxy ${cluster} ($lines lines)"; \
           fi; \
         else \
           failed_clusters="$failed_clusters $cluster"; \
         fi; \
       done \
    && if [ -n "$failed_clusters" ]; then \
         echo "FATAL: MISP galaxies missing:$failed_clusters — refuse to ship a degraded image"; \
         exit 1; \
       fi \
    && chown -R recon:recon backend/intel/misp_galaxy

# Offline IP/domain blocklists in vendor/ — OPTIONAL (warn but don't fail).
# Boost the confidence-engine scoring for known-bad IPs/domains; the
# platform functions without them. Each file gets a minimum-lines floor
# check so a 404 from upstream (empty file) is treated as failed even if
# curl exits 0.
RUN mkdir -p vendor/firehol vendor/ipsum vendor/phishing-db \
    && _check_or_drop() { \
         f="$1"; min="$2"; name="$3"; \
         if [ -f "$f" ]; then \
           l=$(wc -l < "$f"); \
           if [ "$l" -lt "$min" ]; then \
             echo "WARN: $name under $min lines ($l) — dropping"; \
             rm -f "$f"; \
           else \
             echo "OK: $name ($l lines)"; \
           fi; \
         fi; \
       } \
    && for list in firehol_level1 firehol_level2 firehol_abusers_1d \
                   malware_filter dshield spamhaus_drop spamhaus_edrop; do \
         curl -fSL --retry 3 --retry-delay 2 \
           -o "vendor/firehol/${list}.netset" \
           "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/${list}.netset" \
         || (echo "WARN: firehol ${list}.netset download failed" \
             && rm -f "vendor/firehol/${list}.netset"); \
         _check_or_drop "vendor/firehol/${list}.netset" 50 "firehol/${list}"; \
       done \
    && (curl -fSL --retry 3 --retry-delay 2 \
          -o vendor/ipsum/ipsum.txt \
          https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt \
        || (echo "WARN: ipsum.txt download failed" \
            && rm -f vendor/ipsum/ipsum.txt)) \
    && _check_or_drop vendor/ipsum/ipsum.txt 1000 "ipsum.txt" \
    && for list in ALL-phishing-domains phishing-domains-ACTIVE; do \
         curl -fSL --retry 3 --retry-delay 2 \
           -o "vendor/phishing-db/${list}.lst" \
           "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/${list}.lst" \
         || (echo "WARN: phishing-db ${list}.lst download failed" \
             && rm -f "vendor/phishing-db/${list}.lst"); \
         _check_or_drop "vendor/phishing-db/${list}.lst" 100 "phishing-db/${list}"; \
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
