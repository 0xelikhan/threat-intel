#!/usr/bin/env bash
# Fetch MISP Galaxy clusters into backend/intel/misp_galaxy/.
#
# Run after a clean checkout (or to refresh stale clusters). Required at
# build time so the lookup index has something to index against.
#
# Source: github.com/MISP/misp-galaxy/clusters (MIT, MISP Project)

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${ROOT}/backend/intel/misp_galaxy"
BASE="https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters"

mkdir -p "${DEST}"

CLUSTERS=(
  # Core actor + malware family clusters (round-5)
  threat-actor.json
  malpedia.json
  ransomware.json
  rat.json
  tool.json

  # Round-16: cross-walk + canonicalisation clusters
  mitre-intrusion-set.json       # MITRE's curated G#### actor catalog
  mitre-tool.json                # S#### tool catalog with technique links
  microsoft-activity-group.json  # Microsoft Storm-/Typhoon-style naming
  sector.json                    # canonical industry sectors
  target-information.json        # country profiles (calling-code, lang, …)
)

for cluster in "${CLUSTERS[@]}"; do
  url="${BASE}/${cluster}"
  out="${DEST}/${cluster}"
  echo "Fetching ${cluster}..."
  if curl -sS -L --max-time 60 -o "${out}.tmp" "${url}"; then
    mv "${out}.tmp" "${out}"
    bytes=$(wc -c <"${out}" | tr -d ' ')
    echo "  OK · ${bytes} bytes"
  else
    rm -f "${out}.tmp"
    echo "  FAIL — leaving previous version in place if any" >&2
  fi
done

echo "Done. Clusters at ${DEST}/"
ls -la "${DEST}/"
