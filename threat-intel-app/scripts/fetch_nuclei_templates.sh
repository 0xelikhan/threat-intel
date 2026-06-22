#!/usr/bin/env bash
# Populates vendor/nuclei-templates so backend/intel/nuclei_index.py can build
# its CVE → public-detection-template index. Idempotent: re-running fast-forwards.
#
# Usage:  ./scripts/fetch_nuclei_templates.sh
#
# The CVE enricher works fine without this — nuclei lookups return [] when
# the dir is missing — but having the index populated gives the analyst
# a concrete signal beyond CVSS + EPSS + KEV. The repo is ~250 MB; clone
# is depth=1 so it stays around 30 MB.

set -euo pipefail

REPO_URL="https://github.com/projectdiscovery/nuclei-templates.git"
TARGET="$(cd "$(dirname "$0")/.." && pwd)/vendor/nuclei-templates"

mkdir -p "$(dirname "$TARGET")"

if [ -d "$TARGET/.git" ]; then
    echo "Updating existing nuclei-templates clone at $TARGET"
    git -C "$TARGET" fetch --depth=1 origin
    git -C "$TARGET" reset --hard origin/HEAD
else
    echo "Cloning nuclei-templates (depth=1) into $TARGET"
    git clone --depth=1 "$REPO_URL" "$TARGET"
fi

# Print a quick summary so the operator can confirm.
TEMPLATES_WITH_CVE=$(grep -rl "cve-id:" "$TARGET" --include='*.yaml' 2>/dev/null | wc -l)
echo "Done. $TEMPLATES_WITH_CVE templates with cve-id metadata available."
