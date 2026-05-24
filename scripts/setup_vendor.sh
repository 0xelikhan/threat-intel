#!/usr/bin/env bash
# Clone every third-party repo RECON depends on into threat-intel-app/vendor/
# and download the MITRE ATT&CK STIX dataset. Idempotent: re-running skips
# directories that already exist.
#
# Usage:
#   bash scripts/setup_vendor.sh           # clone everything
#   FORCE=1 bash scripts/setup_vendor.sh   # re-clone (rm -rf first)

set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="$ROOT/threat-intel-app/vendor"
MITRE_DIR="$ROOT/threat-intel-app/backend/intel/mitre"

mkdir -p "$VENDOR" "$MITRE_DIR"

clone() {
  local url="$1"
  local name="$2"
  local dest="$VENDOR/$name"
  if [[ -n "$FORCE" && -d "$dest" ]]; then rm -rf "$dest"; fi
  if [[ -d "$dest" ]]; then
    echo "  [skip] $name (already present)"
  else
    echo "  [clone] $name"
    git clone --depth 1 "$url" "$dest"
  fi
}

echo "=> vendor repos"
clone https://github.com/OpenCTI-Platform/opencti          opencti
clone https://github.com/MISP/misp-warninglists            misp-warninglists
clone https://github.com/SigmaHQ/sigma                     sigma
clone https://github.com/elastic/detection-rules           elastic-rules
clone https://github.com/smicallef/spiderfoot              spiderfoot
clone https://github.com/TheHive-Project/Cortex-Analyzers  cortex-analyzers
clone https://github.com/kbandla/APTnotes                  aptnotes
clone https://github.com/Neo23x0/signature-base            signature-base
clone https://github.com/redcanaryco/atomic-red-team       atomic-red-team

echo "=> MITRE ATT&CK enterprise dataset"
if [[ -f "$MITRE_DIR/enterprise-attack.json" && -z "$FORCE" ]]; then
  echo "  [skip] enterprise-attack.json (already present)"
else
  curl -fsSL \
    -o "$MITRE_DIR/enterprise-attack.json" \
    https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
  echo "  [ok] enterprise-attack.json downloaded"
fi

echo "=> done. RECON's intel modules expect vendor/ and backend/intel/mitre/ to be present."
