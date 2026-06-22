#!/usr/bin/env bash
# Populates vendor/ with round-6 corpora.
# Each clone is --depth=1; idempotent re-runs fast-forward.
#
# Live-API sources (Shodan InternetDB, HIBP, OpenSSF Scorecards, Red Hat
# Security Data, OSV.dev, OpenPhish) require no vendoring — they're
# fetched at runtime.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="$ROOT/vendor"
mkdir -p "$VENDOR"

clone_or_update() {
    local name="$1"
    local url="$2"
    local target="$VENDOR/$name"
    if [ -d "$target/.git" ]; then
        echo "Updating $name"
        git -C "$target" fetch --depth=1 origin
        git -C "$target" reset --hard origin/HEAD
    else
        echo "Cloning $name"
        git clone --depth=1 "$url" "$target"
    fi
}

clone_or_update "trickest-cve"                "https://github.com/trickest/cve.git"
clone_or_update "mvt"                          "https://github.com/mvt-project/mvt.git"
clone_or_update "etda-cybermonitor"            "https://github.com/etda-pt/cybermonitor.git" || true
clone_or_update "payloadsallthethings"         "https://github.com/swisskyrepo/PayloadsAllTheThings.git"

# MITRE ATT&CK for ICS — single STIX JSON, fetch with curl into the
# same intel/mitre/ dir as the Enterprise matrix.
ICS_DEST="$ROOT/backend/intel/mitre/ics-attack.json"
if [ ! -f "$ICS_DEST" ]; then
    echo "Fetching ATT&CK for ICS JSON..."
    curl -fsSL -o "$ICS_DEST" \
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json"
fi

# MITRE CAPEC — single XML, vendored in vendor/capec/.
CAPEC_DIR="$VENDOR/capec"
mkdir -p "$CAPEC_DIR"
if [ ! -f "$CAPEC_DIR/capec_latest.xml" ]; then
    echo "Fetching CAPEC XML..."
    curl -fsSL -o "$CAPEC_DIR/capec_latest.xml" \
        "https://capec.mitre.org/data/xml/capec_latest.xml"
fi

# CSAF vendor advisories — operator-configurable. We don't bulk-fetch
# every vendor's published CSAF tree; that's too much disk. Instead the
# operator drops per-vendor CSAF JSON into vendor/csaf/<vendor>/ as
# their incident workflow requires.
CSAF_DIR="$VENDOR/csaf"
mkdir -p "$CSAF_DIR"
if [ ! -d "$CSAF_DIR/cisco" ] && [ ! -d "$CSAF_DIR/redhat" ]; then
    echo "CSAF vendor dirs are empty — module skips silently until populated."
    echo "  See https://www.first.org/csaf/csaf_listing for known feeds."
fi

echo "Round-6 vendored corpora staged."
