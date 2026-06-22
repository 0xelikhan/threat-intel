#!/usr/bin/env bash
# Populates vendor/ with round-8 corpora.
#
# Live-API sources (endoflife.date, Mozilla Observatory) need no vendoring.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="$ROOT/vendor"
mkdir -p "$VENDOR"

clone_or_update() {
    local name="$1"; local url="$2"
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

# OFAC SDN list (public domain, US Treasury). XML is the canonical
# machine-readable form. Re-run weekly — Treasury updates the SDN list
# every few business days.
OFAC_DIR="$VENDOR/ofac"
mkdir -p "$OFAC_DIR"
echo "Fetching OFAC SDN XML..."
curl -fsSL -o "$OFAC_DIR/sdn.xml" \
    "https://www.treasury.gov/ofac/downloads/sdn.xml" \
    || echo "OFAC SDN fetch failed — operator can populate $OFAC_DIR/sdn.xml manually."

# Chrome HSTS preload list — BSD-licensed JSON.
HSTS_DIR="$VENDOR/hsts"
mkdir -p "$HSTS_DIR"
if [ ! -f "$HSTS_DIR/transport_security_state_static.json" ]; then
    echo "Fetching Chromium HSTS preload list..."
    curl -fsSL -o "$HSTS_DIR/transport_security_state_static.json" \
        "https://chromium.googlesource.com/chromium/src/+/main/net/http/transport_security_state_static.json?format=TEXT" \
        || echo "HSTS preload fetch failed — falling back to built-in subset."
fi

# WADComs — MIT, Windows-AD attack reference (markdown corpus)
clone_or_update "wadcoms" "https://github.com/WADComs/WADComs.github.io.git"

# OWASP Cheat Sheet Series — CC-BY-4.0 markdown corpus
clone_or_update "owasp-cheatsheets" "https://github.com/OWASP/CheatSheetSeries.git"

echo "Round-8 corpora staged."
