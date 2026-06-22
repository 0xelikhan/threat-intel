#!/usr/bin/env bash
# Populates vendor/ with round-7 corpora.
#
# Live-API sources (MSRC, Shodan InternetDB, vendor RSS, OSV, OpenSSF
# Scorecards, GitHub /meta, cloud-provider feeds) need no vendoring.

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

# ET Open Suricata rules — packaged tarball; we clone the GitHub mirror
# maintained by Emerging Threats.
clone_or_update "emerging-threats-open" "https://github.com/oisf/emerging-threats-archive.git" || true

# Snort Community rules — Cisco-published mirror, depth=1
clone_or_update "snort-community"       "https://github.com/sweetsoftware/snort3-community-rules.git" || true

# FireHOL blocklists — Apache-2.0, ~400 IP blocklists
clone_or_update "firehol-blocklists"    "https://github.com/firehol/blocklist-ipsets.git"

# ATT&CK for Mobile (Apache-2.0 STIX)
MOBILE_DEST="$ROOT/backend/intel/mitre/mobile-attack.json"
if [ ! -f "$MOBILE_DEST" ]; then
    echo "Fetching ATT&CK for Mobile JSON..."
    curl -fsSL -o "$MOBILE_DEST" \
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json"
fi

# Mozilla Public Suffix List — single file, MPL-2.0 on the data
PSL_DIR="$VENDOR/publicsuffix"
mkdir -p "$PSL_DIR"
if [ ! -f "$PSL_DIR/list.dat" ]; then
    echo "Fetching Public Suffix List..."
    curl -fsSL -o "$PSL_DIR/list.dat" \
        "https://publicsuffix.org/list/public_suffix_list.dat"
fi

# Azure service tags — operator must download manually because Microsoft
# rotates the JSON filename weekly behind a redirect. We mkdir the dir
# so the loader has somewhere to look.
mkdir -p "$VENDOR/azure-service-tags"

# Optional Apple/Adobe RSS + Oracle JSON — live-fetched, no vendoring needed.
# Optional ransomwhe.re dataset (operator downloads addresses.json once)
mkdir -p "$VENDOR/ransomwhere"

# Optional NIST OSCAL + ETW + GuardDuty operator overrides
mkdir -p "$VENDOR/nist-oscal" "$VENDOR/etw" "$VENDOR/guardduty"

# Optional ETDA cybermonitor (BSD-2)
clone_or_update "etda-cybermonitor"     "https://github.com/etda-pt/cybermonitor.git" || true

echo "Round-7 corpora staged."
