#!/usr/bin/env bash
# Populates vendor/ with the round-4 detection/data corpora consumed by:
#   - intel/sublime_rules.py     (Sublime email detection)
#   - intel/chronicle_rules.py   (Google Chronicle YARA-L)
#   - intel/olafhartong_th.py    (olafhartong ThreatHunting + sentinel-attack)
#   - intel/attack_datasets.py   (Splunk attack_data labelled fixtures)
#
# Each clone is --depth=1. Idempotent: re-running fast-forwards.

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

clone_or_update "sublime-rules"                  "https://github.com/sublime-security/sublime-rules.git"
clone_or_update "chronicle-detection-rules"      "https://github.com/chronicle/detection-rules.git"
clone_or_update "olafhartong-threathunting"      "https://github.com/olafhartong/ThreatHunting.git"
clone_or_update "sentinel-attack"                "https://github.com/BlueTeamLabs/sentinel-attack.git"
clone_or_update "splunk-attack-data"             "https://github.com/splunk/attack_data.git"

echo "All round-4 detection corpora present in $VENDOR/"
