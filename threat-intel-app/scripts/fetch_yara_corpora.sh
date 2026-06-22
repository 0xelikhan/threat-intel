#!/usr/bin/env bash
# Populates vendor/ with the 7 YARA rule corpora referenced by
# backend/intel/yara_scanner.py RULE_SOURCES (beyond signature-base /
# Mandiant-RTC / Yara-Rules, which are already vendored).
#
# Each clone is --depth=1 to keep the disk footprint manageable.
# Re-running fast-forwards.

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

clone_or_update "reversinglabs-yara-rules"      "https://github.com/reversinglabs/reversinglabs-yara-rules.git"
clone_or_update "volexity-threat-intel"         "https://github.com/volexity/threat-intel.git"
clone_or_update "eset-malware-ioc"              "https://github.com/eset/malware-ioc.git"
clone_or_update "trellix-atr-yara"              "https://github.com/advanced-threat-research/Yara-Rules.git"
clone_or_update "bartblaze-yara"                "https://github.com/bartblaze/Yara-rules.git"
clone_or_update "threathunting-keywords-yara"   "https://github.com/mthcht/ThreatHunting-Keywords-yara-rules.git"
clone_or_update "malcontent"                    "https://github.com/chainguard-dev/malcontent.git"

echo "All 7 YARA corpora present in $VENDOR/"
