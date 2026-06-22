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

# awesome-yara deep-walk additions (13 net-new corpora):
clone_or_update "ditekshen-detection"           "https://github.com/ditekshen/detection.git"
clone_or_update "delivrto-detections"           "https://github.com/delivr-to/detections.git"
clone_or_update "filescanio-fsyara"             "https://github.com/filescanio/fsYara.git"
clone_or_update "chronicle-gcti"                "https://github.com/chronicle/GCTI.git"
clone_or_update "conventionengine"              "https://github.com/stvemillertime/ConventionEngine.git"
clone_or_update "inquest-yara-rules"            "https://github.com/InQuest/yara-rules.git"
clone_or_update "jeff0falltrades-yara"          "https://github.com/jeFF0Falltrades/YARA-Signatures.git"
clone_or_update "intezer-yara-rules"            "https://github.com/intezer/yara-rules.git"
clone_or_update "rapid7-labs"                   "https://github.com/rapid7/Rapid7-Labs.git"
clone_or_update "securitymagic-yara"            "https://github.com/securitymagic/yara.git"
clone_or_update "f0wl-yara"                     "https://github.com/f0wl/yara_rules.git"
clone_or_update "cystack-stealer-fingerprints"  "https://github.com/cystack/stealer-fingerprints.git"
clone_or_update "operation-epic-fury"           "https://github.com/paolocostanzo/operation-epic-fury-rules.git"

echo "All 20 YARA corpora present in $VENDOR/"
