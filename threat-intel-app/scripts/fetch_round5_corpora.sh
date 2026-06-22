#!/usr/bin/env bash
# Populates vendor/ with the round-5 corpora consumed by the new loaders.
# Each clone is --depth=1. Idempotent: re-running fast-forwards.
#
# Note: CodeQL is huge (~1GB full). The fetcher does a SPARSE-CHECKOUT
# limited to security queries in each language so the on-disk footprint
# stays around 150MB. RECON falls back to a built-in subset if CodeQL
# isn't fetched.

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

clone_or_update "stratus-red-team"              "https://github.com/DataDog/stratus-red-team.git"
clone_or_update "falco-rules"                    "https://github.com/falcosecurity/rules.git"
clone_or_update "owasp-crs"                      "https://github.com/coreruleset/coreruleset.git"
clone_or_update "malapi-io"                      "https://github.com/mrd0x/MalAPI.io.git"
clone_or_update "ghsa-advisory-database"         "https://github.com/github/advisory-database.git"

# CodeQL — sparse-checkout, security queries only.
CODEQL_DIR="$VENDOR/codeql"
if [ ! -d "$CODEQL_DIR/.git" ]; then
    echo "Setting up CodeQL sparse-checkout..."
    git clone --depth=1 --filter=blob:none --sparse \
        https://github.com/github/codeql.git "$CODEQL_DIR"
    (
        cd "$CODEQL_DIR"
        git sparse-checkout set \
            "javascript/ql/src/Security" \
            "python/ql/src/Security"     \
            "java/ql/src/Security"       \
            "csharp/ql/src/Security"     \
            "cpp/ql/src/Security"        \
            "go/ql/src/Security"         \
            "ruby/ql/src/Security"       \
            "swift/ql/src/Security"
    )
else
    echo "Updating CodeQL (sparse)..."
    git -C "$CODEQL_DIR" fetch --depth=1 origin
    git -C "$CODEQL_DIR" reset --hard origin/HEAD
fi

# D3FEND vendored JSON-LD — small static file. The MITRE-published
# offensive-to-defensive mapping is downloadable from d3fend.mitre.org.
# Operator can curl it into place manually; loader uses a built-in
# fallback subset when missing.
D3FEND_DIR="$VENDOR/d3fend"
mkdir -p "$D3FEND_DIR"
if [ ! -f "$D3FEND_DIR/attack_to_defend.json" ]; then
    echo "D3FEND vendored JSON not present at $D3FEND_DIR/attack_to_defend.json."
    echo "  (Module falls back to built-in subset — operator can populate later.)"
fi

echo "All round-5 corpora ready."
