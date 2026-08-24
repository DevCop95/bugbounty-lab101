#!/usr/bin/env bash
# Passive Shodan CTL integration for the scope-enforced bug bounty workflow.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

usage() {
    echo "Usage: $0 <authorized-domain> <output-directory>" >&2
}

find_recons101x() {
    if [ -n "${SHODAN_RECONSX_BIN:-}" ]; then
        if [ -x "$SHODAN_RECONSX_BIN" ]; then
            printf '%s\n' "$SHODAN_RECONSX_BIN"
            return 0
        fi
        log_warning "SHODAN_RECONSX_BIN is not executable: $SHODAN_RECONSX_BIN"
        return 1
    fi

    if command -v recons101x >/dev/null 2>&1; then
        command -v recons101x
        return 0
    fi

    local vendored="$REPO_ROOT/vendor/shodan_reconsx/scan.sh"
    if [ -x "$vendored" ]; then
        printf '%s\n' "$vendored"
        return 0
    fi

    return 1
}

if [ "$#" -ne 2 ]; then
    usage
    exit 2
fi

TARGET="$1"
OUTPUT_DIR="$2"
RAW_OUTPUT="$OUTPUT_DIR/shodan_reconsx_raw.txt"
HOSTNAMES_OUTPUT="$OUTPUT_DIR/shodan_subdomains.txt"

require_scope "$TARGET" >/dev/null || exit 1
mkdir -p "$OUTPUT_DIR"
: > "$RAW_OUTPUT"
: > "$HOSTNAMES_OUTPUT"

if ! RECONS101X_BIN=$(find_recons101x); then
    log_warning "shodan_reconsx is unavailable; skipping passive Shodan CTL enrichment"
    exit 0
fi

log_tool "shodan_reconsx (passive Shodan CTL hostname enumeration)"
if ! "$RECONS101X_BIN" "$TARGET" --format txt --output "$RAW_OUTPUT"; then
    log_warning "shodan_reconsx could not complete for $TARGET; keeping any partial output"
fi

if [ ! -s "$RAW_OUTPUT" ]; then
    log_warning "shodan_reconsx returned no hostnames for $TARGET"
    exit 0
fi

# The tool emits domain<TAB>hostname. Extract only hostnames, then authorize
# each candidate before it can reach HTTP probing or later pipeline stages.
awk -F '\t' 'NF >= 2 && $2 != "" {print $2}' "$RAW_OUTPUT" | sort -u > "$OUTPUT_DIR/shodan_candidates.txt"
scope_filter_file "$OUTPUT_DIR/shodan_candidates.txt" "$HOSTNAMES_OUTPUT"

COUNT=$(wc -l < "$HOSTNAMES_OUTPUT")
log_info "shodan_reconsx added $COUNT in-scope hostnames"
