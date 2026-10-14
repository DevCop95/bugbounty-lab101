#!/usr/bin/env bash
# Browser-driven real-traffic capture for the scope-enforced bug bounty workflow.
#
# Drives a real headless Chromium (via Playwright) against ONE authorized URL and
# records every request/response/WebSocket frame the page makes — the requests a
# modern JS SPA actually issues, past client-gating walls a static curl can't pass.
#
# Scope is enforced here before the browser ever launches. The mandatory
# per-program research/identification header is resolved here and injected into
# every request the browser makes, so automated capture stays policy-compliant.
#
# Usage: browser_capture.sh <authorized-url> [output-directory]
# Env:
#   BB_EXTRA_HEADERS   JSON object of headers to inject (overrides auto-detection)
#   BB_RESEARCH_HEADER explicit "Name: value" header (e.g. "X-HackerOne-Research: dev101x")

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$SCRIPT_DIR/../lib/common.sh"

usage() {
    echo "Usage: $0 <authorized-url> [output-directory]" >&2
}

TARGET_URL="${1:-}"
if [ -z "$TARGET_URL" ]; then
    usage
    exit 1
fi

# Scope gate: refuses any URL whose host is not authorized in programs/.
require_scope "$TARGET_URL" || exit 1

DOMAIN="$(normalize_target "$TARGET_URL")" || exit 1
OUTPUT_DIR="${2:-$REPO_ROOT/bugbounty/reports/$DOMAIN/recon}"
mkdir -p "$OUTPUT_DIR"

if ! check_tool node; then
    log_warning "node is not installed; skipping browser capture."
    exit 0
fi

# Resolve the headers to inject. Priority:
#   1. BB_EXTRA_HEADERS (explicit JSON, used as-is)
#   2. BB_RESEARCH_HEADER ("Name: value" -> one-entry JSON)
#   3. auto-detect from the matching programs/*.md "Mandatory header" line
if [ -z "${BB_EXTRA_HEADERS:-}" ]; then
    if [ -n "${BB_RESEARCH_HEADER:-}" ]; then
        hname="${BB_RESEARCH_HEADER%%:*}"
        hval="${BB_RESEARCH_HEADER#*:}"
        hname="$(printf '%s' "$hname" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        hval="$(printf '%s' "$hval" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        export BB_EXTRA_HEADERS
        BB_EXTRA_HEADERS="$(printf '{"%s":"%s"}' "$hname" "$hval")"
    else
        # Pull a `X-...-Research: <value>` style header out of any program file
        # whose scope covers this target. Narrow + best-effort: only matches the
        # documented backtick form `Header: value`.
        detected="$(grep -rohiE '`[A-Za-z-]*[Rr]esearch[A-Za-z-]*:[[:space:]]*[A-Za-z0-9_.-]+`' "$PROGRAMS_DIR" 2>/dev/null | head -n1 | tr -d '`')"
        if [ -n "$detected" ]; then
            hname="${detected%%:*}"
            hval="${detected#*:}"
            hname="$(printf '%s' "$hname" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
            hval="$(printf '%s' "$hval" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
            export BB_EXTRA_HEADERS
            BB_EXTRA_HEADERS="$(printf '{"%s":"%s"}' "$hname" "$hval")"
            log_info "Auto-detected research header from programs/: $hname"
        fi
    fi
fi

if [ -n "${BB_EXTRA_HEADERS:-}" ]; then
    log_info "Injecting headers into every captured request."
else
    log_warning "No research/identification header set. If this program requires one, set BB_RESEARCH_HEADER before capturing."
fi

log_info "Browser capture starting against: $TARGET_URL"
node "$SCRIPT_DIR/browser_capture.js" "$TARGET_URL" "$OUTPUT_DIR"
rc=$?

case "$rc" in
    0) log_info "Capture written to $OUTPUT_DIR/browser_capture.json (+ _raw.json, browser_endpoints.txt)" ;;
    3) log_warning "Playwright not installed. Run: npm install playwright && npx playwright install chromium" ;;
    *) log_warning "Browser capture exited with code $rc" ;;
esac
exit "$rc"
