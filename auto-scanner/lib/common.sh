#!/bin/bash
# ============================================

# Generated reports and temporary evidence are private by default.
umask 077
# common.sh — Shared library for auto-scanner
# ============================================
# Source this file from any script:
#   source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
# or from within lib/:
#   source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
# ============================================

# Version
# shellcheck disable=SC2034
BB_VERSION="1.1"

# ── Colors ──────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# ── Logging ─────────────────────────────────────────────────────────
log_info()    { echo -e "${GREEN}[✓]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[✗]${NC} $1"; }
log_action()  { echo -e "${BLUE}[→]${NC} $1"; }
log_tool()    { echo -e "${WHITE}[⚙]${NC} Using: $1"; }

# ── Repository paths and scope authorization ───────────────────────
COMMON_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$COMMON_LIB_DIR/../.." && pwd)"
readonly COMMON_LIB_DIR REPO_ROOT
readonly PROGRAMS_DIR="$REPO_ROOT/programs"
readonly SCOPE_GUARD="$REPO_ROOT/scripts/scope_guard.py"

normalize_target() {
    python3 "$SCOPE_GUARD" --normalize "$1"
}

require_scope() {
    local result
    local programs_dir="${2:-$PROGRAMS_DIR}"
    if ! result=$(python3 "$SCOPE_GUARD" --programs-dir "$programs_dir" "$1"); then
        log_error "Target authorization failed"
        return 1
    fi
    log_info "Scope authorized: ${result%%$'\t'*} (${result#*$'\t'})"
}

scope_filter_file() {
    local input_file="$1"
    local output_file="$2"
    local programs_dir="${3:-$PROGRAMS_DIR}"
    local candidate
    : > "$output_file"
    while IFS= read -r candidate; do
        [ -n "$candidate" ] || continue
        if python3 "$SCOPE_GUARD" --programs-dir "$programs_dir" "$candidate" >/dev/null 2>&1; then
            printf '%s\n' "$candidate" >> "$output_file"
        fi
    done < "$input_file"
}

# ── Domain parsing ──────────────────────────────────────────────────
# Usage: DOMAIN=$(parse_domain "https://example.com/path")
parse_domain() {
    echo "$1" | sed -E 's|^https?://||' | sed 's|/.*||' | sed 's|:.*||'
}

# Usage: PROTOCOL=$(parse_protocol "https://example.com")
parse_protocol() {
    echo "$1" | grep -q "^https" && echo "https" || echo "http"
}

# ── Tool checking ──────────────────────────────────────────────────
# Usage: if check_tool nmap; then ... fi
check_tool() {
    command -v "$1" &>/dev/null
}

# ── Safe temporary directory ────────────────────────────────────────
# Usage: safe_tmpdir TEMP_DIR "autopentest"
# The caller owns the EXIT trap so it is registered in the current shell.
safe_tmpdir() {
    local variable_name="$1"
    local prefix="${2:-bblab}"
    local tmpdir
    tmpdir=$(mktemp -d "/tmp/${prefix}.XXXXXX")
    printf -v "$variable_name" '%s' "$tmpdir"
}

cleanup_tmpdir() {
    [ -z "${1:-}" ] || rm -rf -- "$1"
}

# ── Script directory resolution ─────────────────────────────────────
# Usage: SCRIPT_DIR=$(resolve_script_dir)
resolve_script_dir() {
    cd "$(dirname "${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}")" && pwd
}

# ── Banner printer ──────────────────────────────────────────────────
print_banner() {
    local title="$1"
    local subtitle="${2:-}"
    # shellcheck disable=SC2034
    local width=66
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    printf "║  %-62s  ║\n" "$title"
    if [ -n "$subtitle" ]; then
        printf "║  %-62s  ║\n" "$subtitle"
    fi
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ── Section printer ────────────────────────────────────────────────
print_section() {
    echo ""
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${MAGENTA}  $1${NC}"
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
}
