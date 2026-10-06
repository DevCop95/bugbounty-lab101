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
BB_VERSION="1.1.0"

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
    # Evidence trail: everything dropped goes here, and unlisted-but-live
    # candidates go to candidates-pending-scope.txt for manual review instead of
    # vanishing silently.
    local discard_log="${output_file%.*}.discarded.txt"
    local candidates_file
    candidates_file="$(dirname "$output_file")/candidates-pending-scope.txt"
    : > "$output_file"
    : > "$discard_log"
    # Input may be absent when an upstream tool (e.g. katana) is not installed —
    # produce an empty output instead of erroring.
    [ -f "$input_file" ] || return 0
    while IFS= read -r candidate; do
        [ -n "$candidate" ] || continue
        if python3 "$SCOPE_GUARD" --programs-dir "$programs_dir" "$candidate" >/dev/null 2>&1; then
            printf '%s\n' "$candidate" >> "$output_file"
        else
            printf '%s\n' "$candidate" >> "$discard_log"
            printf '%s\n' "$candidate" >> "$candidates_file"
        fi
    done < "$input_file"
    if [ -s "$candidates_file" ]; then
        sort -u "$candidates_file" -o "$candidates_file"
    fi
}

# ── Portable IP resolution ──────────────────────────────────────────
# Not every box ships `dig` (dnsutils). Resolve the first A record using
# whatever is available: dig -> host -> getent -> python3. Prints the IP or
# nothing. Usage: ip=$(resolve_ip "$DOMAIN")
resolve_ip() {
    local host="$1" ip=""
    [ -n "$host" ] || return 0
    if command -v dig >/dev/null 2>&1; then
        ip=$(dig +short A "$host" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
    fi
    if [ -z "$ip" ] && command -v host >/dev/null 2>&1; then
        ip=$(host -t A "$host" 2>/dev/null | awk '/has address/{print $NF; exit}')
    fi
    if [ -z "$ip" ] && command -v getent >/dev/null 2>&1; then
        ip=$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1; exit}')
    fi
    if [ -z "$ip" ] && command -v python3 >/dev/null 2>&1; then
        ip=$(python3 -c "import socket,sys
try: print(socket.gethostbyname(sys.argv[1]))
except Exception: pass" "$host" 2>/dev/null)
    fi
    printf '%s' "$ip"
}

# ── CDN / shared-edge safety guard ──────────────────────────────────
# Scope in bug bounty is granted by hostname, but active scans (nmap -sS,
# -p-, --script vuln) hit a resolved IP. If that IP belongs to a CDN /
# shared edge (Cloudflare, Fastly, Akamai, etc.), scanning it is both
# useless (you hit the edge, not the asset) and OUT OF SCOPE — you would be
# port-scanning a third party. These are the published edge ranges of the
# major CDNs; membership is tested with python3's ipaddress module.
# Usage: if cdn_name=$(ip_cdn_owner "1.2.3.4"); then echo "behind $cdn_name"; fi
ip_cdn_owner() {
    local ip="$1"
    [ -n "$ip" ] || return 1
    python3 - "$ip" <<'PY'
import ipaddress, sys
ip = sys.argv[1]
cdn = {
    "Cloudflare": ["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22",
        "103.31.4.0/22","141.101.64.0/18","108.162.192.0/18","190.93.240.0/20",
        "188.114.96.0/20","197.234.240.0/22","198.41.128.0/17","162.158.0.0/15",
        "104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22"],
    "Fastly":   ["151.101.0.0/16","199.232.0.0/16"],
    "Akamai":   ["23.32.0.0/11","23.192.0.0/11","104.64.0.0/10","184.24.0.0/13","2.16.0.0/13"],
    "Incapsula":["198.143.32.0/19","149.126.72.0/21","103.28.248.0/22"],
    "Sucuri":   ["192.88.134.0/23","185.93.228.0/22","66.248.200.0/22"],
}
try:
    addr = ipaddress.ip_address(ip)
except ValueError:
    sys.exit(2)
for name, nets in cdn.items():
    if any(addr in ipaddress.ip_network(n) for n in nets):
        print(name); sys.exit(0)
sys.exit(1)
PY
}

# Returns 0 and prints a warning if DOMAIN resolves behind a known CDN edge,
# so an active-scan stage can skip nmap against a third-party IP.
# Usage: if resolves_behind_cdn "$DOMAIN" "$TARGET_IP"; then skip_active; fi
resolves_behind_cdn() {
    local domain="$1" ip="$2" owner
    [ -n "$ip" ] || return 1
    if owner=$(ip_cdn_owner "$ip"); then
        log_warning "$domain resolves to $ip, which is a $owner edge IP."
        log_warning "Skipping active port/vuln scans: that IP is a third party, not the in-scope asset (out of scope)."
        return 0
    fi
    return 1
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
