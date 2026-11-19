#!/bin/bash
# ============================================
# Bug Bounty Hunter - Complete Framework
# ============================================

set -uo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUGBOUNTY_DIR="$SCRIPT_DIR"
REPORTS_DIR="$BUGBOUNTY_DIR/reports"
TARGETS_DIR="$BUGBOUNTY_DIR/targets"
NOTES_DIR="$BUGBOUNTY_DIR/notes"
# shellcheck source=../auto-scanner/lib/common.sh
source "$BUGBOUNTY_DIR/../auto-scanner/lib/common.sh"

# HackerOne handle - override with: BB_RESEARCHER=otro-handle ./bugbounty-hunter.sh ...
RESEARCHER="${BB_RESEARCHER:-dev101x}"

mkdir -p "$REPORTS_DIR" "$TARGETS_DIR" "$NOTES_DIR" "$PROGRAMS_DIR"

# ============================================
# MAIN FUNCTIONS
# ============================================

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║          BUG BOUNTY HUNTER FRAMEWORK v${BB_VERSION}              ║"
    printf "║          HackerOne · @%-36s║\n" "${RESEARCHER}"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ============================================
# SCOPE SAFETY CHECK
# ============================================
# Before touching a target, requires a scope file in programs/.
# This prevents testing assets outside the authorized scope of a program
# from HackerOne (violating scope can void the bounty or access
# to the program). Use 'new' to create a program scope file.

check_scope() {
    local target="${1:-}"
    local result

    if [ -z "$target" ]; then
        echo -e "${RED}[!] Target is missing${NC}"
        return 1
    fi

    if ! result=$(python3 "$SCOPE_GUARD" --programs-dir "$PROGRAMS_DIR" "$target"); then
        echo -e "${RED}[!] Scope denied for '$target'. Aborting.${NC}"
        return 1
    fi
    SCOPE_TARGET="${result%%$'\t'*}"
    echo -e "${GREEN}[✓] Scope OK - $SCOPE_TARGET covered by $(basename "${result#*$'\t'}")${NC}"
}

state_dir_for() {
    printf '%s/%s/.state\n' "$REPORTS_DIR" "$1"
}

phase_done() {
    [ "${BB_RESUME:-0}" = "1" ] && [ -f "$(state_dir_for "$1")/$2.done" ]
}

mark_phase_done() {
    local sdir
    sdir="$(state_dir_for "$1")"
    mkdir -p "$sdir"
    date -u +%Y-%m-%dT%H:%M:%SZ > "$sdir/$2.done"
}

clear_state_dir() {
    local sdir
    sdir="$(state_dir_for "$1")"
    [ -d "$sdir" ] && rm -rf -- "$sdir"
    return 0
}

# ============================================
# CREATE PROGRAM (scope tracker)
# ============================================

new_program() {
    local NAME="$1"
    local TEMPLATE="$PROGRAMS_DIR/_template.md"
    local DEST="$PROGRAMS_DIR/$NAME.md"

    if [ -z "$NAME" ]; then
        echo -e "${RED}Usage: $0 new <program-name>${NC}"
        return 1
    fi

    if [[ ! "$NAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$ ]]; then
        echo -e "${RED}[!] Program name may only contain letters, numbers, dots, underscores, and hyphens.${NC}"
        return 1
    fi

    if [ -f "$DEST" ]; then
        echo -e "${YELLOW}[!] Already exists: $DEST${NC}"
        return 1
    fi

    if [ -f "$TEMPLATE" ]; then
        python3 - "$TEMPLATE" "$DEST" "$NAME" "$RESEARCHER" <<'PY'
from datetime import datetime, timezone
from pathlib import Path
import sys

src, dst, name, researcher = sys.argv[1:5]
today = datetime.now(timezone.utc).date().isoformat()
content = Path(src).read_text(encoding="utf-8")
content = content.replace("[Program Name]", name)
content = content.replace("[YYYY-MM-DD]", today)
content = content.replace("| **Researcher** | dev101x |", f"| **Researcher** | {researcher} |")
Path(dst).write_text(content, encoding="utf-8")
PY
    else
        printf '# %s\n\n## In Scope\n- \n\n## Out of Scope\n- \n' "$NAME" > "$DEST"
    fi

    echo -e "${GREEN}[✓] Program created: $DEST${NC}"
    echo -e "${YELLOW}    Edit it and add domains/assets in 'In Scope' before scanning.${NC}"
}

# ============================================
# DNS HIJACKING / NETWORK-LEVEL BLOCKING DETECTION
# ============================================
# Some networks (ISP/country) redirect complete categories of domains
# (gambling, adult, streaming, etc.) to an IP sinkhole instead of resolving
# the real domain. If undetected, any scanner ends up "auditing"
# the sinkhole instead of the real target. Compare local resolver against public
# DNS (8.8.8.8 / 1.1.1.1) before launching recon against a new domain,
# especially in gambling/adult/streaming niches.

resolve_check() {
    local HOST="$1"
    local LOCAL_IPS PUBLIC_IPS FIRST_PUBLIC_IP LOCAL_PROBE

    if [ -z "$HOST" ]; then
        echo -e "${RED}Usage: $0 resolve <host>${NC}"
        return 1
    fi

    if ! check_tool dig; then
        LOCAL_IPS=$(resolve_ip "$HOST")
        echo -e "${YELLOW}Local IP:${NC}  ${LOCAL_IPS:-unavailable}"
        echo -e "${YELLOW}[!] 'dig' is not installed; cannot compare against public DNS (8.8.8.8 / 1.1.1.1). Install dnsutils.${NC}"
        return 1
    fi

    LOCAL_IPS=$(timeout 5 dig +short "$HOST" A 2>/dev/null | sort -u)
    PUBLIC_IPS=$( { timeout 5 dig +short @8.8.8.8 "$HOST" A 2>/dev/null; timeout 5 dig +short @1.1.1.1 "$HOST" A 2>/dev/null; } | sort -u)
    FIRST_PUBLIC_IP=$(echo "$PUBLIC_IPS" | head -1)

    echo -e "${YELLOW}Local DNS:${NC}  $(echo "$LOCAL_IPS" | tr '\n' ' ')"
    echo -e "${YELLOW}Public DNS (8.8.8.8+1.1.1.1):${NC} $(echo "$PUBLIC_IPS" | tr '\n' ' ')"

    if [ -z "$LOCAL_IPS" ] || [ -z "$PUBLIC_IPS" ]; then
        echo -e "${YELLOW}[!] Could not compare (some query did not respond).${NC}"
        return 1
    fi

    # Services with anycast/round-robin (GitHub, Cloudflare, etc.) return
    # different IPs to different resolvers without that being a hijack, so
    # a different IP set is NOT sufficient as a signal. The strong signal is
    # CONTENT: if the local IP redirects/serves a blocking page
    # (.gov domain, or words like blocked/restricted/warning/illegal),
    # it's a real sinkhole, not just load balancing. A sinkhole may
    # also close port 443 without responding — we test HTTP:80 as
    # fallback in that case instead of assuming "no response" is clean.
    local first_local
    first_local="$(echo "$LOCAL_IPS" | head -1)"
    
    local probe_tmp
    probe_tmp=$(mktemp "${TMPDIR:-/tmp}/bblab-probe.XXXXXX")
    # shellcheck disable=SC2064
    trap "rm -f '$probe_tmp'" RETURN

    LOCAL_PROBE=$(timeout 8 curl -s -D - -o "$probe_tmp" -m 6 --resolve "$HOST:443:$first_local" "https://$HOST/" 2>/dev/null)
    LOCAL_PROBE="$LOCAL_PROBE $(cat "$probe_tmp" 2>/dev/null)"

    if [ -z "$LOCAL_PROBE" ] || [ "$(echo "$LOCAL_PROBE" | tr -d '[:space:]')" = "" ]; then
        LOCAL_PROBE=$(timeout 8 curl -s -D - -o "$probe_tmp" -m 6 --resolve "$HOST:80:$first_local" "http://$HOST/" 2>/dev/null)
        LOCAL_PROBE="$LOCAL_PROBE $(cat "$probe_tmp" 2>/dev/null)"
    fi
    rm -f "$probe_tmp"

    if echo "$LOCAL_PROBE" | grep -qiE '\.gov(\.[a-z]{2})?[/"'\''>]|blocked|restricted|illegal|advertencia|coljuegos|regulat'; then
        echo -e "${RED}[!] The local IP serves/redirects to what appears to be a blocking page (.gov domain or censorship keywords).${NC}"
        echo -e "${RED}    This IS a network sinkhole (ISP/country), not the real site.${NC}"
        echo -e "${YELLOW}    Use the public IP with curl: curl --resolve $HOST:443:$FIRST_PUBLIC_IP https://$HOST/${NC}"
        return 1
    fi

    if [ -z "$LOCAL_PROBE" ] || [ "$(echo "$LOCAL_PROBE" | tr -d '[:space:]')" = "" ]; then
        echo -e "${YELLOW}[!] The local IP did not respond on 443 or 80 — inconclusive, do not assume it is clean.${NC}"
        echo -e "${YELLOW}    If the domain is in a sensitive niche (gambling/adult/streaming), use the public IP anyway:${NC}"
        echo -e "${YELLOW}    curl --resolve $HOST:443:$FIRST_PUBLIC_IP https://$HOST/${NC}"
        return 1
    fi

    echo -e "${GREEN}[✓] No signs of blocking page — local resolution appears trustworthy.${NC}"
    [ "$LOCAL_IPS" != "$PUBLIC_IPS" ] && echo -e "${YELLOW}    (Different IPs between local and public — normal for CDN/anycast, not alarming by itself)${NC}"
    return 0
}

# ============================================
# PHASE 1: DEEP RECONNAISSANCE
# ============================================

reconnaissance() {
    local TARGET="$1"
    local OUTPUT_DIR="$REPORTS_DIR/$TARGET/recon"
    local TARGET_REGEX="${TARGET//./\\.}"
    local RESEARCH_HEADER=""
    local RATE_LIMIT
    local CRT_DELAY="${BB_CRT_RETRY_DELAY:-3}"
    local -a hdr_args=()
    RESEARCH_HEADER=$(resolve_program_header "$TARGET" "$PROGRAMS_DIR" 2>/dev/null || true)
    [ -n "$RESEARCH_HEADER" ] && hdr_args=(-H "$RESEARCH_HEADER")
    RATE_LIMIT="$(resolve_program_rate_limit "$TARGET" "$PROGRAMS_DIR")"

    mkdir -p "$OUTPUT_DIR" "$OUTPUT_DIR/.baseline"

    echo -e "${CYAN}[1/8] DEEP RECONNAISSANCE - $TARGET (rate-limit: ${RATE_LIMIT} req/s)${NC}"

    echo -e "${YELLOW}[1.1] Subdomain Enumeration${NC}"
    local RAW_SUBDOMAINS="$OUTPUT_DIR/subdomains_raw.txt"
    : > "$RAW_SUBDOMAINS"

    # Always probe the target host itself, even if no subdomains are discovered
    # (e.g. crt.sh down + no subfinder/amass). It is in scope by definition.
    printf '%s\n' "$TARGET" >> "$RAW_SUBDOMAINS"

    if check_tool subfinder; then
        subfinder -d "$TARGET" -silent 2>/dev/null >> "$RAW_SUBDOMAINS" || true
    else
        echo -e "${YELLOW}  [!] subfinder is not installed; continuing${NC}"
    fi
    if check_tool amass; then
        amass enum -passive -d "$TARGET" >> "$RAW_SUBDOMAINS" 2>/dev/null || true
    else
        echo -e "${YELLOW}  [!] amass is not installed; continuing${NC}"
    fi

    # crt.sh — Certificate Transparency, passive, no API key required.
    # crt.sh is frequently flaky (502): validate the body is JSON and retry a
    # couple of times; parse with jq when available, else a safe grep fallback.
    if check_tool curl; then
        local crt_raw=""
        for _ in 1 2 3; do
            crt_raw=$(curl -s -m 15 --connect-timeout 8 "https://crt.sh/?q=%25.${TARGET}&output=json" 2>/dev/null || true)
            case "$crt_raw" in
                "["*) break ;;              # looks like a JSON array → good
                *) crt_raw=""; [ "$CRT_DELAY" -gt 0 ] 2>/dev/null && sleep "$CRT_DELAY" || true ;;
            esac
        done
        if [ -n "$crt_raw" ]; then
            if check_tool jq; then
                printf '%s' "$crt_raw" \
                    | jq -r '.[].name_value' 2>/dev/null \
                    | sed 's/^\*\.//' | grep -iE "\.?${TARGET_REGEX}$" \
                    | sort -u >> "$RAW_SUBDOMAINS" || true
            else
                printf '%s' "$crt_raw" \
                    | grep -oE '"name_value":"[^"]+"' | cut -d'"' -f4 \
                    | sed 's/\\n/\n/g' | sed 's/^\*\.//' \
                    | grep -iE "\.?${TARGET_REGEX}$" | sort -u >> "$RAW_SUBDOMAINS" || true
            fi
        else
            echo -e "${YELLOW}  [!] crt.sh unavailable (502/timeout); skipping CT source${NC}"
        fi

        # certspotter — second Certificate Transparency source, far more stable
        # than crt.sh, no API key needed for basic use. Covers crt.sh's gaps when
        # it 502s.
        local cs_raw
        cs_raw=$(curl -s -m 15 --connect-timeout 8 "https://api.certspotter.com/v1/issuances?domain=${TARGET}&include_subdomains=true&expand=dns_names" 2>/dev/null || true)
        case "$cs_raw" in
            "["*)
                if check_tool jq; then
                    printf '%s' "$cs_raw" \
                        | jq -r '.[].dns_names[]?' 2>/dev/null \
                        | sed 's/^\*\.//' | grep -iE "\.?${TARGET_REGEX}$" \
                        | sort -u >> "$RAW_SUBDOMAINS" || true
                else
                    printf '%s' "$cs_raw" \
                        | grep -oE '"[a-zA-Z0-9.*_-]+\.'"${TARGET_REGEX}"'"' | tr -d '"' \
                        | sed 's/^\*\.//' | sort -u >> "$RAW_SUBDOMAINS" || true
                fi
                ;;
            *)
                echo -e "${YELLOW}  [!] certspotter returned no usable data; skipping${NC}"
                ;;
        esac
    fi

    if [ -x "$BUGBOUNTY_DIR/../auto-scanner/integrations/shodan_reconsx.sh" ]; then
        "$BUGBOUNTY_DIR/../auto-scanner/integrations/shodan_reconsx.sh" \
            "$TARGET" "$OUTPUT_DIR" || true
        [ -f "$OUTPUT_DIR/shodan_subdomains.txt" ] && cat "$OUTPUT_DIR/shodan_subdomains.txt" >> "$RAW_SUBDOMAINS"
    fi

    sort -u "$RAW_SUBDOMAINS" -o "$RAW_SUBDOMAINS"
    scope_filter_file "$RAW_SUBDOMAINS" "$OUTPUT_DIR/subdomains.txt"
    cp "$OUTPUT_DIR/subdomains.txt" "$OUTPUT_DIR/authorized_subdomains.txt"
    python3 "$RECON_UTILS" diff-baseline \
        "$OUTPUT_DIR/authorized_subdomains.txt" \
        --baseline "$OUTPUT_DIR/.baseline/subdomains.txt" \
        --new-out "$OUTPUT_DIR/new_subdomains.txt" || true

    SUBS=$(wc -l < "$OUTPUT_DIR/authorized_subdomains.txt")
    local NEW_SUBS
    NEW_SUBS=$(wc -l < "$OUTPUT_DIR/new_subdomains.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}  ✓ $SUBS authorized subdomains (${NEW_SUBS} new since last baseline)${NC}"

    # BB_PASSIVE_ONLY=1 stops before any stage that touches the target directly
    # (httpx/katana). gau/waybackurls/crt.sh above are passive and still run.
    if [ -n "${BB_PASSIVE_ONLY:-}" ]; then
        echo -e "${YELLOW}  [passive-only] skipping httpx/katana (active stages)${NC}"
    else
        echo -e "${YELLOW}[1.2] HTTP probing${NC}"
        local target_ip
        target_ip="$(resolve_ip "$TARGET")"
        if [ -n "$target_ip" ]; then
            resolves_behind_cdn "$TARGET" "$target_ip" || true
        fi

        # Guard: there are TWO different tools called 'httpx' — ProjectDiscovery's
        # recon httpx (what this pipeline needs) and the Python httpx HTTP-client
        # CLI. Only PD's accepts -silent; if the wrong one is installed, say so
        # instead of failing silently.
        if ! check_tool httpx; then
            echo -e "${YELLOW}  [!] httpx not installed; skipping HTTP probing${NC}"
        elif httpx -version 2>&1 | grep -qi "usage:"; then
            echo -e "${YELLOW}  [!] installed 'httpx' is not ProjectDiscovery httpx (looks like the Python httpx CLI); skipping. Install PD httpx.${NC}"
        else
            # Enriched output: tech, title, server, CNAME, ASN, status — enables
            # subdomain-takeover triage and per-asset tech fingerprinting.
            httpx -l "$OUTPUT_DIR/authorized_subdomains.txt" \
                "${hdr_args[@]}" \
                -rl "$RATE_LIMIT" \
                -td -title -server -cname -asn -status-code -json \
                -o "$OUTPUT_DIR/httpx.json" -silent 2>/dev/null \
                || httpx -l "$OUTPUT_DIR/authorized_subdomains.txt" "${hdr_args[@]}" -rl "$RATE_LIMIT" -o "$OUTPUT_DIR/httpx.txt" -silent 2>/dev/null || true
        fi

        python3 "$RECON_UTILS" parse-httpx \
            "$OUTPUT_DIR/httpx.json" \
            --httpx-txt "$OUTPUT_DIR/httpx.txt" \
            --live-out "$OUTPUT_DIR/live_urls.txt" \
            --tech-out "$OUTPUT_DIR/technologies.txt" \
            --takeover-out "$OUTPUT_DIR/takeover_candidates.txt" || true
        python3 "$RECON_UTILS" diff-baseline \
            "$OUTPUT_DIR/live_urls.txt" \
            --baseline "$OUTPUT_DIR/.baseline/live_urls.txt" \
            --new-out "$OUTPUT_DIR/new_live_urls.txt" || true
        if [ -s "$OUTPUT_DIR/takeover_candidates.txt" ]; then
            echo -e "${RED}  [!] Potential subdomain takeover CNAME candidates detected: $OUTPUT_DIR/takeover_candidates.txt${NC}"
        fi
    fi

    echo -e "${YELLOW}[1.3] Wayback URLs${NC}"
    : > "$OUTPUT_DIR/wayback_raw.txt"
    if check_tool gau; then
        echo "$TARGET" | gau --threads 5 2>/dev/null >> "$OUTPUT_DIR/wayback_raw.txt" || true
    else
        echo -e "${YELLOW}  [!] gau is not installed; continuing${NC}"
    fi
    if check_tool waybackurls; then
        waybackurls "$TARGET" >> "$OUTPUT_DIR/wayback_raw.txt" 2>/dev/null || true
    else
        echo -e "${YELLOW}  [!] waybackurls is not installed; continuing${NC}"
    fi
    sort -u "$OUTPUT_DIR/wayback_raw.txt" -o "$OUTPUT_DIR/wayback_raw.txt"
    scope_filter_file "$OUTPUT_DIR/wayback_raw.txt" "$OUTPUT_DIR/wayback.txt"

    if [ -n "${BB_PASSIVE_ONLY:-}" ]; then
        echo -e "${YELLOW}  [passive-only] skipping katana crawl${NC}"
    else
        echo -e "${YELLOW}[1.4] JS endpoints${NC}"
        # -cs restricts the crawl to the in-scope FQDN so it cannot wander to
        # unlisted subdomains.
        if check_tool katana; then
            katana -u "https://$TARGET" -d 3 -jc \
                "${hdr_args[@]}" \
                -rl "$RATE_LIMIT" \
                -cs "^https?://${TARGET_REGEX}(:[0-9]+)?(/|$)" \
                -o "$OUTPUT_DIR/js_endpoints_raw.txt" -silent 2>/dev/null || true
        else
            echo -e "${YELLOW}  [!] katana not installed; skipping crawl${NC}"
            : > "$OUTPUT_DIR/js_endpoints_raw.txt"
        fi
        scope_filter_file "$OUTPUT_DIR/js_endpoints_raw.txt" "$OUTPUT_DIR/js_endpoints.txt"

        echo -e "${YELLOW}[1.4b] JS secret/endpoint analysis${NC}"
        # Pull endpoints + secrets out of discovered JS (best-effort, optional tools).
        grep -iE '\.js(\?|$)' "$OUTPUT_DIR/js_endpoints.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/js_files.txt" || true
        if check_tool jsluice && [ -s "$OUTPUT_DIR/js_files.txt" ] && check_tool curl; then
            while IFS= read -r jsurl; do
                [ -n "$jsurl" ] || continue
                curl -s -m 15 --connect-timeout 8 "${hdr_args[@]}" "$jsurl" 2>/dev/null | jsluice urls 2>/dev/null || true
            done < "$OUTPUT_DIR/js_files.txt" | sort -u > "$OUTPUT_DIR/js_extracted_urls.txt" || true
        elif ! check_tool jsluice; then
            echo -e "${YELLOW}  [!] jsluice not installed; skipping JS URL extraction${NC}"
        fi
        if check_tool secretfinder && [ -s "$OUTPUT_DIR/js_files.txt" ]; then
            while IFS= read -r jsurl; do
                [ -n "$jsurl" ] || continue
                secretfinder -i "$jsurl" -o cli 2>/dev/null || true
            done < "$OUTPUT_DIR/js_files.txt" >> "$OUTPUT_DIR/js_secrets.txt" || true
        fi
        # Source maps leak original source + internal routes.
        grep -iE '\.js(\?|$)' "$OUTPUT_DIR/js_files.txt" 2>/dev/null \
            | sed -E 's/(\.js)(\?.*)?$/\1.map/' | sort -u > "$OUTPUT_DIR/js_sourcemaps_candidates.txt" || true

        echo -e "${YELLOW}[1.4c] API surface discovery${NC}"
        # Probe common API/spec paths (in-scope host only).
        : > "$OUTPUT_DIR/api_specs.txt"
        if check_tool curl; then
            for sp in /swagger.json /openapi.json /v2/api-docs /v3/api-docs /api-docs /graphql /.well-known/openid-configuration; do
                code=$(curl -s -m 15 --connect-timeout 8 "${hdr_args[@]}" -o /dev/null -w "%{http_code}" "https://${TARGET}${sp}" 2>/dev/null || echo "000")
                [ "$code" = "200" ] && echo "https://${TARGET}${sp}  ($code)" >> "$OUTPUT_DIR/api_specs.txt"
            done
        fi

        echo -e "${YELLOW}[1.4d] Browser-driven real-traffic capture${NC}"
        # Drive a real headless Chromium so we see the requests the SPA actually
        # makes (real headers, XHR/fetch/WS) past client-gating walls a static
        # curl can't pass. Scope-enforced + mandatory research header injected by
        # the wrapper. Optional: skipped cleanly when node/playwright absent.
        if [ -x "$BUGBOUNTY_DIR/../auto-scanner/integrations/browser_capture.sh" ]; then
            "$BUGBOUNTY_DIR/../auto-scanner/integrations/browser_capture.sh" \
                "https://$TARGET" "$OUTPUT_DIR" || true
        fi
    fi

    echo -e "${YELLOW}[1.5] Parameter discovery & URL normalization${NC}"
    python3 "$RECON_UTILS" clean-urls \
        "$OUTPUT_DIR/wayback.txt" \
        "$OUTPUT_DIR/js_endpoints.txt" \
        "$OUTPUT_DIR/browser_urls_in_scope.txt" \
        --out "$OUTPUT_DIR/clean_urls.txt" \
        --params-out "$OUTPUT_DIR/params.txt" \
        --buckets-dir "$OUTPUT_DIR" || true

    if check_tool unfurl && [ -s "$OUTPUT_DIR/wayback.txt" ]; then
        { cat "$OUTPUT_DIR/params.txt"; grep "?" "$OUTPUT_DIR/wayback.txt" 2>/dev/null | unfurl keys 2>/dev/null || true; } \
            | grep -v '^$' | sort -u > "$OUTPUT_DIR/params.tmp" && mv "$OUTPUT_DIR/params.tmp" "$OUTPUT_DIR/params.txt"
    fi
    # Active param mining (optional tools, skipped in passive-only).
    if [ -z "${BB_PASSIVE_ONLY:-}" ]; then
        if check_tool paramspider; then
            paramspider -d "$TARGET" -o "$OUTPUT_DIR/paramspider.txt" 2>/dev/null || true
        fi
        if check_tool arjun; then
            arjun -u "https://$TARGET" -oT "$OUTPUT_DIR/arjun.txt" 2>/dev/null || true
        fi
    fi

    echo -e "${GREEN}[✓] Reconnaissance completed${NC}"
}

# ============================================
# PHASE 2: VULNERABILITY SCANNING
# ============================================

vuln_scan() {
    local TARGET="$1"
    local OUTPUT_DIR="$REPORTS_DIR/$TARGET/vulns"
    local RESEARCH_HEADER=""
    local RATE_LIMIT
    local -a hdr_args=()
    RESEARCH_HEADER=$(resolve_program_header "$TARGET" "$PROGRAMS_DIR" 2>/dev/null || true)
    [ -n "$RESEARCH_HEADER" ] && hdr_args=(-H "$RESEARCH_HEADER")
    RATE_LIMIT="$(resolve_program_rate_limit "$TARGET" "$PROGRAMS_DIR")"

    mkdir -p "$OUTPUT_DIR"

    echo -e "${CYAN}[2/8] VULNERABILITY SCANNING (rate-limit: ${RATE_LIMIT} req/s)${NC}"

    local nuclei_targets="$OUTPUT_DIR/nuclei_targets.txt"
    if [ -s "$OUTPUT_DIR/../recon/live_urls.txt" ]; then
        cp "$OUTPUT_DIR/../recon/live_urls.txt" "$nuclei_targets"
    else
        printf 'https://%s\n' "$TARGET" > "$nuclei_targets"
    fi

    if check_tool nuclei; then
        echo -e "${YELLOW}[2.1] Nuclei scan${NC}"
        nuclei -l "$nuclei_targets" "${hdr_args[@]}" -rl "$RATE_LIMIT" -severity critical,high,medium -o "$OUTPUT_DIR/nuclei.txt" -silent 2>/dev/null || true

        echo -e "${YELLOW}[2.2] CORS misconfiguration${NC}"
        nuclei -l "$nuclei_targets" "${hdr_args[@]}" -rl "$RATE_LIMIT" -tags cors -o "$OUTPUT_DIR/cors.txt" -silent 2>/dev/null || true
    else
        echo -e "${YELLOW}  [!] nuclei not installed; skipping template scans${NC}"
    fi

    echo -e "${YELLOW}[2.3] XSS detection${NC}"
    local xss_raw="$OUTPUT_DIR/xss_candidates_raw.txt"
    local xss_candidates="$OUTPUT_DIR/xss_candidates.txt"
    : > "$xss_raw"
    [ -s "$OUTPUT_DIR/../recon/candidates_xss.txt" ] && cat "$OUTPUT_DIR/../recon/candidates_xss.txt" >> "$xss_raw"
    if [ -s "$OUTPUT_DIR/../recon/params.txt" ]; then
        while IFS= read -r param; do
            param="${param%$'\r'}"
            [ -n "$param" ] || continue
            printf 'https://%s/?%s=test\n' "$TARGET" "$param" >> "$xss_raw"
        done < <(head -n 100 "$OUTPUT_DIR/../recon/params.txt")
    fi
    awk 'NF && !seen[$0]++' "$xss_raw" | head -n 100 > "$xss_candidates"
    if [ -s "$xss_candidates" ] && check_tool dalfox; then
        dalfox pipe --silence "${hdr_args[@]}" -o "$OUTPUT_DIR/xss.txt" < "$xss_candidates" 2>/dev/null || true
    elif ! check_tool dalfox; then
        echo -e "${YELLOW}  [!] dalfox not installed; skipping XSS scan${NC}"
    fi

    echo -e "${YELLOW}[2.4] SQL Injection${NC}"
    local sqlmap_targets="$OUTPUT_DIR/sqlmap_targets.txt"
    : > "$sqlmap_targets"
    if [ -s "$OUTPUT_DIR/../recon/candidates_sqli.txt" ]; then
        head -n 50 "$OUTPUT_DIR/../recon/candidates_sqli.txt" > "$sqlmap_targets" || true
    elif [ -s "$OUTPUT_DIR/../recon/clean_urls.txt" ]; then
        grep "=" "$OUTPUT_DIR/../recon/clean_urls.txt" 2>/dev/null | head -n 50 > "$sqlmap_targets" || true
    elif [ -s "$OUTPUT_DIR/../recon/wayback.txt" ]; then
        grep "=" "$OUTPUT_DIR/../recon/wayback.txt" 2>/dev/null | head -n 50 > "$sqlmap_targets" || true
    fi
    if [ -s "$sqlmap_targets" ] && check_tool sqlmap; then
        sqlmap -m "$sqlmap_targets" --batch --level=1 --risk=1 "${hdr_args[@]}" --output-dir="$OUTPUT_DIR/sqlmap" 2>/dev/null || true
    elif ! check_tool sqlmap; then
        echo -e "${YELLOW}  [!] sqlmap not installed; skipping SQLi scan${NC}"
    fi

    if check_tool nuclei; then
        echo -e "${YELLOW}[2.5] SSRF detection${NC}"
        nuclei -l "$nuclei_targets" "${hdr_args[@]}" -rl "$RATE_LIMIT" -tags ssrf -o "$OUTPUT_DIR/ssrf.txt" -silent 2>/dev/null || true

        echo -e "${YELLOW}[2.6] Open redirect${NC}"
        nuclei -l "$nuclei_targets" "${hdr_args[@]}" -rl "$RATE_LIMIT" -tags redirect -o "$OUTPUT_DIR/redirect.txt" -silent 2>/dev/null || true

        echo -e "${YELLOW}[2.7] IDOR detection${NC}"
        nuclei -l "$nuclei_targets" "${hdr_args[@]}" -rl "$RATE_LIMIT" -tags idor -o "$OUTPUT_DIR/idor.txt" -silent 2>/dev/null || true
    fi

    echo -e "${GREEN}[✓] Vulnerability scanning completed${NC}"
}

# ============================================
# PHASE 3: ADVANCED BRUTE FORCE
# ============================================

advanced_bruteforce() {
    local TARGET="$1"
    local OUTPUT_DIR="$REPORTS_DIR/$TARGET/brute"
    local SECLISTS_BASE="${SECLISTS_DIR:-/usr/share/wordlists/seclists}"
    local RESEARCH_HEADER=""
    local RATE_LIMIT
    local -a hdr_args=()
    RESEARCH_HEADER=$(resolve_program_header "$TARGET" "$PROGRAMS_DIR" 2>/dev/null || true)
    [ -n "$RESEARCH_HEADER" ] && hdr_args=(-H "$RESEARCH_HEADER")
    RATE_LIMIT="$(resolve_program_rate_limit "$TARGET" "$PROGRAMS_DIR")"

    mkdir -p "$OUTPUT_DIR"

    echo -e "${CYAN}[3/8] ADVANCED BRUTE FORCE (rate-limit: ${RATE_LIMIT} req/s)${NC}"

    local wl_dirs="$SECLISTS_BASE/Discovery/Web-Content/raft-large-directories.txt"
    local wl_vhosts="$SECLISTS_BASE/Discovery/DNS/subdomains-top1million-5000.txt"
    local wl_common="$SECLISTS_BASE/Discovery/Web-Content/common.txt"

    echo -e "${YELLOW}[3.1] Directory fuzzing${NC}"
    if check_tool feroxbuster && [ -f "$wl_dirs" ]; then
        feroxbuster -u "https://$TARGET" "${hdr_args[@]}" --rate-limit "$RATE_LIMIT" -w "$wl_dirs" -o "$OUTPUT_DIR/dirs.txt" -q 2>/dev/null || true
    else
        echo -e "${YELLOW}  [!] feroxbuster or wordlist missing; skipping directory fuzzing${NC}"
    fi

    echo -e "${YELLOW}[3.2] VHost fuzzing${NC}"
    if check_tool feroxbuster && [ -f "$wl_vhosts" ]; then
        feroxbuster -u "https://$TARGET" "${hdr_args[@]}" --rate-limit "$RATE_LIMIT" -w "$wl_vhosts" --vhosts -o "$OUTPUT_DIR/vhosts.txt" -q 2>/dev/null || true
    else
        echo -e "${YELLOW}  [!] feroxbuster or wordlist missing; skipping vhost fuzzing${NC}"
    fi

    echo -e "${YELLOW}[3.3] Parameter fuzzing${NC}"
    if check_tool ffuf && [ -f "$wl_common" ]; then
        ffuf -u "https://$TARGET/FUZZ" "${hdr_args[@]}" -rate "$RATE_LIMIT" -w "$wl_common" -o "$OUTPUT_DIR/ffuf.txt" -q 2>/dev/null || true
    else
        echo -e "${YELLOW}  [!] ffuf or wordlist missing; skipping parameter fuzzing${NC}"
    fi

    echo -e "${GREEN}[✓] Brute force completed${NC}"
}

# ============================================
# PHASE 4: SECRETS AND API KEYS
# ============================================

secrets_hunting() {
    local TARGET="$1"
    local OUTPUT_DIR="$REPORTS_DIR/$TARGET/secrets"
    local RESEARCH_HEADER=""
    local -a hdr_args=()
    RESEARCH_HEADER=$(resolve_program_header "$TARGET" "$PROGRAMS_DIR" 2>/dev/null || true)
    [ -n "$RESEARCH_HEADER" ] && hdr_args=(-H "$RESEARCH_HEADER")

    mkdir -p "$OUTPUT_DIR"

    echo -e "${CYAN}[4/8] SECRET HUNTING${NC}"

    echo -e "${YELLOW}[4.1] JS secrets${NC}"
    if [ -n "${BB_PASSIVE_ONLY:-}" ]; then
        echo -e "${YELLOW}  [passive-only] skipping active JS file fetching${NC}"
    else
        local js_list=""
        if [ -s "$OUTPUT_DIR/../recon/js_files.txt" ]; then
            js_list="$OUTPUT_DIR/../recon/js_files.txt"
        elif [ -s "$OUTPUT_DIR/../recon/js_endpoints.txt" ]; then
            js_list="$OUTPUT_DIR/js_files_fallback.txt"
            grep -iE '\.js(\?|$)' "$OUTPUT_DIR/../recon/js_endpoints.txt" 2>/dev/null | sort -u > "$js_list" || true
        fi
        if [ -n "$js_list" ] && [ -s "$js_list" ] && check_tool curl; then
            : > "$OUTPUT_DIR/js_secrets.txt"
            while IFS= read -r url; do
                url="${url%$'\r'}"
                [ -n "$url" ] || continue
                curl -s -m 15 --connect-timeout 8 "${hdr_args[@]}" "$url" 2>/dev/null \
                    | grep -iE "(api_key|apikey|secret|token|password|aws|azure|gcp|firebase)" \
                    | awk -v u="$url" '{print "[" u "] " $0}' >> "$OUTPUT_DIR/js_secrets.txt" || true
            done < "$js_list"
        fi
    fi

    echo -e "${YELLOW}[4.2] GitHub dorking${NC}"
    echo "Public repositories with secrets:"
    echo "  - site:github.com \"$TARGET\" password"
    echo "  - site:github.com \"$TARGET\" api_key"
    echo "  - site:github.com \"$TARGET\" secret"

    echo -e "${YELLOW}[4.3] Cloud bucket enumeration${NC}"
    echo "Check S3/Azure/GCP buckets:"
    echo "  - https://$TARGET.s3.amazonaws.com"
    echo "  - https://$TARGET.blob.core.windows.net"
    echo "  - https://storage.googleapis.com/$TARGET"

    echo -e "${GREEN}[✓] Secret hunting completed${NC}"
}

# ============================================
# PHASE 5: BUSINESS LOGIC
# ============================================

business_logic() {
    local TARGET="$1"

    echo -e "${CYAN}[5/8] BUSINESS LOGIC TESTING${NC}"

    echo -e "${YELLOW}Areas to investigate:${NC}"
    echo "  1. Authentication flow (login, registration, recovery)"
    echo "  2. Role/permission changes"
    echo "  3. Rate limiting on sensitive actions"
    echo "  4. Payment/discount logic"
    echo "  5. Hidden parameter manipulation"
    echo "  6. Race conditions"
    echo "  7. Mass assignment"
    echo "  8. IDOR on non-obvious endpoints"

    echo -e "${GREEN}[✓] Business logic checklist generated${NC}"
}

# ============================================
# PHASE 6: API TESTING
# ============================================

api_testing() {
    local TARGET="$1"
    local OUTPUT_DIR="$REPORTS_DIR/$TARGET/api"
    local RESEARCH_HEADER=""
    local -a hdr_args=()
    RESEARCH_HEADER=$(resolve_program_header "$TARGET" "$PROGRAMS_DIR" 2>/dev/null || true)
    [ -n "$RESEARCH_HEADER" ] && hdr_args=(-H "$RESEARCH_HEADER")

    mkdir -p "$OUTPUT_DIR"

    echo -e "${CYAN}[6/8] API TESTING${NC}"

    echo -e "${YELLOW}[6.1] API endpoint discovery${NC}"
    {
        [ -s "$OUTPUT_DIR/../recon/clean_urls.txt" ] && grep -iE "(api|v1|v2|v3|graphql|rest)" "$OUTPUT_DIR/../recon/clean_urls.txt" 2>/dev/null || true
        [ -s "$OUTPUT_DIR/../recon/wayback.txt" ] && grep -iE "(api|v1|v2|v3|graphql|rest)" "$OUTPUT_DIR/../recon/wayback.txt" 2>/dev/null || true
    } | sort -u > "$OUTPUT_DIR/api_endpoints.txt" || true

    if [ -n "${BB_PASSIVE_ONLY:-}" ]; then
        echo -e "${YELLOW}  [passive-only] skipping active API documentation and GraphQL probes${NC}"
        echo -e "${GREEN}[✓] API testing completed${NC}"
        return 0
    fi

    echo -e "${YELLOW}[6.2] API documentation${NC}"
    local found_records=""
    if check_tool curl; then
        local path status slug out_doc
        for path in /swagger.json /openapi.json /api-docs /swagger-ui.html /graphql; do
            status=$(curl -s -m 15 --connect-timeout 8 "${hdr_args[@]}" -o /dev/null -w "%{http_code}" "https://$TARGET$path" 2>/dev/null || echo "000")
            if [ "$status" = "200" ]; then
                echo -e "${GREEN}  ✓ API documentation found: $path${NC}"
                slug=$(printf '%s' "${path#/}" | tr '/.' '__')
                out_doc="$OUTPUT_DIR/doc_${slug}"
                curl -s -m 15 --connect-timeout 8 "${hdr_args[@]}" "https://$TARGET$path" > "$out_doc" 2>/dev/null || true
                found_records+="${path}"$'\t'"${status}"$'\t'"${out_doc}"$'\n'
            fi
        done
    fi
    python3 -c '
import json, sys
records = []
for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    path, status, file_path = line.split("\t", 2)
    records.append({"path": path, "status": int(status), "file": file_path})
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump({"target": sys.argv[2], "discovered": records}, fh, indent=2)
' "$OUTPUT_DIR/api_docs_index.json" "$TARGET" <<< "$found_records"

    echo -e "${YELLOW}[6.3] GraphQL introspection${NC}"
    if check_tool curl; then
        curl -s -m 15 --connect-timeout 8 -X POST "https://$TARGET/graphql" "${hdr_args[@]}" -H "Content-Type: application/json" -d '{"query":"{__schema{types{name,fields{name}}}}"}' > "$OUTPUT_DIR/graphql_schema.json" 2>/dev/null || true
    fi

    echo -e "${GREEN}[✓] API testing completed${NC}"
}

# ============================================
# PHASE 7: CHAIN ATTACKS
# ============================================

chain_attacks() {
    local TARGET="$1"
    
    echo -e "${CYAN}[7/8] Attack Chains${NC}"
    
    echo -e "${YELLOW}High-impact combinations:${NC}"
    echo ""
    echo "  1. CORS + CSRF → Account takeover"
    echo "  2. XSS + Cookie theft → Session hijacking"
    echo "  3. IDOR + Privilege escalation → Admin access"
    echo "  4. SSRF + Internal services → RCE"
    echo "  5. Open redirect + OAuth → Account takeover"
    echo "  6. Race condition + Financial → Double spending"
    echo "  7. Mass assignment + Role change → Privilege escalation"
    echo "  8. SQL Injection + File read → Full compromise"
}

# ============================================
# PHASE 8: REPORT AND DISCLOSURE
# ============================================

generate_report() {
    local TARGET="$1"
    local OUTPUT_DIR="$REPORTS_DIR/$TARGET"
    local REPORT_FILE policy_json prog_name platform
    REPORT_FILE="$OUTPUT_DIR/report-$(date +%Y%m%d).md"

    mkdir -p "$OUTPUT_DIR"
    echo -e "${CYAN}[8/8] REPORT GENERATION${NC}"

    prog_name=""
    platform="HackerOne"
    if policy_json=$(python3 "$SCOPE_GUARD" --programs-dir "$PROGRAMS_DIR" --policy-json "$TARGET" 2>/dev/null); then
        prog_name=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("program_name") or "")' "$policy_json" 2>/dev/null || true)
        platform=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("platform") or "HackerOne")' "$policy_json" 2>/dev/null || echo "HackerOne")
    fi

    python3 "$RECON_UTILS" build-report \
        --template "$BUGBOUNTY_DIR/templates/report-template.md" \
        --output "$REPORT_FILE" \
        --target "$TARGET" \
        --reports-dir "$OUTPUT_DIR" \
        --researcher "$RESEARCHER" \
        --program "$prog_name" \
        --platform "$platform"

    echo -e "${GREEN}[✓] Report generated: $REPORT_FILE${NC}"
}

# ============================================
# BUG BOUNTY PLATFORMS
# ============================================

show_platforms() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  BUG BOUNTY PLATFORMS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}Main platforms:${NC}"
    echo "  1. HackerOne    - https://hackerone.com"
    echo "  2. Bugcrowd     - https://bugcrowd.com"
    echo "  3. Intigriti    - https://intigriti.com"
    echo "  4. YesWeHack    - https://yeswehack.com"
    echo "  5. Synack       - https://synack.com"
    echo "  6. Cobalt       - https://cobalt.io"
    echo ""
    echo -e "${YELLOW}Featured programs:${NC}"
    echo "  - Google VRP      - https://bughunters.google.com"
    echo "  - Apple           - https://security.apple.com"
    echo "  - Microsoft       - https://msrc.microsoft.com"
    echo "  - Meta            - https://www.facebook.com/whitehat"
    echo "  - GitHub          - https://bounty.github.com"
    echo "  - Tesla           - https://bugcrowd.com/tesla"
}

# ============================================
# 0-DAY RESEARCH
# ============================================

zeroday_research() {
    local TARGET="$1"
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  0-DAY RESEARCH METHODOLOGY${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}Steps to find 0-days:${NC}"
    echo ""
    echo "  1. TARGET SELECTION"
    echo "     - Widely used open source software"
    echo "     - Popular frameworks"
    echo "     - Critical applications"
    echo ""
    echo "  2. CODE REVIEW"
    echo "     - Manually audit source code"
    echo "     - Use static analysis tools (Semgrep, CodeQL)"
    echo "     - Search for dangerous patterns"
    echo ""
    echo "  3. FUZZING"
    echo "     - AFL++, LibFuzzer, Honggfuzz"
    echo "     - Mutation-based fuzzing"
    echo "     - Coverage-guided fuzzing"
    echo ""
    echo "  4. ANALYSIS"
    echo "     - Crash analysis"
    echo "     - Root cause analysis"
    echo "     - Exploitability assessment"
    echo ""
    echo "  5. DOCUMENTATION"
    echo "     - PoC creation"
    echo "     - Impact assessment"
    echo "     - Remediation suggestions"
    echo ""
    echo -e "${GREEN}Tools for 0-day research:${NC}"
    echo "  - Semgrep      - Static analysis"
    echo "  - CodeQL       - Semantic code analysis"
    echo "  - AFL++        - Fuzzing"
    echo "  - Ghidra       - Reverse engineering"
    echo "  - Binary Ninja - Binary analysis"
    echo "  - Frida        - Dynamic instrumentation"
    echo "  - strace/ltrace - System call tracing"
}

# ============================================
# PHASE 9: ENCODING BYPASS TECHNIQUES
# ============================================

encoding_bypass() {
    local TARGET="$1"
    local OUTPUT_DIR="$REPORTS_DIR/$TARGET/encoding"
    
    mkdir -p "$OUTPUT_DIR"
    
    echo -e "${CYAN}[9/9] ENCODING BYPASS TECHNIQUES${NC}"
    
    echo -e "${YELLOW}[9.1] Base64 Encoding${NC}"
    echo "  Payloads for WAF bypass:"
    echo ""
    echo "  LFI:"
    echo "    Original: url/?f=etc/passwd (403)"
    echo "    Encoded:  url/?f=L2V0Yy9wYXNzd2Q= (200)"
    echo ""
    echo "  Command to encode:"
    echo "    echo -n 'etc/passwd' | base64"
    echo "  Result: ZXRjL3Bhc3N3ZA=="
    echo ""
    echo "  Common payloads:"
    echo "    /etc/passwd        => ZXRjL3Bhc3N3ZA=="
    echo "    /etc/shadow        => ZXRjL3NoYWRvdw=="
    echo "    /etc/hosts         => ZXRjL2hvc3Rz"
    echo "    C:\\Windows\\System32 => QzpcV2luZG93c1xTeXN0ZW0zMg=="
    echo ""
    
    echo -e "${YELLOW}[9.2] Double URL Encoding${NC}"
    echo "  Payloads for bypass:"
    echo ""
    echo "  Single URL encode:"
    echo "    < = %3C"
    echo "    > = %3E"
    echo "    / = %2F"
    echo "    ' = %27"
    echo "    \" = %22"
    echo ""
    echo "  Double URL encode:"
    echo "    < = %253C"
    echo "    > = %253E"
    echo "    / = %252F"
    echo ""
    echo "  Triple encode:"
    echo "    < = %25253C"
    echo ""
    
    echo -e "${YELLOW}[9.3] Unicode Encoding${NC}"
    echo "  Payloads for bypass:"
    echo ""
    echo "  SQL Injection:"
    echo "    ' = \\u0027"
    echo "    \" = \\u0022"
    echo "    OR = \\u004F\\u0052"
    echo ""
    echo "  XSS:"
    echo "    < = \\u003C"
    echo "    > = \\u003E"
    echo "    script = \\u0073\\u0063\\u0072\\u0069\\u0070\\u0074"
    echo ""
    
    echo -e "${YELLOW}[9.4] HTML Entity Encoding${NC}"
    echo "  Payloads for bypass:"
    echo ""
    echo "  < = &#60; or &#x3C;"
    echo "  > = &#62; or &#x3E;"
    echo "  ' = &#39; or &#x27;"
    echo "  \" = &#34; or &#x22;"
    echo "  & = &#38; or &#x26;"
    echo ""
    
    echo -e "${YELLOW}[9.5] Mixed Encoding Attacks${NC}"
    echo "  Combinations for bypass:"
    echo ""
    echo "  SQL Injection:"
    echo "    ' OR 1=1 --"
    echo "    => %27%20OR%201%3D1%20--"
    echo "    => %27%20%4F%52%201%3D1%20--"
    echo "    => \\u0027 \\u004F\\u0052 1=1 --"
    echo ""
    echo "  XSS:"
    echo "    <script>alert(1)</script>"
    echo "    => %3Cscript%3Ealert(1)%3C/script%3E"
    echo "    => \\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E"
    echo "    => &#60;script&#62;alert(1)&#60;/script&#62;"
    echo ""
    echo "  LFI:"
    echo "    ../../etc/passwd"
    echo "    => ..%2F..%2F..%2Fetc%2Fpasswd"
    echo "    => ....//....//....//etc/passwd"
    echo "    => ..%252F..%252F..%252Fetc%252Fpasswd"
    echo ""
    
    echo -e "${YELLOW}[9.6] Case Manipulation${NC}"
    echo "  Payloads for bypass:"
    echo ""
    echo "  SQL Keywords:"
    echo "    SELECT => SeLeCt, sElEcT, sELECT"
    echo "    UNION => UnIoN, uNiOn, UNION"
    echo "    FROM => FrOm, fRoM, FROM"
    echo ""
    echo "  Tags HTML:"
    echo "    <ScRiPt>, <SCRIPT>, <sCrIpT>"
    echo ""
    
    echo -e "${YELLOW}[9.7] Null Byte Injection${NC}"
    echo "  Payloads for bypass:"
    echo ""
    echo "  LFI:"
    echo "    /etc/passwd%00"
    echo "    /etc/passwd.jpg%00"
    echo "    /etc/passwd%00.png"
    echo ""
    
    echo -e "${YELLOW}[9.8] Comment Injection${NC}"
    echo "  Payloads for bypass:"
    echo ""
    echo "  SQL Injection:"
    echo "    ' /*!UNION*/ /*!SELECT*/ 1,2,3 --"
    echo "    ' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3 --"
    echo ""
    echo "  PHP:"
    echo "    /?file=....//....//etc/passwd"
    echo ""
    
    echo -e "${YELLOW}[9.9] Encoding Tools${NC}"
    echo "  Useful tools:"
    echo ""
    echo "  Base64:"
    echo "    echo -n 'payload' | base64"
    echo "    echo 'encoded' | base64 -d"
    echo ""
    echo "  URL Encode:"
    echo "    python3 -c 'import urllib.parse; print(urllib.parse.quote(\"payload\"))'"
    echo "    python3 -c 'import urllib.parse; print(urllib.parse.unquote(\"encoded\"))'"
    echo ""
    echo "  Hex:"
    echo "    echo -n 'payload' | xxd -p"
    echo "    echo 'hex' | xxd -r -p"
    echo ""
    
    echo -e "${GREEN}[✓] Encoding bypass techniques listed${NC}"
}

# ============================================
# MAIN
# ============================================

# Handle --help and --version before flag stripping when used as first arg
case "${1:-}" in
    --version|-V)
        echo "bugbounty-hunter ${BB_VERSION}"
        exit 0
        ;;
    --help|-h)
        set -- help
        ;;
esac

BB_RESUME="${BB_RESUME:-0}"
BB_FRESH="${BB_FRESH:-0}"
POSITIONAL=()
while [ $# -gt 0 ]; do
    case "$1" in
        --passive-only)
            export BB_PASSIVE_ONLY=1
            shift
            ;;
        --resume)
            BB_RESUME=1
            shift
            ;;
        --fresh)
            BB_FRESH=1
            shift
            ;;
        --rate-limit=*)
            _rl_val="${1#*=}"
            if [[ ! "$_rl_val" =~ ^[1-9][0-9]*$ ]]; then
                echo -e "${RED}[!] --rate-limit requires a positive integer${NC}" >&2
                exit 1
            fi
            export BB_RATE_LIMIT="$_rl_val"
            shift
            ;;
        --rate-limit)
            if [ $# -lt 2 ] || [[ ! "${2:-}" =~ ^[1-9][0-9]*$ ]]; then
                echo -e "${RED}[!] --rate-limit requires a positive integer${NC}" >&2
                exit 1
            fi
            export BB_RATE_LIMIT="$2"
            shift 2
            ;;
        --version|-V)
            echo "bugbounty-hunter ${BB_VERSION}"
            exit 0
            ;;
        --help|-h)
            POSITIONAL=(help)
            break
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done
if [ "${#POSITIONAL[@]}" -gt 0 ]; then
    set -- "${POSITIONAL[@]}"
else
    set --
fi

print_banner

case "${1:-help}" in
    new)
        new_program "${2:-}"
        ;;
    scope)
        check_scope "${2:-}" || exit 1
        _rl_summary="$(resolve_program_rate_limit "$SCOPE_TARGET" "$PROGRAMS_DIR")"
        _hdr_summary="$(resolve_program_header "$SCOPE_TARGET" "$PROGRAMS_DIR" 2>/dev/null || true)"
        echo -e "${GREEN}    Policy: rate-limit=${_rl_summary} req/s | header=${_hdr_summary:-none}${NC}"
        ;;
    scope-explain)
        if [ -z "${2:-}" ]; then
            echo -e "${RED}Usage: $0 scope-explain <target>${NC}" >&2
            exit 1
        fi
        python3 "$SCOPE_GUARD" --programs-dir "$PROGRAMS_DIR" --explain "$2"
        ;;
    scope-audit)
        python3 "$SCOPE_GUARD" --programs-dir "$PROGRAMS_DIR" --audit
        ;;
    scope-export)
        _exp_fmt="${2:-}"
        if [ -z "$_exp_fmt" ]; then
            echo -e "${RED}Usage: $0 scope-export <burp|json|txt|domains|wildcards|cidrs> [program] [output]${NC}" >&2
            exit 1
        fi
        _exp_args=(--programs-dir "$PROGRAMS_DIR" --export "$_exp_fmt")
        [ -n "${3:-}" ] && _exp_args+=(--program "$3")
        [ -n "${4:-}" ] && _exp_args+=(--output "$4")
        python3 "$SCOPE_GUARD" "${_exp_args[@]}"
        ;;
    scope-import)
        _imp_src="${2:-}"
        _imp_prog="${3:-}"
        if [ -z "$_imp_src" ] || [ -z "$_imp_prog" ]; then
            echo -e "${RED}Usage: $0 scope-import <file.csv|file.json|file.txt> <program-name>${NC}" >&2
            exit 1
        fi
        if [ ! -f "$_imp_src" ]; then
            echo -e "${RED}[!] File not found: $_imp_src${NC}" >&2
            exit 1
        fi
        if [[ ! "$_imp_prog" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$ ]]; then
            echo -e "${RED}[!] Program name may only contain letters, numbers, dots, underscores, and hyphens.${NC}" >&2
            exit 1
        fi
        _imp_dest="$PROGRAMS_DIR/${_imp_prog}.md"
        if [ -e "$_imp_dest" ]; then
            echo -e "${YELLOW}[!] Already exists (refusing overwrite): $_imp_dest${NC}" >&2
            exit 1
        fi
        case "${_imp_src,,}" in
            *.csv)  _imp_flag="--import-h1-csv" ;;
            *.json) _imp_flag="--import-json" ;;
            *)      _imp_flag="--import-txt" ;;
        esac
        python3 "$SCOPE_GUARD" "$_imp_flag" "$_imp_src" --program-name "$_imp_prog" --researcher "$RESEARCHER" --output "$_imp_dest" || exit 1
        echo -e "${GREEN}[✓] Program imported: $_imp_dest${NC}"
        ;;
    scope-diff)
        if [ -z "${2:-}" ] || [ -z "${3:-}" ]; then
            echo -e "${RED}Usage: $0 scope-diff <old-file> <new-file>${NC}" >&2
            exit 1
        fi
        python3 "$SCOPE_GUARD" --diff "$2" "$3"
        ;;
    resolve)
        check_scope "${2:-}" || exit 1
        resolve_check "$SCOPE_TARGET"
        ;;
    recon)
        check_scope "${2:-}" || exit 1
        [ "$BB_FRESH" = "1" ] && clear_state_dir "$SCOPE_TARGET"
        reconnaissance "$SCOPE_TARGET"
        mark_phase_done "$SCOPE_TARGET" "recon"
        ;;
    vuln)
        check_scope "${2:-}" || exit 1
        vuln_scan "$SCOPE_TARGET"
        mark_phase_done "$SCOPE_TARGET" "vuln"
        ;;
    brute)
        check_scope "${2:-}" || exit 1
        advanced_bruteforce "$SCOPE_TARGET"
        mark_phase_done "$SCOPE_TARGET" "brute"
        ;;
    secrets)
        check_scope "${2:-}" || exit 1
        secrets_hunting "$SCOPE_TARGET"
        mark_phase_done "$SCOPE_TARGET" "secrets"
        ;;
    api)
        check_scope "${2:-}" || exit 1
        api_testing "$SCOPE_TARGET"
        mark_phase_done "$SCOPE_TARGET" "api"
        ;;
    report)
        check_scope "${2:-}" || exit 1
        generate_report "$SCOPE_TARGET"
        mark_phase_done "$SCOPE_TARGET" "report"
        ;;
    platforms)
        show_platforms
        ;;
    zeroday)
        zeroday_research "${2:-}"
        ;;
    encode|encoding|bypass)
        encoding_bypass "${2:-}"
        ;;
    full)
        TARGET="${2:-}"
        if [ -z "$TARGET" ]; then
            echo -e "${RED}Usage: $0 full <domain>${NC}"
            exit 1
        fi
        check_scope "$TARGET" || exit 1
        [ "$BB_FRESH" = "1" ] && clear_state_dir "$SCOPE_TARGET"
        for _phase_pair in \
            "recon:reconnaissance" \
            "vuln:vuln_scan" \
            "brute:advanced_bruteforce" \
            "secrets:secrets_hunting" \
            "api:api_testing" \
            "business:business_logic" \
            "chains:chain_attacks" \
            "report:generate_report"; do
            _pname="${_phase_pair%%:*}"
            _pfunc="${_phase_pair#*:}"
            if phase_done "$SCOPE_TARGET" "$_pname"; then
                log_warning "Skipping phase '$_pname' (checkpoint present; pass --fresh to re-run)"
            else
                if "$_pfunc" "$SCOPE_TARGET"; then
                    mark_phase_done "$SCOPE_TARGET" "$_pname"
                fi
            fi
        done
        ;;
    *)
        echo ""
        echo "Usage: $0 <command> [target] [flags]"
        echo ""
        echo "Commands:"
        echo "  new <program>                    - Create scope file for a program"
        echo "  scope <target>                   - Check if a target is in scope (+ policy)"
        echo "  scope-explain <target>           - Show detailed scope verdict and policy rules"
        echo "  scope-audit                      - Audit all programs/*.md for conflicts & freshness"
        echo "  scope-export <fmt> [prog] [out]  - Export scope (burp|json|txt|domains|wildcards|cidrs)"
        echo "  scope-import <file> <prog>       - Import H1 CSV / JSON / TXT into programs/<prog>.md"
        echo "  scope-diff <old> <new>           - Diff two scope files (.md/.csv/.json/.txt)"
        echo "  resolve <host>                   - Detect DNS hijack/blocking (local vs 8.8.8.8)"
        echo "  full <domain>                    - Complete pipeline (recon->report)"
        echo "  recon <domain>                   - Reconnaissance only"
        echo "  vuln <domain>                    - Vulnerabilities only"
        echo "  brute <domain>                   - Brute force only"
        echo "  secrets <domain>                 - Secrets only"
        echo "  api <domain>                     - APIs only"
        echo "  encode <domain>                  - Encoding bypass techniques"
        echo "  report <domain>                  - Generate report with telemetry summary"
        echo "  platforms                        - View platforms"
        echo "  zeroday                          - 0-day methodology"
        echo ""
        echo "Flags:"
        echo "  --passive-only                   - Skip stages that touch the target directly"
        echo "  --resume                         - Skip completed phases in full mode (.state/*.done)"
        echo "  --fresh                          - Clear previous phase checkpoints before running"
        echo "  --rate-limit <req/s>             - Override max request rate for active tools"
        echo ""
        echo "Current researcher: $RESEARCHER (change with BB_RESEARCHER=handle)"
        echo "Scope tracker: $PROGRAMS_DIR"
        echo ""
        ;;
esac
