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

BB_VERSION="1.1"

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
        cp "$TEMPLATE" "$DEST"
        sed -i "s/\[Program Name\]/$NAME/" "$DEST" 2>/dev/null
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
    
    mkdir -p "$OUTPUT_DIR"
    
    echo -e "${CYAN}[1/8] DEEP RECONNAISSANCE - $TARGET${NC}"
    
    echo -e "${YELLOW}[1.1] Subdomain Enumeration${NC}"
    subfinder -d "$TARGET" -o "$OUTPUT_DIR/subdomains.txt" 2>/dev/null
    amass enum -passive -d "$TARGET" >> "$OUTPUT_DIR/subdomains.txt" 2>/dev/null
    sort -u "$OUTPUT_DIR/subdomains.txt" -o "$OUTPUT_DIR/subdomains.txt"

    scope_filter_file "$OUTPUT_DIR/subdomains.txt" "$OUTPUT_DIR/authorized_subdomains.txt"
    
    SUBS=$(wc -l < "$OUTPUT_DIR/subdomains.txt")
    echo -e "${GREEN}  ✓ $SUBS subdomains found${NC}"
    
    echo -e "${YELLOW}[1.2] HTTP probing${NC}"
    httpx -l "$OUTPUT_DIR/authorized_subdomains.txt" -o "$OUTPUT_DIR/httpx.txt" -silent 2>/dev/null
    
    echo -e "${YELLOW}[1.3] Wayback URLs${NC}"
    echo "$TARGET" | gau --threads 5 2>/dev/null | sort -u > "$OUTPUT_DIR/wayback_raw.txt"
    waybackurls "$TARGET" >> "$OUTPUT_DIR/wayback_raw.txt" 2>/dev/null
    sort -u "$OUTPUT_DIR/wayback_raw.txt" -o "$OUTPUT_DIR/wayback_raw.txt"
    scope_filter_file "$OUTPUT_DIR/wayback_raw.txt" "$OUTPUT_DIR/wayback.txt"
    
    echo -e "${YELLOW}[1.4] JS endpoints${NC}"
    katana -u "https://$TARGET" -d 3 -jc \
        -cs "^https?://${TARGET_REGEX}(:[0-9]+)?(/|$)" \
        -o "$OUTPUT_DIR/js_endpoints_raw.txt" -silent 2>/dev/null
    scope_filter_file "$OUTPUT_DIR/js_endpoints_raw.txt" "$OUTPUT_DIR/js_endpoints.txt"
    
    echo -e "${YELLOW}[1.5] Parameter discovery${NC}"
    cat "$OUTPUT_DIR/wayback.txt" | grep "?" | unfurl keys | sort -u > "$OUTPUT_DIR/params.txt" 2>/dev/null
    
    echo -e "${GREEN}[✓] Reconnaissance completed${NC}"
}

# ============================================
# PHASE 2: VULNERABILITY SCANNING
# ============================================

vuln_scan() {
    local TARGET="$1"
    local OUTPUT_DIR="$REPORTS_DIR/$TARGET/vulns"
    
    mkdir -p "$OUTPUT_DIR"
    
    echo -e "${CYAN}[2/8] VULNERABILITY SCANNING${NC}"
    
    echo -e "${YELLOW}[2.1] Nuclei scan${NC}"
    echo "https://$TARGET" | nuclei -severity critical,high,medium -o "$OUTPUT_DIR/nuclei.txt" -silent 2>/dev/null
    
    echo -e "${YELLOW}[2.2] CORS misconfiguration${NC}"
    nuclei -u "https://$TARGET" -t nuclei-templates/http/misconfiguration/cors* -o "$OUTPUT_DIR/cors.txt" -silent 2>/dev/null
    
    echo -e "${YELLOW}[2.3] XSS detection${NC}"
    cat "$OUTPUT_DIR/../recon/params.txt" 2>/dev/null | head -100 | while read param; do
        echo "https://$TARGET/?$param=test" | dalfox pipe --silence -o "$OUTPUT_DIR/xss.txt" 2>/dev/null
    done
    
    echo -e "${YELLOW}[2.4] SQL Injection${NC}"
    cat "$OUTPUT_DIR/../recon/wayback.txt" 2>/dev/null | grep "=" | head -50 | sqlmap --batch --level=1 --risk=1 --output-dir="$OUTPUT_DIR/sqlmap" 2>/dev/null
    
    echo -e "${YELLOW}[2.5] SSRF detection${NC}"
    echo "https://$TARGET" | nuclei -t nuclei-templates/http/vulnerabilities/ssrf* -o "$OUTPUT_DIR/ssrf.txt" -silent 2>/dev/null
    
    echo -e "${YELLOW}[2.6] Open redirect${NC}"
    echo "https://$TARGET" | nuclei -t nuclei-templates/http/vulnerabilities/redirect* -o "$OUTPUT_DIR/redirect.txt" -silent 2>/dev/null
    
    echo -e "${YELLOW}[2.7] IDOR detection${NC}"
    nuclei -u "https://$TARGET" -t nuclei-templates/http/vulnerabilities/idor* -o "$OUTPUT_DIR/idor.txt" -silent 2>/dev/null
    
    echo -e "${GREEN}[✓] Vulnerability scanning completed${NC}"
}

# ============================================
# PHASE 3: ADVANCED BRUTE FORCE
# ============================================

advanced_bruteforce() {
    local TARGET="$1"
    local OUTPUT_DIR="$REPORTS_DIR/$TARGET/brute"
    
    mkdir -p "$OUTPUT_DIR"
    
    echo -e "${CYAN}[3/8] ADVANCED BRUTE FORCE${NC}"
    
    echo -e "${YELLOW}[3.1] Directory fuzzing${NC}"
    feroxbuster -u "https://$TARGET" -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -o "$OUTPUT_DIR/dirs.txt" -q 2>/dev/null
    
    echo -e "${YELLOW}[3.2] VHost fuzzing${NC}"
    feroxbuster -u "https://$TARGET" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt --vhosts -o "$OUTPUT_DIR/vhosts.txt" -q 2>/dev/null
    
    echo -e "${YELLOW}[3.3] Parameter fuzzing${NC}"
    ffuf -u "https://$TARGET/FUZZ" -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -o "$OUTPUT_DIR/ffuf.txt" -q 2>/dev/null
    
    echo -e "${GREEN}[✓] Brute force completed${NC}"
}

# ============================================
# PHASE 4: SECRETS AND API KEYS
# ============================================

secrets_hunting() {
    local TARGET="$1"
    local OUTPUT_DIR="$REPORTS_DIR/$TARGET/secrets"
    
    mkdir -p "$OUTPUT_DIR"
    
    echo -e "${CYAN}[4/8] SECRET HUNTING${NC}"
    
    echo -e "${YELLOW}[4.1] JS secrets${NC}"
    cat "$OUTPUT_DIR/../recon/js_endpoints.txt" 2>/dev/null | while read url; do
        curl -s "$url" 2>/dev/null | grep -iE "(api_key|apikey|secret|token|password|aws|azure|gcp|firebase)" >> "$OUTPUT_DIR/js_secrets.txt"
    done
    
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
    
    mkdir -p "$OUTPUT_DIR"
    
    echo -e "${CYAN}[6/8] API TESTING${NC}"
    
    echo -e "${YELLOW}[6.1] API endpoint discovery${NC}"
    cat "$OUTPUT_DIR/../recon/wayback.txt" 2>/dev/null | grep -iE "(api|v1|v2|v3|graphql|rest)" > "$OUTPUT_DIR/api_endpoints.txt"
    
    echo -e "${YELLOW}[6.2] API documentation${NC}"
    for path in /swagger.json /openapi.json /api-docs /swagger-ui.html /graphql; do
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$path" 2>/dev/null)
        if [ "$STATUS" = "200" ]; then
            echo -e "${GREEN}  ✓ API documentation found: $path${NC}"
            curl -s "https://$TARGET$path" >> "$OUTPUT_DIR/api_docs.json"
        fi
    done
    
    echo -e "${YELLOW}[6.3] GraphQL introspection${NC}"
    curl -s -X POST "https://$TARGET/graphql" -H "Content-Type: application/json" -d '{"query":"{__schema{types{name,fields{name}}}}"}' > "$OUTPUT_DIR/graphql_schema.json" 2>/dev/null
    
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
    local REPORT_FILE
    REPORT_FILE="$OUTPUT_DIR/report-$(date +%Y%m%d).md"

    mkdir -p "$OUTPUT_DIR"
    echo -e "${CYAN}[8/8] REPORT GENERATION${NC}"

    cat > "$REPORT_FILE" <<EOF
# Bug Bounty Report

## Platform
HackerOne

## Program
[H1 program name]

## Researcher
${RESEARCHER}

## Target
${TARGET}

## Date
$(date -Iseconds)

## H1 Report URL
[Filled after submission - hackerone.com/reports/xxxxx]

## Executive Summary
[Brief description of the finding]

## Vulnerability Details

### Type
[SQLi/XSS/SSRF/IDOR/etc.]

### Severity
[HIGH/MEDIUM/LOW]

### CVSS Score
[Score]

### CWE
[CWE-XXX]

## Steps to Reproduce

1. Step 1
2. Step 2
3. Step 3

## Impact
[Description of potential impact]

## Remediation
[Suggested fix]

## References
- [CWE Link]
- [OWASP Link]

## Appendix
[Screenshots, logs, PoC code]
EOF

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

# Handle --help and --version before banner
case "${1:-}" in
    --version|-V)
        echo "bugbounty-hunter ${BB_VERSION}"
        exit 0
        ;;
    --help|-h)
        ;& # fall through to help
esac

print_banner

case "${1:-help}" in
    new)
        new_program "${2:-}"
        ;;
    scope)
        check_scope "${2:-}"
        ;;
    resolve)
        check_scope "${2:-}" || exit 1
        resolve_check "$SCOPE_TARGET"
        ;;
    recon)
        check_scope "${2:-}" || exit 1
        reconnaissance "$SCOPE_TARGET"
        ;;
    vuln)
        check_scope "${2:-}" || exit 1
        vuln_scan "$SCOPE_TARGET"
        ;;
    brute)
        check_scope "${2:-}" || exit 1
        advanced_bruteforce "$SCOPE_TARGET"
        ;;
    secrets)
        check_scope "${2:-}" || exit 1
        secrets_hunting "$SCOPE_TARGET"
        ;;
    api)
        check_scope "${2:-}" || exit 1
        api_testing "$SCOPE_TARGET"
        ;;
    report)
        check_scope "${2:-}" || exit 1
        generate_report "$SCOPE_TARGET"
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
        reconnaissance "$SCOPE_TARGET"
        vuln_scan "$SCOPE_TARGET"
        advanced_bruteforce "$SCOPE_TARGET"
        secrets_hunting "$SCOPE_TARGET"
        api_testing "$SCOPE_TARGET"
        business_logic "$SCOPE_TARGET"
        chain_attacks "$SCOPE_TARGET"
        generate_report "$SCOPE_TARGET"
        ;;
    *)
        echo ""
        echo "Usage: $0 <command> [target]"
        echo ""
        echo "Commands:"
        echo "  new <program>     - Create scope file for an H1 program"
        echo "  scope <domain>    - Check if a target is in scope"
        echo "  resolve <host>    - Detect DNS hijack/blocking (local vs 8.8.8.8)"
        echo "  full <domain>     - Complete pipeline (recon->report)"
        echo "  recon <domain>    - Reconnaissance only"
        echo "  vuln <domain>     - Vulnerabilities only"
        echo "  brute <domain>    - Brute force only"
        echo "  secrets <domain>  - Secrets only"
        echo "  api <domain>      - APIs only"
        echo "  encode <domain>   - Encoding bypass techniques"
        echo "  report <domain>   - Generate report"
        echo "  platforms         - View platforms"
        echo "  zeroday           - 0-day methodology"
        echo ""
        echo "Current researcher: $RESEARCHER (change with BB_RESEARCHER=handle)"
        echo "Scope tracker: $PROGRAMS_DIR"
        echo ""
        ;;
esac
