#!/bin/bash
# ============================================
# Auto-Scan Daemon - Threat Intel Integration + Auto Scanner
# ============================================
# When it detects new CVEs or critical threats,
# it runs automatic scans against targets
# ============================================

set -euo pipefail

# Configuration
FEED_URL="https://raw.githubusercontent.com/DevCop95/cYHBernews/refs/heads/main/noticias.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
DATA_DIR="$SCRIPT_DIR/threat-intel"
REPORT_DIR="$SCRIPT_DIR/reports"
LOG_DIR="$SCRIPT_DIR/logs"
SCAN_QUEUE="$DATA_DIR/scan_queue.json"
LAST_CHECK="$DATA_DIR/last_check_daemon.json"
# shellcheck disable=SC2034
CONFIG_FILE="$SCRIPT_DIR/daemon.conf"

mkdir -p "$DATA_DIR" "$REPORT_DIR" "$LOG_DIR"

# Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
# shellcheck disable=SC2034
MAGENTA='\033[0;35m'
NC='\033[0m'

# Default configuration
SCAN_INTERVAL=${SCAN_INTERVAL:-3600}  # 1 hour
TARGETS_FILE=${TARGETS_FILE:-"$DATA_DIR/targets.json"}
AUTO_SCAN=${AUTO_SCAN:-true}
MAX_CONCURRENT=${MAX_CONCURRENT:-3}
LOG_FILE="$LOG_DIR/daemon-$(date +%Y-%m-%d).log"

# ============================================
# LOG FUNCTIONS
# ============================================

log() {
    local msg
    msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo -e "${CYAN}$msg${NC}" | tee -a "$LOG_FILE"
}

log_error() {
    local msg
    msg="[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1"
    echo -e "${RED}$msg${NC}" | tee -a "$LOG_FILE"
}

log_success() {
    local msg
    msg="[$(date '+%Y-%m-%d %H:%M:%S')] OK: $1"
    echo -e "${GREEN}$msg${NC}" | tee -a "$LOG_FILE"
}

# ============================================
# MONITORING FUNCTIONS
# ============================================

fetch_feed() {
    log "Fetching threat feed..."
    if curl -s "$FEED_URL" -o "$DATA_DIR/noticias.json" 2>/dev/null; then
        log_success "Feed updated"
        return 0
    else
        log_error "Error fetching feed"
        return 1
    fi
}

detect_new_threats() {
    log "Detecting new threats..."
    
    # Get most recent ID
    CURRENT_ID=$(cat "$DATA_DIR/noticias.json" | jq -r '.[0].id')
    
    # Verify last check
    if [ -f "$LAST_CHECK" ]; then
        LAST_ID=$(cat "$LAST_CHECK")
    else
        LAST_ID=$CURRENT_ID
        echo "$CURRENT_ID" > "$LAST_CHECK"
    fi
    
    if [ "$CURRENT_ID" != "$LAST_ID" ]; then
        log "New threats detected (IDs: $LAST_ID -> $CURRENT_ID)"
        
        # Extract new critical/high threats
        NEW_THREATS=$(cat "$DATA_DIR/noticias.json" | jq -r "
            [.[] | select(.id > $LAST_ID and (.severidad == \"CRITICA\" or .severidad == \"ALTA\"))] |
            length
        ")
        
        if [ "$NEW_THREATS" -gt 0 ]; then
            log "$NEW_THREATS new critical/high threats"
            
            # Save to scan queue
            cat "$DATA_DIR/noticias.json" | jq -r "
                [.[] | select(.id > $LAST_ID and (.severidad == \"CRITICA\" or .severidad == \"ALTA\"))] |
                [.[] | {
                    id: .id,
                    titulo: .titulo,
                    severidad: .severidad,
                    cves: .iocs.cve // [],
                    ttps: [.ttps[]?.name // empty],
                    necesita_escaneo: (if (.iocs.cve | length) > 0 or (.resumen | test(\"exploit|remote|code execution|rce|privilege\"; \"i\")) then true else false end)
                }]
            " > "$SCAN_QUEUE"
            
            echo "$CURRENT_ID" > "$LAST_CHECK"
            return 0
        else
            log "No new critical threats"
            echo "$CURRENT_ID" > "$LAST_CHECK"
            return 1
        fi
    else
        log "No changes in feed"
        return 1
    fi
}

# ============================================
# AUTOMATIC SCAN FUNCTIONS
# ============================================

scan_target() {
    local target="$1"
    local threat_info="$2"

    if ! require_scope "$target"; then
        log_error "Skipping unauthorized target: $target"
        return 1
    fi
    
    log "Scanning target: $target"
    
    # Create report directory
    local scan_dir
    scan_dir="$REPORT_DIR/auto-scan-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$scan_dir"
    
    # Run quick scan
    "$SCRIPT_DIR/quickscan.sh" "$target" > "$scan_dir/quick-scan.txt" 2>&1
    
    # Check for vulnerable services
    local vulns_found
    vulns_found=$(grep -ci "vulnerability\|vuln\|cve\|exploit" "$scan_dir/quick-scan.txt" 2>/dev/null || true)
    vulns_found=${vulns_found:-0}
    
    if [ "$vulns_found" -gt 0 ]; then
        log "Potential vulnerabilities found in $target"
        
        # Run full scan
        "$SCRIPT_DIR/autopentest-pro.sh" "$target" > "$scan_dir/full-scan.txt" 2>&1 &
        local scan_pid=$!
        
        # Save threat info
        jq -n \
            --arg target "$target" \
            --arg scan_date "$(date -Iseconds)" \
            --argjson threat_info "$threat_info" \
            --argjson vulnerabilities_found "$vulns_found" \
            --argjson scan_pid "$scan_pid" \
            '{
                target: $target,
                scan_date: $scan_date,
                threat_info: $threat_info,
                vulnerabilities_found: $vulnerabilities_found,
                scan_pid: $scan_pid
            }' > "$scan_dir/threat-info.json"
        
        log_success "Full scan started (PID: $scan_pid)"
        return 0
    else
        log "No vulnerabilities detected in $target"
        return 1
    fi
}

auto_scan_for_threats() {
    if [ ! -f "$SCAN_QUEUE" ]; then
        return 0
    fi
    
    local queue_length
    queue_length=$(cat "$SCAN_QUEUE" | jq 'length')
    
    if [ "$queue_length" -eq 0 ]; then
        return 0
    fi
    
    log "Processing scan queue ($queue_length threats)..."
    
    # Load targets
    if [ ! -f "$TARGETS_FILE" ]; then
        log "No targets configured. Creating example file..."
        create_targets_file
        return 0
    fi
    
    # Process each threat that needs scanning
    cat "$SCAN_QUEUE" | jq -c '.[] | select(.necesita_escaneo == true)' | while read -r threat; do
        local threat_id
        threat_id=$(echo "$threat" | jq -r '.id')
        local cves
        cves=$(echo "$threat" | jq -r '.cves | join(", ")')
        
        log "Processing threat ID: $threat_id (CVEs: $cves)"
        
        # Scan each target
        cat "$TARGETS_FILE" | jq -r '.targets[].url' | while read -r target; do
            if [ -n "$target" ]; then
                scan_target "$target" "$threat" || true
            fi
        done
    done
    
    # Clear queue
    echo "[]" > "$SCAN_QUEUE"
    log_success "Scan queue processed"
}

create_targets_file() {
    cat > "$TARGETS_FILE" << 'EOF'
{
    "targets": [
        {
            "name": "Target Example A",
            "url": "https://example-a.com",
            "type": "web",
            "priority": "high"
        },
        {
            "name": "Target Example B",
            "url": "https://example-b.com",
            "type": "web",
            "priority": "high"
        }
    ],
    "scan_options": {
        "quick_scan": true,
        "full_scan_on_vuln": true,
        "max_concurrent": 3
    }
}
EOF
    log "Targets file created at $TARGETS_FILE"
    log "Edit this file to add your targets"
}

# ============================================
# CVE SCAN FUNCTIONS
# ============================================

scan_for_specific_cve() {
    local cve="$1"
    local target="$2"
    local host

    if ! require_scope "$target"; then
        log_error "Skipping unauthorized target: $target"
        return 1
    fi
    host=$(normalize_target "$target") || return 1
    
    log "Scanning for $cve on $target"
    
    # Search exploits for the CVE
    local exploit_info
    exploit_info=$(searchsploit "$cve" 2>/dev/null | head -20 || echo "No exploits found")
    
    # Check if the target is vulnerable
    local scan_result
    scan_result="$REPORT_DIR/cve-scan-$(date +%Y%m%d-%H%M%S).md"
    
    cat > "$scan_result" << EOF
# CVE Scan: $cve

**Target:** $target
**Date:** $(date -Iseconds)

## Available Exploits

\`\`\`
$exploit_info
\`\`\`

## Scan Result

EOF
    
    # Run nmap with specific scripts
    nmap -sV --script "*$cve*" "$host" >> "$scan_result" 2>/dev/null || true
    
    log_success "CVE scan completed: $scan_result"
}

scan_critical_cves() {
    log "Scanning recent critical CVEs..."
    
    # Get critical CVEs from the last 7 days
    local critical_cves
    critical_cves=$(cat "$DATA_DIR/noticias.json" | jq -r "
        [.[] | select(
            .severidad == \"CRITICA\" and
            (.iocs.cve | length) > 0
        )] | .[0:10][] | .iocs.cve[]
    " 2>/dev/null | sort -u)
    
    if [ -z "$critical_cves" ]; then
        log "No recent critical CVEs"
        return 0
    fi
    
    log "Critical CVEs to scan:"
    echo "$critical_cves" | while read -r cve; do
        echo "  - $cve"
        
        # Scan each target
        if [ -f "$TARGETS_FILE" ]; then
            cat "$TARGETS_FILE" | jq -r '.targets[].url' | while read -r target; do
                if [ -n "$target" ]; then
                    scan_for_specific_cve "$cve" "$target"
                fi
            done
        fi
    done
}

# ============================================
# INTEGRATION FUNCTIONS
# ============================================

update_registry_with_threats() {
    log "Updating registry with new threats..."
    
    # Extract tools mentioned in threats
    local new_tools
    new_tools=$(cat "$DATA_DIR/noticias.json" | jq -r "
        [.[] | select(.severidad == \"CRITICA\" or .severidad == \"ALTA\")] |
        .[].resumen | scan(\"(metasploit|sqlmap|nmap|hydra|burp|nuclei|gobuster)\") | 
        unique | .[]
    " 2>/dev/null)
    
    if [ -n "$new_tools" ]; then
        log "Relevant tools detected: $new_tools"
    fi
}

generate_daily_brief() {
    log "Generating daily brief..."
    
    local brief_file
    brief_file="$REPORT_DIR/daily-brief-$(date +%Y-%m-%d).md"
    
    cat > "$brief_file" << 'EOF'
# Daily Threat Brief

**Date:** DATE_PLACEHOLDER

---

## Summary

EOF
    
    # Add statistics
    local stats
    stats=$(cat "$DATA_DIR/noticias.json" | jq -r "
        \"| Metric | Value |\n|---------|-------|\n\",
        \"| Total news items | \([.[]] | length) |\n\",
        \"| Critical | \([.[] | select(.severidad == \"CRITICA\")] | length) |\n\",
        \"| High | \([.[] | select(.severidad == \"ALTA\")] | length) |\n\",
        \"| Medium | \([.[] | select(.severidad == \"MEDIA\")] | length) |\n\",
        \"| With CVEs | \([.[] | select(.iocs.cve | length > 0)] | length) |\n\"
    ")
    
    echo "$stats" >> "$brief_file"
    
    # Add critical CVEs
    cat >> "$brief_file" << 'EOF'

## Recent Critical CVEs

EOF
    
    cat "$DATA_DIR/noticias.json" | jq -r '
        [.[] | select(.severidad == "CRITICA" and (.iocs.cve | length) > 0)] | .[0:5][] |
        "- **\(.titulo)**: \(.iocs.cve | join(", "))\n  \(.resumen[0:150])...\n"
    ' >> "$brief_file" 2>/dev/null
    
    # Add actions taken
    cat >> "$brief_file" << 'EOF'

## Automatic Actions

- Scans executed against targets
- IOCs exported for blocking
- Tools registry updated

---

*Automatically generated by Threat Intel Daemon*
EOF
    
    sed -i "s/DATE_PLACEHOLDER/$(date -Iseconds)/" "$brief_file"
    
    log_success "Daily brief generated: $brief_file"
}

# ============================================
# NOTIFICATION FUNCTIONS
# ============================================

send_notification() {
    local message="$1"
    local severity="$2"
    
    # Log
    log "NOTIFICATION [$severity]: $message"
    
    # Save to notification file
    echo "[$(date -Iseconds)] [$severity] $message" >> "$LOG_DIR/notifications.log"
    
    # Here you can add integration with:
    # - Telegram bot
    # - Discord webhook
    # - Email
    # - Slack
}

notify_critical_threat() {
    local threat_info="$1"
    
    local title
    title=$(echo "$threat_info" | jq -r '.titulo')
    local severity
    severity=$(echo "$threat_info" | jq -r '.severidad')
    local cves
    cves=$(echo "$threat_info" | jq -r '.cves | join(", ")')
    
    send_notification "NEW CRITICAL THREAT: $title (CVEs: $cves)" "CRITICAL"
}

# ============================================
# MAIN LOOP
# ============================================

show_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         AUTO-SCAN DAEMON - Threat Intel Integration        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo -e "${YELLOW}Targets:${NC}"
    if [ -f "$TARGETS_FILE" ]; then
        cat "$TARGETS_FILE" | jq -r '.targets[] | "  - \(.name): \(.url)"' 2>/dev/null
    else
        echo "  (Not configured - run: $0 setup)"
    fi
    echo ""
    echo -e "${YELLOW}Interval:${NC} ${SCAN_INTERVAL}s"
    echo -e "${YELLOW}Log:${NC} $LOG_FILE"
    echo ""
}

run_daemon() {
    show_banner
    
    log "Starting daemon..."
    
    while true; do
        log "=== Check cycle ==="
        
        # 1. Fetch feed
        fetch_feed || true
        
        # 2. Detect new threats
        if detect_new_threats; then
            # 3. Notify critical threats
            cat "$SCAN_QUEUE" | jq -c '.[] | select(.severidad == "CRITICA")' 2>/dev/null | while read -r threat; do
                notify_critical_threat "$threat"
            done
            
            # 4. Run automatic scans
            if [ "$AUTO_SCAN" = "true" ]; then
                auto_scan_for_threats
            fi
        fi
        
        # 5. Scan critical CVEs periodically
        scan_critical_cves
        
        # 6. Generate daily brief (once per day)
        if [ "$(date +%H)" = "08" ] && [ ! -f "$REPORT_DIR/daily-brief-$(date +%Y-%m-%d).md" ]; then
            generate_daily_brief
        fi
        
        log "Next cycle in ${SCAN_INTERVAL}s"
        sleep "$SCAN_INTERVAL"
    done
}

# ============================================
# ENTRY POINT
# ============================================

case "${1:-daemon}" in
    daemon)
        run_daemon
        ;;
    once)
        fetch_feed
        detect_new_threats
        auto_scan_for_threats
        scan_critical_cves
        ;;
    setup)
        create_targets_file
        echo -e "${GREEN}[✓] Initial setup completed${NC}"
        echo -e "${YELLOW}Edit $TARGETS_FILE to add your targets${NC}"
        ;;
    status)
        echo -e "${CYAN}=== Daemon Status ===${NC}"
        echo "Last check: $(cat "$LAST_CHECK" 2>/dev/null || echo 'Never')"
        echo "Targets: $(cat "$TARGETS_FILE" | jq '.targets | length' 2>/dev/null || echo '0')"
        echo "Scan queue: $(cat "$SCAN_QUEUE" | jq 'length' 2>/dev/null || echo '0')"
        echo "Current log: $LOG_FILE"
        ;;
    *)
        echo "Usage: $0 [daemon|once|setup|status]"
        echo ""
        echo "  daemon  - Run daemon in loop (default)"
        echo "  once    - Run once"
        echo "  setup   - Configure initial targets"
        echo "  status  - View daemon status"
        ;;
esac
