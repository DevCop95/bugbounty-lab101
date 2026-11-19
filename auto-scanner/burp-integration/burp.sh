#!/bin/bash
# ============================================
# Burp Suite Integration - Shell Wrapper
# ============================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$SCRIPT_DIR/burp_api.py"

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Default configuration (respect environment overrides)
BURP_HOST="${BURP_HOST:-localhost}"
BURP_PORT="${BURP_PORT:-1337}"

show_help() {
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           Burp Suite Integration - Shell Wrapper            ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  status              - Burp status"
    echo "  proxy on/off        - Enable/disable proxy"
    echo "  proxy history       - View proxy history"
    echo "  target add <url>    - Add URL to target"
    echo "  target scope        - View target scope"
    echo "  scope-export [p][o] - Export programs/*.md to Burp Suite JSON"
    echo "  spider <url>        - Start spider"
    echo "  scan <url>          - Active scan"
    echo "  issues              - View findings"
    echo "  issues export       - Export findings"
    echo "  repeater <url>      - Send to Repeater"
    echo "  launch              - Launch Burp Suite"
    echo "  config              - View configuration"
    echo ""
    echo "Examples:"
    echo "  $0 status"
    echo "  $0 proxy on"
    echo "  $0 target add https://example.com"
    echo "  $0 scope-export acme-corp burp_scope.json"
    echo "  $0 scan https://example.com"
    echo "  $0 issues export"
}

check_burp_running() {
    if curl -s "http://$BURP_HOST:$BURP_PORT/burp/api" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

launch_burp() {
    echo -e "${YELLOW}Launching Burp Suite...${NC}"
    
    # Find Burp Suite
    BURP_PATHS=(
        "/usr/bin/burpsuite"
        "/opt/BurpSuiteCommunity/burpsuite"
        "/opt/BurpSuiteProfessional/burpsuite"
        "$HOME/BurpSuiteCommunity/burpsuite"
        "$HOME/BurpSuiteProfessional/burpsuite"
    )
    
    for path in "${BURP_PATHS[@]}"; do
        if [ -f "$path" ] || [ -f "$path.sh" ]; then
            echo -e "${GREEN}Found: $path${NC}"
            "$path" &
            echo -e "${GREEN}Burp Suite launched${NC}"
            echo -e "${YELLOW}Remember to enable the API: Burp → Settings → Burp API → Enable${NC}"
            return 0
        fi
    done
    
    # Try with command
    if command -v burpsuite &>/dev/null; then
        burpsuite &
        echo -e "${GREEN}Burp Suite launched${NC}"
        return 0
    fi
    
    echo -e "${RED}Burp Suite not found${NC}"
    return 1
}

show_config() {
    echo -e "${CYAN}Current configuration:${NC}"
    echo "  Host: $BURP_HOST"
    echo "  Port: $BURP_PORT"
    echo "  API URL: http://$BURP_HOST:$BURP_PORT/burp/api"
    echo ""
    
    if check_burp_running; then
        echo -e "${GREEN}✓ Burp Suite is running${NC}"
    else
        echo -e "${RED}✗ Burp Suite is NOT running${NC}"
        echo "  Run: $0 launch"
    fi
}

# Check if Burp is running (not needed for offline commands)
_cmd="${1:-help}"
if ! check_burp_running && [ "$_cmd" != "launch" ] && [ "$_cmd" != "config" ] && [ "$_cmd" != "help" ] && [ "$_cmd" != "--help" ] && [ "$_cmd" != "-h" ] && [ "$_cmd" != "scope-export" ]; then
    echo -e "${RED}Burp Suite is not running${NC}"
    echo -e "${YELLOW}Run: $0 launch${NC}"
    echo ""
    read -r -p "Launch Burp Suite now? (y/n): " -n 1
    echo ""
    if [[ "$REPLY" =~ ^[YySs]$ ]]; then
        launch_burp
        sleep 5
    fi
fi

# Execute command
case "$_cmd" in
    status)
        python3 "$PYTHON" --host "$BURP_HOST" --port "$BURP_PORT" status
        ;;
    proxy)
        case "${2:-}" in
            on|enable)
                python3 "$PYTHON" --host "$BURP_HOST" --port "$BURP_PORT" proxy --enable
                ;;
            off|disable)
                python3 "$PYTHON" --host "$BURP_HOST" --port "$BURP_PORT" proxy --disable
                ;;
            history)
                python3 "$PYTHON" --host "$BURP_HOST" --port "$BURP_PORT" proxy --history
                ;;
            *)
                python3 "$PYTHON" --host "$BURP_HOST" --port "$BURP_PORT" proxy
                ;;
        esac
        ;;
    target)
        case "${2:-}" in
            add)
                python3 "$PYTHON" --host "$BURP_HOST" --port "$BURP_PORT" target add "${3:-}"
                ;;
            scope|list)
                python3 "$PYTHON" --host "$BURP_HOST" --port "$BURP_PORT" target scope
                ;;
            *)
                python3 "$PYTHON" --host "$BURP_HOST" --port "$BURP_PORT" target scope
                ;;
        esac
        ;;
    scope-export)
        _exp_args=(scope-export)
        [ -n "${2:-}" ] && _exp_args+=(--program "$2")
        [ -n "${3:-}" ] && _exp_args+=(--output "$3")
        python3 "$PYTHON" "${_exp_args[@]}"
        ;;
    spider)
        python3 "$PYTHON" --host "$BURP_HOST" --port "$BURP_PORT" spider start "${2:-}"
        ;;
    scan)
        if [ -n "${2:-}" ]; then
            python3 "$PYTHON" --host "$BURP_HOST" --port "$BURP_PORT" scan start "$2"
        else
            python3 "$PYTHON" --host "$BURP_HOST" --port "$BURP_PORT" scan status
        fi
        ;;
    issues)
        case "${2:-}" in
            export)
                python3 "$PYTHON" --host "$BURP_HOST" --port "$BURP_PORT" issues export
                ;;
            details)
                python3 "$PYTHON" --host "$BURP_HOST" --port "$BURP_PORT" issues details "${3:-}"
                ;;
            *)
                python3 "$PYTHON" --host "$BURP_HOST" --port "$BURP_PORT" issues list
                ;;
        esac
        ;;
    repeater)
        python3 "$PYTHON" --host "$BURP_HOST" --port "$BURP_PORT" repeater --url "${2:-}"
        ;;
    launch)
        launch_burp
        ;;
    config)
        show_config
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        show_help
        ;;
esac
