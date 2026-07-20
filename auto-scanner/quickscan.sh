#!/bin/bash
# ============================================
# Quick Scan - Fast Scanning
# ============================================
# Usage: ./quickscan.sh https://your-site.com
# 
# Quick scan for when you need fast results
# ============================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Check arguments
if [ $# -eq 0 ]; then
    echo -e "${RED}Usage: $0 <url>${NC}"
    exit 1
fi

TARGET_URL="$1"
require_scope "$TARGET_URL" || exit 1
DOMAIN=$(normalize_target "$TARGET_URL") || exit 1
TARGET_IP=$(dig +short "$DOMAIN" | head -1)

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                   QUICK SCAN v1.0                           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${BLUE}Target:${NC} $TARGET_URL"
echo -e "${BLUE}IP:${NC} $TARGET_IP"
echo ""

# 1. Check if online
echo -e "${YELLOW}[1/5]${NC} Checking connectivity..."
if curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL" | grep -q "200\|301\|302"; then
    echo -e "${GREEN}  ✓ Online${NC}"
else
    echo -e "${RED}  ✗ Offline or not accessible${NC}"
    exit 1
fi

# 2. Headers HTTP
echo -e "${YELLOW}[2/5]${NC} Analyzing HTTP headers..."
echo ""
curl -sI "$TARGET_URL" | head -15
echo ""

# 3. Puertos abiertos
echo -e "${YELLOW}[3/5]${NC} Scanning main ports..."
echo ""
nmap -sT --top-ports 20 -T4 "$TARGET_IP" 2>/dev/null | grep -E "^[0-9]+/tcp|^PORT"
echo ""

# 4. Verificar HTTPS
echo -e "${YELLOW}[4/5]${NC} Checking HTTPS..."
if echo "$TARGET_URL" | grep -q "^https"; then
    echo -e "${GREEN}  ✓ HTTPS enabled${NC}"
    
    # Check certificate
    EXPIRY=$(echo | openssl s_client -connect "$DOMAIN":443 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    if [ -n "$EXPIRY" ]; then
        echo "  Certificate expires: $EXPIRY"
    fi
else
    echo -e "${RED}  ✗ HTTP only (unencrypted)${NC}"
fi

# 5. Archivos sensibles
echo -e "${YELLOW}[5/5]${NC} Searching for sensitive files..."
echo ""

SENSITIVE=("/.env" "/.git/config" "/wp-config.php" "/phpinfo.php" "/robots.txt" "/sitemap.xml")
FOUND=0

for file in "${SENSITIVE[@]}"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}${file}" 2>/dev/null)
    
    if [ "$STATUS" = "200" ]; then
        echo -e "${RED}  ✗ ${file} - EXPOSED${NC}"
        FOUND=$((FOUND + 1))
    fi
done

if [ $FOUND -eq 0 ]; then
    echo -e "${GREEN}  ✓ No sensitive files found${NC}"
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Quick scan completed${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "For a full scan run:"
echo "  ./autopentest.sh $TARGET_URL"
echo ""
