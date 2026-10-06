#!/bin/bash
# ============================================
# KEV / Threat-Intel Correlation
# ============================================
# Pulls the CISA Known-Exploited-Vulnerabilities catalog (public, no API key)
# and correlates it against a list of products/technologies you detected on a
# target (e.g. from `httpx -td`). Prints KEV entries whose vendor/product match,
# so you prioritize CVEs that are BOTH in your target's stack AND known-exploited.
#
# Optional extra sources (documented, enable as needed):
#   - EPSS score per CVE:  https://api.first.org/data/v1/epss?cve=CVE-XXXX-YYYY
#   - NVD 2.0 detail:      https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...
#   - OSV (OSS deps):      https://api.osv.dev/v1/query
#   - nuclei-templates:    new templates often land days after a CVE is public
#
# Usage:
#   ./kev-correlate.sh <tech-list-file>        # one product/vendor per line
#   ./kev-correlate.sh --tech "Grafana,Kibana,Next.js"
#   httpx -td ... | ./kev-correlate.sh -       # read tech tokens from stdin
#   WEBHOOK_URL=https://hooks.slack.com/... ./kev-correlate.sh tech.txt   # alert
# ============================================

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_DIR="$(dirname "$0")/threat-intel"
KEV_CACHE="$CACHE_DIR/kev.json"
mkdir -p "$CACHE_DIR"

have() { command -v "$1" >/dev/null 2>&1; }

if ! have jq; then
    echo -e "${RED}jq is required for this script.${NC}" >&2
    exit 1
fi

# ── Collect technology tokens ────────────────────────────────────────
TECH=""
case "${1:-}" in
    --tech)
        TECH=$(echo "${2:-}" | tr ',' '\n')
        ;;
    -)
        # stdin: grab words that look like product names from httpx/-td output
        TECH=$(tr ',[]' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -vE '^$')
        ;;
    "")
        echo -e "${YELLOW}Usage: $0 <tech-list-file> | --tech \"A,B\" | -${NC}"
        exit 1
        ;;
    *)
        if [ -f "$1" ]; then
            TECH=$(cat "$1")
        else
            echo -e "${RED}File not found: $1${NC}" >&2
            exit 1
        fi
        ;;
esac

TECH=$(echo "$TECH" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -vE '^$' | sort -u)
if [ -z "$TECH" ]; then
    echo -e "${YELLOW}No technology tokens provided.${NC}"
    exit 1
fi

# ── Fetch KEV catalog (cache 12h) ────────────────────────────────────
echo -e "${CYAN}Fetching CISA KEV catalog...${NC}"
if [ ! -f "$KEV_CACHE" ] || [ "$(find "$KEV_CACHE" -mmin +720 2>/dev/null)" ]; then
    if ! curl -s "$KEV_URL" -o "$KEV_CACHE" 2>/dev/null || ! jq -e . "$KEV_CACHE" >/dev/null 2>&1; then
        echo -e "${RED}Could not fetch/parse the KEV catalog.${NC}" >&2
        exit 1
    fi
fi
TOTAL=$(jq '.vulnerabilities | length' "$KEV_CACHE" 2>/dev/null || echo "?")
echo -e "${GREEN}  KEV entries: $TOTAL${NC}"

# ── Correlate ────────────────────────────────────────────────────────
echo -e "${CYAN}Correlating against your target's stack...${NC}"
MATCHES=0
ALERT_LINES=""
while IFS= read -r token; do
    [ -n "$token" ] || continue
    # Case-insensitive substring match on vendorProject or product.
    results=$(jq -r --arg t "$token" '
        .vulnerabilities[]
        | select((.vendorProject + " " + .product) | ascii_downcase | contains($t | ascii_downcase))
        | "\(.cveID)\t\(.vendorProject) \(.product)\t\(.vulnerabilityName)"
    ' "$KEV_CACHE" 2>/dev/null)
    if [ -n "$results" ]; then
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            cve=$(echo "$line" | cut -f1)
            desc=$(echo "$line" | cut -f2-)
            echo -e "${RED}  [KEV] $cve${NC}  ($token) — $desc"
            ALERT_LINES="${ALERT_LINES}\n$cve ($token) — $desc"
            MATCHES=$((MATCHES + 1))
        done <<<"$results"
    fi
done <<<"$TECH"

echo ""
if [ "$MATCHES" -eq 0 ]; then
    echo -e "${GREEN}No KEV entries matched the provided stack.${NC}"
    exit 0
fi
echo -e "${YELLOW}$MATCHES known-exploited CVE(s) matched your target's stack — prioritize these.${NC}"
echo -e "${YELLOW}Tip: add EPSS with  curl -s 'https://api.first.org/data/v1/epss?cve=<CVE>'${NC}"

# ── Optional webhook alert ───────────────────────────────────────────
if [ -n "${WEBHOOK_URL:-}" ]; then
    payload=$(printf '{"text":"KEV match (%s): %b"}' "$MATCHES" "$ALERT_LINES")
    curl -s -X POST -H "Content-Type: application/json" -d "$payload" "$WEBHOOK_URL" >/dev/null 2>&1 \
        && echo -e "${GREEN}Alert posted to webhook.${NC}" \
        || echo -e "${YELLOW}Webhook post failed.${NC}"
fi
