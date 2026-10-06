#!/bin/bash
# ============================================
# GitHub Repo Scanner
# ============================================
# Usage: ./github-scan.sh <user/repo>
#
# Scans a GitHub repository for:
# - Secret files committed to the tree (.env, id_rsa, *.pem, ...)
# - Verified secrets across the FULL git history (trufflehog / gitleaks)
# - Dependency-confusion risk (internal/unclaimed package names)
#
# Auth: export GITHUB_TOKEN=<pat> for higher API limits and code search.
# Optional engines (auto-detected): trufflehog, gitleaks, git, jq.
# ============================================

set -uo pipefail   # NOTE: no `-e` — a non-match from grep/curl must not abort the scan.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

if [ $# -eq 0 ]; then
    echo -e "${RED}Usage: $0 <user/repo>${NC}"
    echo "Example: $0 your-user/your-repo"
    exit 1
fi

REPO="$1"
REPO_URL="https://github.com/$REPO"
API_URL="https://api.github.com/repos/$REPO"

# Build auth header array only when a token is present (empty array = no header).
AUTH_HEADER=()
if [ -n "${GITHUB_TOKEN:-}" ]; then
    AUTH_HEADER=(-H "Authorization: Bearer $GITHUB_TOKEN")
fi

have() { command -v "$1" >/dev/null 2>&1; }

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                GITHUB REPO SCANNER v2.0                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${BLUE}Repository:${NC} $REPO_URL"
if [ ${#AUTH_HEADER[@]} -eq 0 ]; then
    echo -e "${YELLOW}No GITHUB_TOKEN set — API limits are low and code search is disabled.${NC}"
fi
echo ""

# ── 1. Repository information ────────────────────────────────────────
echo -e "${YELLOW}[1/5]${NC} Getting repository information..."
REPO_INFO=$(curl -s "${AUTH_HEADER[@]}" "$API_URL")

if have jq; then
    MESSAGE=$(echo "$REPO_INFO" | jq -r '.message // empty')
    if [ "$MESSAGE" = "Not Found" ]; then
        echo -e "${RED}  ✗ Repository not found${NC}"; exit 1
    fi
    if echo "$MESSAGE" | grep -qi "rate limit"; then
        echo -e "${RED}  ✗ GitHub API rate limit exceeded. Set GITHUB_TOKEN for higher limits.${NC}"; exit 1
    fi
    echo -e "${GREEN}  ✓ Repository found${NC}"
    echo "    Name:        $(echo "$REPO_INFO" | jq -r '.full_name // "?"')"
    echo "    Description: $(echo "$REPO_INFO" | jq -r '.description // "—"')"
    echo "    Stars:       $(echo "$REPO_INFO" | jq -r '.stargazers_count // 0')"
    echo "    Default br.: $(echo "$REPO_INFO" | jq -r '.default_branch // "main"')"
    DEFAULT_BRANCH=$(echo "$REPO_INFO" | jq -r '.default_branch // "main"')
else
    echo -e "${YELLOW}  (jq not installed — install jq for reliable parsing)${NC}"
    if echo "$REPO_INFO" | grep -q '"message": *"Not Found"'; then
        echo -e "${RED}  ✗ Repository not found${NC}"; exit 1
    fi
    DEFAULT_BRANCH="main"
fi
echo ""

# ── 2. Secret files committed to the tree ────────────────────────────
# A public repo serving these is a real finding: the file should never have
# been committed. We check the default branch plus master/main.
echo -e "${YELLOW}[2/5]${NC} Checking for secret files committed to the repo..."
SENSITIVE_FILES=(
    ".env" ".env.local" ".env.production" ".env.development"
    "config/database.yml" "config/secrets.yml" "wp-config.php" "config.php"
    "configuration.php" "settings.py" "credentials.json" "service-account.json"
    "id_rsa" "id_dsa" "id_ecdsa" "id_ed25519" ".htpasswd" "web.config"
    "appsettings.json" "appsettings.Development.json" "local.settings.json"
    "firebase.json" "gcloud.json" "key.json" "private.key" "private.pem" ".npmrc" ".pypirc"
)
FOUND_SENSITIVE=0
BRANCHES=("$DEFAULT_BRANCH" "master" "main")
# de-dup branches
read -r -a BRANCHES <<<"$(printf '%s\n' "${BRANCHES[@]}" | awk '!seen[$0]++' | tr '\n' ' ')"
for file in "${SENSITIVE_FILES[@]}"; do
    for br in "${BRANCHES[@]}"; do
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://raw.githubusercontent.com/$REPO/$br/$file" 2>/dev/null || echo "000")
        if [ "$STATUS" = "200" ]; then
            echo -e "${RED}  ✗ $file (branch: $br) — committed to repo${NC}"
            FOUND_SENSITIVE=$((FOUND_SENSITIVE + 1))
            break
        fi
    done
done
[ "$FOUND_SENSITIVE" -eq 0 ] && echo -e "${GREEN}  ✓ No obvious secret files committed${NC}"
echo ""

# ── 3. Verified secrets across full history (real engine) ────────────
echo -e "${YELLOW}[3/5]${NC} Scanning full git history for verified secrets..."
if have trufflehog; then
    echo -e "${BLUE}  → trufflehog (verified only)${NC}"
    trufflehog git "$REPO_URL" --only-verified --no-update 2>/dev/null || \
        echo -e "${YELLOW}  (trufflehog returned no verified secrets or could not clone)${NC}"
elif have gitleaks && have git; then
    echo -e "${BLUE}  → gitleaks (full history)${NC}"
    TMP_CLONE=$(mktemp -d "/tmp/ghscan.XXXXXX")
    if git clone --quiet "$REPO_URL" "$TMP_CLONE" 2>/dev/null; then
        gitleaks detect --source "$TMP_CLONE" --no-banner 2>/dev/null || \
            echo -e "${YELLOW}  (gitleaks found nothing or errored)${NC}"
    else
        echo -e "${YELLOW}  (could not clone repo for gitleaks)${NC}"
    fi
    rm -rf -- "$TMP_CLONE"
else
    echo -e "${YELLOW}  ⚠ Neither trufflehog nor gitleaks installed — history NOT scanned.${NC}"
    echo -e "${YELLOW}    Install one: 'trufflehog' (recommended) or 'gitleaks'.${NC}"
    echo -e "${YELLOW}    (The old count-only code-search check was removed: it required auth,"
    echo -e "     never used GITHUB_TOKEN, and only printed result counts — not actionable.)${NC}"
fi
echo ""

# ── 4. Dependency-confusion surface ──────────────────────────────────
# Pull package names from manifests and flag internal/unclaimed names that
# do NOT exist on the public registry (claimable → dependency confusion).
echo -e "${YELLOW}[4/5]${NC} Checking dependency-confusion surface..."
if have jq; then
    PKG_JSON=$(curl -s "https://raw.githubusercontent.com/$REPO/$DEFAULT_BRANCH/package.json" 2>/dev/null)
    if echo "$PKG_JSON" | jq -e . >/dev/null 2>&1; then
        NAMES=$(echo "$PKG_JSON" | jq -r '((.dependencies // {}) + (.devDependencies // {})) | keys[]' 2>/dev/null)
        CONF=0
        while IFS= read -r pkg; do
            [ -n "$pkg" ] || continue
            # npm registry: 404 = name not published publicly = potentially claimable
            code=$(curl -s -o /dev/null -w "%{http_code}" "https://registry.npmjs.org/$pkg" 2>/dev/null || echo "000")
            if [ "$code" = "404" ]; then
                echo -e "${RED}  ✗ '$pkg' not on public npm (dependency-confusion candidate)${NC}"
                CONF=$((CONF + 1))
            fi
        done <<<"$NAMES"
        [ "$CONF" -eq 0 ] && echo -e "${GREEN}  ✓ All npm deps resolve publicly${NC}"
    else
        echo -e "${GREEN}  ✓ No parseable package.json on default branch${NC}"
    fi
else
    echo -e "${YELLOW}  (jq required for dependency-confusion check — skipped)${NC}"
fi
echo ""

# ── 5. CI/CD presence (informational) ────────────────────────────────
echo -e "${YELLOW}[5/5]${NC} Checking CI/CD configuration (informational)..."
CI_FILES=(".github/workflows/ci.yml" ".travis.yml" "Jenkinsfile" ".circleci/config.yml" "azure-pipelines.yml" ".gitlab-ci.yml")
for file in "${CI_FILES[@]}"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://raw.githubusercontent.com/$REPO/$DEFAULT_BRANCH/$file" 2>/dev/null || echo "000")
    [ "$STATUS" = "200" ] && echo -e "${GREEN}  ✓ $file present${NC}"
done
echo ""

# ── Summary ──────────────────────────────────────────────────────────
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
if [ "$FOUND_SENSITIVE" -gt 0 ]; then
    echo -e "${RED}⚠ $FOUND_SENSITIVE secret file(s) committed to the repo${NC}"
    echo "RECOMMENDED: remove from tree, rotate the secrets, purge git history (git filter-repo / BFG), add to .gitignore."
else
    echo -e "${GREEN}✓ No committed secret files found (history scan depends on engine availability above)${NC}"
fi
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
