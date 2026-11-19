#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_REPO="$(mktemp -d)"
trap 'rm -rf "$TMP_REPO"' EXIT

export BB_CRT_RETRY_DELAY=0

mkdir -p "$TMP_REPO/programs"
cp -r "$ROOT/scripts" "$ROOT/auto-scanner" "$ROOT/bugbounty" "$TMP_REPO/"
cp "$ROOT/programs/README.md" "$ROOT/programs/_template.md" "$TMP_REPO/programs/"

cat > "$TMP_REPO/programs/aaa-other.md" <<'EOF'
# Other Program

| Field | Value |
|-------|-------|
| **Status** | Active |

## In Scope
- other.example

## Special Rules
- Mandatory header: `X-Other-Research: wrong-handle`
EOF

cat > "$TMP_REPO/programs/zzz-target.md" <<'EOF'
# Target Program

| Field | Value |
|-------|-------|
| **Platform** | Intigriti |
| **Status** | Active |

## In Scope
- target.example
- *.target.example

## Special Rules
- Rate limit: 7 req/s
- Mandatory header: `X-Target-Research: my-handle`
EOF

cat > "$TMP_REPO/programs/noheader.md" <<'EOF'
# No Header Program

| Field | Value |
|-------|-------|
| **Status** | Active |

## In Scope
- noheader.example
EOF

# 1. BB_VERSION consistency (single source in common.sh)
ver_out="$(bash "$TMP_REPO/bugbounty/bugbounty-hunter.sh" --version)"
if [ "$ver_out" != "bugbounty-hunter 1.3.0" ]; then
    echo "Unexpected BB_VERSION output: $ver_out" >&2
    exit 1
fi

# 2. browser_capture.sh resolves ONLY the matching program's header, valid JSON escaping, and URL scope filtering
mkdir -p "$TMP_REPO/mockbin"
cat > "$TMP_REPO/mockbin/node" <<'EOF'
#!/usr/bin/env bash
out_dir="${3:-}"
printf 'CAPTURED_HEADERS=%s\n' "${BB_EXTRA_HEADERS:-EMPTY}"
if [ -n "$out_dir" ]; then
    mkdir -p "$out_dir"
    printf 'https://target.example/api/v1/profile\nhttps://thirdparty.invalid/analytics.js\n' > "$out_dir/browser_urls_raw.txt"
fi
exit 0
EOF
chmod +x "$TMP_REPO/mockbin/node"

out_target="$(PATH="$TMP_REPO/mockbin:$PATH" bash "$TMP_REPO/auto-scanner/integrations/browser_capture.sh" "https://target.example" "$TMP_REPO/bc_out1" 2>&1)"
if ! printf '%s' "$out_target" | grep -q 'CAPTURED_HEADERS={"X-Target-Research":"my-handle"}'; then
    echo "Wrong header injected for target.example: $out_target" >&2
    exit 1
fi
if [ "$(cat "$TMP_REPO/bc_out1/browser_urls_in_scope.txt")" != "https://target.example/api/v1/profile" ]; then
    echo "browser_capture.sh did not scope-filter browser_urls_raw.txt:" >&2
    cat "$TMP_REPO/bc_out1/browser_urls_in_scope.txt" >&2
    exit 1
fi

out_nohdr="$(PATH="$TMP_REPO/mockbin:$PATH" bash "$TMP_REPO/auto-scanner/integrations/browser_capture.sh" "https://noheader.example" "$TMP_REPO/bc_out2" 2>&1)"
if ! printf '%s' "$out_nohdr" | grep -q 'CAPTURED_HEADERS=EMPTY'; then
    echo "Cross-program header leaked to noheader.example: $out_nohdr" >&2
    exit 1
fi

escaped_json="$(PATH="$TMP_REPO/mockbin:$PATH" BB_RESEARCH_HEADER='X-Test: a"b\c' bash "$TMP_REPO/auto-scanner/integrations/browser_capture.sh" "https://target.example" "$TMP_REPO/bc_out3" 2>&1 | sed -n 's/CAPTURED_HEADERS=//p')"
python3 -c 'import json, sys; d = json.loads(sys.argv[1]); assert d == {"X-Test": "a\"b\\c"}, d' "$escaped_json"

# 3. CLI flag positioning (--passive-only anywhere + --rate-limit override)
mkdir -p "$TMP_REPO/mocktools"
cat > "$TMP_REPO/mocktools/subfinder" <<'EOF'
#!/usr/bin/env bash
printf 'sub.target.example\n'
EOF
cat > "$TMP_REPO/mocktools/httpx" <<'EOF'
#!/usr/bin/env bash
printf 'HTTPX_ARGS=%s\n' "$*" >> "$(dirname "$0")/../httpx_args.log"
out=""
while [ $# -gt 0 ]; do
    if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
if [ -n "$out" ]; then
    printf '{"url":"https://target.example","status_code":200,"tech":["Nginx"],"cname":"target.edge.net"}\n' > "$out"
    printf '{"url":"https://sub.target.example","status_code":404,"tech":["S3"],"cname":"old.github.io"}\n' >> "$out"
fi
EOF
cat > "$TMP_REPO/mocktools/katana" <<'EOF'
#!/usr/bin/env bash
printf 'KATANA_ARGS=%s\n' "$*" >> "$(dirname "$0")/../katana_args.log"
out=""
while [ $# -gt 0 ]; do
    if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
[ -n "$out" ] && printf 'https://target.example/static/app.js\n' > "$out"
EOF
cat > "$TMP_REPO/mocktools/gau" <<'EOF'
#!/usr/bin/env bash
cat >/dev/null
printf 'https://target.example/logo.png\nhttps://target.example/orders?id=10&sort=asc\nhttps://target.example/orders?sort=desc&id=20\nhttps://target.example/search?q=xss\n'
EOF
cat > "$TMP_REPO/mocktools/curl" <<'EOF'
#!/usr/bin/env bash
url="${@: -1}"
if printf '%s' "$*" | grep -q -- '-w %{http_code}'; then
    case "$url" in
        */swagger.json|*/swagger-ui.html) printf '200'; exit 0 ;;
        *) printf '404'; exit 0 ;;
    esac
fi
case "$url" in
    */swagger.json) printf '{"openapi":"3.0"}' ;;
    */swagger-ui.html) printf '<html>Swagger UI</html>' ;;
    */app.js) printf 'const api_key = "dummy-test-value";\n' ;;
    */graphql) printf '{"data":null}' ;;
    *) exit 0 ;;
esac
EOF
chmod +x "$TMP_REPO/mocktools/subfinder" "$TMP_REPO/mocktools/httpx" "$TMP_REPO/mocktools/katana" "$TMP_REPO/mocktools/gau" "$TMP_REPO/mocktools/curl"

# Flag BEFORE subcommand must skip active stages
PATH="$TMP_REPO/mocktools:$PATH" bash "$TMP_REPO/bugbounty/bugbounty-hunter.sh" --passive-only recon target.example >/dev/null 2>&1
if [ -e "$TMP_REPO/httpx_args.log" ] || [ -e "$TMP_REPO/katana_args.log" ]; then
    echo "--passive-only before subcommand failed to skip active httpx/katana" >&2
    exit 1
fi

# Active recon run (program rate limit = 7)
rm -f "$TMP_REPO/httpx_args.log" "$TMP_REPO/katana_args.log"
PATH="$TMP_REPO/mocktools:$TMP_REPO/mockbin:$PATH" bash "$TMP_REPO/bugbounty/bugbounty-hunter.sh" recon target.example >/dev/null 2>&1

recon_dir="$TMP_REPO/bugbounty/reports/target.example/recon"
raw_subs="$recon_dir/subdomains_raw.txt"
if ! grep -qx 'target.example' "$raw_subs" || ! grep -qx 'sub.target.example' "$raw_subs"; then
    echo "subfinder overwrote apex target in $raw_subs:" >&2
    cat "$raw_subs" >&2
    exit 1
fi
if ! grep -q -- '-H X-Target-Research: my-handle' "$TMP_REPO/httpx_args.log" || ! grep -q -- '-rl 7' "$TMP_REPO/httpx_args.log"; then
    echo "Expected research header and -rl 7 in httpx args:" >&2
    cat "$TMP_REPO/httpx_args.log" >&2
    exit 1
fi
if ! grep -q -- '-rl 7' "$TMP_REPO/katana_args.log"; then
    echo "Expected -rl 7 in katana args:" >&2
    cat "$TMP_REPO/katana_args.log" >&2
    exit 1
fi
if ! grep -qx 'https://sub.target.example' "$recon_dir/live_urls.txt"; then
    echo "parse-httpx did not populate live_urls.txt" >&2
    exit 1
fi
if ! grep -q 'old.github.io' "$recon_dir/takeover_candidates.txt"; then
    echo "parse-httpx did not record takeover candidate" >&2
    exit 1
fi
if grep -q 'logo.png' "$recon_dir/clean_urls.txt" || [ ! -f "$recon_dir/candidates_sqli.txt" ]; then
    echo "clean-urls failed to strip static noise" >&2
    exit 1
fi
if ! grep -q 'orders?id=' "$recon_dir/candidates_sqli.txt"; then
    echo "clean-urls did not route ?id= into candidates_sqli.txt" >&2
    exit 1
fi

# 4. vuln_scan receives live_urls, -tags, --rate-limit 3 override, dalfox, and sqlmap candidates
cat > "$TMP_REPO/mocktools/nuclei" <<'EOF'
#!/usr/bin/env bash
printf 'NUCLEI_ARGS=%s\n' "$*" >> "$(dirname "$0")/../nuclei_args.log"
EOF
cat > "$TMP_REPO/mocktools/dalfox" <<'EOF'
#!/usr/bin/env bash
out=""
while [ $# -gt 0 ]; do
    if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
cat > "$out"
EOF
cat > "$TMP_REPO/mocktools/sqlmap" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$(dirname "$0")/../sqlmap_args.log"
EOF
chmod +x "$TMP_REPO/mocktools/nuclei" "$TMP_REPO/mocktools/dalfox" "$TMP_REPO/mocktools/sqlmap"

PATH="$TMP_REPO/mocktools:$PATH" bash "$TMP_REPO/bugbounty/bugbounty-hunter.sh" vuln target.example --rate-limit 3 >/dev/null 2>&1
if ! grep -q -- '-rl 3' "$TMP_REPO/nuclei_args.log" || ! grep -q -- '-tags cors' "$TMP_REPO/nuclei_args.log"; then
    echo "nuclei did not receive -rl 3 and -tags cors:" >&2
    cat "$TMP_REPO/nuclei_args.log" >&2
    exit 1
fi
xss_out="$TMP_REPO/bugbounty/reports/target.example/vulns/xss.txt"
if ! grep -q '/search?q=xss' "$xss_out" || ! grep -q 'id=test' "$xss_out"; then
    echo "dalfox missed expected candidates in $xss_out:" >&2
    cat "$xss_out" >&2
    exit 1
fi
if ! grep -q -- '-m ' "$TMP_REPO/sqlmap_args.log"; then
    echo "sqlmap was not invoked with -m:" >&2
    cat "$TMP_REPO/sqlmap_args.log" >&2
    exit 1
fi

# 5. secrets respects --passive-only and when active prefixes matched JS URL
PATH="$TMP_REPO/mocktools:$PATH" BB_PASSIVE_ONLY=1 bash "$TMP_REPO/bugbounty/bugbounty-hunter.sh" secrets target.example >/dev/null 2>&1
if [ -s "$TMP_REPO/bugbounty/reports/target.example/secrets/js_secrets.txt" ]; then
    echo "secrets_hunting ran curl despite BB_PASSIVE_ONLY=1" >&2
    exit 1
fi
PATH="$TMP_REPO/mocktools:$PATH" bash "$TMP_REPO/bugbounty/bugbounty-hunter.sh" secrets target.example >/dev/null 2>&1
if ! grep -q '^\[https://target.example/static/app.js\] ' "$TMP_REPO/bugbounty/reports/target.example/secrets/js_secrets.txt"; then
    echo "secrets_hunting did not record [URL] attribution:" >&2
    cat "$TMP_REPO/bugbounty/reports/target.example/secrets/js_secrets.txt" >&2
    exit 1
fi

# 6. api_testing respects BB_PASSIVE_ONLY=1 and writes valid JSON index otherwise
rm -f "$TMP_REPO/bugbounty/reports/target.example/api/api_docs_index.json"
PATH="$TMP_REPO/mocktools:$PATH" BB_PASSIVE_ONLY=1 bash "$TMP_REPO/bugbounty/bugbounty-hunter.sh" api target.example >/dev/null 2>&1
if [ -e "$TMP_REPO/bugbounty/reports/target.example/api/api_docs_index.json" ]; then
    echo "api_testing ran active probes despite BB_PASSIVE_ONLY=1" >&2
    exit 1
fi
PATH="$TMP_REPO/mocktools:$PATH" bash "$TMP_REPO/bugbounty/bugbounty-hunter.sh" api target.example >/dev/null 2>&1
python3 -c '
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
paths = [d["path"] for d in data["discovered"]]
assert "/swagger.json" in paths and "/swagger-ui.html" in paths, paths
' "$TMP_REPO/bugbounty/reports/target.example/api/api_docs_index.json"

# 7. --resume skips already completed phases and --fresh clears checkpoints
rm -f "$TMP_REPO/nuclei_args.log"
PATH="$TMP_REPO/mocktools:$TMP_REPO/mockbin:$PATH" bash "$TMP_REPO/bugbounty/bugbounty-hunter.sh" full target.example --resume >/dev/null 2>&1
if [ -e "$TMP_REPO/nuclei_args.log" ]; then
    echo "--resume did not skip vuln phase despite checkpoint marker" >&2
    exit 1
fi
if [ ! -f "$TMP_REPO/bugbounty/reports/target.example/.state/report.done" ]; then
    echo "full did not create report.done checkpoint" >&2
    exit 1
fi
rep_file="$(ls "$TMP_REPO/bugbounty/reports/target.example"/report-*.md | head -n1)"
if ! grep -q 'Target Program' "$rep_file" || ! grep -q 'Recon & Scan Telemetry Summary' "$rep_file"; then
    echo "report did not use template + telemetry summary:" >&2
    cat "$rep_file" >&2
    exit 1
fi

PATH="$TMP_REPO/mocktools:$TMP_REPO/mockbin:$PATH" BB_PASSIVE_ONLY=1 bash "$TMP_REPO/bugbounty/bugbounty-hunter.sh" full target.example --fresh --resume >/dev/null 2>&1
if [ ! -f "$TMP_REPO/bugbounty/reports/target.example/.state/vuln.done" ]; then
    echo "--fresh failed to re-run cleared phases" >&2
    exit 1
fi

# 8. scope-audit & kev-correlate.sh safe JSON webhook encoding
bash "$TMP_REPO/bugbounty/bugbounty-hunter.sh" scope-audit >/dev/null 2>&1
mkdir -p "$TMP_REPO/auto-scanner/threat-intel"
printf '{"vulnerabilities":[{"cveID":"CVE-2026-0001","vendorProject":"Quote \\"Vendor\\"","product":"TestApp","vulnerabilityName":"Test Bug"}]}\n' > "$TMP_REPO/auto-scanner/threat-intel/kev.json"
cat > "$TMP_REPO/mocktools/curl" <<'EOF'
#!/usr/bin/env bash
while [ $# -gt 0 ]; do
    if [ "$1" = "-d" ]; then
        printf '%s' "$2" > "$(dirname "$0")/../kev_payload.json"
        exit 0
    fi
    shift
done
EOF
chmod +x "$TMP_REPO/mocktools/curl"
PATH="$TMP_REPO/mocktools:$PATH" WEBHOOK_URL="https://webhook.invalid/test" bash "$TMP_REPO/auto-scanner/kev-correlate.sh" --tech "TestApp" >/dev/null 2>&1
python3 -c 'import json, sys; d = json.load(open(sys.argv[1], encoding="utf-8")); assert "CVE-2026-0001" in d["text"], d' "$TMP_REPO/kev_payload.json"

# 9. check-sensitive-files.sh rejects tracked private programs/*.md and cookies.txt
git -C "$TMP_REPO" init -q
git -C "$TMP_REPO" config user.email "test@example.com"
git -C "$TMP_REPO" config user.name "Test"
cp "$ROOT/.gitignore" "$TMP_REPO/.gitignore"
git -C "$TMP_REPO" add scripts/check-sensitive-files.sh programs/README.md programs/_template.md
if git -C "$TMP_REPO" add programs/aaa-other.md 2>/dev/null; then
    echo ".gitignore failed to ignore private programs/*.md" >&2
    exit 1
fi
git -C "$TMP_REPO" add -f programs/aaa-other.md
if (cd "$TMP_REPO" && bash scripts/check-sensitive-files.sh >/dev/null 2>&1); then
    echo "check-sensitive-files.sh failed to reject tracked private program" >&2
    exit 1
fi

echo "Pipeline regression tests passed."
