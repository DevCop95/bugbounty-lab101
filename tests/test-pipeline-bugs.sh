#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_REPO="$(mktemp -d)"
trap 'rm -rf "$TMP_REPO"' EXIT

mkdir -p "$TMP_REPO/programs"
cp -r "$ROOT/scripts" "$ROOT/auto-scanner" "$ROOT/bugbounty" "$TMP_REPO/"
cp "$ROOT/programs/README.md" "$ROOT/programs/_template.md" "$TMP_REPO/programs/"

cat > "$TMP_REPO/programs/aaa-other.md" <<'EOF'
# Other Program

## In Scope
- other.example
- Mandatory header: `X-Other-Research: wrong-handle`
EOF

cat > "$TMP_REPO/programs/zzz-target.md" <<'EOF'
# Target Program

## In Scope
- target.example
- *.target.example
- Mandatory header: `X-Target-Research: my-handle`
EOF

cat > "$TMP_REPO/programs/noheader.md" <<'EOF'
# No Header Program

## In Scope
- noheader.example
EOF

# 1. BB_VERSION consistency (single source in common.sh)
ver_out="$(bash "$TMP_REPO/bugbounty/bugbounty-hunter.sh" --version)"
if [ "$ver_out" != "bugbounty-hunter 1.2.1" ]; then
    echo "Unexpected BB_VERSION output: $ver_out" >&2
    exit 1
fi

# 2. browser_capture.sh resolves ONLY the matching program's header + valid JSON escaping
mkdir -p "$TMP_REPO/mockbin"
cat > "$TMP_REPO/mockbin/node" <<'EOF'
#!/usr/bin/env bash
printf 'CAPTURED_HEADERS=%s\n' "${BB_EXTRA_HEADERS:-EMPTY}"
exit 0
EOF
chmod +x "$TMP_REPO/mockbin/node"

out_target="$(PATH="$TMP_REPO/mockbin:$PATH" bash "$TMP_REPO/auto-scanner/integrations/browser_capture.sh" "https://target.example" "$TMP_REPO/bc_out1" 2>&1)"
if ! printf '%s' "$out_target" | grep -q 'CAPTURED_HEADERS={"X-Target-Research":"my-handle"}'; then
    echo "Wrong header injected for target.example: $out_target" >&2
    exit 1
fi

out_nohdr="$(PATH="$TMP_REPO/mockbin:$PATH" bash "$TMP_REPO/auto-scanner/integrations/browser_capture.sh" "https://noheader.example" "$TMP_REPO/bc_out2" 2>&1)"
if ! printf '%s' "$out_nohdr" | grep -q 'CAPTURED_HEADERS=EMPTY'; then
    echo "Cross-program header leaked to noheader.example: $out_nohdr" >&2
    exit 1
fi

escaped_json="$(PATH="$TMP_REPO/mockbin:$PATH" BB_RESEARCH_HEADER='X-Test: a"b\c' bash "$TMP_REPO/auto-scanner/integrations/browser_capture.sh" "https://target.example" "$TMP_REPO/bc_out3" 2>&1 | sed -n 's/CAPTURED_HEADERS=//p')"
python3 -c 'import json, sys; d = json.loads(sys.argv[1]); assert d == {"X-Test": "a\"b\\c"}, d' "$escaped_json"

# 3. subfinder appends without overwriting apex target, and research header is propagated to httpx
mkdir -p "$TMP_REPO/mocktools"
cat > "$TMP_REPO/mocktools/subfinder" <<'EOF'
#!/usr/bin/env bash
printf 'sub.target.example\n'
EOF
cat > "$TMP_REPO/mocktools/httpx" <<'EOF'
#!/usr/bin/env bash
printf 'HTTPX_ARGS=%s\n' "$*" >> "$(dirname "$0")/../httpx_args.log"
EOF
cat > "$TMP_REPO/mocktools/curl" <<'EOF'
#!/usr/bin/env bash
url="${@: -1}"
if [ "$1" = "-s" ] && printf '%s' "$*" | grep -q -- '-w %{http_code}'; then
    case "$url" in
        */swagger.json|*/swagger-ui.html) printf '200'; exit 0 ;;
        *) printf '404'; exit 0 ;;
    esac
fi
case "$url" in
    */swagger.json) printf '{"openapi":"3.0"}' ;;
    */swagger-ui.html) printf '<html>Swagger UI</html>' ;;
    */graphql) printf '{"data":null}' ;;
    *) exit 0 ;;
esac
EOF
chmod +x "$TMP_REPO/mocktools/subfinder" "$TMP_REPO/mocktools/httpx" "$TMP_REPO/mocktools/curl"

PATH="$TMP_REPO/mocktools:$PATH" bash "$TMP_REPO/bugbounty/bugbounty-hunter.sh" recon target.example >/dev/null 2>&1
raw_subs="$TMP_REPO/bugbounty/reports/target.example/recon/subdomains_raw.txt"
if ! grep -qx 'target.example' "$raw_subs" || ! grep -qx 'sub.target.example' "$raw_subs"; then
    echo "subfinder overwrote apex target in $raw_subs:" >&2
    cat "$raw_subs" >&2
    exit 1
fi
if ! grep -q -- '-H X-Target-Research: my-handle' "$TMP_REPO/httpx_args.log"; then
    echo "Research header was not forwarded to httpx:" >&2
    cat "$TMP_REPO/httpx_args.log" >&2
    exit 1
fi

# 4. dalfox preserves all parameters and sqlmap uses -m <file>
printf 'p1\np2\n' > "$TMP_REPO/bugbounty/reports/target.example/recon/params.txt"
printf 'https://target.example/?a=1\nhttps://target.example/?b=2\n' > "$TMP_REPO/bugbounty/reports/target.example/recon/wayback.txt"

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
chmod +x "$TMP_REPO/mocktools/dalfox" "$TMP_REPO/mocktools/sqlmap"

PATH="$TMP_REPO/mocktools:$PATH" bash "$TMP_REPO/bugbounty/bugbounty-hunter.sh" vuln target.example >/dev/null 2>&1
xss_out="$TMP_REPO/bugbounty/reports/target.example/vulns/xss.txt"
if ! grep -q 'p1=test' "$xss_out" || ! grep -q 'p2=test' "$xss_out"; then
    echo "dalfox lost parameters in $xss_out:" >&2
    cat "$xss_out" >&2
    exit 1
fi
if ! grep -q -- '-m ' "$TMP_REPO/sqlmap_args.log"; then
    echo "sqlmap was not invoked with -m:" >&2
    cat "$TMP_REPO/sqlmap_args.log" >&2
    exit 1
fi

# 5. api_testing respects BB_PASSIVE_ONLY=1 and writes valid JSON index otherwise
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

# 6. check-sensitive-files.sh rejects tracked private programs/*.md and cookies.txt
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
