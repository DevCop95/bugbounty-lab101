#!/bin/bash
set -eo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT
mkdir -p "$TEMP_DIR/programs"

cat > "$TEMP_DIR/programs/test.md" <<'EOF'
# Test

## In Scope
- example.com

## Out of Scope
- blocked.example.com
EOF

# shellcheck source=../auto-scanner/lib/common.sh
source "$ROOT/auto-scanner/lib/common.sh"

require_scope "https://example.com/path" "$TEMP_DIR/programs" >/dev/null
if require_scope "not-example.com" "$TEMP_DIR/programs" >/dev/null 2>&1; then
    echo "Substring target was incorrectly authorized" >&2
    exit 1
fi
if FORCE=1 require_scope "unauthorized.example" "$TEMP_DIR/programs" >/dev/null 2>&1; then
    echo "FORCE bypassed scope authorization" >&2
    exit 1
fi

printf '%s\n' 'example.com' 'not-example.com' 'blocked.example.com' > "$TEMP_DIR/candidates.txt"
scope_filter_file "$TEMP_DIR/candidates.txt" "$TEMP_DIR/authorized.txt" "$TEMP_DIR/programs"
if [ "$(cat "$TEMP_DIR/authorized.txt")" != "example.com" ]; then
    echo "Scope filtering retained an unauthorized target" >&2
    exit 1
fi

mkdir -p "$TEMP_DIR/bin"
cat > "$TEMP_DIR/bin/dig" <<'EOF'
#!/bin/bash
touch "$MARKER"
EOF
chmod +x "$TEMP_DIR/bin/dig"
export MARKER="$TEMP_DIR/tool-ran"
if PATH="$TEMP_DIR/bin:$PATH" bash "$ROOT/auto-scanner/quickscan.sh" \
    "https://unauthorized.example" >/dev/null 2>&1; then
    echo "Unauthorized quick scan unexpectedly succeeded" >&2
    exit 1
fi
if [ -e "$MARKER" ]; then
    echo "A scan tool ran before scope authorization" >&2
    exit 1
fi

if env PATH="$TEMP_DIR/bin:$PATH" PROGRAMS_DIR="$TEMP_DIR/programs" SCOPE_GUARD=/bin/true \
    bash "$ROOT/auto-scanner/quickscan.sh" "https://unauthorized.example" >/dev/null 2>&1; then
    echo "Environment variables bypassed scanner authorization" >&2
    exit 1
fi
if [ -e "$MARKER" ]; then
    echo "A scan tool ran after an environment authorization bypass" >&2
    exit 1
fi

if bash "$ROOT/bugbounty/bugbounty-hunter.sh" new "../escape" >/dev/null 2>&1; then
    echo "Program path traversal was accepted" >&2
    exit 1
fi

echo "Shell scope checks passed."
