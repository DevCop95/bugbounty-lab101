#!/bin/bash
set -eo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT
mkdir -p "$TEMP_DIR/programs"

cat > "$TEMP_DIR/programs/test.md" <<'EOF'
# Test

| Field | Value |
|-------|-------|
| **Status** | Active |

## In Scope
- example.com
- https://portal.example/api/*
- svc.example:8443

## Out of Scope
- blocked.example.com
- https://portal.example/api/logout*

## Special Rules
- Rate limit: 12 req/s
EOF

# shellcheck source=../auto-scanner/lib/common.sh
source "$ROOT/auto-scanner/lib/common.sh"

require_scope "https://example.com/path" "$TEMP_DIR/programs" >/dev/null
require_scope "https://portal.example/api/users" "$TEMP_DIR/programs" >/dev/null
require_scope "https://svc.example:8443/health" "$TEMP_DIR/programs" >/dev/null

if require_scope "https://portal.example/api/logout" "$TEMP_DIR/programs" >/dev/null 2>&1; then
    echo "Out-of-scope path was incorrectly authorized" >&2
    exit 1
fi
if require_scope "https://svc.example/health" "$TEMP_DIR/programs" >/dev/null 2>&1; then
    echo "Wrong port was incorrectly authorized" >&2
    exit 1
fi
if require_scope "not-example.com" "$TEMP_DIR/programs" >/dev/null 2>&1; then
    echo "Substring target was incorrectly authorized" >&2
    exit 1
fi
if FORCE=1 require_scope "unauthorized.example" "$TEMP_DIR/programs" >/dev/null 2>&1; then
    echo "FORCE bypassed scope authorization" >&2
    exit 1
fi

rl_prog="$(resolve_program_rate_limit "example.com" "$TEMP_DIR/programs")"
if [ "$rl_prog" != "12" ]; then
    echo "Expected program rate limit 12, got: $rl_prog" >&2
    exit 1
fi
rl_env="$(BB_RATE_LIMIT=4 resolve_program_rate_limit "example.com" "$TEMP_DIR/programs")"
if [ "$rl_env" != "4" ]; then
    echo "Expected BB_RATE_LIMIT=4 override, got: $rl_env" >&2
    exit 1
fi
rl_def="$(resolve_program_rate_limit "unmatched.example" "$TEMP_DIR/programs")"
if [ "$rl_def" != "10" ]; then
    echo "Expected fallback rate limit 10, got: $rl_def" >&2
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
