#!/bin/bash
set -eo pipefail

forbidden='(^|/)(bugbounty/reports|auto-scanner/reports|reports|evidence)(/|$)|(^|/)js_secrets\.txt$'
matches=$(git ls-files | grep -E "$forbidden" || true)

if [ -n "$matches" ]; then
    echo "Sensitive generated files are tracked:" >&2
    echo "$matches" >&2
    exit 1
fi

sensitive_names='(^|/)(\.env($|\.)|credentials?\.(json|ya?ml)$)|\.(pem|key|p12|pfx)$'
matches=$(git ls-files | grep -Ei "$sensitive_names" || true)
if [ -n "$matches" ]; then
    echo "Sensitive credential files are tracked:" >&2
    echo "$matches" >&2
    exit 1
fi

secret_patterns='AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|sk-[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----'
matches=$(git grep -nEI "$secret_patterns" -- . ':!scripts/check-sensitive-files.sh' || true)
if [ -n "$matches" ]; then
    echo "Potential hardcoded secrets found:" >&2
    echo "$matches" >&2
    exit 1
fi

echo "No raw reports, credential files, or common secret patterns are tracked."
