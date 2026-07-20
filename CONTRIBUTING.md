# Contributing to Bug Bounty Lab

Thanks for your interest in contributing! This guide covers the basics.

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR-USER/bugbounty-lab101
   cd bugbounty-lab101
   ```
3. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature
   ```

## Code Standards

### Shell Scripts

- **Bash 4+** required (for associative arrays, `${BASH_SOURCE}`, etc.)
- Use `set -eo pipefail` at the top of all scripts
- Use `mktemp` for temporary files — never predictable `/tmp/name_$$` patterns
- Add a cleanup `trap` for any temp resources:
  ```bash
  source "$SCRIPT_DIR/lib/common.sh"
  safe_tmpdir TEMP_DIR "myscript"
  trap 'cleanup_tmpdir "$TEMP_DIR"' EXIT
  ```
- Resolve script directory with:
  ```bash
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  ```
- Check tools before using them:
  ```bash
  if command -v nmap &>/dev/null; then ...
  ```

### Language

- All user-facing output, comments, and documentation **in English**
- Variable names and function names in English

### Style

- Use the shared library where possible:
  ```bash
  source "$SCRIPT_DIR/lib/common.sh"
  ```
- Run `shellcheck` before submitting:
  ```bash
  shellcheck your-script.sh
  ```

## What to Contribute

- **New scan modules** — add as standalone scripts in `auto-scanner/`
- **Tool categories** — update `tools/registry.sh`
- **Documentation** — improve `docs/`, add CVEs to watchlists
- **Bug fixes** — check Issues or find something that breaks
- **Wordlists / templates** — improve `bugbounty/templates/`

## Pull Request Process

1. Run `shellcheck` on any modified `.sh` files
2. Test your changes on Kali Linux (or equivalent)
3. Update relevant documentation if you add features
4. Keep PRs focused — one feature/fix per PR
5. Write a clear description of what changed and why

## Scope & Ethics

This project is for **authorized security testing only**. Do not contribute:
- Malicious tools designed for unauthorized access
- Exploits without responsible disclosure context
- Credentials, API keys, or personal data

## Questions?

Open an Issue or start a Discussion on GitHub.
