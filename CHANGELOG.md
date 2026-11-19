# Changelog

All notable changes to this project will be documented in this file.

## [1.3.0] - 2026-11-19

### Added
- **Scope Engine v2 (`scripts/scope_guard.py`)**:
  - Path-scoped URL rules with boundary safety (`/admin` matches `/admin/...` not `/administrator`), `/*`, and prefix `*` globs.
  - Explicit port scoping (`host:port`, `https://host:port/path`) and label-glob wildcards (`staging-*.example.com`, `*.api-*.example.com`).
  - Program status enforcement (`Paused`, `Retired`, `Closed`, `Inactive`, `Archived` programs no longer authorize targets while keeping global `Out of Scope` blocks active) plus staleness warnings controlled by `BB_SCOPE_MAX_AGE_DAYS` (default `30`).
  - Policy metadata extraction (research headers including `X-Security-Testing` / `X-Bug-Bounty` / `X-HackerOne-Research` and rate-limit directives from `## Special Rules`).
  - CLI operations & `bugbounty-hunter.sh` subcommands: `scope-explain`, `scope-audit`, `scope-export` (`burp` `advanced_mode` JSON, `json`, `txt`, `domains`, `wildcards`, `cidrs`), `scope-import` (HackerOne CSV, `bounty-targets-data`/platform JSON, TXT), and `scope-diff`.
- **Recon & Reporting Utilities (`scripts/recon_utils.py`)**:
  - `parse-httpx`: converts `httpx.json` (or `httpx.txt`) into `live_urls.txt`, `technologies.txt`, and cloud/SaaS `takeover_candidates.txt`.
  - `clean-urls`: strips static asset noise (preserving `.js`), deduplicates URLs by `(scheme, host, path, sorted params)`, extracts parameter names, and produces `gf`-style `candidates_{xss,sqli,ssrf_redirect,lfi,idor}.txt`.
  - `diff-baseline`: diffs subdomains and live URLs against `.baseline/` history to emit `new_subdomains.txt` and `new_live_urls.txt`.
  - `build-report`: renders `bugbounty/templates/report-template.md` with resolved program metadata and an automated `Recon & Scan Telemetry Summary` table.
- **Resumable & Rate-Limited Pipeline (`bugbounty/bugbounty-hunter.sh`, `auto-scanner/lib/common.sh`)**:
  - Added `--resume`, `--fresh`, and `--rate-limit <N>` flags parsed at any CLI position alongside `--passive-only`.
  - Enforced resolved per-program or default (`10 req/s`) rate limits across `httpx`, `katana`, `nuclei`, `feroxbuster`, and `ffuf`, and HTTP connect/max timeouts across `curl` probes.
  - Connected recon artifacts (`live_urls.txt`, `candidates_xss.txt`, `candidates_sqli.txt`, `js_files.txt`) directly into `vuln_scan`, `secrets_hunting`, `api_testing`, and `generate_report`, and switched Nuclei category scans from fragile relative paths to `-tags` (`cors`, `ssrf`, `redirect`, `idor`).
  - Expanded IPv6 Cloudflare/Fastly CIDR checks in `ip_cdn_owner()` and added portable Python substitution in `new_program()`.
- **Integrations**:
  - `browser_capture.js` / `browser_capture.sh`: redacts sensitive keys in JSON and form-encoded POST bodies by default and filters `browser_urls_raw.txt` into `browser_urls_in_scope.txt`.
  - `burp_api.py` / `burp.sh`: added offline `scope-export` command for Burp `advanced_mode` JSON and respected `BURP_HOST` / `BURP_PORT` env overrides.
  - `kev-correlate.sh`: switched webhook alert JSON payload construction to `jq -n`.
- **Tests**: Added `tests/test_recon_utils.py` and expanded `tests/test_scope_guard.py`, `tests/test_burp_api.py`, `tests/test-shell-scope.sh`, and `tests/test-pipeline-bugs.sh`; bumped `BB_VERSION` to `1.3.0`.

## [1.2.1] - 2026-11-19

### Fixed
- **Version drift**: Removed duplicate `BB_VERSION="1.2.0"` assignment in `bugbounty/bugbounty-hunter.sh` and bumped the single source of truth in `auto-scanner/lib/common.sh` to `1.2.1`.
- **Cross-program header leak & JSON escaping**: Replaced directory-wide `grep` in `browser_capture.sh` with `resolve_program_header` (reads only the matching `programs/*.md` file) and `encode_header_json` (Python `json.dumps`) in `auto-scanner/lib/common.sh`.
- **Pipeline data-loss bugs in `bugbounty/bugbounty-hunter.sh`**:
  - `subfinder` now appends (`>>`) instead of `-o` truncating the apex target from `subdomains_raw.txt`.
  - `dalfox` now runs once over `xss_candidates.txt` instead of overwriting `xss.txt` per parameter.
  - `sqlmap` now receives `-m "$OUTPUT_DIR/sqlmap_targets.txt"` instead of ignoring piped URLs.
  - `api_testing` now respects `BB_PASSIVE_ONLY=1` and writes individual doc files plus a valid `api_docs_index.json` instead of concatenating HTML into JSON.
  - Propagated `RESEARCH_HEADER` and `check_tool` / wordlist existence guards across `httpx`, `katana`, `curl`, `nuclei`, `feroxbuster`, `ffuf`, and `resolve_check`.
- **`burp_api.py`**: Reads `BURP_HOST`, `BURP_PORT`, and `BURP_API_KEY` from environment variables, passes an explicit `timeout` (default `30s`) to `urllib.request.urlopen`, and standardizes help/docstrings in English.
- **OPSEC & hygiene**:
  - `browser_capture.js` now redacts `Authorization`/`Cookie`/`Set-Cookie`/`X-API-Key`/`X-Auth-Token` headers by default (`BB_CAPTURE_UNREDACTED=1` to opt out), closes the browser in `try/finally`, writes outputs with mode `0600`, and updates the desktop User-Agent.
  - `.gitignore` and `scripts/check-sensitive-files.sh` now ignore/reject private `programs/*.md` files, `cookies.txt`, `*credentials*`, and `*-keys-*.json`.
  - Normalized CRLF line endings to LF across all tracked code and workflow files.

### Added
- **Batch scope filtering (`scripts/scope_guard.py --filter-file`)**: `scope_filter_file()` now processes all candidate lines in a single Python invocation instead of spawning a subprocess per line.
- **Regression test suites**: Expanded `tests/test_scope_guard.py` and `tests/test_burp_api.py`, added `tests/test_duplicate_check.py` and `tests/test-pipeline-bugs.sh`, plus Node syntax/redaction checks and LF enforcement in `.github/workflows/shellcheck.yml` and `.github/dependabot.yml`.

## [1.2.0] - 2026-10-14

### Added
- **Browser-driven real-traffic capture** (`auto-scanner/integrations/browser_capture.js`
  + `browser_capture.sh`) — drives a real headless Chromium via Playwright against
  one authorized URL and records every request/response/WebSocket frame the page
  actually makes, with real headers. This sees the requests a modern JS SPA
  issues past client-gating walls (dynamic client-id, `Client-Version`,
  anti-automation checks) that a static `curl` can't reproduce and that otherwise
  return generic `4xx`/`410` walls. Scope-enforced before the browser launches;
  degrades gracefully when node/Playwright are absent. Wired into the recon
  pipeline as stage `[1.4d]` (skipped under `--passive-only`).
- **Per-program custom-header injection** — the capture wrapper resolves a
  mandatory research/identification header from `BB_EXTRA_HEADERS`,
  `BB_RESEARCH_HEADER`, or auto-detected from the matching `programs/*.md`, and
  injects it into every request the browser makes, so programs that require such
  a header (e.g. `X-HackerOne-Research: <handle>`) can be scanned without
  forfeiting eligibility.
- **Two-agent research/verify workflow** (`docs/agent-workflow.md`) — codifies the
  investigator + independent-reviewer pattern: every claim backed by something
  executed and observed, severity never inflated beyond what was proven, and a
  reviewer sign-off before any submission.

## [1.1.0] - 2026-10-06

### Added
- **AI / LLM security reference** (`docs/ai-llm-security.md`) — prompt injection
  (direct + indirect), system-prompt extraction, insecure output handling,
  tool/function-call abuse, LLM data exfiltration, and malicious model-file RCE,
  mapped to the OWASP LLM Top 10. Closes the biggest 2026 coverage gap.
- **Vulnerability-class deep-dives** in `bugbounty/QUICK-REFERENCE.md`: account
  takeover via password reset, broken access control/IDOR depth, mass assignment,
  race conditions, JWT/OAuth flaws, GraphQL abuse, prototype pollution, web cache
  poisoning/deception, CORS misconfiguration, subdomain takeover, CSV injection,
  path traversal with encoding bypass (CWE-22), NoSQL/Elasticsearch Painless
  script injection (CWE-943/94), and cloud secrets/identity in JS bundles
  (CWE-200/798, incl. AWS Cognito IdentityPoolId abuse).
- **`scripts/duplicate_check.py`** — pre-submission self-duplicate check
  (fuzzy-matches a new finding against your `programs/*.md` "Submitted Reports"
  tables) plus a structured Hacktivity search template. Stdlib only.
- **`auto-scanner/kev-correlate.sh`** — correlates the live CISA KEV catalog
  against a target's detected stack (from `httpx -td`), with optional webhook
  alerting and documented EPSS/NVD/OSV extension points.
- **Recon depth** in `bugbounty-hunter.sh`: crt.sh + certspotter (two Certificate Transparency sources) for subdomains,
  enriched `httpx` output (`-td -title -server -cname -asn -json`), JS
  endpoint/secret analysis (`jsluice`/`secretfinder`, source-map candidates),
  API-spec discovery (swagger/openapi/graphql), and optional `paramspider`/`arjun`
  param mining — all guarded, skipped gracefully when a tool is absent.
- **`--passive-only` flag** (and `BB_PASSIVE_ONLY=1`) that skips every stage that
  touches the target directly (httpx/katana/param-mining).
- CVE watchlist now has a **Source column** (NVD link per row) and adds
  high-volume perimeter/DevOps families: GitLab ATO (CVE-2023-7028), CitrixBleed
  (CVE-2023-4966), Ivanti (CVE-2023-46805 + CVE-2024-21887), FortiOS
  (CVE-2024-21762), Jenkins (CVE-2024-23897).

### Changed
- **`report-template.md`**: per-metric CVSS justification, a narrative "Attack
  Scenario" section, explicit "Privileges required" and "Affected users/assets"
  fields, a PoC video/GIF slot, and expanded pre-submission checklist.
- **`scope_filter_file`** (`lib/common.sh`) now logs discarded candidates to
  `*.discarded.txt` and collects unlisted-but-seen hosts in
  `candidates-pending-scope.txt` for manual scope review instead of dropping them
  silently.
- `BB_VERSION` bumped to `1.1.0`.

### Fixed
- **Portable IP resolution** (`resolve_ip` in `lib/common.sh`, dig → host → getent
  → python3): `quickscan.sh`, `pentest-express.sh`, `autopentest.sh` and
  `autopentest-pro.sh` no longer hard-fail with `dig: command not found` on boxes
  without `dnsutils`. This also unblocks the CDN guard (it needs a resolved IP).
- `scope_filter_file` no longer errors with "No such file or directory" when an
  upstream tool (e.g. katana) is absent and produces no input file.
- crt.sh integration validates the body is JSON and retries (crt.sh frequently
  returns 502), parsing with `jq` when available; recon now also probes the
  target host itself even when no subdomains are discovered.
- HTTP-probing stage detects when the installed `httpx` is the Python HTTP-client
  CLI rather than ProjectDiscovery's `httpx`, and skips with a clear message
  instead of failing silently.
- `pentest-express.sh` reflected-XSS check: `grep -c ... || echo 0` produced
  `"0\n0"` and broke the numeric test; corrected.

## [1.0.7] - 2026-10-06

### Fixed
- **`auto-scanner/github-scan.sh` rewritten** — the old version was largely
  non-functional: it only read the root of `master`/`main`, the secret "search"
  was count-only via an API that requires auth yet never used `GITHUB_TOKEN`, and
  it checked `github.com/<repo>/.git/config` (always 404). The new version uses
  `GITHUB_TOKEN` when present, parses with `jq`, scans the **full git history**
  with `trufflehog` (verified-only) or `gitleaks`, keeps a committed-secret-file
  check across branches, and adds a **dependency-confusion** check (flags npm
  deps that do not resolve on the public registry). The bogus `.git/config`
  check was removed.
- **`auto-scanner/threat-monitor-daemon.sh`** — severity ordering was alphabetical
  (`sort_by(.severidad)` → ALTA < BAJA < CRITICA < MEDIA, wrong). Now sorts by a
  numeric rank so CRITICA surfaces first. New-item detection now uses `max(.id)`
  instead of `.[0].id`, so it no longer assumes the feed is pre-sorted.
- **`auto-scanner/tools/registry.sh`** — fixed 3 malformed tool URLs that had a
  space instead of `/` (`dnsgen`, `linkfinder`, `bbsql`).

### Added
- **CDN / shared-edge scope guard** in `auto-scanner/lib/common.sh`
  (`ip_cdn_owner` / `resolves_behind_cdn`). Active scanners (`quickscan.sh`,
  `autopentest.sh`, `autopentest-pro.sh`, `pentest-express.sh`) now skip nmap
  when the target resolves to a Cloudflare/Fastly/Akamai/Incapsula/Sucuri edge
  IP — port-scanning that IP hits a third party and is out of scope.

### Changed
- `BB_VERSION` bumped to `1.0.7` in `bugbounty-hunter.sh` and `auto-scanner/lib/common.sh`.

## [1.0.6] - 2026-10-06

### Added
- **Technique Deep-Dives** section in `bugbounty/QUICK-REFERENCE.md` covering four
  modern web classes with detection steps and real-world context:
  - Server-Side Template Injection (SSTI, CWE-1336/CWE-94) — incl. Handlebars AST injection
  - XML External Entity (XXE, CWE-611) — file read, blind/OOB, SAML/Office-upload surfaces
  - Insecure `postMessage` (CWE-345/CWE-346) — origin-validation bypass → authorized requests on behalf of a victim
  - Insecure Deserialization (CWE-502) — Python pickle RCE and the ML model-file (`.pkl`/`joblib`/`.pt`) vector

### Changed
- `BB_VERSION` bumped to `1.0.6` in `bugbounty-hunter.sh` and `auto-scanner/lib/common.sh`.

## [1.0.5] - 2026-08-24

### Added
- Passive `shodan_reconsx` integration in the scope-enforced reconnaissance pipeline.
- `vendor/shodan_reconsx` pinned as a Git submodule at the upstream `main` commit used by this release.
- Automatic extraction and scope filtering of Shodan CTL hostnames before HTTP probing.

### Improved
- Recon now reports only authorized subdomains in `subdomains.txt` and counts the filtered set.
- Missing `subfinder` and `amass` installations are reported without aborting the remaining recon stages.
- Stale subdomain candidates are cleared at the start of each recon run.

## [1.1] - 2026-07-09

### Added
- **Shared library** (`auto-scanner/lib/common.sh`) — centralized colors, domain parsing, tool checking, and safe temp directory creation
- `--help` and `--version` flags for `bugbounty-hunter.sh`
- `LICENSE` (MIT)
- `CONTRIBUTING.md` — contribution guidelines and code standards
- `CHANGELOG.md` — this file
- `.github/workflows/shellcheck.yml` — CI with ShellCheck static analysis
- Auto-detect URL in `pentest.sh` — `pentest https://target.com` now runs pro scan directly
- GitHub API rate limit detection in `github-scan.sh`

### Fixed
- **Broken URLs** in `show_platforms()` — Chinese characters replaced with real URLs
- **Banner box** not closing properly in `bugbounty-hunter.sh`
- **SQL Injection test** in `autopentest.sh` never injected the payload — now properly URL-encodes and appends
- **Missing `BLUE` color** in `file-upload-scanner.sh` caused invisible output
- **Indentation bugs** in `autopentest-pro.sh`, `autopentest.sh`, and `quickscan.sh`
- **Variable scope leaks** — `MISSING_HEADERS`, `COOKIES`, `CORS`, `TARGET_IP` now properly globalized
- **`encoding_bypass()`** removed from `full` pipeline (reference-only, not a scan)
- **`set -e` + `((TOTAL++))`** crash in `tool-checker.sh`
- **`$?` pattern** incompatible with `set -e` in `auto-scan-daemon.sh`

### Security
- All `/tmp` directories now use `mktemp` with unpredictable names (prevents symlink attacks)
- Added `trap cleanup EXIT` to all scripts that create temp dirs
- Report generation uses heredoc with variable expansion instead of fragile `sed` replacements
- Added `set -o pipefail` to all scripts

### Changed
- **Language standardized to English** — all user-facing output, comments, and function names
- Consistent `PHASE` naming (was mixed `FASE`/`PHASE`)
- `REPORT_DIR` uses `$SCRIPT_DIR`-based paths instead of fragile `../reports`
- `threat-intel-monitor.sh` uses `BASH_SOURCE` path resolution
- `pentest.sh` help banner uses proper English title
- Version bumped to 1.1

### Documentation
- Fixed `README.md` — wrong `cd pentesting-lab` directory, added T3MP3ST clone instructions, TOC, dynamic badges
- Updated `auto-scanner/README.md` with complete file listing
- Fixed `QUICK-REFERENCE.md` placeholder handle → `dev101x`
- `.gitignore` comments translated to English

## [1.0] - 2025

### Added
- Initial release
- `bugbounty-hunter.sh` — scope-enforced bug bounty workflow
- `auto-scanner/` — 400+ tool arsenal with multiple scan modes
- `programs/` — HackerOne scope tracker
- `legacy-vm-practice/` — local VM lab
- T3MP3ST integration
- Threat intelligence monitoring
- Burp Suite integration
