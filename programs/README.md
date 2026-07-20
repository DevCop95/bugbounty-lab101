# Programs — Scope Tracker

One file per HackerOne program you participate in. It is the source of truth
for what can be touched and what cannot — `bugbounty/bugbounty-hunter.sh` reads these files
before scanning any target.

## Why this exists

Testing out of scope on a HackerOne program can mean:
- Reward cancellation even if the finding is valid.
- Suspension or ban from the program (or the entire H1 account).
- In the worst case, legal exposure if the asset doesn't belong to the program.

Before launching any scan, `dev101x` must have the scope documented here,
not just in memory or in a browser tab.

## Usage

```bash
# Create the scope file for a new program
../bugbounty/bugbounty-hunter.sh new program-name

# Edit programs/program-name.md:
#   - Fill in "In Scope" with the exact domains/assets from the program policy
#   - Fill in "Out of Scope" with what the program explicitly excludes
#   - Copy special rules (rate limits, excluded vuln types, etc.)

# Verify a target is covered before scanning
../bugbounty/bugbounty-hunter.sh scope target.com
```

Each file follows the template in [`_template.md`](_template.md).

## Golden rule

If a target doesn't appear in any file in `programs/`, every active scanner
blocks it. There is no `FORCE` bypass: document the authorization before
running a scan. Exact hosts, `*.example.com` wildcards, and CIDR ranges are
supported; an entry in any `Out of Scope` section always wins.

Raw output under `bugbounty/reports/`, `auto-scanner/reports/`, `reports/`, and
`evidence/` is intentionally ignored by Git because it may contain credentials
or embargoed findings. Publish only a manually redacted copy outside those
directories.
