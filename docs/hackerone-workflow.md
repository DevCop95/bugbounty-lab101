# HackerOne Workflow — dev101x

End-to-end methodology for working HackerOne programs with this lab.
Complements `bugbounty/QUICK-REFERENCE.md` (commands and payloads) — this document
covers the process around the tools: choosing a program, staying within
scope, not duplicating reports, and submitting something a triager will accept quickly.

---

## 1. Choosing a program

- Prioritize programs with **fast response times and a good bounty track record** (check
  the program's public statistics on its HackerOne page: median first
  response time, median bounty time, recent report activity).
- VDPs (Vulnerability Disclosure Programs, no reward) are good for
  building reputation/signal on HackerOne when the profile is new.
- Read the full policy before touching anything: scope, exclusions, whether they allow
  active scanning/automation, and whether prior authentication is required (some
  programs require you to register your IP or use specific test accounts).

## 2. Document the scope before scanning

```bash
cd bugbounty
./bugbounty-hunter.sh new program-name
# Or import directly from HackerOne CSV / JSON / TXT:
./bugbounty-hunter.sh scope-import h1-scope.csv program-name
```

This creates `programs/program-name.md`. Copy the "In scope", "Out of scope", and "Special Rules" (rate limits, required identification headers) from the program's policy there, verbatim — not a summary from memory.
`bugbounty-hunter.sh` blocks any active phase (`recon`, `vuln`, `brute`, `secrets`, `api`, `full`)
against a target not documented in an **Active** file in `programs/`. Use `scope-explain <target>`, `scope-audit`, `scope-diff <old> <new>`, and `scope-export burp <prog> burp.json` to inspect, verify freshness, and sync with Burp Suite. See [`programs/README.md`](../programs/README.md).

Re-check the scope if you return to a program after several weeks (`scope-audit` warns after 30 days by default) — scopes change.

## 3. Scanning methodology

1. `recon` — subdomains, HTTP probing, wayback/JS endpoints, parameters.
2. `vuln` — nuclei, automated XSS/SQLi/SSRF/redirect/IDOR.
3. `brute` — directories, vhosts, parameters.
4. `secrets` — secrets in JS, GitHub dorks, cloud buckets.
5. `api` — API documentation, GraphQL introspection.
6. **Manual** review of all the above — scanners generate candidates,
   not findings. Everything that goes into a report gets re-verified by hand.
7. `business_logic` / `chain_attacks` as checklists — not automated,
   but they guide where to look (auth flows, non-obvious IDOR, low-impact
   chains that matter when combined).
8. **AI-assisted code review, when there is "code" to read**:
   JS bundles from the SPA, or the repo if the program includes
   self-hosted/open-source software. See [`docs/ai-assisted-code-review.md`](ai-assisted-code-review.md)
   — the winning method is disciplined file-by-file coverage with
   structured reporting, not a loose autonomous agent over the entire
   codebase hoping to look in the right place.
9. **Fingerprinting against the known CVE watchlist**: if the detected
   stack matches something from [`docs/known-cve-watchlist.md`](known-cve-watchlist.md)
   (Next.js, Kibana, Langflow, Confluence/Jira, PAN-OS GlobalProtect, etc.),
   explicitly test that specific CVE instead of relying solely on
   generic `vuln` scanning — these are the ones most frequently found in
   real HackerOne programs according to Hacktivity.
10. **If the stack doesn't match a known product/CVE**, fall back to
    [`docs/known-cwe-watchlist.md`](known-cwe-watchlist.md) — the ranking by
    vulnerability class (XSS, info disclosure, access control/IDOR are,
    in that order, the overwhelming majority of reports on HackerOne) to
    decide where to prioritize manual review.

## 4. Before writing the report: search for duplicates

The #1 cause of reports closed as "Duplicate" or "Not Applicable" is not
searching first. Before reporting:

- Search **Hacktivity** (`hackerone.com/hacktivity`) for public reports from
  the same program using keywords from the finding (endpoint, technology,
  vuln type).
- Review the "Sent Reports" you already have noted in
  `programs/program-name.md` for the same program.
- If the program has public third-party reports, skim the titles — an
  open S3 bucket or a CORS misconfiguration already reported isn't worth a
  second report.

## 5. Report quality

Use `bugbounty/templates/report-template.md` as a base. A report that gets
paid quickly has:

- **Specific title**: `Reflected XSS in /search?q= parameter` not
  `XSS vulnerability found`.
- **Numbered steps reproducible by someone who never saw the target** —
  the triager doesn't have the context you have.
- **Minimal but complete PoC**: real request/response, or script, not just a
  prose description.
- **Concrete impact**, not generic. "An attacker could..." connected to a
  real scenario from the program's business (for example: reconnaissance → SSO config →
  RBAC bypass → sensitive data escalates the real impact of individual
  low/medium findings).
- **Correct CVSS and CWE** — an inflated CVSS or a wrong CWE is a common
  reason for re-triage and delays payment.

## 6. After submitting

- Fill in the "H1 Report URL" field in the local report and in the
  "Sent Reports" table in `programs/program-name.md`.
- Respond quickly if the triager asks for more info — the hacker's response speed
  also affects signal/reputation on HackerOne.
- If they request a retest after a fix, run `scope` again before retesting —
  the scope may have changed.
- Respect the program's disclosure embargo; don't publish details until
  the program explicitly authorizes it.

## 7. Building reputation as dev101x

- HackerOne reputation combines signal (valid/invalid reports),
  accumulated impact, and responsiveness. Prioritize quality over volume: a well-chained
  and well-written report is worth more than five "missing security
  header" reports with no business impact.
- No-bounty VDPs still add signal and are good ground to practice the full
  methodology (recon → chain → report) without payment pressure.
- Save every report submitted (bounty or not) in `programs/*.md` — over
  time that becomes your own history of what type of finding works in what
  type of program.
