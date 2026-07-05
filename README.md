<div align="center">

```
          ██████╗ ███████╗██╗   ██╗ ██╗ ██████╗  ██╗██╗  ██╗
          ██╔══██╗██╔════╝██║   ██║███║██╔═████╗███║╚██╗██╔╝
          ██║  ██║█████╗  ██║   ██║╚██║██║██╔██║╚██║ ╚███╔╝
          ██║  ██║██╔══╝  ╚██╗ ██╔╝ ██║████╔╝██║ ██║ ██╔██╗
          ██████╔╝███████╗ ╚████╔╝  ██║╚██████╔╝ ██║██╔╝ ██╗
          ╚═════╝ ╚══════╝  ╚═══╝   ╚═╝ ╚═════╝  ╚═╝╚═╝  ╚═╝
```

# BUG BOUNTY LAB

### Bug Bounty Workspace for HackerOne Researchers

[![HackerOne](https://img.shields.io/badge/HackerOne-Workbench-000000?style=for-the-badge&logo=hackerone&logoColor=white)](https://hackerone.com/)
[![Kali Linux](https://img.shields.io/badge/Kali-Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![Tools](https://img.shields.io/badge/400%2B-Tools-FF6B35?style=for-the-badge)]()
[![Scope Safe](https://img.shields.io/badge/Scope-Enforced-00CA4E?style=for-the-badge)]()

</div>

---

## What Is This?

A workspace built around the **real bug bounty workflow on HackerOne**: choose a program, document scope, scan within boundaries, chain findings, and report in a format triagers accept fast. The 400+ generic pentesting arsenal and local VM lab are available as support — not the entry point.

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  SCOPE                RECON/VULN              REPORT                │
│  ═════                ══════════              ══════                │
│                                                                     │
│  ┌───────────┐      ┌───────────────────┐    ┌───────────────┐      │
│  │programs/  │────▶  bugbounty-hunter   ───▶  report.md     │      │
│  │*.md       │      │      .sh          │    │ (H1 template) │      │
│  └───────────┘      └────────┬──────────┘    └───────┬───────┘      │
│  scope check                 │                       │              │
│  (blocks if not              ▼                       ▼              │
│   documented)       ┌─────────────┐         ┌──────────────┐        │
│                     │auto-scanner │         │  Hacktivity  │        │
│                     │ (arsenal)   │         │  dedup check │        │
│                     └─────────────┘         └──────────────┘        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### 1. Permissions
```bash
cd pentesting-lab
chmod +x bugbounty/*.sh auto-scanner/*.sh
```

### 2. Document program scope
```bash
cd bugbounty
./bugbounty-hunter.sh new program-name
# Edit ../programs/program-name.md with the EXACT scope from the H1 policy
```

### 3. Verify scope and scan
```bash
./bugbounty-hunter.sh scope target.com     # must say "Scope OK" before proceeding
./bugbounty-hunter.sh full target.com       # recon -> vuln -> brute -> secrets -> api -> report
```

### 4. Report
```bash
./bugbounty-hunter.sh report target.com
# Complete bugbounty/reports/target.com/report-YYYYMMDD.md with the H1 template
```

Before submitting, read [`docs/hackerone-workflow.md`](docs/hackerone-workflow.md) (Hacktivity dedup, report quality, post-submission steps).

---

## Main Commands

<div align="center">

| Command | Description | Example |
|---------|-------------|---------|
| `bugbounty-hunter.sh new <prog>` | Create scope tracker for a program | `./bugbounty-hunter.sh new acme-corp` |
| `bugbounty-hunter.sh scope <target>` | Verify target is in scope | `./bugbounty-hunter.sh scope target.com` |
| `bugbounty-hunter.sh full <target>` | Full pipeline (recon to report) | `./bugbounty-hunter.sh full target.com` |
| `bugbounty-hunter.sh recon <target>` | Recon only | `./bugbounty-hunter.sh recon target.com` |
| `bugbounty-hunter.sh report <target>` | Generate report with H1 template | `./bugbounty-hunter.sh report target.com` |
| `pentest.sh <url>` | Generic arsenal (400+ tools) | `pentest.sh https://target.com` |
| `pentest.sh matrix` | Full tool matrix | `pentest.sh matrix` |
| `pentest.sh search <function>` | Search for a tool | `pentest.sh search sql_injection` |
| `pentest.sh express <url>` | Express scan | `pentest.sh express https://target.com` |
| `pentest.sh install` | Install missing tools | `pentest.sh install` |

</div>

All active scanning commands in `bugbounty-hunter.sh` verify scope against `programs/*.md` before touching the target.

---

## Tool Matrix by Phase

```
╔═════════════════════════════════════════════════════════════════════════╗
║                                                                         ║
║  PHASE 1          PHASE 2          PHASE 3          PHASE 4             ║
║  RECON            SCANNING         ENUMERATION      EXPLOITATION        ║
║                                                                         ║
║  ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐          ║
║  │   nmap    │─▶   nikto     ──▶  enum4l     ──▶  sqlmap              
║  │   amass   │   │ gobuster  │   │  smbclnt  │   │metasploit │          ║
║  │   dig     │   │  whatweb  │   │  ldapsrc  │   │  xsser    │          ║
║  │   whois   │   │   wfuzz   │   │  rpcclnt  │   │  wpscan   │          ║
║  └───────────┘   └───────────┘   └───────────┘   └───────────┘          ║
║        │              │               │               │                 ║
║        ▼              ▼               ▼               ▼                 ║
║  ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐          ║
║  │  theHarv  │   │   dirb    │   │ snmpwalk  │   │ msfvenom  │          ║
║  │  recon-ng │   │   ffuf    │   │  nbtscan  │   │ searchsp  │          ║
║  └───────────┘   └───────────┘   └───────────┘   └───────────┘          ║
║                                                                         ║
╠═════════════════════════════════════════════════════════════════════════╣
║                                                                         ║
║  PHASE 5          PHASE 6          PHASE 7          PHASE 8             ║
║  BUSINESS LOGIC   API TESTING      CHAIN ATTACKS    REPORT              ║
║                                                                         ║
║  ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐          ║
║  │auth flow  │   │  swagger  │   │CORS+CSRF  │   │    H1     │          ║
║  │race cond  │   │  graphql  │   │SSRF+RCE   │   │  REPORT   │          ║
║  │mass assn  │   │  nuclei   │   │IDOR+priv  │   │   .md     │          ║
║  └───────────┘   └───────────┘   └───────────┘   └───────────┘          ║
║                                                                         ║
╚═════════════════════════════════════════════════════════════════════════╝
```

---

## Tools by Category (auto-scanner/ — support arsenal)

<div align="center">

### Reconnaissance (50+ tools)

```
┌────────────────────────────────────────────────────────────────┐
│  NETWORK SCANNING:                                             │
│  nmap        masscan      zmap         unicornscan             │
│  netdiscover                                                   │
│                                                                │
│  DNS ENUMERATION:                                              │
│  dnsrecon    dig          host         dnsenum                 │
│  dnsmap      sublist3r    subfinder    subbrute                │
│  dnsgen      gotator      fierce       dnspoodle               │
│                                                                │
│  HTTP RECON:                                                   │
│  httpx       httprobe     gau          waybackurls             │
│  katana      gospider     hakrawler    linkfinder              │
│  jsfinder    secretfinder paramspider  arjun                   │
│                                                                │
│  CLOUD RECON:                                                  │
│  s3scanner   cloud_enum   lazys3       bucket_finder           │
│                                                                │
│  SUBDOMAIN TAKEOVER:                                           │
│  subjack     subover      nuclei       canari                  │
└────────────────────────────────────────────────────────────────┘
```

### Web (20+ tools)

```
┌─────────────────────────────────────────────────────────────────┐
│  SCANNERS:        nikto  whatweb  wapiti  arachni  skipfish     │
│  DIRECTORY BRUTE: gobuster  dirb  feroxbuster  dirsearch        │
│  FUZZING:         wfuzz  ffuf  arjun  x8  paramspider           │
│  VULNERABILITIES: sqlmap  xsser  dalfox  commix  xsstrike       │
│  CMS:             wpscan  joomscan  droopescan  cmseek  cariddi │
└─────────────────────────────────────────────────────────────────┘
```

</div>

---

## Report Example (HackerOne format)

```markdown
# Bug Bounty Report

## Platform
HackerOne

## Program
[program name]

## Researcher
[your-handle]

## Target
prime.example.com

## Weakness (H1 taxonomy)
CWE-538: Insertion of Sensitive Information into Externally-Accessible File

## Executive Summary
S3 bucket with listing enabled exposes N files without authentication,
including internal HR documents.

## Steps to Reproduce
1. curl -k https://prime.example.com/file-service/static/
2. ...

## Impact
[Concrete business impact, not generic]
```

Full template at [`bugbounty/templates/report-template.md`](bugbounty/templates/report-template.md).

---

## Workflow

```
                      ┌─────────────────────┐
                      │  Choose H1 Program  │
                      └──────────┬──────────┘
                                 ▼
                      ┌─────────────────────┐
                      │ bugbounty-hunter.sh │
                      │   new <program>     │
                      └──────────┬──────────┘
                                 ▼
                      ┌─────────────────────┐
                      │  Document scope in  │
                      │   programs/*.md     │
                      └──────────┬──────────┘
                                 ▼
                ┌────────────────────────────────┐
                │ bugbounty-hunter.sh full <t>   │
                └────────────────┬───────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
       ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
       │ RECON/VULN   │   │ MANUAL VERIF │   │ CHAIN ATTACK │
       │  (scripts)   │   │  (manual)    │   │  (manual)    │
       └──────┬───────┘   └──────┬───────┘   └──────┬───────┘
              └──────────────────┼──────────────────┘
                                 ▼
                      ┌─────────────────────┐
                      │  Dedup in Hacktivity│
                      └──────────┬──────────┘
                                 ▼
                      ┌─────────────────────┐
                      │  Submit H1 Report   │
                      └─────────────────────┘
```

Full methodology at [`docs/hackerone-workflow.md`](docs/hackerone-workflow.md).

---

## Practice Without Touching Real Programs

`legacy-vm-practice/` is yours: private IPs you spin up, no third-party scope to respect. Use it to learn new techniques before applying them to a real program.

```bash
cd legacy-vm-practice
./scripts/setup_network.sh   # requires sudo
./scripts/download_vms.sh
./scripts/start_lab.sh
./scripts/verify_lab.sh
```

See `legacy-vm-practice/README.md` and `legacy-vm-practice/docs/quickstart.md`.

---

## Project Structure

```
bugbounty-lab/
│
├── README.md                       # This file — overview + usage guide
│
├── programs/                       # Scope tracker: one .md per H1 program
│   ├── README.md
│   └── _template.md
│
├── bugbounty/                      # Core bug bounty engine
│   ├── bugbounty-hunter.sh         # scope/new/recon/vuln/brute/secrets/api/report
│   ├── QUICK-REFERENCE.md          # Commands, payloads, bounty by severity
│   ├── templates/report-template.md
│   └── reports/<target>/           # Output per phase + final report
│
├── auto-scanner/                   # Generic arsenal (400+ tools, not H1-specific)
│   ├── pentest.sh                  # Unified command (incl. `pentest.sh bounty ...`)
│   ├── tools/registry.sh
│   ├── burp-integration/
│   └── reports/
│
├── docs/
│   ├── hackerone-workflow.md       # H1 methodology: choose program, dedup, quality
│   ├── ai-assisted-code-review.md  # AI-assisted code/JS review
│   ├── known-cve-watchlist.md      # Most reported CVEs in Hacktivity
│   ├── known-cwe-watchlist.md      # Most reported vuln classes in Hacktivity
│   └── recursos/learning-resources.md
│
└── legacy-vm-practice/             # Classic VM lab (DVWA, Metasploitable...)
```

---

## Important Rules

1. **Never scan an asset that is not documented as In Scope in `programs/<program>.md`.** `bugbounty-hunter.sh` blocks it by default — `FORCE=1` is a signal that scope is missing, not a normal shortcut.
2. **Respect each program's exclusions and special rules** (rate limits, excluded vuln types, test accounts).
3. **Check for duplicates in Hacktivity before reporting.**
4. **Do not run destructive actions** against real targets — see the checklist in `bugbounty/templates/report-template.md`.
5. **`legacy-vm-practice/` is yours**: private IPs you spin up, no third-party scope. Use it to learn new techniques.

---

## Troubleshooting

**`bugbounty-hunter.sh` says "No scope file"**
Run `./bugbounty-hunter.sh new <program>` and add the domain to the `## In Scope` section of the generated file in `programs/`.

**Missing tools (subfinder, nuclei, httpx, etc.)**
```bash
./auto-scanner/pentest.sh install
```

**VM lab won't start**
See troubleshooting in `legacy-vm-practice/README.md` (Host-Only Adapter, NAT, firewall).

---

## Learning Resources

<div align="center">

| Resource | Focus |
|----------|-------|
| [Hacker101](https://www.hacker101.com/) | CTFs + HackerOne videos, badges for private programs |
| [HackerOne Hacktivity](https://hackerone.com/hacktivity) | Public reports — study quality and avoid duplicates |
| [HackerOne Directory](https://hackerone.com/directory/programs) | Choose program by scope and response stats |
| [PortSwigger Web Security Academy](https://portswigger.net/web-security) | Technical fundamentals of web vulnerabilities |

</div>

Full list at [`docs/recursos/learning-resources.md`](docs/recursos/learning-resources.md).

---

## Disclaimer

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  WARNING                                                                     ║
║                                                                              ║
║  This lab is designed for AUTHORIZED bug bounty via HackerOne.               ║
║                                                                              ║
║  Only test assets within the program's published scope                       ║
║  bugbounty-hunter.sh blocks targets without documented scope in programs/    ║
║  Unauthorized use of these tools is ILLEGAL                                  ║
║  Respect each program's exclusions and special rules                         ║
║  Always use these tools ETHICALLY and RESPONSIBLY                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## Arsenal Stats

<div align="center">

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   RECON              200+ tools   ████████████████ 100%         │
│   ENUMERATION         60+ tools   ██████████░░░░░░  60%         │
│   WEB                 20+ tools   ████░░░░░░░░░░░░  20%         │
│   EXPLOITATION        80+ tools   ████████████████  80%         │
│   POST-EXPLOIT        50+ tools   ████████████░░░░  60%         │
│                                                                 │
│   TOTAL: 400+ categorized tools                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

</div>

---

<div align="center">

```
+=============================================================+
|                                                             |
|   Bug Bounty Lab  •  HackerOne  •  400+ Tools               |
|                                                             |
+=============================================================+
```

**Happy hunting.**

</div>
