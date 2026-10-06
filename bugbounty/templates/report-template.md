# Bug Bounty Report Template

## 📋 Report Information

| Field | Value |
|-------|-------|
| **Program** | [Program name] |
| **Platform** | HackerOne |
| **Target** | [Exact domain/URL/asset listed in scope] |
| **Date** | [YYYY-MM-DD] |
| **Researcher** | dev101x |
| **Severity** | [Critical/High/Medium/Low/Info] |
| **Weakness (H1 taxonomy)** | [e.g. CWE-79: Cross-site Scripting (XSS)] |
| **H1 Report URL** | [Completed after submission: hackerone.com/reports/XXXXXX] |
| **Duplicate verified in Hacktivity** | [Yes/No — see docs/hackerone-workflow.md] |
| **Privileges required** | [None / Authenticated low-priv user / Admin — one line, even though CVSS PR says it too] |
| **Affected users / assets** | [Scope of impact: all users / all tenants / one org / N endpoints — triagers use this to justify severity] |

---

## 🎯 Executive Summary

[Brief description of the finding in 2-3 sentences]

---

## 🎭 Attack Scenario

[One short narrative paragraph: how a real attacker exploits this in production,
end to end, and what they gain. This is NOT the CVSS impact — it's the story a
triager reads to "get it" in 10 seconds. Intigriti in particular expects this.
Example: "An unauthenticated attacker sends a crafted reset request with a
spoofed Host header; the victim clicks the emailed link, which points at the
attacker's server and leaks the valid reset token; the attacker resets the
victim's password and takes over the account."]

---

## 🔍 Vulnerability Details

### Type
[e.g: SQL Injection, XSS, SSRF, IDOR, etc.]

### CWE
[CWE-XXX]

### CVSS Score
[X.X]

### Vector
[AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H]

### CVSS justification (per metric)
> Justify each metric in one line. This pre-empts the #1 cause of re-triage
> (disputed severity, see `docs/hackerone-workflow.md`) and stops you inflating
> the score by accident.

- **AV** (Attack Vector): [why Network/Adjacent/Local/Physical]
- **AC** (Attack Complexity): [why Low/High]
- **PR** (Privileges Required): [why None/Low/High]
- **UI** (User Interaction): [why None/Required]
- **S** (Scope): [why Unchanged/Changed — changed only if it breaks out of the vulnerable component's authority]
- **C / I / A**: [why each is High/Low/None]

---

## 📝 Steps to Reproduce

### 1. Prerequisites
```
[What is needed to reproduce]
```

### 2. Detailed steps

**Step 1: [Description]**
```
[Action to perform]
```

**Step 2: [Description]**
```
[Action to perform]
```

**Step 3: [Description]**
```
[Action to perform]
```

### 3. Expected result
```
[What should happen]
```

### 4. Actual result (with the bug)
```
[What happens with the vulnerability]
```

---

## 💥 Impact

### Confidentiality
[High/Medium/Low - Description]

### Integrity
[High/Medium/Low - Description]

### Availability
[High/Medium/Low - Description]

### Business Impact
[Description of business impact]

---

## 📸 Evidence

### Screenshots
[Attach relevant screenshots]

### PoC Video / GIF (recommended for XSS, CSRF, race conditions, multi-step flows)
[A 20–60s clip showing the exploit end to end. Many triagers (Intigriti/Bugcrowd
especially) accept these faster than static screenshots for interactive bugs.]

### PoC Code
```python
# Proof of Concept code
[ Code demonstrating the vulnerability ]
```

### HTTP Request/Response
```http
POST /vulnerable-endpoint HTTP/1.1
Host: target.com
Content-Type: application/json

{"param": "malicious_value"}
```

```http
HTTP/1.1 200 OK
[Response showing vulnerability]
```

---

## 🔧 Remediation Recommendation

### Short-term Fix
[Quick immediate fix]

### Long-term Fix
[Complete long-term fix]

### Code Example
```php
// Secure code example
[ Corrected code ]
```

---

## 📚 References

- [OWASP - Vulnerability type]
- [CWE - CWE-XXX]
- [CVE - If applicable]
- [Official documentation]

---

## 📝 Additional Notes

[Extra relevant information]

---

## ✅ Checklist

- [ ] I have verified that the vulnerability is reproducible
- [ ] I have documented all steps clearly
- [ ] I have included sufficient evidence
- [ ] I have assessed the impact correctly
- [ ] I justified each CVSS metric (not just the score)
- [ ] I wrote the Attack Scenario narrative
- [ ] I stated privileges required and affected-user/asset scope
- [ ] I have suggested a fix
- [ ] I have not performed destructive actions
- [ ] I have respected the program limits (`programs/<program>.md`)
- [ ] I searched for the finding in Hacktivity/program public reports before submitting (`scripts/duplicate_check.py`)
- [ ] The title is specific (endpoint + vuln type), not generic

---

*dev101x — Bug Bounty Framework*
