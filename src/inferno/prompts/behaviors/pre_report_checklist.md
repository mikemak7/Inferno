# Pre-Report Checklist

**STOP. Before reporting ANY finding, complete this checklist.**

Submitting invalid findings wastes program time, damages your reputation, and may result in account suspension. This checklist prevents common mistakes that lead to rejection.

---

## Final Validation Checklist

### 1. Impact Validation

- [ ] **Demonstrated (not theoretical) impact**
  - Can you complete this sentence WITHOUT "could/might/may"?
    - "An attacker **can** [specific action] resulting in [concrete harm]"
  - Do you have proof (screenshots, response data, command output)?
  - Is the impact measurable (number of records, dollar amount, access level)?

**If NO:** Go back and demonstrate actual impact. Theory = rejection.

---

### 2. Escalation Documentation

- [ ] **Escalation attempted and documented (3-5 attempts minimum)**
  - Did you test horizontal escalation (other users/resources)?
  - Did you test vertical escalation (admin/privileged access)?
  - Did you attempt to chain with other vulnerabilities?
  - Did you test write/modify/delete operations (not just read)?
  - Is each escalation attempt documented with results?

**If NO:** Go back and escalate. Single-vector findings without escalation are typically rejected or downgraded.

---

### 3. Environment Validation

- [ ] **Target is production, not staging/dev/test**
  - Is the domain the main production domain (example.com)?
  - Or is it a subdomain like staging.example.com, dev.example.com, test.example.com?
  - Or is it an IP address, localhost, or internal hostname?
  - Does the response include "staging", "development", "test" in headers/content?

**If NO:** Finding is likely Out-of-Scope or Info severity at best. Check program policy.

**Common Non-Production Indicators:**
```
❌ staging.example.com
❌ dev.example.com
❌ test.example.com
❌ demo.example.com
❌ sandbox.example.com
❌ uat.example.com
❌ 192.168.x.x, 10.x.x.x (internal IPs)
❌ localhost, 127.0.0.1
❌ Headers: "X-Environment: staging"
❌ Page content: "Development Environment"
```

---

### 4. Data Disclosure Validation

- [ ] **Data isn't intentionally public (blockchain, public APIs, open data)**
  - Is this a blockchain explorer showing transaction data? (Intentionally public)
  - Is this a public API returning documented responses? (Expected behavior)
  - Is this government/civic open data? (Meant to be public)
  - Is this a public GitHub repository? (Intentionally disclosed)
  - Is this publicly documented in official API docs? (Feature, not bug)

**If YES (data is intentionally public):** This is not a vulnerability. Do not report.

**Intentionally Public (NOT vulnerabilities):**
```
❌ Blockchain transaction data
❌ Public API responses (matching documentation)
❌ GitHub public repositories
❌ Open government data portals
❌ Public social media content
❌ Publicly documented API endpoints
❌ Open source code
❌ Public DNS records
```

---

### 5. Severity Validation

- [ ] **Severity matches proven impact (not theoretical)**
  - Critical: RCE, auth bypass to admin, mass breach, credential theft (ALL proven)
  - High: Unauthorized data access, privilege escalation, SQL injection (demonstrated)
  - Medium: SSRF, stored XSS, limited IDOR (real impact shown)
  - Low: Info disclosure, version leaks, minor misconfig (confirmed vuln)
  - Info: Best practices, non-production issues, intentional public data

**Apply Automatic Adjustments:**
- Used "could/might/may"? → -1.0 severity
- Staging/dev/test environment? → -2.0 severity (likely Info or Out-of-Scope)
- Successful escalation? → +1.0 severity
- Chained vulnerabilities? → +0.5 severity

**If severity seems off:** Re-read `severity_calibration.md` and recalibrate.

---

### 6. Scope Validation

- [ ] **Finding is likely in-scope for typical bug bounty programs**
  - Is the vulnerability on an in-scope domain/asset?
  - Did you check the program's scope rules?
  - Is it a commonly out-of-scope issue? (See list below)

**Commonly Out-of-Scope Issues:**
```
❌ SPF/DKIM/DMARC issues
❌ Missing security headers (CSP, HSTS) without demonstrated exploit
❌ SSL/TLS configuration issues (unless you can exploit)
❌ Denial of Service (DoS) without explicit permission
❌ Social engineering attacks
❌ Physical security issues
❌ Open redirects without proven attack chain
❌ Self-XSS (attacker must use their own account)
❌ Content injection without JavaScript execution
❌ Rate limiting issues without demonstrated abuse
❌ CSRF on logout/non-sensitive actions
❌ Clickjacking on pages with no sensitive actions
❌ Homograph/IDN attacks
❌ CSV injection without demonstrated RCE
❌ Password policy issues (no minimum length, etc.)
❌ Username enumeration (unless leading to account takeover)
❌ Autocomplete enabled on forms
❌ Lack of security.txt file
❌ Outdated software without known CVE
```

**If your finding matches above:** Double-check program policy. May be explicitly out-of-scope.

---

## Pre-Report Decision Matrix

| Checklist Item | Status | Action |
|----------------|--------|--------|
| **Demonstrated Impact** | ✅ Pass | Continue |
| | ❌ Fail | **STOP**: Demonstrate actual impact or do not report |
| **Escalation (3-5 attempts)** | ✅ Pass | Continue |
| | ❌ Fail | **STOP**: Escalate further before reporting |
| **Production Environment** | ✅ Pass | Continue |
| | ❌ Fail | **STOP**: Likely Out-of-Scope or Info severity |
| **Not Intentionally Public** | ✅ Pass | Continue |
| | ❌ Fail | **STOP**: Not a vulnerability, do not report |
| **Severity Calibrated** | ✅ Pass | Continue |
| | ❌ Fail | **STOP**: Recalibrate using severity_calibration.md |
| **Likely In-Scope** | ✅ Pass | **PROCEED TO REPORT** |
| | ❌ Fail | **STOP**: Check program policy or do not report |

---

## Report Submission Decision

### ✅ SAFE TO REPORT

All boxes checked? Proceed with confidence:

```
✅ Impact is demonstrated (not theoretical)
✅ Escalation documented (3-5 attempts)
✅ Production environment confirmed
✅ Data is not intentionally public
✅ Severity matches proven impact
✅ Finding is in-scope
```

**Your report should include:**
1. Clear title with vulnerability type and impact
2. Concise summary (2-3 sentences)
3. Detailed step-by-step reproduction
4. Proof (screenshots, response data, command output)
5. Escalation attempts documented
6. Impact assessment (concrete numbers/specifics)
7. Recommended remediation

---

### ❌ DO NOT REPORT

If ANY box is unchecked:

**Missing Demonstrated Impact:**
```
DO NOT REPORT: "SQL injection could lead to data breach"
INSTEAD: Demonstrate data extraction, count records, show sample data
```

**Missing Escalation:**
```
DO NOT REPORT: "IDOR found at /api/users/1234"
INSTEAD: Test 100+ user IDs, attempt write access, try admin endpoints
```

**Non-Production Environment:**
```
DO NOT REPORT: "RCE on staging.example.com"
INSTEAD: Check if vulnerability exists on production (example.com)
         If staging-only, mark as Info or Out-of-Scope
```

**Intentionally Public Data:**
```
DO NOT REPORT: "API returns user profile data without authentication"
INSTEAD: Check if this is documented public API behavior
         If yes, not a vulnerability
```

**Incorrect Severity:**
```
DO NOT REPORT: "Critical - SSRF to internal network"
INSTEAD: Calibrate to Medium (unless you stole credentials → High/Critical)
```

**Likely Out-of-Scope:**
```
DO NOT REPORT: "Missing HSTS header"
INSTEAD: Check program policy - commonly out-of-scope
         If allowed, mark as Info severity with recommendation
```

---

## Common Rejection Reasons

Learn from these to avoid wasted effort:

| Rejection Reason | How to Prevent |
|------------------|----------------|
| **"Theoretical impact only"** | Demonstrate actual exploitation, not "could lead to" |
| **"Non-production environment"** | Verify target is production before testing |
| **"Insufficient evidence"** | Provide screenshots, response data, step-by-step reproduction |
| **"Duplicate report"** | Search existing reports, this checklist doesn't prevent duplicates |
| **"Out of scope"** | Read program policy carefully, check scope section |
| **"Not a security issue"** | Verify data isn't intentionally public, ensure real security impact |
| **"Cannot reproduce"** | Provide exact steps, URLs, payloads; test again before submitting |
| **"Informational"** | Don't report best practices/recommendations as vulnerabilities |
| **"Self-exploitation only"** | Demonstrate attack against other users, not just your own account |
| **"Missing impact"** | Answer "So what?" - explain concrete harm to business/users |

---

## Final Checks Before Clicking "Submit"

**30-Second Sanity Check:**

1. Can I answer "So what?" without using "could/might/may"? **YES / NO**
2. Did I attempt escalation at least 3 times? **YES / NO**
3. Is the target domain production (not staging/dev/test)? **YES / NO**
4. Is the data NOT intentionally public? **YES / NO**
5. Does my severity match proven impact? **YES / NO**
6. Is this issue likely in-scope? **YES / NO**

**All YES?** → Report with confidence

**Any NO?** → **DO NOT SUBMIT** - fix the issue first

---

## Remember

- **Your reputation is built on report quality, not quantity**
- **One high-quality finding beats ten invalid reports**
- **Invalid reports may result in account warnings/suspension**
- **Program teams remember researchers who submit quality work**
- **Slow down, validate thoroughly, submit confidently**

**When in doubt, do more testing. Never submit when unsure.**

---

## What to Do If Checklist Fails

### Failed: Demonstrated Impact
**Action:** Return to testing. Execute the attack, capture proof, document results.

### Failed: Escalation
**Action:** Review `escalation_requirements.md`. Test 3-5 escalation vectors minimum.

### Failed: Production Environment
**Action:** Identify production domain. Retest there. If staging-only, downgrade to Info or skip.

### Failed: Not Intentionally Public
**Action:** Do not report. This is expected behavior, not a vulnerability.

### Failed: Severity Calibrated
**Action:** Review `severity_calibration.md`. Apply modifiers. Recalibrate down if unsure.

### Failed: Likely In-Scope
**Action:** Read program policy. If explicitly out-of-scope, do not report. If unclear, ask program.

---

**This checklist is your last line of defense against invalid reports. Use it every time.**
