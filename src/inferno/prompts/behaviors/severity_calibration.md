# Severity Calibration

Severity ratings must reflect **proven impact**, not theoretical risk. This guide provides strict calibration rules for bug bounty programs.

## Severity Levels

### Critical (9.0-10.0)

**Requirements (ALL must be met):**
- Remote Code Execution (RCE) with proof of execution
- OR authentication bypass leading to full admin access (demonstrated)
- OR private key/credential exposure leading to system compromise (proven)
- OR mass data breach affecting 10,000+ records (confirmed)
- OR direct financial loss/theft (executed transaction)

**Examples:**
```
✅ CRITICAL: Unauthenticated RCE via /api/execute
   Proof: curl -X POST /api/execute -d '{"cmd":"id"}'
   Response: uid=0(root) gid=0(root)

✅ CRITICAL: Authentication bypass to admin panel
   Proof: Added X-Admin: true header → accessed /admin/users
   Impact: Created new admin account, deleted user accounts

✅ CRITICAL: AWS secret key in public S3 bucket
   Proof: Downloaded key, ran aws s3 ls → listed 50 production buckets
   Impact: Full access to customer data, could modify/delete

❌ NOT CRITICAL: SQL injection that reads database
   Why: Data breach, not system compromise (High severity instead)

❌ NOT CRITICAL: SSRF to internal network
   Why: Network access, not proven system compromise (High/Medium)
```

### High (7.0-8.9)

**Requirements (ONE must be met):**
- PROVEN unauthorized access to other users' data (not your own)
- OR privilege escalation from user to admin (successful)
- OR credential/API key exposure with confirmed sensitive access
- OR SQL injection with data exfiltration (100+ records)
- OR stored XSS leading to session hijacking (demonstrated)

**Examples:**
```
✅ HIGH: IDOR accessing 5,000 user profiles
   Proof: /api/users/1 through /api/users/5000 return full profiles
   Data: names, emails, phone numbers, addresses

✅ HIGH: SQL injection dumping users table
   Proof: ' UNION SELECT username,password FROM users--
   Result: 1,247 password hashes retrieved

✅ HIGH: Stored XSS stealing admin session
   Proof: Injected <script> in bio, admin viewed profile,
   Result: Captured admin cookie, used to access /admin

❌ NOT HIGH: IDOR accessing your own data with different IDs
   Why: No unauthorized access (Info/Low severity)

❌ NOT HIGH: Reflected XSS requiring user interaction
   Why: No proven session theft (Medium severity instead)
```

### Medium (4.0-6.9)

**Requirements (ONE must be met):**
- Real security impact beyond information disclosure
- OR SSRF with access to internal services (confirmed)
- OR stored XSS without demonstrated session theft
- OR authentication issues with limited scope
- OR IDOR with minimal sensitive data exposure

**Examples:**
```
✅ MEDIUM: SSRF accessing internal Redis
   Proof: http://localhost:6379 via url parameter
   Result: Retrieved cached session data (no credentials found)

✅ MEDIUM: Stored XSS in comment field
   Proof: <script>alert(document.domain)</script> persists
   Note: Did not achieve session theft (would be High if proven)

✅ MEDIUM: IDOR exposing order IDs (no PII)
   Proof: /api/orders/1234 shows order total and items
   Impact: Limited - no names, addresses, or payment info

❌ NOT MEDIUM: Stack traces with file paths
   Why: Information disclosure only (Low severity)

❌ NOT MEDIUM: Self-XSS requiring attacker to use own account
   Why: No attack vector against others (Info severity)
```

### Low (0.1-3.9)

**Requirements:**
- Confirmed vulnerability with minimal security impact
- OR information disclosure without sensitive data
- OR security misconfiguration without exploitation path
- OR rate limiting issues without abuse demonstrated

**Examples:**
```
✅ LOW: Stack traces revealing framework version
   Proof: Error page shows "Django 2.1.5" and file paths
   Impact: Information disclosure only

✅ LOW: Missing rate limiting on /api/search
   Proof: Sent 1000 requests/second, all processed
   Impact: Potential DoS (not demonstrated)

✅ LOW: Server headers revealing technology
   Proof: Server: Apache/2.4.41 (Ubuntu)
   Impact: Version disclosure

❌ NOT LOW: Public API documentation
   Why: Intentional disclosure (Info severity)

❌ NOT LOW: SSL/TLS configuration on staging server
   Why: Non-production environment (Info or out-of-scope)
```

### Informational (0.0)

**Characteristics:**
- No security impact
- OR intentionally public information
- OR best practice recommendations
- OR issues on non-production environments

**Examples:**
```
✅ INFO: Missing security headers (CSP, HSTS)
   Note: Recommendations, not vulnerabilities

✅ INFO: Outdated JavaScript libraries (no known CVE)
   Note: Version disclosure without exploit

✅ INFO: Public GitHub repository
   Note: Intentionally public

✅ INFO: Verbose error messages on staging
   Note: Non-production environment

✅ INFO: Blockchain transaction data
   Note: Intentionally public by design
```

## Automatic Severity Adjustments

Apply these modifiers to your initial severity assessment:

| Condition | Adjustment | Example |
|-----------|------------|---------|
| **Description uses "could/might/may"** | -1.0 severity | "Could lead to RCE" → High instead of Critical |
| **Theoretical chain (not proven)** | -1.5 severity | "If combined with XSS..." → Medium instead of High |
| **Escalation successfully demonstrated** | +1.0 severity | IDOR + write access → High instead of Medium |
| **Multiple vulnerabilities chained** | +0.5 severity | SSRF + credential theft → Critical instead of High |
| **Staging/dev/test environment** | -2.0 severity | RCE on staging → Medium instead of Critical |
| **Requires user interaction** | -0.5 severity | Reflected XSS → Medium instead of High |
| **Self-exploitation only** | -3.0 severity | Self-XSS → Info instead of Medium |
| **Public/intentional data** | Set to Info | Blockchain data → Info (not Low) |
| **Mass scale demonstrated** | +0.5 severity | IDOR on 10,000 users → High instead of Medium |
| **Admin/privileged access achieved** | +1.0 severity | User → Admin → Critical instead of High |

## Severity Calculation Examples

### Example 1: SQL Injection
```
Initial Assessment: Critical (RCE potential)
Reality Check:
  - Extracted data only (no RCE proven) → High
  - Retrieved 50 records (not mass breach) → Medium
  - Used "could lead to" language → -1.0 → Low
  - No escalation attempted → -0.5 → Low

Final Severity: Low (3.0)
Reason: Theoretical impact, minimal proven harm
```

### Example 2: IDOR with Escalation
```
Initial Assessment: Medium (unauthorized access)
Reality Check:
  - Accessed other users' data → Medium (base)
  - Tested write access (successful) → +1.0 → High
  - Enumerated 5,000 records → +0.5 → High
  - Production environment → no change

Final Severity: High (8.0)
Reason: Proven read+write access at scale
```

### Example 3: SSRF Chain
```
Initial Assessment: Medium (SSRF to internal network)
Reality Check:
  - Accessed AWS metadata → Medium (base)
  - Retrieved IAM credentials → +1.0 → High
  - Tested credentials (S3 access confirmed) → +0.5 → Critical
  - Production environment → no change

Final Severity: Critical (9.0)
Reason: Full chain demonstrated with system access
```

### Example 4: XSS on Staging
```
Initial Assessment: High (stored XSS)
Reality Check:
  - Stored XSS (persistent) → High (base)
  - No session theft demonstrated → -0.5 → Medium
  - Staging environment → -2.0 → Low
  - Production not affected → no change

Final Severity: Low (2.0)
Reason: Non-production environment invalidates impact
```

## Common Severity Mistakes

### Overrated Findings

```
❌ CLAIMED: Critical - Open redirect allows phishing
   ✅ ACTUAL: Low - Redirects to attacker.com (no account compromise)

❌ CLAIMED: High - Missing CSRF token on logout
   ✅ ACTUAL: Info - Logout has no security impact

❌ CLAIMED: Medium - Email enumeration on registration
   ✅ ACTUAL: Low - "Email already exists" is standard UX

❌ CLAIMED: High - Subdomain takeover on dev.example.com
   ✅ ACTUAL: Low/Info - Non-production subdomain

❌ CLAIMED: Critical - SSRF to internal network
   ✅ ACTUAL: Medium - Network access without proven exploitation
```

### Underrated Findings

```
❌ CLAIMED: Medium - IDOR on /api/users/{id}
   ✅ ACTUAL: High - Accessed 10,000 users + successfully modified data

❌ CLAIMED: Low - Exposed .env file
   ✅ ACTUAL: Critical - Contains AWS keys with full S3 access (proven)

❌ CLAIMED: Medium - SQL injection in search
   ✅ ACTUAL: High - Extracted 50,000 user records with PII

❌ CLAIMED: Info - API key in JavaScript
   ✅ ACTUAL: High - API key grants admin access (tested and confirmed)
```

## Calibration Checklist

Before finalizing severity, verify:

- [ ] Severity matches **proven impact**, not theoretical maximum
- [ ] Applied -1.0 penalty if using "could/might/may" language
- [ ] Applied -2.0 penalty if finding is on staging/dev/test
- [ ] Applied +1.0 bonus if escalation was successful
- [ ] Applied +0.5 bonus if multiple vulns were chained
- [ ] Checked that Critical findings have **system compromise proof**
- [ ] Checked that High findings have **unauthorized access proof**
- [ ] Checked that Medium findings have **real security impact**
- [ ] Checked that Low findings are **confirmed vulnerabilities**
- [ ] Checked that Info findings are **truly informational**

## Severity Decision Tree

```
START: Did you achieve RCE or full system compromise?
├─ YES → Critical (if proven with command output/shell access)
└─ NO → Continue

Did you access other users' sensitive data or achieve privilege escalation?
├─ YES → High (if 100+ records OR admin access OR credentials stolen)
└─ NO → Continue

Does the finding have security impact beyond information disclosure?
├─ YES → Medium (if SSRF to internal, stored XSS, auth issues)
└─ NO → Continue

Is there a confirmed vulnerability with minimal impact?
├─ YES → Low (version disclosure, stack traces, misconfigurations)
└─ NO → Info (best practices, intentional public data)

MODIFIERS:
- Staging/dev/test? → -2.0 severity levels
- "Could/might/may" language? → -1.0 severity level
- Successful escalation? → +1.0 severity level
- Chained vulnerabilities? → +0.5 severity level
```

## Remember

1. **Severity = Proven Impact, not theoretical maximum**
2. **"Could lead to" automatically disqualifies Critical/High**
3. **Staging environment findings are Low/Info at best**
4. **Escalation is the difference between Medium and High**
5. **When in doubt, calibrate DOWN (fewer false positives)**

**Your reputation depends on accurate severity ratings. Overrating findings destroys credibility.**
