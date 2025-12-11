# "So What?" Finding Validation

Before reporting ANY finding, you MUST answer the "So What?" question. A vulnerability without demonstrable impact is not a valid finding.

## Required Questions

For every potential finding, you MUST answer these three questions with CONCRETE evidence:

### 1. What can an attacker ACTUALLY DO?

**Bad Examples (Vague):**
- "Data is exposed"
- "User information can be accessed"
- "Authentication can be bypassed"

**Good Examples (Concrete):**
- "Access 50,000 customer email addresses via `/api/users?limit=50000`"
- "Read any user's private messages by changing `conversation_id` parameter"
- "Execute commands as root via `/admin/system/exec` endpoint"

### 2. What is the CONCRETE harm?

**Bad Examples (Theoretical):**
- "Could lead to account takeover"
- "May allow unauthorized access"
- "Might expose sensitive data"

**Good Examples (Proven):**
- "Transferred $500 from victim account to attacker wallet"
- "Downloaded user's SSN, credit card, and home address"
- "Deleted 1,200 customer records from production database"

### 3. Is it ACTUALLY exploitable (not theoretical)?

**Bad Examples (Unproven):**
- "Theoretical race condition could cause..."
- "If an attacker chains this with..."
- "With specific timing, might be possible to..."

**Good Examples (Demonstrated):**
- "Executed `id` command, received `uid=0(root)` response"
- "Retrieved admin JWT token and accessed `/admin/dashboard`"
- "Injected `' OR '1'='1` and dumped entire users table"

## Auto-Rejection Triggers

If your finding description contains these phrases, **automatically demote severity by 2 levels**:

- "could lead to"
- "might allow"
- "potentially enables"
- "theoretical"
- "may be possible"
- "with the right conditions"
- "if combined with"
- "in certain scenarios"

## Proof Requirements by Severity

| Severity | Minimum Proof Required |
|----------|------------------------|
| **Critical** | Full exploit chain executed + sensitive data exfiltrated/modified |
| **High** | Successful unauthorized action performed (read/write/delete) |
| **Medium** | Abnormal behavior triggered + clear attack vector identified |
| **Low** | Vulnerability confirmed but limited/no direct impact shown |
| **Info** | Observation only, no security impact |

## Examples

### REJECT: Vague Impact
```
Finding: Open redirect on /redirect?url=
Impact: Could lead to phishing attacks
Proof: Redirects to evil.com

Why rejected: No proven harm, just a redirect. So what?
```

### ACCEPT: Concrete Impact
```
Finding: IDOR in /api/orders/{id}
Impact: Retrieved 2,847 orders from other users, including full names,
        addresses, phone numbers, and order contents
Proof: Changed order_id from 1001 to 1-3000, received 200 OK with order details
       Sample: Order #1523 - John Doe, 123 Main St, phone, $450 purchase
Escalation: Tested write access - successfully cancelled order #1524 (not mine)

Why accepted: Concrete numbers, specific data types, proven read+write access
```

### REJECT: Theoretical Chain
```
Finding: SSRF to internal network
Impact: Could potentially access AWS metadata and steal credentials
Proof: Accessed http://169.254.169.254 via ssrf parameter

Why rejected: "Could potentially" - did you actually GET credentials? No? Then it's Info/Low.
```

### ACCEPT: Proven Chain
```
Finding: SSRF to AWS metadata → credential theft
Impact: Exfiltrated AWS access keys with S3 full access, listed 47 buckets
Proof:
  1. SSRF: http://169.254.169.254/latest/meta-data/iam/security-credentials/web-server
  2. Retrieved: AKIA... access key + secret
  3. aws s3 ls --profile stolen → listed production buckets
  4. Did NOT download data (out of scope)

Why accepted: Full chain demonstrated with concrete results at each step
```

## Validation Checklist

Before reporting, verify:

- [ ] Impact is stated in **numbers/specifics**, not possibilities
- [ ] You **personally executed** the attack (not "could be done")
- [ ] The harm is **business-relevant** (data breach, financial loss, access control bypass)
- [ ] You can answer "So what?" without using "could/might/may"
- [ ] A security team would immediately understand why this matters

**If you cannot check all boxes, do NOT report. Investigate further or escalate first.**
