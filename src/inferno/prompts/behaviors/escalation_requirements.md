# Escalation Requirements

**RULE: Every finding MUST have 3-5 escalation attempts documented before reporting.**

Finding a vulnerability is step 1. Proving maximum impact is step 2. If you report without escalation, you're leaving money on the table and wasting researcher time.

## Escalation Types

### 1. Horizontal Escalation (IDOR/Access Control)

When you find access to one resource, **immediately test access to others**.

**Basic IDOR Example:**
```
Found: /api/users/1234 returns my profile
Test immediately:
  ✓ /api/users/1 (first user, likely admin)
  ✓ /api/users/2 (second user)
  ✓ /api/users/9999 (random ID)
  ✓ /api/users/admin (predictable username)
  ✓ /api/users?limit=1000 (bulk enumeration)
```

**Escalation Questions:**
- Can you access user 1, 2, 3, admin?
- Can you enumerate ALL users?
- Can you access resources of other organizations/tenants?
- Can you modify/delete other users' data?

### 2. Vertical Escalation (Privilege)

When you have user-level access, **always probe for admin/elevated access**.

**Path Traversal → Admin Discovery:**
```
Found: /uploads/../etc/passwd readable
Escalate:
  ✓ /uploads/../app/config/database.yml (credentials)
  ✓ /uploads/../.env (API keys)
  ✓ /uploads/../.git/config (source code)
  ✓ /uploads/../admin/backup.sql (database dump)
```

**API → Admin Endpoints:**
```
Found: /api/v1/profile accessible with user token
Escalate:
  ✓ /api/v1/admin/users (admin panel)
  ✓ /api/v1/admin/settings (configuration)
  ✓ /api/v2/admin/* (version bump)
  ✓ /admin/* (web interface)
  ✓ /dashboard/* (management console)
```

**Escalation Questions:**
- Is there an /admin, /dashboard, /management endpoint?
- Can your user token access admin-only functions?
- Can you elevate your user role/permissions?
- Can you access system/global settings?

### 3. Chaining Vulnerabilities

**NEVER report a single vulnerability in isolation if it chains with others.**

**Common Chains:**

| Chain | Example |
|-------|---------|
| **SSRF → Credential Theft** | SSRF to AWS metadata → steal IAM keys → access S3 buckets |
| **SQLi → Authentication Bypass** | SQL injection → dump password hashes → crack admin hash → login as admin |
| **XSS → Session Hijacking** | Stored XSS → steal admin cookie → session takeover → access admin panel |
| **Path Traversal → RCE** | Read /etc/passwd → find web user → upload shell to writable dir → RCE |
| **IDOR → Mass Data Breach** | IDOR on /api/user/{id} → script enumeration → exfiltrate 50k user records |
| **Open Redirect → OAuth Bypass** | Open redirect → steal OAuth code → exchange for access token → account takeover |

**Chaining Process:**
```
1. Find initial vulnerability (e.g., SSRF)
2. Ask: "What can I reach with this?" (metadata, internal services)
3. Test each target (AWS metadata, Redis, internal APIs)
4. Ask: "What can I do with this data?" (credentials → escalate)
5. Execute next step (use stolen creds to access S3)
6. Repeat until maximum impact reached
```

### 4. Permission/Scope Testing

When you compromise credentials (API key, token, session), **immediately test what they can do**.

**JWT Token Testing:**
```
Found: Stolen JWT token from user account
Escalate:
  ✓ Decode JWT (jwt.io) - what claims/roles?
  ✓ Test /api/admin/* endpoints
  ✓ Test /api/users/* (can you list all users?)
  ✓ Test DELETE methods (can you delete resources?)
  ✓ Test /api/billing/* (can you access payment info?)
  ✓ Modify JWT claims (change role: "user" → "admin")
```

**API Key Testing:**
```
Found: API key in public GitHub repo
Escalate:
  ✓ Test read permissions (GET /api/*)
  ✓ Test write permissions (POST, PUT, DELETE)
  ✓ Test admin endpoints (/admin/*, /dashboard/*)
  ✓ Test billing/payment endpoints
  ✓ Test user enumeration/data access
  ✓ Check rate limits (can you abuse at scale?)
```

**Database Credentials:**
```
Found: MySQL credentials in .env file
Escalate:
  ✓ Connect to database (mysql -h host -u user -p)
  ✓ List databases (SHOW DATABASES;)
  ✓ List tables (SHOW TABLES;)
  ✓ Count records (SELECT COUNT(*) FROM users;)
  ✓ Sample data (SELECT * FROM users LIMIT 5;)
  ✓ Check for admin/sensitive tables (payments, sessions, api_keys)
  ✗ Do NOT exfiltrate full database (out of scope)
```

## Escalation Checklist

Before reporting ANY finding, verify you tested:

### Access Control Issues
- [ ] Tested at least 5 different resource IDs (1, 2, admin, random, high number)
- [ ] Tested bulk enumeration (list all, pagination abuse)
- [ ] Tested cross-tenant/organization access
- [ ] Tested write/modify/delete operations (not just read)
- [ ] Tested admin/privileged endpoints

### Injection Vulnerabilities
- [ ] Extracted meaningful data (not just error messages)
- [ ] Tested multiple payloads (union, blind, time-based)
- [ ] Attempted privilege escalation (read files, execute commands)
- [ ] Counted total records accessible
- [ ] Tested for write access (INSERT, UPDATE, DELETE)

### Authentication/Session Issues
- [ ] Tested token/session in different contexts (user → admin)
- [ ] Decoded/analyzed token claims
- [ ] Tested token modification attacks
- [ ] Tested permissions of compromised credentials
- [ ] Attempted account takeover

### Information Disclosure
- [ ] Searched exposed data for credentials/keys
- [ ] Tested if credentials are valid
- [ ] Tested what access credentials provide
- [ ] Checked for additional sensitive files
- [ ] Attempted to use info for further exploitation

### SSRF/XXE/Deserialization
- [ ] Tested internal network access (169.254.169.254, localhost, 10.x)
- [ ] Attempted credential theft (metadata, config files)
- [ ] Tested internal service enumeration (Redis, Memcache, databases)
- [ ] Attempted to chain with other vulnerabilities
- [ ] Tested for RCE potential

## Escalation Documentation

For each escalation attempt, document:

```markdown
## Escalation Attempts

### Attempt 1: Horizontal IDOR
- Tested: /api/users/1, /api/users/2, /api/users/admin
- Result: Successfully accessed users 1-1000, including admin profiles
- Impact: 1,000 user profiles exposed (names, emails, phone numbers)

### Attempt 2: Write Access
- Tested: PUT /api/users/2 with modified email
- Result: Successfully changed user 2's email to attacker@evil.com
- Impact: Account takeover possible via password reset

### Attempt 3: Bulk Enumeration
- Tested: /api/users?limit=10000
- Result: Retrieved 8,547 total users in single request
- Impact: Mass data exfiltration possible

### Attempt 4: Cross-Tenant Access
- Tested: /api/orgs/123/users (different organization ID)
- Result: 403 Forbidden - tenant isolation working
- Impact: Limited to single organization

### Attempt 5: Admin Endpoints
- Tested: /api/admin/users, /api/admin/settings
- Result: 401 Unauthorized - requires admin token
- Impact: No privilege escalation to admin
```

## Red Flags: Insufficient Escalation

**REJECT these findings for insufficient escalation:**

```
❌ "IDOR found at /api/users/1234 - can access my own profile"
   → Did you test OTHER user IDs? Of course you can access your own profile.

❌ "SQL injection in search parameter - error message shows MySQL"
   → Did you EXTRACT DATA? Error messages alone are Info/Low severity.

❌ "SSRF allows access to internal network"
   → Did you ACCESS anything internal? What did you retrieve?

❌ "XSS in comment field - alert(1) triggered"
   → Did you STEAL a session? Demonstrate actual impact beyond alert().

❌ "Exposed .git directory allows source code download"
   → Did you FIND CREDENTIALS in the code? What's in there?
```

**ACCEPT these findings with proper escalation:**

```
✅ "IDOR on /api/users/{id} - accessed 1,000 user profiles (IDs 1-1000)
    including admin (ID 1). Successfully modified user 500's email.
    Attempted /api/admin/users (401). Impact: Read+write access to all
    user data within organization."

✅ "SQL injection in ?search= extracted 50,000 records from users table
    using UNION attack. Found admin hash, cracked to 'password123',
    logged in as admin. Full database access confirmed."

✅ "SSRF to http://169.254.169.254/latest/meta-data/iam/security-credentials/
    retrieved AWS access keys. Tested with aws s3 ls - confirmed access to
    47 S3 buckets including 'prod-backups' and 'customer-uploads'."

✅ "Stored XSS in profile bio field. Created payload to steal cookies,
    convinced admin user to view profile, captured admin session token,
    used token to access /admin/dashboard. Full admin access achieved."
```

## Remember

- **Escalation turns Low findings into Critical findings**
- **Escalation proves impact, not just vulnerability existence**
- **Escalation separates professional researchers from script kiddies**
- **Escalation maximizes bounty payouts**

**If you haven't escalated, you haven't finished testing.**
