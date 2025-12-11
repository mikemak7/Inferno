<vulnerability_chaining>
## Combine Vulnerabilities for Maximum Impact

Single vulnerabilities are good. Chained vulnerabilities are better.

### Chaining Patterns

| First Finding | Chain With | Result |
|---------------|------------|--------|
| Info Disclosure | SSRF | Access internal systems |
| SQLi (read) | Credential extraction | Account takeover |
| XSS | Session stealing | Account takeover |
| SSRF | Cloud metadata | AWS/GCP key extraction |
| LFI | Source code | Hardcoded credentials |
| Config exposure | Default creds | Admin access |
| API key leaked | Permission check | Privilege escalation |

### Chaining Examples

**Chain 1: SQLi → Credential → Login**
```
1. Found SQLi in search parameter
2. Extract password hashes: ' UNION SELECT password FROM users--
3. Crack hash or bypass auth
4. Login as admin
5. Report: "SQLi leads to admin account takeover"
```

**Chain 2: SSRF → Cloud Metadata → RCE**
```
1. Found SSRF in URL parameter
2. Hit: http://169.254.169.254/latest/meta-data/iam/security-credentials/
3. Extract AWS keys
4. Use keys to access S3/EC2
5. Report: "SSRF leads to AWS account compromise"
```

**Chain 3: Info Disclosure → Default Creds → Admin**
```
1. Found /api/v1/settings exposed (shows username format)
2. Try default password combinations
3. Successfully login as admin
4. Report: "Config disclosure + weak creds = admin access"
```

### After Every Finding, Ask:

1. "What else can I access WITH this finding?"
2. "What credentials/tokens does this expose?"
3. "What internal systems can I reach from here?"
4. "Can I combine this with something else I found?"

### Chaining Checklist

When you find credentials:
- [ ] Try them on login pages
- [ ] Try them on SSH/FTP/database
- [ ] Try them on admin panels
- [ ] Try them on API endpoints

When you find SSRF:
- [ ] Hit cloud metadata (169.254.169.254)
- [ ] Scan internal network (127.0.0.1, 10.x, 192.168.x)
- [ ] Access internal services

When you find LFI:
- [ ] Read /etc/passwd
- [ ] Read application config files
- [ ] Read source code for hardcoded secrets
- [ ] Read .env files

When you find SQLi:
- [ ] Extract user table
- [ ] Extract credentials
- [ ] Check for file read (LOAD_FILE)
- [ ] Check for file write (INTO OUTFILE)
</vulnerability_chaining>
