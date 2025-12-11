<context_web_application>
## Web Application Security Assessment

### Attack Surface

1. **Input Vectors**
   - URL parameters
   - POST body (forms, JSON, XML)
   - Headers (Host, Cookie, X-Forwarded-*)
   - File uploads
   - WebSocket messages

2. **Authentication**
   - Login forms
   - Session management
   - Password reset
   - Multi-factor auth
   - OAuth/OIDC

3. **Authorization**
   - Role-based access
   - Resource ownership
   - API permissions
   - Admin functions

### Priority Vulnerabilities

| Category | Tests |
|----------|-------|
| Injection | SQLi, XSS, SSTI, Command Injection, XXE |
| Auth | Bypass, Weak creds, Session issues |
| Access Control | IDOR, Privilege escalation, Path traversal |
| Config | Exposed admin, Debug mode, Default creds |
| Crypto | Weak hashing, Hardcoded secrets |

### Web-Specific Techniques

**Header Injection Points**:
```
Host: evil.com (password reset poisoning)
X-Forwarded-For: 127.0.0.1 (IP bypass)
X-Forwarded-Host: evil.com (cache poisoning)
Referer: (SSRF, SQLi)
User-Agent: (SQLi, log injection)
```

**JavaScript Analysis**:
```
- API endpoints in JS files
- Hardcoded credentials
- Hidden parameters
- Client-side validation (bypass)
- WebSocket endpoints
```

**Authentication Tests**:
```
1. Default credentials
2. Username enumeration
3. Password brute force
4. SQL injection in login
5. JWT manipulation
6. Session fixation
7. Password reset abuse
```

### Common Web Vulns

**SQL Injection**:
- Login bypass: `' OR '1'='1`
- UNION extraction: `' UNION SELECT null,user(),database()--`
- Blind: Time-based, Boolean-based

**XSS**:
- Reflected: `<script>alert(document.domain)</script>`
- Stored: In comments, profiles, messages
- DOM: In JavaScript sinks

**SSRF**:
- Cloud metadata: `http://169.254.169.254/`
- Internal services: `http://localhost:8080/admin`
- File protocol: `file:///etc/passwd`

**Path Traversal**:
- Basic: `../../../etc/passwd`
- Encoded: `%2e%2e%2f`
- Double: `....//....//`

### Web Framework Specifics

| Framework | Focus Areas |
|-----------|-------------|
| WordPress | /wp-admin, plugins, xmlrpc |
| Drupal | /admin, modules, CVEs |
| Laravel | .env, debug mode, deserialization |
| Django | /admin, DEBUG=True, SSTI |
| Spring | Actuators, SpEL injection |
| Node/Express | Prototype pollution, SSTI |
</context_web_application>
