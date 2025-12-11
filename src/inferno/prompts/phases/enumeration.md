<phase_enumeration>
## Phase 2: Enumeration

**Goal**: Deep-dive into discovered services to find vulnerability vectors.

### Web Application Enumeration

1. **Directory/File Discovery**
   - gobuster with appropriate wordlist
   - Check for: /admin, /api, /backup, /.git, /.env
   - Try file extensions: .php, .asp, .bak, .old, .txt

2. **API Enumeration** (ALWAYS USE FUZZING TOOLS)
   - **REQUIRED**: Use ffuf or gobuster for API endpoint discovery:
     ```bash
     # Primary: ffuf with Inferno's bundled wordlist
     ffuf -u http://{target}/api/FUZZ -w wordlists/api-endpoints.txt -mc all -fc 404

     # Alternative: gobuster
     gobuster dir -u http://{target}/api -w wordlists/api-endpoints.txt -t 50

     # Parameter fuzzing on discovered endpoints
     ffuf -u "http://{target}/api/users?FUZZ=1" -w wordlists/parameters.txt -mc all -fc 404
     ```
   - Fuzz for API versions: /api/v1/FUZZ, /api/v2/FUZZ, /v1/FUZZ
   - Check for Swagger/OpenAPI docs: /swagger.json, /openapi.json, /api-docs, /swagger-ui.html
   - Test each HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS)
   - **Never manually guess endpoints** - always fuzz first

   **Wordlists (bundled with Inferno):**
   - `wordlists/api-endpoints.txt` - API paths
   - `wordlists/common-dirs.txt` - Directories
   - `wordlists/parameters.txt` - Parameters

3. **Parameter Discovery**
   - URL parameters
   - POST body parameters
   - Headers (X-Forwarded-For, Host, etc.)
   - Cookies

4. **Authentication Analysis**
   - Login mechanisms
   - Session management
   - Password reset flows
   - OAuth/OIDC endpoints

### Service Enumeration

| Service | Enumeration |
|---------|-------------|
| HTTP/HTTPS | Directory brute, vhost discovery |
| SSH | Version, auth methods |
| FTP | Anonymous access, version |
| SMB | Shares, null sessions |
| MySQL | Version, default creds |
| RDP | NLA status, version |

### Enumeration Patterns

**API Endpoint Discovery** (MANDATORY FUZZING):
```bash
# STEP 1: ALWAYS fuzz first - never guess endpoints
ffuf -u http://{target}/api/FUZZ -w wordlists/api-endpoints.txt -mc all -fc 404
ffuf -u http://{target}/api/v1/FUZZ -w wordlists/api-endpoints.txt -mc all -fc 404

# STEP 2: Fuzz for parameters on discovered endpoints
ffuf -u "http://{target}/api/v1/users?FUZZ=test" -w wordlists/parameters.txt -mc all -fc 404

# STEP 3: Test HTTP methods on each endpoint
for method in GET POST PUT DELETE PATCH; do
  curl -X $method http://{target}/api/v1/users -v
done
```

**After fuzzing, test discovered endpoints**:
```
Found via ffuf: /api/v1/users, /api/v1/admin, /api/v1/orders
Test each:
- GET /api/v1/users (list users?)
- GET /api/v1/users/1 (IDOR?)
- POST /api/v1/users (create user?)
- GET /api/v1/admin (admin functions?)
```

**Authentication Enumeration**:
```
Found: /login
Test:
- Username enumeration (different error messages?)
- Password brute force (rate limited?)
- Default credentials (admin:admin, admin:password)
- SQLi in login form
- Password reset flow abuse
```

### Gate Check

Before moving to exploitation, verify:
- [ ] All endpoints documented
- [ ] Parameters identified
- [ ] Authentication flow understood
- [ ] Potential vectors listed

**Question**: "Do I have specific exploitation hypotheses with expected outcomes?"
- NO → Enumerate more
- YES → Move to Phase 3: Exploitation
</phase_enumeration>
