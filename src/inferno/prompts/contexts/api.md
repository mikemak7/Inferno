<context_api_security>
## API Security Assessment

### API Discovery

1. **Documentation**
   - /swagger.json, /openapi.json
   - /api-docs, /docs
   - /graphql (introspection)

2. **Endpoint Enumeration**
   - Version differences (/v1, /v2)
   - HTTP method variations
   - Parameter discovery

3. **Authentication**
   - API keys
   - JWT tokens
   - OAuth tokens
   - Basic auth

### API Attack Vectors

| Vector | Description |
|--------|-------------|
| BOLA/IDOR | Access other users' objects |
| BFLA | Access unauthorized functions |
| Mass Assignment | Modify protected fields |
| Rate Limiting | Brute force, DoS |
| Injection | SQLi, NoSQLi, Command injection |
| Data Exposure | Excessive data in responses |

### Testing Patterns

**IDOR/BOLA Testing**:
```
GET /api/v1/users/123  → Your data
GET /api/v1/users/124  → Other user's data? (IDOR)
GET /api/v1/users/1    → Admin data? (Privilege escalation)
```

**Method Testing**:
```
Endpoint: /api/v1/users/123
GET    → Read (allowed)
PUT    → Update (should be denied?)
DELETE → Delete (should be denied?)
POST   → Create (should be denied?)
```

**Mass Assignment**:
```
POST /api/v1/users
{
  "name": "test",
  "email": "test@test.com",
  "role": "admin",        ← Can I set this?
  "is_admin": true,       ← Or this?
  "verified": true        ← Or this?
}
```

### JWT Testing

```
1. None algorithm attack
   - Change alg: "HS256" → "none"
   - Remove signature

2. Algorithm confusion
   - Change RS256 → HS256
   - Sign with public key

3. Token manipulation
   - Change user_id, role
   - Extend expiration

4. Secret brute force
   - hashcat -a 0 -m 16500
```

### GraphQL Testing

```
1. Introspection
   query { __schema { types { name fields { name } } } }

2. Nested query DoS
   { user { friends { friends { friends ... } } } }

3. Batch attacks
   [{"query":"..."}, {"query":"..."}, ...]

4. Field suggestions
   Error messages reveal valid fields
```

### API Security Checklist

- [ ] Authentication bypass attempts
- [ ] IDOR on all resource endpoints
- [ ] Method tampering (GET→POST→PUT→DELETE)
- [ ] Parameter pollution
- [ ] Rate limiting verification
- [ ] Input validation (SQLi, XSS, etc.)
- [ ] Response data exposure
- [ ] Version endpoint differences
- [ ] Admin endpoint access
</context_api_security>
