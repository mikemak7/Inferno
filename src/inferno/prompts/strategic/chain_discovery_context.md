## Attack Chain Intelligence

% if not chains:
No attack chains discovered yet. Look for opportunities to chain findings for greater impact.
% else:

### Attack Chain Overview

**Total Chains Discovered**: ${len(chains)}
**Chains Tested**: ${len([c for c in chains if c.tested])}
**Successful Chains**: ${len([c for c in chains if c.success])}

<%
from operator import attrgetter
sorted_chains = sorted(chains, key=lambda c: c.score, reverse=True)
high_value_chains = [c for c in chains if c.score >= 8.0]
medium_value_chains = [c for c in chains if 5.0 <= c.score < 8.0]
low_value_chains = [c for c in chains if c.score < 5.0]
%>

**Chain Value Distribution**:
- High Value (8.0+): ${len(high_value_chains)} chains
- Medium Value (5.0-7.9): ${len(medium_value_chains)} chains
- Low Value (<5.0): ${len(low_value_chains)} chains

---

### High-Value Chains (Priority Exploitation)

% if high_value_chains:
% for idx, chain in enumerate(high_value_chains[:5], 1):

#### Chain ${idx}: ${chain.name}
**Score**: ${chain.score}/10 | **Impact**: ${chain.impact} | **Complexity**: ${chain.complexity}

<%def name="format_chain_step(step, step_num)">
**Step ${step_num}: ${step.action}**
% if step.tool:
- Tool: `${step.tool}`
% endif
% if step.target:
- Target: ${step.target}
% endif
% if step.payload:
- Payload: `${step.payload}`
% endif
% if step.expected_result:
- Expected Result: ${step.expected_result}
% endif
% if step.success_criteria:
- Success Criteria: ${step.success_criteria}
% endif
% if step.fallback:
- Fallback: ${step.fallback}
% endif
</%def>

**Attack Flow**:
% for step_idx, step in enumerate(chain.steps, 1):
${format_chain_step(step, step_idx)}
% endfor

**Prerequisites**:
% if chain.prerequisites:
% for prereq in chain.prerequisites:
- ${prereq}
% endfor
% else:
None - can execute immediately
% endif

**Expected Impact**:
${chain.impact_description}

% if chain.cvss_score:
**CVSS Score**: ${chain.cvss_score} (${chain.severity})
% endif

% if chain.tested:
% if chain.success:
**STATUS**: ✓ SUCCESSFULLY EXPLOITED
% if chain.results:
**Results**:
% for result in chain.results:
- ${result}
% endfor
% endif
% else:
**STATUS**: ✗ TESTED BUT FAILED
% if chain.failure_reason:
**Failure Reason**: ${chain.failure_reason}
% endif
% endif
% else:
**STATUS**: ⏳ NOT YET TESTED - HIGH PRIORITY
% endif

% if chain.poc:
**Proof of Concept**:
```${chain.poc_format or 'bash'}
${chain.poc}
```
% endif

% if chain.remediation:
**Remediation**: ${chain.remediation}
% endif

---
% endfor

% if len(high_value_chains) > 5:
... and ${len(high_value_chains) - 5} more high-value chains

% endif

% else:
No high-value chains identified yet. Continue reconnaissance and vulnerability discovery.
% endif

---

### Chain Patterns to Watch For

These patterns indicate chaining opportunities:

#### 1. Information Disclosure → Privilege Escalation
```
Step 1: Exploit endpoint enumeration (IDOR, directory traversal)
Step 2: Discover admin endpoints or credentials
Step 3: Authenticate with discovered credentials
Step 4: Access privileged functionality
```
**Indicators**:
- Exposed API documentation
- Leaked credentials in responses
- User enumeration possible
- Weak session management

#### 2. XSS → Account Takeover
```
Step 1: Find stored XSS vulnerability
Step 2: Craft payload to steal session tokens
Step 3: Inject payload via vulnerable parameter
Step 4: Wait for admin/victim to trigger payload
Step 5: Use stolen token for account access
```
**Indicators**:
- Stored XSS in user-generated content
- Session tokens in cookies (not HttpOnly)
- Admin panel accessible
- No CSRF protection

#### 3. SSRF → Cloud Metadata → RCE
```
Step 1: Identify SSRF vulnerability
Step 2: Access cloud metadata (169.254.169.254)
Step 3: Extract IAM credentials
Step 4: Use credentials for cloud API access
Step 5: Execute commands via cloud services
```
**Indicators**:
- Running on AWS/GCP/Azure
- URL/redirect parameters
- Image upload/processing
- Webhook functionality

#### 4. SQLi → File Write → RCE
```
Step 1: Confirm SQL injection
Step 2: Enumerate database users/privileges
Step 3: Write web shell using INTO OUTFILE
Step 4: Access web shell for RCE
```
**Indicators**:
- MySQL with FILE privileges
- Known web root path
- SQL injection confirmed
- Write permissions on web directory

#### 5. Authentication Bypass → IDOR → Data Exfiltration
```
Step 1: Bypass authentication (JWT null algo, SQL injection)
Step 2: Access authenticated endpoints
Step 3: Enumerate object IDs (IDOR)
Step 4: Extract sensitive data
```
**Indicators**:
- Weak JWT validation
- Predictable session tokens
- IDOR vulnerabilities present
- Sensitive data endpoints

#### 6. CSRF → Privileged Action
```
Step 1: Identify state-changing action without CSRF token
Step 2: Craft CSRF payload
Step 3: Deliver to victim (XSS, email, etc.)
Step 4: Victim executes privileged action
```
**Indicators**:
- No anti-CSRF tokens
- State-changing GET requests
- XSS available for delivery
- Sensitive actions (password change, fund transfer)

#### 7. Race Condition → Business Logic Bypass
```
Step 1: Identify rate-limited action (coupon, vote, transfer)
Step 2: Prepare parallel requests
Step 3: Execute race condition attack
Step 4: Bypass limit (double spend, multiple redemptions)
```
**Indicators**:
- Financial transactions
- Voting systems
- Promotional codes
- Resource allocation

#### 8. Deserialization → RCE
```
Step 1: Identify deserialization point (cookies, parameters)
Step 2: Determine serialization format (PHP, Java, Python)
Step 3: Craft malicious payload (ysoserial, phpggc)
Step 4: Execute arbitrary code
```
**Indicators**:
- Base64-encoded cookies
- Java/PHP/Python tech stack
- Object notation in parameters
- Session data tampering possible

#### 9. XXE → File Read → Credential Extraction
```
Step 1: Find XML processing endpoint
Step 2: Inject XXE payload for file read
Step 3: Extract sensitive files (/etc/passwd, config files)
Step 4: Discover credentials/API keys
Step 5: Use credentials for further access
```
**Indicators**:
- XML input accepted
- File upload with XML processing
- SOAP API endpoints
- Error messages revealing XML parser

#### 10. Subdomain Takeover → Phishing/Cookie Theft
```
Step 1: Enumerate subdomains
Step 2: Identify dangling DNS records
Step 3: Claim subdomain (S3, GitHub Pages, etc.)
Step 4: Host phishing page or cookie-stealing script
```
**Indicators**:
- Many subdomains
- CNAME to external services
- Wildcard cookies (*.domain.com)
- User-facing subdomains

---

### Chain Discovery Heuristics

% if chain_patterns:

**Active Patterns** (detected in current assessment):
% for pattern in chain_patterns:
- **${pattern.name}**: ${pattern.description}
  * Confidence: ${pattern.confidence}%
  * Next Step: ${pattern.next_step}
% endfor

% endif

**Automatic Chain Detection**:

When you discover:
- **Information Disclosure** → Look for credentials, API keys, endpoints to exploit
- **Authentication Bypass** → Test all protected endpoints
- **SSRF** → Check cloud metadata, internal services
- **SQLi** → Enumerate DB structure, check for file write permissions
- **XSS** → Look for admin panels, session tokens in cookies
- **File Upload** → Try to upload web shells, check execution
- **IDOR** → Enumerate all objects, look for admin/sensitive data
- **XXE** → Read config files, credentials, source code
- **Deserialization** → Craft RCE payloads
- **CSRF** → Find privileged state-changing actions

**Correlation Triggers**:
% if correlation_triggers:
% for trigger in correlation_triggers:
- ${trigger.finding_type} + ${trigger.complementary_finding} = ${trigger.chain_opportunity}
% endfor
% else:
- SQLi + File Write = RCE
- XSS + Session Token = Account Takeover
- SSRF + Cloud Environment = Credential Theft
- IDOR + Admin Endpoint = Privilege Escalation
- Auth Bypass + IDOR = Mass Data Breach
% endif

---

### Medium-Value Chains

% if medium_value_chains:

**Secondary Exploitation Paths** (${len(medium_value_chains)} chains):

% for idx, chain in enumerate(medium_value_chains[:3], 1):
${idx}. **${chain.name}** (Score: ${chain.score}/10)
   - Steps: ${len(chain.steps)}
   - Impact: ${chain.impact}
   - Status: ${'✓ Tested' if chain.tested else '⏳ Pending'}
   % if chain.quick_summary:
   - Summary: ${chain.quick_summary}
   % endif
% endfor

% if len(medium_value_chains) > 3:
... and ${len(medium_value_chains) - 3} more medium-value chains
% endif

**Recommendation**: Exploit medium chains if high-value chains fail or after completing high-priority targets.

% endif

---

### Chain Execution Strategy

**For CTF Mode** (time-limited):
1. Execute highest-scoring chain immediately
2. Skip validation - go straight for the flag
3. Use parallel sub-agents for multi-step chains
4. If chain fails at step N, try alternative paths before backtracking

**For Bug Bounty/Pentest**:
1. Validate each step before proceeding
2. Document each step for report
3. Generate PoC for successful chains
4. Calculate CVSS scores for impact assessment
5. Test remediation to ensure completeness

**Parallel Execution**:
% if len(chains) >= 3:
You can test multiple chains in parallel using sub-agents:
- Spawn `exploiter` sub-agent for Chain 1
- Spawn `exploiter` sub-agent for Chain 2
- Meta-agent coordinates and aggregates results

**Recommended**: Test top ${min(3, len(high_value_chains))} chains in parallel for speed.
% endif

---

### Chain Dependency Graph

% if chain_dependencies:

Some chains depend on others. Execute in order:

```
${chain_dependency_graph}
```

**Execution Order**:
% for idx, chain_id in enumerate(chain_execution_order, 1):
${idx}. ${chains_by_id[chain_id].name}
% endfor

% endif

---

### Failed Chain Analysis

% if failed_chains:

**Chains That Failed** (learn from failures):

% for chain in failed_chains[:3]:
- **${chain.name}**
  * Failed at Step: ${chain.failed_step}
  * Reason: ${chain.failure_reason}
  * Possible Fix: ${chain.suggested_fix or 'Try alternative payload or approach'}
% endfor

% endif

---

### Chain Optimization Tips

1. **Minimize Steps**: Fewer steps = less chance of failure
2. **Validate Early**: Confirm vulnerability before building complex chain
3. **Cache Results**: Reuse information from earlier steps (tokens, cookies, etc.)
4. **Error Handling**: Have fallback for each critical step
5. **Timing**: Consider rate limits and detection between steps
6. **State Management**: Track session state, cookies, tokens across chain

---

### Tools for Chain Execution

**Recommended Tools by Chain Type**:
- **Multi-step Attacks**: `exploit_chain` tool (automated execution)
- **Attack Planning**: `attack_graph` (optimal path finding)
- **Payload Evolution**: `payload_mutator` (WAF bypass)
- **Validation**: `validation_engine` (confirm each step)
- **PoC Generation**: `poc_generator` (document successful chains)

**Example Usage**:
```python
# Execute pre-built chain
exploit_chain.execute(
    chain_id="sqli_to_rce_001",
    target="https://target.com",
    parallel=True  # Execute independent steps in parallel
)
```

---

**Strategic Guidance**:

% if len(high_value_chains) > 0:
**PRIORITY**: ${len(high_value_chains)} high-value chain(s) available. Execute immediately.
% elif len(medium_value_chains) > 0:
**FOCUS**: Build high-value chains from medium-value findings, or execute medium chains.
% else:
**ACTION**: Continue vulnerability discovery. Look for chainable findings:
- Authentication weaknesses
- Information disclosure
- Injection points (SQLi, XSS, XXE, SSTI)
- Access control issues (IDOR, broken auth)
% endif

% if ctf_mode:
**CTF OPTIMIZATION**: Chain discovery accelerates flag capture. Prioritize chains over individual vulns.
% endif

% endif
