## Application Model Intelligence

% if not model:
No application model data available yet. Begin reconnaissance to build understanding.
% else:

### Target Profile
**Base URL**: ${model.base_url}
**Discovered Endpoints**: ${len(model.endpoints)}
**Parameter Count**: ${sum(len(ep.parameters) for ep in model.endpoints)}
**Authentication**: ${'Detected' if model.auth_patterns else 'Unknown'}

### Technology Stack
% if model.tech_stack:
The target uses the following technologies:
% for tech, confidence in model.tech_stack.items():
- **${tech}**: ${confidence}% confidence
% endfor

**Attack Surface Implications**:
% if 'PHP' in model.tech_stack:
- PHP detected: Test for type juggling, LFI, RFI, insecure deserialization
% endif
% if 'WordPress' in model.tech_stack:
- WordPress: Check plugin vulns, XML-RPC, wp-json endpoints
% endif
% if 'Node.js' in model.tech_stack:
- Node.js: Test for prototype pollution, SSRF, command injection
% endif
% if 'Django' in model.tech_stack:
- Django: Check for SSTI, SQL injection (ORM bypass), debug mode
% endif
% if 'Flask' in model.tech_stack:
- Flask: Test for SSTI (Jinja2), debug pin exposure, werkzeug console
% endif
% if 'ASP.NET' in model.tech_stack:
- ASP.NET: Check ViewState tampering, XXE, deserialization vulns
% endif
% else:
Technology stack not yet identified. Fingerprint during reconnaissance.
% endif

### Discovered Endpoints
% if model.endpoints:
Priority endpoints ranked by attack surface:
<%
    from operator import attrgetter
    sorted_endpoints = sorted(model.endpoints, key=lambda e: len(e.parameters) + (10 if e.requires_auth else 0), reverse=True)
%>
% for idx, endpoint in enumerate(sorted_endpoints[:15], 1):
${idx}. **${endpoint.method} ${endpoint.path}**
   - Parameters: ${len(endpoint.parameters)} (${'_'.join(p.name for p in endpoint.parameters[:3])}${', ...' if len(endpoint.parameters) > 3 else ''})
   - Auth Required: ${'YES' if endpoint.requires_auth else 'NO'}
   - Response Type: ${endpoint.response_type or 'Unknown'}
   % if endpoint.rate_limited:
   - Rate Limited: YES (use evasion techniques)
   % endif
   % if endpoint.waf_detected:
   - WAF Detected: YES (requires bypass payloads)
   % endif
% endfor
% if len(model.endpoints) > 15:

... and ${len(model.endpoints) - 15} more endpoints (use endpoint_discovery for full list)
% endif
% else:
No endpoints discovered yet. Start with crawling and endpoint enumeration.
% endif

### Identity Parameters (IDOR Attack Surface)
% if model.identity_parameters:
The following parameters control object access - **HIGH PRIORITY for IDOR testing**:

<%def name="format_identity_param(param)">
- **${param.name}** in ${param.endpoint_path}
  * Type: ${param.param_type} (${param.location})
  * Sample Values: ${', '.join(map(str, param.sample_values[:5]))}
  * Pattern: ${param.value_pattern or 'Sequential/Random'}
  * Predictability: ${'HIGH' if param.predictable else 'LOW'}
  % if param.referenced_object:
  * References: ${param.referenced_object} objects
  % endif
</%def>

% for param in model.identity_parameters[:10]:
${format_identity_param(param)}
% endfor

**IDOR Testing Strategy**:
1. Test horizontal privilege escalation (access other users' resources)
2. Test vertical privilege escalation (access admin/privileged resources)
3. Try parameter pollution (id=1&id=2) and array formats (id[]=1)
4. Test negative/large/special values (-1, 999999, 0, UUID variants)
5. Check for indirect object references (hash, UUID, encoded values)
% else:
No identity parameters identified yet. Look for: id, user_id, account_id, order_id, etc.
% endif

### Authentication Patterns
% if model.auth_patterns:
Authentication mechanisms detected:
% for pattern in model.auth_patterns:
- **${pattern.type}**: ${pattern.description}
  % if pattern.type == 'JWT':
  * Algorithm: ${pattern.algorithm or 'Unknown'}
  * Signing: ${pattern.signing or 'Unknown'}
  * **Test**: None algorithm, weak secret, key confusion, claim injection
  % elif pattern.type == 'Session':
  * Cookie Name: ${pattern.cookie_name or 'Unknown'}
  * **Test**: Session fixation, prediction, hijacking, cookie tampering
  % elif pattern.type == 'OAuth':
  * Provider: ${pattern.provider or 'Unknown'}
  * **Test**: redirect_uri bypass, token leakage, CSRF on callback
  % elif pattern.type == 'API Key':
  * Location: ${pattern.location or 'Header'}
  * **Test**: Key enumeration, rate limit bypass, privilege escalation
  % elif pattern.type == 'Basic Auth':
  * **Test**: Credential brute-force, default credentials, weak passwords
  % endif
% endfor
% else:
Authentication patterns not yet analyzed. Test authentication flows to identify mechanisms.
% endif

### Response Fingerprints
% if model.response_fingerprints:
Distinctive response patterns (useful for blind attack detection):

<%def name="format_fingerprint(fp)">
**${fp.scenario}**:
% if fp.status_codes:
- Status Codes: ${', '.join(map(str, fp.status_codes))}
% endif
% if fp.headers:
- Headers: ${', '.join(f'{k}: {v}' for k, v in list(fp.headers.items())[:3])}
% endif
% if fp.body_patterns:
- Body Patterns: ${', '.join(fp.body_patterns[:3])}
% endif
% if fp.timing:
- Response Time: ~${fp.timing}ms
% endif
</%def>

% for fp in model.response_fingerprints[:8]:
${format_fingerprint(fp)}

% endfor

**Detection Strategy**: Use these fingerprints for blind SQLi, SSRF, XXE timing/out-of-band attacks.
% else:
Response fingerprints not yet cataloged. Build baseline during reconnaissance.
% endif

### Business Logic Workflows
% if model.workflows:
Identified workflows (potential for logic flaws):

% for workflow in model.workflows:
**${workflow.name}**:
% if workflow.steps:
% for step_idx, step in enumerate(workflow.steps, 1):
  ${step_idx}. ${step.action} (${step.endpoint})
% endfor
% endif
  * **Test For**:
    - Step skipping (can you skip steps 1-2 and go to step 3?)
    - Race conditions (parallel execution of steps)
    - State tampering (modify intermediate state)
    - Replay attacks (reuse earlier steps)
    - Price/quantity manipulation
% endfor
% else:
No workflows mapped yet. Trace multi-step processes (signup, checkout, password reset).
% endif

### High-Value Attack Surfaces
% if model.high_value_targets:

**Prioritized Targets** (ranked by exploit potential):
% for idx, target in enumerate(model.high_value_targets[:10], 1):
${idx}. **${target.endpoint}**
   - Attack Vector: ${target.vector}
   - Severity Potential: ${target.severity}
   - Confidence: ${target.confidence}%
   - Rationale: ${target.rationale}
% endfor

Focus effort on these surfaces for maximum impact.
% else:
High-value targets not yet identified. Build application model first.
% endif

### Data Flow Analysis
% if model.data_flows:
Sensitive data flows detected:

% for flow in model.data_flows[:5]:
- **${flow.data_type}** data: ${flow.source} → ${flow.sink}
  * Encryption: ${'YES' if flow.encrypted else 'NO'}
  * Validation: ${'YES' if flow.validated else 'NO'}
  % if not flow.encrypted or not flow.validated:
  * **RISK**: ${'Unencrypted' if not flow.encrypted else ''} ${'Unvalidated' if not flow.validated else ''}
  % endif
% endfor
% endif

### Parameter Pollution Opportunities
% if model.parameter_relationships:

Cross-parameter correlations detected (test for pollution attacks):
% for rel in model.parameter_relationships[:5]:
- ${rel.param1} ↔ ${rel.param2}: ${rel.relationship_type}
  * **Test**: Send conflicting values, duplicate parameters, nested pollution
% endfor
% endif

---

**Action Items**:
1. Use this model to guide attack prioritization
2. Update model continuously as you discover new endpoints/parameters
3. Cross-reference findings with response fingerprints for validation
4. Focus on identity parameters and high-value targets first
5. Test authentication bypass before authenticated attacks

% endif
