## Attack Plan Status

% if not plan:
No attack plan generated yet. Create a strategic plan based on target reconnaissance.
% else:

### Current Phase: ${plan.current_phase}

<%
phase_progress = {
    'RECONNAISSANCE': 15,
    'MAPPING': 30,
    'VULNERABILITY_DISCOVERY': 60,
    'EXPLOITATION': 85,
    'POST_EXPLOITATION': 95,
    'REPORTING': 100
}
progress = phase_progress.get(plan.current_phase, 0)
%>

**Overall Progress**: ${progress}% | **Token Budget Used**: ${plan.tokens_used}/${plan.total_token_budget} (${int(plan.tokens_used / plan.total_token_budget * 100)}%)

% if plan.time_remaining:
**Time Remaining**: ${plan.time_remaining} | **Urgency**: ${'HIGH - Move fast!' if plan.ctf_mode else 'NORMAL'}
% endif

### Phase Objectives

% if plan.current_phase == 'RECONNAISSANCE':
**RECONNAISSANCE Phase**:
- [ ] Identify technology stack and frameworks
- [ ] Discover all accessible endpoints
- [ ] Map authentication mechanisms
- [ ] Enumerate subdomains and services
- [ ] Gather OSINT intelligence
- [ ] Build initial application model

**Next Phase**: MAPPING (once endpoints discovered)
% elif plan.current_phase == 'MAPPING':
**MAPPING Phase**:
- [ ] Catalog all parameters and their roles
- [ ] Identify identity parameters for IDOR testing
- [ ] Map business logic workflows
- [ ] Document API contracts and relationships
- [ ] Establish response fingerprints
- [ ] Detect WAF/security controls

**Next Phase**: VULNERABILITY_DISCOVERY
% elif plan.current_phase == 'VULNERABILITY_DISCOVERY':
**VULNERABILITY DISCOVERY Phase**:
- [ ] Test for injection vulnerabilities (SQLi, XSS, XXE, etc.)
- [ ] Enumerate IDOR opportunities
- [ ] Check authentication/authorization flaws
- [ ] Test for SSRF and RCE
- [ ] Scan for misconfigurations
- [ ] Identify logic flaws

**Next Phase**: EXPLOITATION (once vulns confirmed)
% elif plan.current_phase == 'EXPLOITATION':
**EXPLOITATION Phase**:
- [ ] Develop working exploits for confirmed vulns
- [ ] Chain vulnerabilities for higher impact
- [ ] Bypass WAF/security controls
- [ ] Escalate privileges
- [ ] Extract sensitive data
- [ ] Capture flags (if CTF)

**Next Phase**: POST_EXPLOITATION or REPORTING
% elif plan.current_phase == 'POST_EXPLOITATION':
**POST-EXPLOITATION Phase**:
- [ ] Maintain persistence
- [ ] Lateral movement
- [ ] Data exfiltration
- [ ] Privilege escalation
- [ ] Document full attack chain

**Next Phase**: REPORTING
% elif plan.current_phase == 'REPORTING':
**REPORTING Phase**:
- [ ] Document all findings
- [ ] Generate PoCs
- [ ] Write recommendations
- [ ] Calculate CVSS scores
- [ ] Prepare deliverables

**Status**: Wrapping up assessment
% endif

### Prioritized Attack Steps

% if plan.attack_steps:
**Next ${min(10, len(plan.attack_steps))} High-Priority Actions**:

<%
from operator import attrgetter
sorted_steps = sorted(plan.attack_steps, key=attrgetter('priority'), reverse=True)
%>

<%def name="format_step(step, idx)">
${idx}. **${step.action}** [Priority: ${step.priority}/10]
   % if step.target:
   - Target: ${step.target}
   % endif
   % if step.tool:
   - Recommended Tool: `${step.tool}`
   % endif
   % if step.expected_outcome:
   - Expected Outcome: ${step.expected_outcome}
   % endif
   % if step.time_estimate:
   - Time Estimate: ${step.time_estimate}
   % endif
   % if step.token_estimate:
   - Token Budget: ~${step.token_estimate} tokens
   % endif
   % if step.dependencies:
   - Dependencies: ${', '.join(step.dependencies)}
   % endif
   % if step.risk_level:
   - Risk Level: ${step.risk_level}
   % endif
   % if step.rationale:
   - Rationale: ${step.rationale}
   % endif
</%def>

% for idx, step in enumerate(sorted_steps[:10], 1):
${format_step(step, idx)}

% endfor

% if len(plan.attack_steps) > 10:
... and ${len(plan.attack_steps) - 10} more steps in queue

% endif

% if plan.ctf_mode:
**CTF OPTIMIZATION**: Execute steps 1-3 in parallel using sub-agents for speed.
% endif

% else:
No specific attack steps planned. Generate steps based on reconnaissance findings.
% endif

### Attack Chains to Explore

% if plan.attack_chains:
**Multi-Step Exploitation Paths**:

% for idx, chain in enumerate(plan.attack_chains[:5], 1):
**Chain ${idx}: ${chain.name}** (Impact: ${chain.impact}, Difficulty: ${chain.difficulty})

% if chain.steps:
% for step_idx, step in enumerate(chain.steps, 1):
   ${step_idx}. ${step.description}
      % if step.success_criteria:
      → Success if: ${step.success_criteria}
      % endif
% endfor
% endif

   **Potential Impact**: ${chain.impact_description}
   **Prerequisites**: ${', '.join(chain.prerequisites) if chain.prerequisites else 'None'}

% endfor

% if len(plan.attack_chains) > 5:
... and ${len(plan.attack_chains) - 5} more chains identified
% endif

**Strategy**: Prioritize chains with highest impact/difficulty ratio.
% else:
No attack chains identified yet. Look for opportunities to chain findings.
% endif

### Token Budget Allocation

<%
    recon_budget = int(plan.total_token_budget * 0.15)
    mapping_budget = int(plan.total_token_budget * 0.15)
    discovery_budget = int(plan.total_token_budget * 0.40)
    exploitation_budget = int(plan.total_token_budget * 0.25)
    reporting_budget = int(plan.total_token_budget * 0.05)
%>

**Recommended Budget by Phase**:
- Reconnaissance: ${recon_budget} tokens (15%)
- Mapping: ${mapping_budget} tokens (15%)
- Vulnerability Discovery: ${discovery_budget} tokens (40%)
- Exploitation: ${exploitation_budget} tokens (25%)
- Reporting: ${reporting_budget} tokens (5%)

% if plan.current_phase == 'RECONNAISSANCE':
**Current Phase Budget**: ${recon_budget} tokens available
% elif plan.current_phase == 'MAPPING':
**Current Phase Budget**: ${mapping_budget} tokens available
% elif plan.current_phase == 'VULNERABILITY_DISCOVERY':
**Current Phase Budget**: ${discovery_budget} tokens available
% elif plan.current_phase == 'EXPLOITATION':
**Current Phase Budget**: ${exploitation_budget} tokens available
% else:
**Current Phase Budget**: ${reporting_budget} tokens available
% endif

% if plan.tokens_used / plan.total_token_budget > 0.75:
**WARNING**: 75%+ of token budget consumed. Prioritize high-impact findings only.
% elif plan.tokens_used / plan.total_token_budget > 0.50:
**NOTICE**: 50%+ of token budget used. Begin prioritizing exploitation over discovery.
% endif

### Findings Summary

% if plan.findings:
**Confirmed Findings**: ${len(plan.findings)}

<%
    from collections import Counter
    severity_counts = Counter(f.severity for f in plan.findings)
%>

% if severity_counts:
- Critical: ${severity_counts.get('CRITICAL', 0)}
- High: ${severity_counts.get('HIGH', 0)}
- Medium: ${severity_counts.get('MEDIUM', 0)}
- Low: ${severity_counts.get('LOW', 0)}
- Info: ${severity_counts.get('INFO', 0)}
% endif

**Recent Findings** (last 5):
% for finding in plan.findings[-5:]:
- [${finding.severity}] ${finding.title} (${finding.vuln_type})
% endfor

% if plan.ctf_mode and not any(f.flag_captured for f in plan.findings):
**CTF STATUS**: No flag captured yet. Escalate exploitation efforts.
% elif plan.ctf_mode:
**CTF STATUS**: Flag captured! ${'Continue for additional flags' if len([f for f in plan.findings if f.flag_captured]) < plan.expected_flags else 'Mission complete'}
% endif

% else:
**Confirmed Findings**: 0

% if plan.current_phase in ['VULNERABILITY_DISCOVERY', 'EXPLOITATION']:
No findings yet in discovery/exploitation phase - this may indicate:
1. Insufficient testing coverage
2. Hardened target (good security posture)
3. Need for different attack vectors
4. WAF/IDS blocking attempts

**Recommendation**: Review attack steps and consider alternative approaches.
% endif
% endif

### Recommended Next Targets

% if plan.next_targets:
**High-Value Targets** (based on current intelligence):

% for idx, target in enumerate(plan.next_targets[:5], 1):
${idx}. **${target.endpoint or target.description}**
   - Attack Type: ${target.attack_type}
   - Expected Severity: ${target.expected_severity}
   - Estimated Effort: ${target.effort}
   - Success Probability: ${target.success_probability}%
   % if target.reasoning:
   - Reasoning: ${target.reasoning}
   % endif
% endfor
% else:
Next targets not yet identified. Analyze reconnaissance data to prioritize.
% endif

### Branch Points & Decision Tracking

% if plan.branch_points:
**Unexplored Branches** (paths to backtrack to):

% for idx, branch in enumerate(plan.branch_points[:5], 1):
${idx}. **${branch.description}** (Turn ${branch.turn_number})
   - Decision: ${branch.decision_made}
   - Alternatives: ${', '.join(branch.alternatives_not_taken)}
   % if branch.context:
   - Context: ${branch.context}
   % endif
% endfor

% if len(plan.branch_points) > 5:
... and ${len(plan.branch_points) - 5} more branches to explore
% endif

**Backtracking Strategy**: If current path fails, return to highest-priority unexplored branch.
% endif

### Constraints & Considerations

% if plan.scope_restrictions:
**Scope Restrictions**:
% for restriction in plan.scope_restrictions:
- ${restriction}
% endfor
% endif

% if plan.rate_limits:
**Rate Limits Detected**:
% for endpoint, limit in plan.rate_limits.items():
- ${endpoint}: ${limit.requests} requests per ${limit.window}
% endfor
**Mitigation**: Use delays, proxy rotation, or distributed scanning.
% endif

% if plan.waf_detected:
**WAF/IDS Active**: ${'YES - Use evasion techniques' if plan.waf_detected else 'NO'}
% if plan.waf_type:
- Type: ${plan.waf_type}
- Bypass Strategy: ${plan.waf_bypass_strategy or 'To be determined'}
% endif
% endif

% if plan.stealth_mode:
**Stealth Mode**: ENABLED - Minimize noise, avoid aggressive scanning
% endif

---

**Strategic Guidance**:
% if plan.ctf_mode:
1. **SPEED IS CRITICAL** - Parallel execution, aggressive techniques
2. Flag locations: ${', '.join(plan.known_flag_locations) if plan.known_flag_locations else 'Unknown - search common locations'}
3. Skip exhaustive testing - focus on quick wins
4. Use sub-agents for parallel reconnaissance and scanning
% else:
1. Follow phase progression systematically
2. Document everything for comprehensive reporting
3. Validate findings to minimize false positives
4. Prioritize by severity × exploitability
5. Respect scope and rate limits
% endif

% if plan.stuck_indicator:
**WARNING**: Progress stalled (${plan.turns_without_progress} turns without findings)
**Recommended Action**:
- Spawn sub-agent for fresh perspective
- Backtrack to unexplored branch
- Try alternative attack vector
- Review application model for missed opportunities
% endif

% endif
