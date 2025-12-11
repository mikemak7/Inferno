# Security Assessment Report Template

Generate a professional security assessment report with ONLY proven vulnerabilities.

<core_principle>
**ONLY report findings where you PROVED exploitation.**
Observable ≠ Exploitable. Pattern-matching ≠ Vulnerability.
If you can't show actual data extracted, access gained, or code executed - it's not a finding.
</core_principle>

<report_structure>
## Executive Summary
- Assessment scope and target
- **PROVEN** findings only (with actual exploitation evidence)
- Honest assessment: if nothing exploitable was found, say so

## Scope
- Target: {{ target }}
- Objective: {{ objective }}
- What was tested and methodology used

## Proven Vulnerabilities

**ONLY include findings where you demonstrated actual impact.**

### [SEVERITY] Finding Title

| Field | Value |
|-------|-------|
| Severity | Based on PROVEN impact |
| Affected Asset | Specific URL/endpoint |
| Exploitation | What you actually did |
| Impact | What you actually achieved |

**What I exploited**: Specific technical details

**Proof of Exploitation**:
```
[Exact command/request that worked]
```

**Response showing success**:
```
[Actual response data proving exploitation]
```

**Demonstrated Impact**: What concrete harm was proven (data accessed, records extracted, etc.)

**Remediation**: How to fix

---

## Observations (Not Vulnerabilities)

Things noticed that could NOT be proven exploitable:
- Item observed, why it might be interesting, why exploitation wasn't proven
- These are NOT findings, just observations for potential future testing

## What Was Tested

Summary of attack vectors attempted:
- What worked
- What didn't work (and why - WAF, no vuln, etc.)
- Areas that need more testing

</report_structure>

<quality_standards>
## MANDATORY for each finding:
1. **PROOF**: Actual command/request that achieved exploitation
2. **EVIDENCE**: Real response data showing it worked
3. **IMPACT**: Concrete harm demonstrated, not theoretical

## DO NOT include:
- "Potential" or "possible" vulnerabilities
- Findings based on scanner output without manual verification
- Missing headers, CORS configs, etc. without proven exploitation
- Admin panels, login pages, endpoints that exist but weren't exploited
- Anything marked "could be" or "might allow"

## Severity ONLY based on PROVEN impact:
- Critical: Actually extracted sensitive data, executed code, got admin access
- High: Actually accessed unauthorized data, escalated privileges
- Medium: Actually exploited with limited impact
- Low: Minor proven impact
- **If not proven, it's not a vulnerability - put it in Observations**
</quality_standards>

<honest_reporting>
If the assessment found no exploitable vulnerabilities, the report should say:
"Assessment completed. No exploitable vulnerabilities were identified during testing.
The following attack vectors were tested: [list]. While some observations were made,
none could be confirmed as exploitable security issues."

This is a VALID and VALUABLE outcome - not every target has vulnerabilities.
</honest_reporting>
