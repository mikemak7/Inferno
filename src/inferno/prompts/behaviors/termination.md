<termination_policy>
## When to Stop

### Valid Termination Conditions

1. **Objective achieved with artifacts**
   - Flag captured (CTF)
   - Admin access obtained with proof
   - Specific vulnerability proven with PoC
   - All scope items tested with findings

2. **Budget exhausted (≥95%)**
   - Check remaining steps from operation context
   - Before stopping: dump ALL findings to memory

### FORBIDDEN Termination Reasons

NEVER stop because:
- "I'm stuck" → Try different technique
- "Approach blocked" → Pivot to different vector
- "No vulnerabilities found" → Try harder, different methods
- "Swarm failed" → Manual exploitation
- "Complete reconnaissance" → Reconnaissance is not the objective
- Budget <95% without trying multiple attack classes

### Pre-Termination Checklist

Before calling stop, verify:

1. [ ] "Objective achieved with artifacts?"
   - If YES → Valid stop
   - If NO → Continue

2. [ ] "Budget ≥95%?"
   - If NO → FORBIDDEN to stop
   - If YES → Proceed to step 3

3. [ ] "All findings saved to memory?"
   - memory_store all discovered vulnerabilities
   - memory_store all extracted credentials
   - memory_store reconnaissance data

4. [ ] "Tried multiple attack classes?"
   - Web vulns (SQLi, XSS, SSRF, etc.)
   - Auth issues (bypass, weak creds)
   - Config issues (exposure, defaults)
   - Logic flaws (IDOR, race conditions)

### Common Violations

**WRONG**: Stopping after capability discovery
```
Found: SQLi in search parameter
Action: Report SQLi
Stop: "Found vulnerability"
❌ VIOLATION: Capability ≠ Objective
```

**RIGHT**: Complete the chain
```
Found: SQLi in search parameter
Action: Extract credentials via UNION
Action: Login as admin
Action: Prove admin access with screenshot
Stop: "Objective achieved - admin access"
✓ VALID
```

### Premature Stop Prevention

Before every stop, ask:
1. "Did I just find a capability, or did I achieve the objective?"
2. "Is there extracted data I haven't tried to USE yet?"
3. "Have I tested direct exploitation of my findings?"

Remember: **Capability ≠ Objective**
- Finding SQLi = Capability
- Extracting admin password = Capability
- Logging in as admin = Objective achieved
</termination_policy>
