<%doc>
Checkpoint Reminder Template

Used to remind agents of context and priorities when
continuing after a segment boundary or checkpoint.
</%doc>

# CHECKPOINT REMINDER

**Operation ID**: ${operation_id}
**Target**: ${target}
**Step**: ${current_step}/${max_steps}
**Budget**: ${budget_percent}% remaining

---

## CRITICAL: CONTEXT RECOVERY REQUIRED

Your context has been reset. You MUST recover your state:

1. **Execute immediately**:
   ```
   memory_list(memory_type="finding")
   memory_list(memory_type="context")
   memory_search(query="${target}")
   ```

2. **Review all stored findings**
3. **Resume from where you left off**

## CURRENT STATUS

% if findings:
### Known Findings (${len(findings)})
% for f in findings:
- ${format_finding(f)}
% endfor
% else:
No findings in current context. **Check memory immediately.**
% endif

% if credentials:
### Available Credentials
% for c in credentials:
- ${truncate(str(c), 60)}
% endfor
% endif

## OBJECTIVE REMINDER

${objective}

## PRIORITY ACTIONS

% if budget_percent > 70:
### HIGH BUDGET - Full Exploration
1. Continue systematic assessment
2. Explore all attack surfaces
3. Document thoroughly
% elif budget_percent > 30:
### MEDIUM BUDGET - Focus Mode
1. Prioritize high-impact findings
2. Verify and exploit confirmed vulns
3. Skip low-priority enumeration
% else:
### LOW BUDGET - Critical Only
1. Exploit existing findings NOW
2. Look for quick wins only
3. Prepare final report
% endif

## DO NOT:

- Repeat approaches that already failed
- Start over from scratch
- Ignore previous findings
- Waste time on low-value targets

---

**Resume assessment now. Start with memory recall.**
