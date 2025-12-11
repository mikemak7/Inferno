# Quality Gate Integration - Quick Start

## 30-Second Overview

The quality gate pipeline validates findings before they go into reports. It's **optional** and **backward compatible**.

## Quick Examples

### Without Quality Gates (Still Works)
```python
from inferno.reporting.generator import ReportGenerator

generator = ReportGenerator()
report = generator.create_report(...)
report.add_finding(finding)  # Works as before
```

### With Quality Gates (New Way)
```python
from inferno.quality import QualityGatePipeline, QualityConfig
from inferno.reporting.generator import ReportGenerator

# Setup (once)
config = QualityConfig(min_quality_score=0.7)
pipeline = QualityGatePipeline(config=config)

# Use with generator
generator = ReportGenerator(quality_pipeline=pipeline)
report = generator.create_report(...)

# Add findings through quality gates
from inferno.quality import FindingCandidate

candidate = FindingCandidate(
    title="SQL Injection",
    description="SQL injection in search",
    initial_severity=Severity.HIGH,
    affected_asset="https://example.com/search",
    evidence="Payload: ' OR 1=1--",
    vuln_type="sqli",
    attacker_action="Extract database",
    concrete_impact="10,000 user records exposed",
    exploitability_proof="curl command worked",
)

# Process through gates
approved = await generator.add_finding_candidate(
    candidate,
    "https://example.com",
    report
)

if approved:
    print(f"Quality Score: {candidate.quality_score}")
else:
    print(f"Rejected: {candidate.rejection_reasons}")
```

## What Gets Added to Findings

```python
# New fields on Finding objects
finding.quality_score          # 0.0-1.0
finding.gates_passed           # ["so_what_gate", "escalation_gate", ...]
finding.escalation_summary     # "Escalation attempts: 3..."
finding.technology_context     # "GenericWebContext"
```

## Modified Files Summary

| File | Change | Breaking? |
|------|--------|-----------|
| `reporting/models.py` | Added 4 quality fields to Finding | ❌ No (has defaults) |
| `reporting/generator.py` | Added quality_pipeline param + new methods | ❌ No (optional) |
| `swarm/validation_agent.py` | Added quality_pipeline param + new method | ❌ No (optional) |
| `prompts/engine.py` | Added 4 behavior files to prompt | ❌ No (just more guidance) |

## Run the Demo

```bash
python3 examples/quality_gate_integration_demo.py
```

Expected:
- Good finding (SQL Injection) → ✅ APPROVED (score: 1.0)
- Bad finding (Version Disclosure) → ❌ REJECTED (so_what_gate failed)

## When to Use

**Use quality gates when:**
- Bug bounty submissions (avoid informational noise)
- Professional pentests (ensure high-quality findings)
- You want severity auto-adjustment based on escalation

**Skip quality gates when:**
- Quick CTF challenges
- Internal testing where all findings matter
- Training/learning scenarios

## Migration Path

1. **Phase 1** (Now): Code is integrated, disabled by default
2. **Phase 2** (Optional): Enable for specific operations via config
3. **Phase 3** (Optional): Make default for bug_bounty mode

## Key Benefits

- ✅ Filters low-quality findings automatically
- ✅ Tracks escalation attempts and successes
- ✅ Adjusts severity based on proven impact
- ✅ Provides detailed rejection reasons
- ✅ Zero changes to existing code needed

## Full Documentation

See `QUALITY_GATE_INTEGRATION.md` for complete details.
