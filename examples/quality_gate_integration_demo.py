#!/usr/bin/env python3
"""
Demonstration of Quality Gate Pipeline integration with Inferno-AI reporting system.

This example shows how to:
1. Create finding candidates
2. Process them through quality gates
3. Add approved findings to reports
4. Handle rejected findings
"""

import asyncio
from datetime import datetime, timezone

from inferno.quality import (
    EscalationGate,
    FindingCandidate,
    PreReportChecklistGate,
    QualityConfig,
    QualityGatePipeline,
    SeverityGate,
    SoWhatGate,
    TechnologyContextGate,
)
from inferno.reporting.generator import ReportGenerator
from inferno.reporting.models import Severity


async def demo_quality_gate_integration():
    """Demonstrate the quality gate pipeline integration."""
    print("=" * 70)
    print("Quality Gate Pipeline Integration Demo")
    print("=" * 70)

    # Step 1: Create quality gate pipeline
    print("\n[Step 1] Creating quality gate pipeline...")
    config = QualityConfig(
        min_quality_score=0.7,
        min_escalation_attempts=2,
        require_production_confirmation=True,
    )

    pipeline = QualityGatePipeline(config=config)

    # Register gates in order
    gates = [
        SoWhatGate(config=config),
        TechnologyContextGate(config=config),
        EscalationGate(config=config),
        SeverityGate(config=config),
        PreReportChecklistGate(config=config),
    ]
    pipeline.register_gates(gates)

    print(f"  ✓ Registered {pipeline.gate_count} quality gates")
    print(f"  ✓ Blocking gates: {pipeline.blocking_gate_count}")
    print(f"  ✓ Gate names: {', '.join(pipeline.gate_names)}")

    # Step 2: Create report generator with quality pipeline
    print("\n[Step 2] Creating report generator with quality pipeline...")
    generator = ReportGenerator(quality_pipeline=pipeline)
    report = generator.create_report(
        operation_id="demo_001",
        target="https://example.com",
        objective="Bug bounty assessment",
        scope="example.com and subdomains",
    )
    print(f"  ✓ Report created: {report.metadata.operation_id}")

    # Step 3: Create finding candidates
    print("\n[Step 3] Creating finding candidates...")

    # Good finding - should pass all gates
    good_candidate = FindingCandidate(
        title="SQL Injection in User Search",
        description="SQL injection allows database access and data exfiltration",
        initial_severity=Severity.HIGH,
        affected_asset="https://example.com/search",
        evidence="Payload: ' OR 1=1-- returned all users",
        vuln_type="sqli",
        attacker_action="Extract user database including passwords",
        concrete_impact="10,000 user records exposed including emails and hashed passwords",
        exploitability_proof="curl 'https://example.com/search?q=%27+OR+1=1--' returned full user table",
        is_production=True,
        impact_demonstrated=True,
    )

    # Add escalation attempts
    from inferno.quality import EscalationAttempt, EscalationSuccess

    good_candidate.add_escalation_attempt(
        EscalationAttempt(
            method="privilege_escalation",
            description="Attempted to access admin panel",
            result="Success",
            evidence="Accessed /admin with extracted credentials",
        )
    )
    good_candidate.add_escalation_attempt(
        EscalationAttempt(
            method="data_exfiltration",
            description="Extracted user database",
            result="Success",
            evidence="Downloaded 10,000 user records",
        )
    )
    good_candidate.add_escalation_success(
        EscalationSuccess(
            from_finding="SQL Injection",
            to_finding="Full Database Access",
            method="Union-based injection",
            severity_increase="HIGH -> CRITICAL",
            impact_description="Complete database compromise",
        )
    )

    print(f"  ✓ Created good candidate: {good_candidate.title}")

    # Bad finding - should fail gates
    bad_candidate = FindingCandidate(
        title="Version Disclosure in HTTP Header",
        description="Server version might be disclosed",
        initial_severity=Severity.MEDIUM,
        affected_asset="https://example.com",
        evidence="Server: nginx/1.18.0",
        vuln_type="information_disclosure",
        attacker_action="Could potentially use version info",
        concrete_impact="May help in reconnaissance",
        exploitability_proof="",  # No real proof
        is_production=False,
        impact_demonstrated=False,
        has_theoretical_language=True,
    )

    print(f"  ✓ Created bad candidate: {bad_candidate.title}")

    # Step 4: Process candidates through quality gates
    print("\n[Step 4] Processing candidates through quality gates...")

    # Process good candidate
    print(f"\n  Processing: {good_candidate.title}")
    approved_good = await generator.add_finding_candidate(
        good_candidate, "https://example.com", report
    )
    if approved_good:
        print(f"    ✓ APPROVED (Quality Score: {good_candidate.quality_score:.2f})")
        print(f"    ✓ Gates passed: {', '.join(good_candidate.gates_passed)}")
        print(f"    ✓ Escalations: {good_candidate.escalation_count}")
    else:
        print(f"    ✗ REJECTED")
        for reason in good_candidate.rejection_reasons:
            print(f"      - {reason}")

    # Process bad candidate
    print(f"\n  Processing: {bad_candidate.title}")
    approved_bad = await generator.add_finding_candidate(
        bad_candidate, "https://example.com", report
    )
    if approved_bad:
        print(f"    ✓ APPROVED (Quality Score: {bad_candidate.quality_score:.2f})")
    else:
        print(f"    ✗ REJECTED (Quality Score: {bad_candidate.quality_score:.2f})")
        print(f"    ✗ Gates failed: {', '.join(bad_candidate.gates_failed)}")
        for reason in bad_candidate.rejection_reasons[:3]:  # First 3 reasons
            print(f"      - {reason}")

    # Step 5: Review results
    print("\n[Step 5] Review results...")
    print(f"\n  Report Statistics:")
    print(f"    Total findings in report: {report.total_findings}")
    print(f"    Critical: {report.critical_count}")
    print(f"    High: {report.high_count}")
    print(f"    Medium: {report.medium_count}")
    print(f"    Low: {report.low_count}")

    rejected = generator.get_rejected_findings()
    print(f"\n  Rejected Findings: {len(rejected)}")
    for title, reason in rejected:
        print(f"    - {title}")
        print(f"      Reason: {reason[:80]}...")

    # Step 6: Display approved finding details
    if report.findings:
        print("\n[Step 6] Approved Finding Details...")
        for finding in report.findings:
            print(f"\n  Title: {finding.title}")
            print(f"  Severity: {finding.severity.value.upper()}")
            print(f"  Quality Score: {finding.quality_score:.2f}")
            print(f"  Gates Passed: {', '.join(finding.gates_passed)}")
            print(f"  Escalation Summary: {finding.escalation_summary[:80]}...")
            print(f"  Technology Context: {finding.technology_context or 'N/A'}")

    print("\n" + "=" * 70)
    print("Demo completed successfully!")
    print("=" * 70)


async def demo_validation_agent_integration():
    """Demonstrate ValidationAgent with quality gates."""
    print("\n\n" + "=" * 70)
    print("ValidationAgent + Quality Gates Integration Demo")
    print("=" * 70)

    print("\nThis demo shows how ValidationAgent can integrate with quality gates")
    print("to provide both technical validation AND bug bounty quality checks.")

    print("\n[Scenario]")
    print("  1. ValidationAgent validates the vulnerability technically")
    print("  2. If validation passes, quality gates check bug bounty standards")
    print("  3. Only findings that pass BOTH are approved for reporting")

    print("\n[Integration Points]")
    print("  - ValidationAgent.validate_with_quality_gates() method")
    print("  - Returns: (ValidatedFinding, quality_approved)")
    print("  - Can be used in swarm/validation_agent.py")

    print("\n[Benefits]")
    print("  ✓ Double validation: technical + quality")
    print("  ✓ Reduces false positives from both angles")
    print("  ✓ Ensures Bug Bounty program standards")
    print("  ✓ Provides detailed rejection reasons")

    print("\n" + "=" * 70)


def main():
    """Run all demos."""
    print("\nInferno-AI Quality Gate Integration Examples\n")

    # Run async demos
    asyncio.run(demo_quality_gate_integration())
    asyncio.run(demo_validation_agent_integration())

    print("\n✓ All demos completed!")
    print("\nNext Steps:")
    print("  1. Review src/inferno/reporting/generator.py for ReportGenerator updates")
    print("  2. Review src/inferno/swarm/validation_agent.py for ValidationAgent updates")
    print("  3. Review src/inferno/reporting/models.py for Finding quality metadata")
    print("  4. Review src/inferno/prompts/engine.py for behavior integration")


if __name__ == "__main__":
    main()
