#!/usr/bin/env python3
"""
Demonstration of Technology Context modules for Inferno-AI Quality Gate system.

This script shows how the technology contexts filter false positives and adjust
severity ratings based on technology-specific patterns.
"""

from inferno.quality.candidate import FindingCandidate
from inferno.quality.contexts import APIContext, BlockchainContext, GenericWebContext
from inferno.reporting.models import Severity


def demo_blockchain_context():
    """Demonstrate blockchain context filtering."""
    print("\n=== Blockchain Context Demo ===")

    context = BlockchainContext()

    # Example 1: Wallet address disclosure (should be filtered)
    candidate1 = FindingCandidate(
        title="Wallet Address Disclosure",
        description="Found exposed wallet addresses in API response",
        initial_severity=Severity.MEDIUM,
        evidence="Address: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
        affected_asset="https://example.com/api/wallet",
        vuln_type="information_disclosure",
    )

    adjustment1 = context.evaluate(candidate1)
    if adjustment1:
        print(f"Finding 1: {candidate1.title}")
        print(f"  Original Severity: {adjustment1.original_severity.value}")
        print(f"  Adjusted Severity: {adjustment1.adjusted_severity.value}")
        print(f"  Public by Design: {adjustment1.is_by_design}")
        print(f"  Rationale: {adjustment1.rationale}")

    # Example 2: Admin RPC method exposed (should remain HIGH)
    candidate2 = FindingCandidate(
        title="Admin RPC Method Exposed",
        description="Admin RPC methods accessible without authentication",
        initial_severity=Severity.MEDIUM,
        evidence="admin_nodeInfo, debug_traceTransaction accessible",
        affected_asset="https://example.com:8545",
        vuln_type="unauthorized_access",
    )

    adjustment2 = context.evaluate(candidate2)
    if adjustment2:
        print(f"\nFinding 2: {candidate2.title}")
        print(f"  Original Severity: {adjustment2.original_severity.value}")
        print(f"  Adjusted Severity: {adjustment2.adjusted_severity.value}")
        print(f"  Public by Design: {adjustment2.is_by_design}")
        print(f"  Rationale: {adjustment2.rationale}")


def demo_api_context():
    """Demonstrate API context filtering."""
    print("\n\n=== API Context Demo ===")

    context = APIContext()

    # Example 1: Public API documentation (should be filtered)
    candidate1 = FindingCandidate(
        title="Swagger Documentation Exposed",
        description="Swagger UI publicly accessible",
        initial_severity=Severity.MEDIUM,
        evidence="swagger.json found at /api-docs",
        affected_asset="https://example.com/api-docs",
        vuln_type="information_disclosure",
    )

    adjustment1 = context.evaluate(candidate1)
    if adjustment1:
        print(f"Finding 1: {candidate1.title}")
        print(f"  Original Severity: {adjustment1.original_severity.value}")
        print(f"  Adjusted Severity: {adjustment1.adjusted_severity.value}")
        print(f"  Public by Design: {adjustment1.is_by_design}")
        print(f"  Rationale: {adjustment1.rationale}")

    # Example 2: Internal endpoints in API docs (should remain HIGH)
    candidate2 = FindingCandidate(
        title="Internal API Endpoints Exposed",
        description="Swagger documentation reveals internal admin endpoints",
        initial_severity=Severity.MEDIUM,
        evidence="Endpoints: /api/admin/users, /api/internal/debug",
        affected_asset="https://example.com/api-docs",
        vuln_type="information_disclosure",
    )

    adjustment2 = context.evaluate(candidate2)
    if adjustment2:
        print(f"\nFinding 2: {candidate2.title}")
        print(f"  Original Severity: {adjustment2.original_severity.value}")
        print(f"  Adjusted Severity: {adjustment2.adjusted_severity.value}")
        print(f"  Public by Design: {adjustment2.is_by_design}")
        print(f"  Rationale: {adjustment2.rationale}")


def demo_generic_web_context():
    """Demonstrate generic web context severity adjustments."""
    print("\n\n=== Generic Web Context Demo ===")

    context = GenericWebContext()

    # Example 1: Version disclosure (should be INFO)
    candidate1 = FindingCandidate(
        title="Version Disclosure",
        description="Server version disclosed in headers",
        initial_severity=Severity.MEDIUM,
        evidence="Server: Apache/2.4.41 (Ubuntu)",
        affected_asset="https://example.com",
        vuln_type="information_disclosure",
    )

    adjustment1 = context.evaluate(candidate1)
    if adjustment1:
        print(f"Finding 1: {candidate1.title}")
        print(f"  Original Severity: {adjustment1.original_severity.value}")
        print(f"  Adjusted Severity: {adjustment1.adjusted_severity.value}")
        print(f"  Rationale: {adjustment1.rationale}")

    # Example 2: Stack trace with credentials (should be HIGH)
    candidate2 = FindingCandidate(
        title="Stack Trace Disclosure",
        description="Application stack trace exposed",
        initial_severity=Severity.LOW,
        evidence="""
        Traceback (most recent call last):
          File "app.py", line 42
        Database connection: mysql://admin:P@ssw0rd123@localhost/prod
        """,
        affected_asset="https://example.com/error",
        vuln_type="information_disclosure",
    )

    adjustment2 = context.evaluate(candidate2)
    if adjustment2:
        print(f"\nFinding 2: {candidate2.title}")
        print(f"  Original Severity: {adjustment2.original_severity.value}")
        print(f"  Adjusted Severity: {adjustment2.adjusted_severity.value}")
        print(f"  Rationale: {adjustment2.rationale}")

    # Example 3: Debug mode without secrets (should be LOW)
    candidate3 = FindingCandidate(
        title="Debug Mode Enabled",
        description="Application running in debug mode",
        initial_severity=Severity.MEDIUM,
        evidence="DEBUG=true in response headers",
        affected_asset="https://example.com",
        vuln_type="misconfiguration",
    )

    adjustment3 = context.evaluate(candidate3)
    if adjustment3:
        print(f"\nFinding 3: {candidate3.title}")
        print(f"  Original Severity: {adjustment3.original_severity.value}")
        print(f"  Adjusted Severity: {adjustment3.adjusted_severity.value}")
        print(f"  Rationale: {adjustment3.rationale}")


def demo_context_detection():
    """Demonstrate automatic context detection."""
    print("\n\n=== Context Detection Demo ===")

    contexts = [
        BlockchainContext(),
        APIContext(),
        GenericWebContext(),
    ]

    test_finding = FindingCandidate(
        title="Transaction Hash Disclosure",
        description="Blockchain transaction hashes exposed",
        initial_severity=Severity.MEDIUM,
        evidence="TX: 0x" + "a" * 64,
        affected_asset="https://example.com/tx",
        vuln_type="information_disclosure",
    )

    print(f"Finding: {test_finding.title}")
    print(f"Testing which contexts apply...\n")

    for context in contexts:
        if context.applies_to(test_finding):
            print(f"  ✓ {context.name} applies")
            adjustment = context.evaluate(test_finding)
            if adjustment:
                print(f"    - Would adjust to: {adjustment.adjusted_severity.value}")
                print(f"    - Reason: {adjustment.rationale[:60]}...")
        else:
            print(f"  ✗ {context.name} does not apply")


if __name__ == "__main__":
    print("Technology Context Modules for Inferno-AI Quality Gate System")
    print("=" * 70)

    demo_blockchain_context()
    demo_api_context()
    demo_generic_web_context()
    demo_context_detection()

    print("\n" + "=" * 70)
    print("Demo completed successfully!")
