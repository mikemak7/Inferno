"""
Unit tests for technology context modules.

Tests the filtering and severity adjustment logic for blockchain,
API, and generic web contexts.
"""

import pytest

from inferno.quality.candidate import FindingCandidate
from inferno.quality.contexts import APIContext, BlockchainContext, GenericWebContext
from inferno.reporting.models import Severity


class TestBlockchainContext:
    """Test cases for BlockchainContext."""

    def test_wallet_address_filtered(self):
        """Test that wallet addresses are filtered as public-by-design."""
        context = BlockchainContext()
        candidate = FindingCandidate(
            title="Wallet Address Disclosure",
            description="Found exposed wallet addresses",
            initial_severity=Severity.MEDIUM,
            evidence="Address: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",  # 40 hex chars
            affected_asset="https://example.com/api/wallet",
            vuln_type="information_disclosure",
        )

        is_public, reason = context.is_public_by_design(candidate)
        assert is_public is True
        assert "public by design" in reason.lower()

    def test_transaction_hash_filtered(self):
        """Test that transaction hashes are filtered."""
        context = BlockchainContext()
        candidate = FindingCandidate(
            title="Transaction Hash Disclosure",
            description="Found transaction hashes",
            initial_severity=Severity.MEDIUM,
            evidence="TX: 0x" + "a" * 64,
            affected_asset="https://example.com/tx",
            vuln_type="information_disclosure",
        )

        is_public, reason = context.is_public_by_design(candidate)
        assert is_public is True
        assert "transaction" in reason.lower()

    def test_admin_rpc_methods_flagged(self):
        """Test that admin RPC methods are flagged as HIGH severity."""
        context = BlockchainContext()
        candidate = FindingCandidate(
            title="Admin RPC Exposed",
            description="Admin methods accessible",
            initial_severity=Severity.MEDIUM,
            evidence="admin_nodeInfo, debug_traceTransaction",
            affected_asset="https://example.com:8545",
            vuln_type="unauthorized_access",
        )

        suggested = context.suggest_severity(candidate)
        assert suggested == Severity.HIGH

    def test_public_rpc_methods_downgraded(self):
        """Test that public RPC methods are downgraded to INFO."""
        context = BlockchainContext()
        candidate = FindingCandidate(
            title="RPC Endpoint Exposed",
            description="RPC accessible",
            initial_severity=Severity.MEDIUM,
            evidence="eth_blockNumber, eth_getBalance available",
            affected_asset="https://example.com:8545",
            vuln_type="information_disclosure",
        )

        is_public, _ = context.is_public_by_design(candidate)
        assert is_public is False  # Not public by design, just low severity

        suggested = context.suggest_severity(candidate)
        assert suggested == Severity.INFO

    def test_applies_to_blockchain_findings(self):
        """Test that context correctly identifies blockchain findings."""
        context = BlockchainContext()

        blockchain_candidate = FindingCandidate(
            title="Ethereum Wallet",
            description="Found wallet",
            initial_severity=Severity.MEDIUM,
            evidence="0x" + "a" * 40,
            affected_asset="https://example.com",
            vuln_type="info",
        )

        non_blockchain_candidate = FindingCandidate(
            title="SQL Injection",
            description="SQL vuln",
            initial_severity=Severity.HIGH,
            evidence="' OR '1'='1",
            affected_asset="https://example.com",
            vuln_type="sqli",
        )

        assert context.applies_to(blockchain_candidate) is True
        assert context.applies_to(non_blockchain_candidate) is False


class TestAPIContext:
    """Test cases for APIContext."""

    def test_swagger_docs_filtered_when_public(self):
        """Test that public Swagger docs are filtered."""
        context = APIContext()
        candidate = FindingCandidate(
            title="Swagger Documentation Exposed",
            description="Swagger UI accessible",
            initial_severity=Severity.MEDIUM,
            evidence="swagger.json at /api-docs",
            affected_asset="https://example.com/api-docs",
            vuln_type="information_disclosure",
        )

        is_public, reason = context.is_public_by_design(candidate)
        assert is_public is True
        assert "intentionally public" in reason.lower()

    def test_internal_endpoints_not_filtered(self):
        """Test that internal endpoints in API docs are NOT filtered."""
        context = APIContext()
        candidate = FindingCandidate(
            title="Internal Endpoints Exposed",
            description="Admin endpoints in docs",
            initial_severity=Severity.MEDIUM,
            evidence="/api/admin/users, /api/internal/debug in swagger.json",
            affected_asset="https://example.com/api-docs",
            vuln_type="information_disclosure",
        )

        is_public, _ = context.is_public_by_design(candidate)
        assert is_public is False

    def test_internal_endpoints_upgraded_severity(self):
        """Test that internal endpoints get upgraded severity."""
        context = APIContext()
        candidate = FindingCandidate(
            title="API Docs with Admin Endpoints",
            description="Admin routes exposed",
            initial_severity=Severity.MEDIUM,
            evidence="/api/admin/delete-user in swagger.json",
            affected_asset="https://example.com/api-docs",
            vuln_type="information_disclosure",
        )

        suggested = context.suggest_severity(candidate)
        assert suggested == Severity.HIGH

    def test_graphql_introspection_downgraded(self):
        """Test that GraphQL introspection without sensitive data is downgraded."""
        context = APIContext()
        candidate = FindingCandidate(
            title="GraphQL Introspection Enabled",
            description="Introspection queries work",
            initial_severity=Severity.HIGH,
            evidence="__schema query successful",
            affected_asset="https://example.com/graphql",
            vuln_type="information_disclosure",
        )

        suggested = context.suggest_severity(candidate)
        assert suggested == Severity.LOW


class TestGenericWebContext:
    """Test cases for GenericWebContext."""

    def test_version_disclosure_downgraded(self):
        """Test that version disclosure is downgraded to INFO."""
        context = GenericWebContext()
        candidate = FindingCandidate(
            title="Version Disclosure",
            description="Server version in headers",
            initial_severity=Severity.MEDIUM,
            evidence="Server: Apache/2.4.41",
            affected_asset="https://example.com",
            vuln_type="information_disclosure",
        )

        suggested = context.suggest_severity(candidate)
        assert suggested == Severity.INFO

    def test_stack_trace_without_credentials_low(self):
        """Test that stack traces without credentials are LOW."""
        context = GenericWebContext()
        candidate = FindingCandidate(
            title="Stack Trace",
            description="Error stack trace",
            initial_severity=Severity.MEDIUM,
            evidence="Traceback:\n  File 'app.py', line 42",
            affected_asset="https://example.com/error",
            vuln_type="information_disclosure",
        )

        suggested = context.suggest_severity(candidate)
        assert suggested == Severity.LOW

    def test_stack_trace_with_credentials_high(self):
        """Test that stack traces with credentials are HIGH."""
        context = GenericWebContext()
        candidate = FindingCandidate(
            title="Stack Trace",
            description="Error with credentials",
            initial_severity=Severity.LOW,
            evidence="mysql://admin:P@ssw0rd@localhost",
            affected_asset="https://example.com/error",
            vuln_type="information_disclosure",
        )

        suggested = context.suggest_severity(candidate)
        assert suggested == Severity.HIGH

    def test_debug_mode_without_secrets_low(self):
        """Test that debug mode without secrets is LOW."""
        context = GenericWebContext()
        candidate = FindingCandidate(
            title="Debug Mode",
            description="Debug enabled",
            initial_severity=Severity.MEDIUM,
            evidence="DEBUG=true",
            affected_asset="https://example.com",
            vuln_type="misconfiguration",
        )

        suggested = context.suggest_severity(candidate)
        assert suggested == Severity.LOW

    def test_debug_mode_with_database_info_high(self):
        """Test that debug mode with database info is HIGH."""
        context = GenericWebContext()
        candidate = FindingCandidate(
            title="Debug Mode",
            description="Debug with DB info",
            initial_severity=Severity.MEDIUM,
            evidence="DEBUG=true, DATABASE=mongodb://localhost:27017/prod",
            affected_asset="https://example.com",
            vuln_type="misconfiguration",
        )

        suggested = context.suggest_severity(candidate)
        assert suggested == Severity.HIGH

    def test_applies_to_all_findings(self):
        """Test that generic context applies to all findings."""
        context = GenericWebContext()

        candidate = FindingCandidate(
            title="Any Finding",
            description="Any description",
            initial_severity=Severity.MEDIUM,
            evidence="Any evidence",
            affected_asset="https://example.com",
            vuln_type="any",
        )

        assert context.applies_to(candidate) is True


class TestContextIntegration:
    """Test integration between multiple contexts."""

    def test_blockchain_takes_precedence_over_generic(self):
        """Test that blockchain context takes precedence."""
        blockchain_ctx = BlockchainContext()
        generic_ctx = GenericWebContext()

        candidate = FindingCandidate(
            title="Transaction Hash Disclosure",
            description="TX hash exposed",
            initial_severity=Severity.MEDIUM,
            evidence="0x" + "a" * 64,
            affected_asset="https://example.com/tx",
            vuln_type="information_disclosure",
        )

        # Both should apply
        assert blockchain_ctx.applies_to(candidate) is True
        assert generic_ctx.applies_to(candidate) is True

        # But blockchain should filter it
        blockchain_adj = blockchain_ctx.evaluate(candidate)
        assert blockchain_adj is not None
        assert blockchain_adj.is_by_design is True

    def test_context_adjustments_accumulate(self):
        """Test that context adjustments accumulate on candidate."""
        context = BlockchainContext()
        candidate = FindingCandidate(
            title="Wallet Disclosure",
            description="Wallet exposed",
            initial_severity=Severity.MEDIUM,
            evidence="0x" + "a" * 40,
            affected_asset="https://example.com",
            vuln_type="info",
        )

        adjustments = context.get_context_adjustments(candidate)
        assert len(adjustments) > 0

        # Apply adjustments
        for adj in adjustments:
            candidate.add_context_adjustment(adj)

        assert len(candidate.context_adjustments) > 0
        assert candidate.is_public_by_design is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
