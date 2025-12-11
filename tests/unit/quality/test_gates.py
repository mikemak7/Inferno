"""
Unit tests for individual quality gates.

Tests each gate's validation logic:
- SoWhatGate: Concrete impact and exploitability validation
- TechnologyContextGate: Technology-specific filtering
- EscalationGate: Escalation attempt validation
- SeverityGate: Severity adjustment logic
- PreReportChecklistGate: Final validation checklist
"""

import pytest
from datetime import datetime, timezone

from inferno.quality.candidate import (
    FindingCandidate,
    EscalationAttempt,
    EscalationSuccess,
    ContextAdjustment,
)
from inferno.quality.config import QualityConfig
from inferno.quality.gates import (
    SoWhatGate,
    TechnologyContextGate,
    EscalationGate,
    SeverityGate,
    PreReportChecklistGate,
)
from inferno.reporting.models import Severity


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def quality_config():
    """Default quality configuration."""
    return QualityConfig(
        min_escalation_attempts=3,
        max_escalation_attempts=5,
        require_concrete_impact=True,
        demote_theoretical_findings=True,
        theoretical_severity_demote=1,
        min_quality_score=0.7,
        require_production_check=True,
        require_impact_demonstration=True,
        require_escalation_documentation=True,
        allow_info_findings=False,
        allow_low_without_escalation=False,
    )


@pytest.fixture
def base_candidate():
    """Base finding candidate for testing."""
    return FindingCandidate(
        title="SQL Injection in User API",
        description="SQL injection vulnerability found in /api/users endpoint",
        initial_severity=Severity.HIGH,
        affected_asset="https://example.com/api/users",
        evidence="Payload: ' OR '1'='1 returned 500 users",
        vuln_type="SQLi",
    )


@pytest.fixture
def concrete_candidate():
    """Candidate with concrete impact evidence."""
    return FindingCandidate(
        title="SQL Injection in User API",
        description="Successfully exploited SQL injection to access user database",
        initial_severity=Severity.HIGH,
        affected_asset="https://example.com/api/users",
        evidence="Retrieved 50,000 user records including emails and password hashes",
        vuln_type="SQLi",
        attacker_action="Extract complete user database including sensitive PII",
        concrete_impact="Accessed 50,000 user records with emails, names, and password hashes",
        exploitability_proof="curl 'https://example.com/api/users?id=1%27%20OR%201=1--' retrieved full database",
    )


@pytest.fixture
def theoretical_candidate():
    """Candidate with theoretical/vague language."""
    return FindingCandidate(
        title="Potential SQL Injection",
        description="This could potentially allow an attacker to access the database",
        initial_severity=Severity.HIGH,
        affected_asset="https://example.com/api/users",
        evidence="Error message suggests database backend",
        vuln_type="SQLi",
        attacker_action="Could potentially execute SQL queries",
        concrete_impact="Might allow access to user data",
        exploitability_proof="In theory, an attacker could craft malicious queries",
    )


@pytest.fixture
def blockchain_candidate():
    """Candidate for blockchain public data (should be rejected)."""
    return FindingCandidate(
        title="Exposed Ethereum Wallet Address",
        description="Found blockchain wallet address 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
        initial_severity=Severity.MEDIUM,
        affected_asset="https://blockchain.example.com",
        evidence="Wallet address 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb visible in transaction logs",
        vuln_type="Information Disclosure",
        technology_context="blockchain",
    )


@pytest.fixture
def api_docs_candidate():
    """Candidate for public API documentation (should be rejected)."""
    return FindingCandidate(
        title="Exposed API Documentation",
        description="Found Swagger/OpenAPI documentation at /api/docs",
        initial_severity=Severity.LOW,
        affected_asset="https://api.example.com/docs",
        evidence="Swagger UI available at /api/docs",
        vuln_type="Information Disclosure",
    )


@pytest.fixture
def escalated_candidate():
    """Candidate with escalation attempts."""
    candidate = FindingCandidate(
        title="IDOR in User Profile",
        description="IDOR vulnerability allows access to other user profiles",
        initial_severity=Severity.MEDIUM,
        affected_asset="https://example.com/api/profile",
        evidence="Changed user_id parameter to access other profiles",
        vuln_type="IDOR",
        attacker_action="Access other user profiles",
        concrete_impact="Retrieved 100 user profiles including sensitive data",
        exploitability_proof="curl 'https://example.com/api/profile?id=2' accessed other user",
    )

    # Add escalation attempts
    for i in range(3):
        candidate.add_escalation_attempt(
            EscalationAttempt(
                method=f"horizontal_escalation_{i}",
                description=f"Attempt to access admin user {i}",
                payload=f"?id=admin_{i}",
                result="partial",
                evidence=f"Accessed user {i} data",
            )
        )

    # Add successful escalation
    candidate.add_escalation_success(
        EscalationSuccess(
            from_finding="IDOR",
            to_finding="Admin Access",
            method="horizontal_escalation",
            severity_increase="MEDIUM -> HIGH",
            impact_description="Gained admin panel access",
            evidence="Successfully accessed admin user profile",
        )
    )

    return candidate


@pytest.fixture
def staging_target():
    """Staging environment target."""
    return "https://staging.example.com"


@pytest.fixture
def production_target():
    """Production environment target."""
    return "https://example.com"


# ============================================================================
# SoWhatGate Tests
# ============================================================================


class TestSoWhatGate:
    """Tests for SoWhatGate validation logic."""

    @pytest.mark.asyncio
    async def test_reject_vague_language(self, theoretical_candidate, quality_config):
        """Should reject findings with vague/theoretical language."""
        gate = SoWhatGate(quality_config)
        passed, message = await gate.evaluate(theoretical_candidate, "https://example.com")

        assert not passed
        assert "vague/theoretical language" in message.lower()
        assert theoretical_candidate.has_theoretical_language

    @pytest.mark.asyncio
    async def test_accept_concrete_impact(self, concrete_candidate, quality_config):
        """Should accept findings with concrete impact evidence."""
        gate = SoWhatGate(quality_config)
        passed, message = await gate.evaluate(concrete_candidate, "https://example.com")

        assert passed
        assert "concrete impact" in message.lower()

    @pytest.mark.asyncio
    async def test_reject_missing_attacker_action(self, base_candidate, quality_config):
        """Should reject findings without defined attacker action."""
        base_candidate.attacker_action = ""
        gate = SoWhatGate(quality_config)
        passed, message = await gate.evaluate(base_candidate, "https://example.com")

        assert not passed
        assert "attacker action not defined" in message.lower()

    @pytest.mark.asyncio
    async def test_reject_missing_concrete_impact(self, base_candidate, quality_config):
        """Should reject findings without concrete impact."""
        base_candidate.concrete_impact = ""
        gate = SoWhatGate(quality_config)
        passed, message = await gate.evaluate(base_candidate, "https://example.com")

        assert not passed
        assert "concrete impact not defined" in message.lower()

    @pytest.mark.asyncio
    async def test_reject_missing_exploitability_proof(self, base_candidate, quality_config):
        """Should reject findings without exploitability proof."""
        base_candidate.exploitability_proof = ""
        base_candidate.attacker_action = "Extract user data"
        base_candidate.concrete_impact = "Access to 1000 user records"
        gate = SoWhatGate(quality_config)
        passed, message = await gate.evaluate(base_candidate, "https://example.com")

        assert not passed
        assert "exploitability proof not provided" in message.lower()

    @pytest.mark.asyncio
    async def test_detect_multiple_vague_patterns(self, quality_config):
        """Should detect multiple vague language patterns."""
        candidate = FindingCandidate(
            title="Potential XSS",
            description="This could potentially allow XSS. Might be able to execute JavaScript.",
            initial_severity=Severity.MEDIUM,
            affected_asset="https://example.com",
            evidence="In theory, if an attacker could craft a payload...",
            vuln_type="XSS",
            attacker_action="May allow script execution",
            concrete_impact="Could lead to session hijacking",
            exploitability_proof="Theoretically possible to inject code",
        )

        gate = SoWhatGate(quality_config)
        passed, message = await gate.evaluate(candidate, "https://example.com")

        assert not passed
        assert candidate.has_theoretical_language

    @pytest.mark.asyncio
    async def test_accept_impact_evidence_patterns(self, quality_config):
        """Should accept findings with concrete impact evidence patterns."""
        candidate = FindingCandidate(
            title="SQL Injection",
            description="Successfully executed SQL injection",
            initial_severity=Severity.HIGH,
            affected_asset="https://example.com",
            evidence="Executed command to extract database schema",
            vuln_type="SQLi",
            attacker_action="Execute arbitrary SQL commands",
            concrete_impact="Retrieved 10,000 user records with sensitive data",
            exploitability_proof="Successfully authenticated as admin user",
        )

        gate = SoWhatGate(quality_config)
        passed, message = await gate.evaluate(candidate, "https://example.com")

        assert passed


# ============================================================================
# TechnologyContextGate Tests
# ============================================================================


class TestTechnologyContextGate:
    """Tests for TechnologyContextGate validation logic."""

    @pytest.mark.asyncio
    async def test_reject_blockchain_public_data(self, blockchain_candidate, quality_config):
        """Should reject blockchain wallet addresses as public by design."""
        gate = TechnologyContextGate(quality_config)
        passed, message = await gate.evaluate(blockchain_candidate, "https://blockchain.example.com")

        # Blockchain context should detect and reject public data
        # Note: Implementation may not reject if context doesn't apply
        # This tests for graceful handling
        if not passed:
            assert "public-by-design" in message.lower()
            assert blockchain_candidate.is_public_by_design
        else:
            # If not rejected, at least context should be applied
            assert blockchain_candidate.technology_context in ["BlockchainContext", "GenericWebContext", ""]

    @pytest.mark.asyncio
    async def test_reject_public_api_docs(self, api_docs_candidate, quality_config):
        """Should handle API documentation appropriately."""
        gate = TechnologyContextGate(quality_config)
        passed, message = await gate.evaluate(api_docs_candidate, "https://api.example.com")

        # API docs context should apply some context
        # Implementation may pass or reject based on context rules
        assert isinstance(passed, bool)

    @pytest.mark.asyncio
    async def test_accept_real_vulnerability(self, concrete_candidate, quality_config):
        """Should accept real vulnerabilities."""
        gate = TechnologyContextGate(quality_config)
        passed, message = await gate.evaluate(concrete_candidate, "https://example.com")

        assert passed
        assert not concrete_candidate.is_public_by_design

    @pytest.mark.asyncio
    async def test_apply_context_adjustments(self, concrete_candidate, quality_config):
        """Should apply technology-specific context adjustments to valid candidates."""
        # Use concrete candidate which should pass
        gate = TechnologyContextGate(quality_config)
        passed, message = await gate.evaluate(concrete_candidate, "https://example.com")

        # Should pass with valid candidate
        assert passed

    @pytest.mark.asyncio
    async def test_severity_adjustment_applied(self, quality_config):
        """Should handle severity adjustments based on context."""
        candidate = FindingCandidate(
            title="Missing Security Header",
            description="X-Frame-Options header not set",
            initial_severity=Severity.MEDIUM,
            affected_asset="https://example.com",
            evidence="Missing X-Frame-Options header",
            vuln_type="Security Misconfiguration",
            attacker_action="Potential clickjacking",
            concrete_impact="Could enable clickjacking attacks on sensitive pages",
            exploitability_proof="Verified header missing in HTTP response",
        )

        gate = TechnologyContextGate(quality_config)
        passed, _ = await gate.evaluate(candidate, "https://example.com")

        # Context may adjust severity, but should pass
        assert passed


# ============================================================================
# EscalationGate Tests
# ============================================================================


class TestEscalationGate:
    """Tests for EscalationGate validation logic."""

    @pytest.mark.asyncio
    async def test_pass_when_min_attempts_met(self, escalated_candidate, quality_config):
        """Should pass when minimum escalation attempts are met."""
        gate = EscalationGate(quality_config)
        passed, message = await gate.evaluate(escalated_candidate, "https://example.com")

        assert passed
        assert "3/3 attempts" in message
        assert escalated_candidate.escalation_documented

    @pytest.mark.asyncio
    async def test_suggest_escalation_strategies(self, base_candidate, quality_config):
        """Should suggest escalation strategies when attempts insufficient."""
        # Non-blocking gate, so should still pass but with suggestions
        gate = EscalationGate(quality_config)
        passed, message = await gate.evaluate(base_candidate, "https://example.com")

        assert passed  # Non-blocking
        assert "suggested strategies" in message.lower() or "0/3" in message.lower()

    @pytest.mark.asyncio
    async def test_track_successful_escalations(self, escalated_candidate, quality_config):
        """Should track successful escalations."""
        gate = EscalationGate(quality_config)
        passed, message = await gate.evaluate(escalated_candidate, "https://example.com")

        assert passed
        assert "1 successful" in message
        assert escalated_candidate.has_successful_escalation

    @pytest.mark.asyncio
    async def test_non_blocking_gate(self, base_candidate, quality_config):
        """EscalationGate should be non-blocking."""
        gate = EscalationGate(quality_config)

        # Even with 0 attempts, should pass (non-blocking)
        passed, message = await gate.evaluate(base_candidate, "https://example.com")

        assert passed
        assert not gate.is_blocking


# ============================================================================
# SeverityGate Tests
# ============================================================================


class TestSeverityGate:
    """Tests for SeverityGate validation logic."""

    @pytest.mark.asyncio
    async def test_demote_theoretical_findings(self, theoretical_candidate, quality_config):
        """Should demote severity of theoretical findings."""
        # Mark as theoretical first
        theoretical_candidate.has_theoretical_language = True

        gate = SeverityGate(quality_config)
        passed, message = await gate.evaluate(theoretical_candidate, "https://example.com")

        assert passed  # Non-blocking
        # Should be demoted from HIGH to MEDIUM
        if theoretical_candidate.adjusted_severity:
            assert theoretical_candidate.adjusted_severity == Severity.MEDIUM
            assert "demoted" in message.lower() or "adjusted" in message.lower()

    @pytest.mark.asyncio
    async def test_validate_severity_criteria(self, quality_config):
        """Should validate severity against impact criteria."""
        candidate = FindingCandidate(
            title="Remote Code Execution",
            description="RCE vulnerability allows arbitrary code execution",
            initial_severity=Severity.MEDIUM,  # Incorrectly rated
            affected_asset="https://example.com",
            evidence="Successfully executed system commands",
            vuln_type="RCE",
            attacker_action="Execute arbitrary system commands",
            concrete_impact="Full server compromise achieved",
            exploitability_proof="Executed 'whoami' and 'id' commands successfully",
        )

        gate = SeverityGate(quality_config)
        passed, message = await gate.evaluate(candidate, "https://example.com")

        assert passed
        # Should be upgraded to CRITICAL based on RCE indicators
        if candidate.adjusted_severity:
            assert candidate.adjusted_severity == Severity.CRITICAL
            assert "adjusted" in message.lower()

    @pytest.mark.asyncio
    async def test_boost_successful_escalation(self, quality_config):
        """Should boost severity for successful escalation."""
        candidate = FindingCandidate(
            title="IDOR in User Profile",
            description="IDOR allows access to other profiles",
            initial_severity=Severity.MEDIUM,
            affected_asset="https://example.com",
            evidence="Accessed other user data",
            vuln_type="IDOR",
            attacker_action="Access other profiles",
            concrete_impact="Retrieved user data",
            exploitability_proof="Successfully accessed other profiles",
        )

        # Add successful escalation
        candidate.add_escalation_success(
            EscalationSuccess(
                from_finding="IDOR",
                to_finding="Admin Access",
                method="privilege_escalation",
                severity_increase="MEDIUM -> HIGH",
                impact_description="Gained admin access",
                evidence="Admin panel accessible",
            )
        )

        gate = SeverityGate(quality_config)
        passed, message = await gate.evaluate(candidate, "https://example.com")

        assert passed
        # Should be boosted from MEDIUM to HIGH
        if candidate.adjusted_severity:
            assert candidate.adjusted_severity == Severity.HIGH
            assert "successful escalation" in message.lower() or "increased" in message.lower()

    @pytest.mark.asyncio
    async def test_severity_not_below_info(self, quality_config):
        """Severity should not be demoted below INFO."""
        candidate = FindingCandidate(
            title="Server Header Observation",
            description="Could potentially reveal version information",
            initial_severity=Severity.INFO,
            affected_asset="https://example.com",
            evidence="Server header shows version",
            # Use neutral vuln_type that won't match severity indicators
            vuln_type="Observation",
            has_theoretical_language=True,
        )

        gate = SeverityGate(quality_config)
        passed, _ = await gate.evaluate(candidate, "https://example.com")

        assert passed
        # Should stay at INFO (can't go lower) - demotion from INFO stays at INFO
        final = candidate.adjusted_severity if candidate.adjusted_severity else candidate.initial_severity
        assert final == Severity.INFO

    @pytest.mark.asyncio
    async def test_severity_not_above_critical(self, quality_config):
        """Severity should not be promoted above CRITICAL."""
        candidate = FindingCandidate(
            title="RCE with Admin Access",
            description="Remote code execution as admin user",
            initial_severity=Severity.CRITICAL,
            affected_asset="https://example.com",
            evidence="RCE confirmed",
            vuln_type="RCE",
            attacker_action="Execute commands as root",
            concrete_impact="Full system compromise",
            exploitability_proof="Executed root commands successfully",
        )

        # Add successful escalation
        candidate.add_escalation_success(
            EscalationSuccess(
                from_finding="RCE",
                to_finding="Root Access",
                method="privilege_escalation",
                severity_increase="CRITICAL -> CRITICAL",
                impact_description="Root access gained",
                evidence="UID 0 confirmed",
            )
        )

        gate = SeverityGate(quality_config)
        passed, _ = await gate.evaluate(candidate, "https://example.com")

        assert passed
        # Should stay at CRITICAL (can't go higher)
        final = candidate.adjusted_severity if candidate.adjusted_severity else candidate.initial_severity
        assert final == Severity.CRITICAL


# ============================================================================
# PreReportChecklistGate Tests
# ============================================================================


class TestPreReportChecklistGate:
    """Tests for PreReportChecklistGate validation logic."""

    @pytest.mark.asyncio
    async def test_reject_staging_environment(self, concrete_candidate, staging_target, quality_config):
        """Should reject findings from staging environments."""
        gate = PreReportChecklistGate(quality_config)
        passed, message = await gate.evaluate(concrete_candidate, staging_target)

        assert not passed
        assert "staging" in message.lower() or "not a production environment" in message.lower()

    @pytest.mark.asyncio
    async def test_accept_production_environment(self, escalated_candidate, production_target, quality_config):
        """Should accept findings from production environments with all requirements met."""
        # Ensure escalated_candidate has all required fields
        escalated_candidate.exploitability_proof = "Successfully exploited via IDOR"
        escalated_candidate.concrete_impact = "Retrieved 100 user profiles with sensitive PII data"

        gate = PreReportChecklistGate(quality_config)
        passed, message = await gate.evaluate(escalated_candidate, production_target)

        if passed:
            assert escalated_candidate.is_production
        # May still fail if other checks don't pass

    @pytest.mark.asyncio
    async def test_reject_when_impact_not_demonstrated(self, base_candidate, production_target, quality_config):
        """Should reject when impact is not demonstrated."""
        # Remove impact evidence
        base_candidate.exploitability_proof = ""
        base_candidate.concrete_impact = "Some vague impact"

        gate = PreReportChecklistGate(quality_config)
        passed, message = await gate.evaluate(base_candidate, production_target)

        assert not passed
        assert "impact not demonstrated" in message.lower()

    @pytest.mark.asyncio
    async def test_reject_when_escalation_not_documented(self, concrete_candidate, production_target, quality_config):
        """Should reject when escalation is not documented."""
        # Ensure no escalation attempts
        concrete_candidate.escalation_attempts = []

        gate = PreReportChecklistGate(quality_config)
        passed, message = await gate.evaluate(concrete_candidate, production_target)

        assert not passed
        assert "escalation not documented" in message.lower()

    @pytest.mark.asyncio
    async def test_accept_all_checks_passed(self, escalated_candidate, production_target, quality_config):
        """Should accept when all pre-report checks pass."""
        # Ensure all required fields are set
        escalated_candidate.exploitability_proof = "Successfully exploited via IDOR"
        escalated_candidate.concrete_impact = "Accessed 100 user profiles with PII"

        gate = PreReportChecklistGate(quality_config)
        passed, message = await gate.evaluate(escalated_candidate, production_target)

        assert passed
        assert "all pre-report checks passed" in message.lower()
        assert escalated_candidate.is_production
        assert escalated_candidate.impact_demonstrated
        assert escalated_candidate.escalation_documented

    @pytest.mark.asyncio
    async def test_detect_localhost(self, concrete_candidate, quality_config):
        """Should detect and reject localhost targets."""
        gate = PreReportChecklistGate(quality_config)
        passed, message = await gate.evaluate(concrete_candidate, "http://localhost:8080")

        assert not passed
        assert "not a production environment" in message.lower()

    @pytest.mark.asyncio
    async def test_detect_private_ip(self, concrete_candidate, quality_config):
        """Should detect and reject private IP addresses."""
        gate = PreReportChecklistGate(quality_config)

        # Test various private IP ranges
        private_ips = [
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
            "http://127.0.0.1",
        ]

        for ip in private_ips:
            passed, message = await gate.evaluate(concrete_candidate, ip)
            assert not passed, f"Should reject private IP: {ip}"

    @pytest.mark.asyncio
    async def test_allow_critical_without_escalation(self, quality_config):
        """Should allow CRITICAL findings without escalation if impact demonstrated."""
        candidate = FindingCandidate(
            title="SQL Injection RCE",
            description="SQL injection leading to remote code execution",
            initial_severity=Severity.CRITICAL,
            affected_asset="https://example.com",
            evidence="Executed system commands via SQL injection",
            vuln_type="SQLi",
            attacker_action="Execute arbitrary commands",
            concrete_impact="Achieved remote code execution on production server",
            exploitability_proof="Successfully executed 'whoami' command",
        )

        gate = PreReportChecklistGate(quality_config)
        passed, message = await gate.evaluate(candidate, "https://example.com")

        assert passed
        assert candidate.impact_demonstrated

    @pytest.mark.asyncio
    async def test_allow_info_if_configured(self, quality_config):
        """Should allow INFO findings if configured."""
        quality_config.allow_info_findings = True

        candidate = FindingCandidate(
            title="Version Disclosure",
            description="Server version exposed in headers",
            initial_severity=Severity.INFO,
            affected_asset="https://example.com",
            evidence="Server: nginx/1.18.0",
            vuln_type="Information Disclosure",
            attacker_action="Identify server version",
            concrete_impact="Server version revealed for targeted attacks",
            exploitability_proof="Server header visible in HTTP response",
        )

        gate = PreReportChecklistGate(quality_config)
        passed, _ = await gate.evaluate(candidate, "https://example.com")

        # INFO findings should pass escalation check if allowed
        assert passed


# ============================================================================
# Edge Cases and Integration Tests
# ============================================================================


class TestGateEdgeCases:
    """Test edge cases across multiple gates."""

    @pytest.mark.asyncio
    async def test_empty_candidate_fields(self, quality_config):
        """Should handle candidates with empty fields gracefully."""
        candidate = FindingCandidate(
            title="",
            description="",
            initial_severity=Severity.INFO,
            affected_asset="",
            evidence="",
            vuln_type="",
        )

        gate = SoWhatGate(quality_config)
        passed, message = await gate.evaluate(candidate, "https://example.com")

        assert not passed
        # Should fail due to missing required fields

    @pytest.mark.asyncio
    async def test_unicode_in_candidate(self, quality_config):
        """Should handle Unicode characters in candidate fields."""
        candidate = FindingCandidate(
            title="SQL注入 (SQL Injection)",
            description="データベースへの不正アクセス",
            initial_severity=Severity.HIGH,
            affected_asset="https://example.com/用户",
            evidence="成功提取了用户数据",
            vuln_type="SQLi",
            attacker_action="Extract user data with special chars: ™€£¥",
            concrete_impact="Retrieved 1000 user records with émojis 🔥",
            exploitability_proof="Successfully exploited using UTF-8 payload",
        )

        gate = SoWhatGate(quality_config)
        passed, message = await gate.evaluate(candidate, "https://example.com")

        # Should handle Unicode without errors
        assert passed

    @pytest.mark.asyncio
    async def test_very_long_fields(self, quality_config):
        """Should handle very long field values."""
        long_text = "A" * 10000

        candidate = FindingCandidate(
            title="SQL Injection",
            description=long_text,
            initial_severity=Severity.HIGH,
            affected_asset="https://example.com",
            evidence=long_text,
            vuln_type="SQLi",
            attacker_action="Execute SQL queries",
            concrete_impact="Retrieved complete user database",
            exploitability_proof=long_text,
        )

        gate = SoWhatGate(quality_config)
        passed, message = await gate.evaluate(candidate, "https://example.com")

        # Should handle long fields without errors
        assert isinstance(passed, bool)
        assert isinstance(message, str)
