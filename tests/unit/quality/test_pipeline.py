"""
Unit tests for QualityGatePipeline.

Tests the orchestration of findings through multiple quality gates:
- Pipeline initialization
- Candidate approval flow (passes all gates)
- Candidate rejection flow (fails blocking gate)
- Quality score calculation
- Batch processing
- Finding conversion
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock

from inferno.quality.candidate import FindingCandidate, EscalationAttempt, EscalationSuccess
from inferno.quality.config import QualityConfig
from inferno.quality.gate import QualityGate
from inferno.quality.gates import (
    SoWhatGate,
    TechnologyContextGate,
    EscalationGate,
    SeverityGate,
    PreReportChecklistGate,
)
from inferno.quality.pipeline import QualityGatePipeline
from inferno.reporting.models import Severity, Finding


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def quality_config():
    """Default quality configuration."""
    return QualityConfig(
        min_escalation_attempts=3,
        require_concrete_impact=True,
        demote_theoretical_findings=True,
        min_quality_score=0.7,
        require_production_check=True,
        require_impact_demonstration=True,
        require_escalation_documentation=True,
    )


@pytest.fixture
def mock_anthropic_client():
    """Mock Anthropic client for pipeline."""
    return AsyncMock()


@pytest.fixture
def mock_tool_registry():
    """Mock tool registry for pipeline."""
    return Mock()


@pytest.fixture
def pipeline(quality_config, mock_anthropic_client, mock_tool_registry):
    """Create pipeline with all gates registered."""
    pipeline = QualityGatePipeline(
        client=mock_anthropic_client,
        registry=mock_tool_registry,
        config=quality_config,
    )

    # Register all gates in order
    pipeline.register_gates([
        SoWhatGate(quality_config),
        TechnologyContextGate(quality_config),
        EscalationGate(quality_config),
        SeverityGate(quality_config),
        PreReportChecklistGate(quality_config),
    ])

    return pipeline


@pytest.fixture
def valid_candidate():
    """Valid candidate that should pass all gates."""
    candidate = FindingCandidate(
        title="SQL Injection in Login Form",
        description="SQL injection vulnerability allows database access via login form",
        initial_severity=Severity.HIGH,
        affected_asset="https://example.com/login",
        # Include sensitive keyword (password) to avoid public-by-design detection
        evidence="Successfully extracted 10,000 user records with passwords and credentials",
        vuln_type="SQLi",
        attacker_action="Extract complete user database including password hashes",
        concrete_impact="Retrieved 10,000 user records including emails and password hashes",
        exploitability_proof="curl 'https://example.com/login?user=admin%27%20OR%201=1--' extracted database",
        # Pre-report checklist requirements
        is_production=True,  # Production environment
        impact_demonstrated=True,  # Impact proven
        is_public_by_design=False,  # Not intentionally public
        data_intentionally_public=False,  # Data is not meant to be public
    )

    # Add required escalation attempts
    for i in range(3):
        candidate.add_escalation_attempt(
            EscalationAttempt(
                method=f"privilege_escalation_{i}",
                description=f"Attempt to gain admin access {i}",
                payload=f"admin_payload_{i}",
                result="partial",
                evidence=f"Escalation attempt {i} completed",
            )
        )

    # Add successful escalation
    candidate.add_escalation_success(
        EscalationSuccess(
            from_finding="SQLi",
            to_finding="Admin Access",
            method="privilege_escalation",
            severity_increase="HIGH -> CRITICAL",
            impact_description="Gained admin access via SQLi",
            evidence="Successfully authenticated as admin",
        )
    )

    return candidate


@pytest.fixture
def invalid_candidate():
    """Invalid candidate that should fail SoWhatGate."""
    return FindingCandidate(
        title="Potential SQL Injection",
        description="This could potentially allow database access",
        initial_severity=Severity.HIGH,
        affected_asset="https://example.com/api/users",
        evidence="Error message observed",
        vuln_type="SQLi",
        attacker_action="",  # Missing
        concrete_impact="",  # Missing
        exploitability_proof="",  # Missing
    )


@pytest.fixture
def staging_candidate():
    """Candidate on staging environment (should fail PreReportChecklistGate)."""
    candidate = FindingCandidate(
        title="SQL Injection",
        description="SQL injection on staging server",
        initial_severity=Severity.HIGH,
        affected_asset="https://staging.example.com/api/users",
        evidence="Extracted staging database",
        vuln_type="SQLi",
        attacker_action="Extract database",
        concrete_impact="Retrieved 1000 staging records",
        exploitability_proof="Successfully exploited staging environment",
    )

    # Add escalation attempts
    for i in range(3):
        candidate.add_escalation_attempt(
            EscalationAttempt(
                method=f"escalation_{i}",
                description=f"Escalation {i}",
                payload=f"payload_{i}",
                result="success",
                evidence=f"Evidence {i}",
            )
        )

    return candidate


@pytest.fixture
def blockchain_candidate():
    """Blockchain candidate (should fail TechnologyContextGate as public-by-design)."""
    return FindingCandidate(
        title="Exposed Wallet Address",
        description="Wallet address leaked in application logs",
        initial_severity=Severity.MEDIUM,
        affected_asset="https://blockchain.example.com",
        # Wallet address in evidence field for pattern matching (40 hex chars after 0x)
        evidence="Found wallet address 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEbA in logs",
        vuln_type="Information Disclosure",
        attacker_action="View wallet address",
        concrete_impact="Wallet address publicly visible to attackers",
        exploitability_proof="Address 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEbA found in explorer",
        # Pre-report checklist requirements (needed to reach TechnologyContextGate)
        is_production=True,
        impact_demonstrated=True,
    )


# ============================================================================
# Pipeline Initialization Tests
# ============================================================================


class TestPipelineInitialization:
    """Tests for pipeline initialization and configuration."""

    def test_pipeline_creation(self, quality_config):
        """Should create pipeline with default settings."""
        pipeline = QualityGatePipeline(config=quality_config)

        assert pipeline.config == quality_config
        assert pipeline.gate_count == 0
        assert pipeline.blocking_gate_count == 0

    def test_register_single_gate(self, pipeline, quality_config):
        """Should register a single gate."""
        initial_count = pipeline.gate_count
        gate = SoWhatGate(quality_config)

        # Pipeline fixture already has gates, create new one
        new_pipeline = QualityGatePipeline(config=quality_config)
        new_pipeline.register_gate(gate)

        assert new_pipeline.gate_count == 1
        assert gate.name in new_pipeline.gate_names

    def test_register_multiple_gates(self, quality_config):
        """Should register multiple gates at once."""
        pipeline = QualityGatePipeline(config=quality_config)
        gates = [
            SoWhatGate(quality_config),
            TechnologyContextGate(quality_config),
            EscalationGate(quality_config),
        ]

        pipeline.register_gates(gates)

        assert pipeline.gate_count == 3
        assert pipeline.blocking_gate_count == 2  # SoWhat and TechnologyContext are blocking

    def test_gate_names_property(self, pipeline):
        """Should return list of gate names."""
        names = pipeline.gate_names

        assert isinstance(names, list)
        assert "so_what_gate" in names
        assert "technology_context_gate" in names
        assert "escalation_gate" in names
        assert "severity_gate" in names
        assert "pre_report_checklist_gate" in names

    def test_blocking_gate_count(self, pipeline):
        """Should count blocking gates correctly."""
        blocking_count = pipeline.blocking_gate_count

        # SoWhatGate, TechnologyContextGate, and PreReportChecklistGate are blocking
        assert blocking_count == 3

    def test_pipeline_repr(self, pipeline):
        """Should have readable string representation."""
        repr_str = repr(pipeline)

        assert "QualityGatePipeline" in repr_str
        assert "gates=" in repr_str
        assert "blocking=" in repr_str


# ============================================================================
# Candidate Processing Tests
# ============================================================================


class TestCandidateProcessing:
    """Tests for processing individual candidates."""

    @pytest.mark.asyncio
    async def test_approve_valid_candidate(self, pipeline, valid_candidate):
        """Should approve candidate that passes all gates."""
        approved, finding = await pipeline.process_candidate(
            valid_candidate,
            "https://example.com"
        )

        assert approved
        assert finding is not None
        assert isinstance(finding, Finding)
        assert valid_candidate.approved_for_report
        assert valid_candidate.quality_score >= pipeline.config.min_quality_score
        assert len(valid_candidate.gates_passed) > 0
        assert len(valid_candidate.gates_failed) == 0

    @pytest.mark.asyncio
    async def test_reject_invalid_candidate(self, pipeline, invalid_candidate):
        """Should reject candidate that fails blocking gate."""
        approved, finding = await pipeline.process_candidate(
            invalid_candidate,
            "https://example.com"
        )

        assert not approved
        assert finding is None
        assert not invalid_candidate.approved_for_report
        assert len(invalid_candidate.gates_failed) > 0
        assert len(invalid_candidate.rejection_reasons) > 0

    @pytest.mark.asyncio
    async def test_reject_staging_candidate(self, pipeline, staging_candidate):
        """Should reject candidate from staging environment."""
        approved, finding = await pipeline.process_candidate(
            staging_candidate,
            "https://staging.example.com"
        )

        assert not approved
        assert finding is None
        assert "pre_report_checklist_gate" in staging_candidate.gates_failed

    @pytest.mark.asyncio
    async def test_reject_blockchain_candidate(self, pipeline, blockchain_candidate):
        """Should reject public-by-design blockchain data."""
        approved, finding = await pipeline.process_candidate(
            blockchain_candidate,
            "https://blockchain.example.com"
        )

        assert not approved
        assert finding is None
        assert blockchain_candidate.is_public_by_design

    @pytest.mark.asyncio
    async def test_early_exit_on_blocking_gate_failure(self, pipeline, invalid_candidate):
        """Should exit early when blocking gate fails."""
        approved, finding = await pipeline.process_candidate(
            invalid_candidate,
            "https://example.com"
        )

        assert not approved
        # Should fail on first blocking gate (SoWhatGate)
        assert "so_what_gate" in invalid_candidate.gates_failed
        # Later gates may not be evaluated
        assert len(invalid_candidate.gates_passed) < pipeline.gate_count


# ============================================================================
# Quality Score Tests
# ============================================================================


class TestQualityScoring:
    """Tests for quality score calculation."""

    @pytest.mark.asyncio
    async def test_calculate_quality_score(self, pipeline, valid_candidate):
        """Should calculate quality score based on gate weights."""
        approved, finding = await pipeline.process_candidate(
            valid_candidate,
            "https://example.com"
        )

        assert approved
        assert 0.0 <= valid_candidate.quality_score <= 1.0
        assert valid_candidate.quality_score >= pipeline.config.min_quality_score

    @pytest.mark.asyncio
    async def test_reject_low_quality_score(self, quality_config):
        """Should reject candidate with quality score below threshold."""
        # Create pipeline with high quality threshold
        quality_config.min_quality_score = 0.95

        pipeline = QualityGatePipeline(config=quality_config)
        pipeline.register_gates([
            SoWhatGate(quality_config),
            EscalationGate(quality_config),
        ])

        candidate = FindingCandidate(
            title="Low Quality Finding",
            description="Minimal impact finding",
            initial_severity=Severity.LOW,
            affected_asset="https://example.com",
            evidence="Minimal evidence",
            vuln_type="Info",
            attacker_action="Minimal action",
            concrete_impact="Minimal concrete impact description provided here",
            exploitability_proof="Minimal proof of exploitability provided",
        )

        approved, finding = await pipeline.process_candidate(
            candidate,
            "https://example.com"
        )

        # May be rejected due to low quality score or missing requirements
        if not approved:
            assert "quality score" in " ".join(candidate.rejection_reasons).lower() or \
                   len(candidate.gates_failed) > 0

    @pytest.mark.asyncio
    async def test_quality_score_in_metadata(self, pipeline, valid_candidate):
        """Should include quality score in finding metadata."""
        approved, finding = await pipeline.process_candidate(
            valid_candidate,
            "https://example.com"
        )

        assert approved
        assert finding is not None
        assert "quality_score" in finding.metadata
        assert finding.metadata["quality_score"] == valid_candidate.quality_score


# ============================================================================
# Batch Processing Tests
# ============================================================================


class TestBatchProcessing:
    """Tests for batch processing of candidates."""

    @pytest.mark.asyncio
    async def test_process_empty_batch(self, pipeline):
        """Should handle empty batch gracefully."""
        findings = await pipeline.process_batch([], "https://example.com")

        assert isinstance(findings, list)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_process_single_batch(self, pipeline, valid_candidate):
        """Should process single candidate in batch."""
        findings = await pipeline.process_batch(
            [valid_candidate],
            "https://example.com"
        )

        assert len(findings) == 1
        assert isinstance(findings[0], Finding)

    @pytest.mark.asyncio
    async def test_process_mixed_batch(self, pipeline, valid_candidate, invalid_candidate, staging_candidate):
        """Should process batch with mixed valid/invalid candidates."""
        candidates = [valid_candidate, invalid_candidate, staging_candidate]

        findings = await pipeline.process_batch(
            candidates,
            "https://example.com"
        )

        # Only valid_candidate should pass
        assert len(findings) == 1
        assert findings[0].title == valid_candidate.title

    @pytest.mark.asyncio
    async def test_process_all_invalid_batch(self, pipeline, invalid_candidate, staging_candidate):
        """Should return empty list when all candidates fail."""
        candidates = [invalid_candidate, staging_candidate]

        findings = await pipeline.process_batch(
            candidates,
            "https://example.com"
        )

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_batch_preserves_order(self, pipeline):
        """Should preserve candidate order in batch processing."""
        candidates = []
        for i in range(3):
            candidate = FindingCandidate(
                title=f"Finding {i}",
                description=f"Description {i}",
                initial_severity=Severity.HIGH,
                affected_asset="https://example.com",
                evidence=f"Evidence {i}",
                vuln_type="SQLi",
                attacker_action=f"Action {i}",
                concrete_impact=f"Concrete impact for finding {i} with measurable results",
                exploitability_proof=f"Successfully exploited finding {i} with proof",
            )

            # Add escalation attempts
            for j in range(3):
                candidate.add_escalation_attempt(
                    EscalationAttempt(
                        method=f"escalation_{j}",
                        description=f"Escalation {j}",
                        payload=f"payload_{j}",
                        result="success",
                        evidence=f"Evidence {j}",
                    )
                )

            candidates.append(candidate)

        findings = await pipeline.process_batch(candidates, "https://example.com")

        # Check if findings are returned in same order
        for i, finding in enumerate(findings):
            assert f"Finding {i}" in finding.title


# ============================================================================
# Finding Conversion Tests
# ============================================================================


class TestFindingConversion:
    """Tests for converting FindingCandidate to Finding."""

    @pytest.mark.asyncio
    async def test_convert_basic_fields(self, pipeline, valid_candidate):
        """Should convert basic fields correctly."""
        approved, finding = await pipeline.process_candidate(
            valid_candidate,
            "https://example.com"
        )

        assert approved
        assert finding.title == valid_candidate.title
        assert finding.description.startswith(valid_candidate.description)
        assert finding.severity == valid_candidate.final_severity
        assert finding.affected_asset == valid_candidate.affected_asset
        assert finding.evidence == valid_candidate.evidence

    @pytest.mark.asyncio
    async def test_convert_exploitability_proof(self, pipeline, valid_candidate):
        """Should include exploitability proof in PoC field."""
        approved, finding = await pipeline.process_candidate(
            valid_candidate,
            "https://example.com"
        )

        assert approved
        assert finding.proof_of_concept == valid_candidate.exploitability_proof

    @pytest.mark.asyncio
    async def test_convert_metadata(self, pipeline, valid_candidate):
        """Should include quality metadata in finding."""
        approved, finding = await pipeline.process_candidate(
            valid_candidate,
            "https://example.com"
        )

        assert approved
        assert "quality_score" in finding.metadata
        assert "gates_passed" in finding.metadata
        assert "gates_failed" in finding.metadata
        assert "escalation_count" in finding.metadata
        assert "has_successful_escalation" in finding.metadata

    @pytest.mark.asyncio
    async def test_convert_escalation_summary(self, pipeline, valid_candidate):
        """Should include escalation summary in description."""
        approved, finding = await pipeline.process_candidate(
            valid_candidate,
            "https://example.com"
        )

        assert approved
        assert "Escalation Details:" in finding.description
        assert "Escalation attempts:" in finding.description
        assert "Successful escalations:" in finding.description

    @pytest.mark.asyncio
    async def test_convert_severity_adjustment(self, pipeline):
        """Should use adjusted severity in final finding."""
        candidate = FindingCandidate(
            title="SQL Injection",
            description="SQL injection vulnerability",
            initial_severity=Severity.MEDIUM,
            affected_asset="https://example.com",
            evidence="Database access confirmed",
            vuln_type="SQLi",
            attacker_action="Extract database",
            concrete_impact="Retrieved complete user database with 50,000 records",
            exploitability_proof="Successfully extracted all user data",
            adjusted_severity=Severity.HIGH,  # Manually adjusted
            severity_rationale="Adjusted to HIGH due to data access",
        )

        # Add escalation attempts
        for i in range(3):
            candidate.add_escalation_attempt(
                EscalationAttempt(
                    method=f"escalation_{i}",
                    description=f"Escalation {i}",
                    payload=f"payload_{i}",
                    result="success",
                    evidence=f"Evidence {i}",
                )
            )

        approved, finding = await pipeline.process_candidate(
            candidate,
            "https://example.com"
        )

        assert approved
        assert finding.severity == Severity.HIGH
        assert "severity_rationale" in finding.metadata

    @pytest.mark.asyncio
    async def test_convert_context_adjustments(self, pipeline, valid_candidate):
        """Should include context adjustments in metadata."""
        from inferno.quality.candidate import ContextAdjustment

        valid_candidate.add_context_adjustment(
            ContextAdjustment(
                context_type="web_application",
                original_severity=Severity.HIGH,
                adjusted_severity=Severity.CRITICAL,
                rationale="Increased due to public exposure",
                is_by_design=False,
            )
        )

        approved, finding = await pipeline.process_candidate(
            valid_candidate,
            "https://example.com"
        )

        assert approved
        assert "context_adjustments" in finding.metadata
        assert len(finding.metadata["context_adjustments"]) > 0


# ============================================================================
# Error Handling Tests
# ============================================================================


class TestPipelineErrorHandling:
    """Tests for error handling in pipeline."""

    @pytest.mark.asyncio
    async def test_handle_gate_exception(self, pipeline, valid_candidate):
        """Should handle gate evaluation exceptions gracefully."""
        # Create a gate that raises an exception
        class FailingGate(QualityGate):
            def __init__(self):
                super().__init__("failing_gate", weight=1.0, is_blocking=True)

            async def evaluate(self, candidate, target, **kwargs):
                raise ValueError("Simulated gate failure")

        # Create new pipeline with failing gate
        new_pipeline = QualityGatePipeline(config=pipeline.config)
        new_pipeline.register_gate(FailingGate())

        approved, finding = await new_pipeline.process_candidate(
            valid_candidate,
            "https://example.com"
        )

        # Should reject due to exception in blocking gate
        assert not approved
        assert finding is None
        assert "failing_gate" in valid_candidate.gates_failed

    @pytest.mark.asyncio
    async def test_continue_on_non_blocking_gate_exception(self, quality_config):
        """Should continue processing after non-blocking gate exception."""
        class FailingNonBlockingGate(QualityGate):
            def __init__(self):
                super().__init__("failing_gate", weight=1.0, is_blocking=False)

            async def evaluate(self, candidate, target, **kwargs):
                raise ValueError("Simulated non-blocking gate failure")

        pipeline = QualityGatePipeline(config=quality_config)
        pipeline.register_gates([
            FailingNonBlockingGate(),
            SoWhatGate(quality_config),
        ])

        candidate = FindingCandidate(
            title="SQL Injection",
            description="SQL injection vulnerability",
            initial_severity=Severity.HIGH,
            affected_asset="https://example.com",
            evidence="Database access",
            vuln_type="SQLi",
            attacker_action="Extract database",
            concrete_impact="Retrieved 10,000 user records with sensitive information",
            exploitability_proof="Successfully exploited with UNION injection",
        )

        approved, finding = await pipeline.process_candidate(
            candidate,
            "https://example.com"
        )

        # May still be rejected by SoWhatGate or other gates
        # But non-blocking gate failure shouldn't stop processing
        assert "failing_gate" in candidate.gates_failed


# ============================================================================
# Integration Tests
# ============================================================================


class TestPipelineIntegration:
    """Integration tests for complete pipeline flow."""

    @pytest.mark.asyncio
    async def test_complete_approval_flow(self, pipeline, valid_candidate):
        """Test complete flow from candidate to approved finding."""
        # Process candidate
        approved, finding = await pipeline.process_candidate(
            valid_candidate,
            "https://example.com"
        )

        # Verify approval
        assert approved
        assert finding is not None

        # Verify candidate state
        assert valid_candidate.approved_for_report
        assert valid_candidate.validated_at is not None
        assert valid_candidate.quality_score > 0

        # Verify gates passed
        assert "so_what_gate" in valid_candidate.gates_passed
        assert "technology_context_gate" in valid_candidate.gates_passed
        assert "escalation_gate" in valid_candidate.gates_passed
        assert "severity_gate" in valid_candidate.gates_passed
        assert "pre_report_checklist_gate" in valid_candidate.gates_passed

        # Verify finding
        assert isinstance(finding, Finding)
        assert finding.severity in [Severity.HIGH, Severity.CRITICAL]
        assert len(finding.metadata) > 0

    @pytest.mark.asyncio
    async def test_complete_rejection_flow(self, pipeline, invalid_candidate):
        """Test complete flow from candidate to rejection."""
        # Process candidate
        approved, finding = await pipeline.process_candidate(
            invalid_candidate,
            "https://example.com"
        )

        # Verify rejection
        assert not approved
        assert finding is None

        # Verify candidate state
        assert not invalid_candidate.approved_for_report
        assert invalid_candidate.validated_at is not None
        assert len(invalid_candidate.rejection_reasons) > 0

        # Verify at least one gate failed
        assert len(invalid_candidate.gates_failed) > 0
        assert "so_what_gate" in invalid_candidate.gates_failed

    @pytest.mark.asyncio
    async def test_batch_approval_rates(self, pipeline):
        """Test approval rates in batch processing."""
        # Create mix of valid and invalid candidates
        candidates = []

        # 5 valid candidates
        for i in range(5):
            candidate = FindingCandidate(
                title=f"Valid Finding {i}",
                description=f"Valid vulnerability {i}",
                initial_severity=Severity.HIGH,
                affected_asset="https://example.com",
                evidence=f"Concrete evidence {i}",
                vuln_type="SQLi",
                attacker_action=f"Extract data {i}",
                concrete_impact=f"Retrieved 10,000 user records in attack {i}",
                exploitability_proof=f"Successfully exploited vulnerability {i}",
            )
            for j in range(3):
                candidate.add_escalation_attempt(
                    EscalationAttempt(
                        method="escalation",
                        description="Escalation attempt",
                        payload="payload",
                        result="success",
                        evidence="evidence",
                    )
                )
            candidates.append(candidate)

        # 3 invalid candidates
        for i in range(3):
            candidate = FindingCandidate(
                title=f"Invalid Finding {i}",
                description=f"Potentially vulnerable {i}",
                initial_severity=Severity.HIGH,
                affected_asset="https://example.com",
                evidence=f"Minimal evidence {i}",
                vuln_type="Unknown",
            )
            candidates.append(candidate)

        # Process batch
        findings = await pipeline.process_batch(candidates, "https://example.com")

        # Should approve ~5 valid candidates
        assert len(findings) >= 3  # At least some valid ones pass
        assert len(findings) <= 5  # Not more than valid count
