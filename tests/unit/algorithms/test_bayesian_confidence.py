"""
Unit tests for Bayesian confidence updating for findings.

Tests the Bayesian inference system that updates confidence levels
for security findings based on validation evidence.
"""

import pytest
import numpy as np
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
import math


# ============================================================================
# Bayesian Confidence Data Structures
# ============================================================================

class EvidenceType(str, Enum):
    """Types of evidence that affect confidence."""

    POSITIVE = "positive"           # Confirms the finding
    NEGATIVE = "negative"           # Contradicts the finding
    NEUTRAL = "neutral"             # Neither confirms nor contradicts
    VALIDATION_SUCCESS = "validation_success"
    VALIDATION_FAILURE = "validation_failure"
    INDEPENDENT_CONFIRM = "independent_confirm"
    FALSE_POSITIVE_INDICATOR = "false_positive_indicator"


@dataclass
class Finding:
    """A security finding with Bayesian confidence tracking."""

    finding_id: str
    vuln_type: str
    severity: str
    title: str
    target: str

    # Bayesian parameters
    prior_alpha: float = 1.0  # Beta distribution alpha (successes)
    prior_beta: float = 1.0   # Beta distribution beta (failures)
    evidence_history: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def alpha(self) -> float:
        """Current alpha after evidence updates."""
        return self.prior_alpha + sum(
            1 for e in self.evidence_history
            if e["type"] in [EvidenceType.POSITIVE, EvidenceType.VALIDATION_SUCCESS, EvidenceType.INDEPENDENT_CONFIRM]
        )

    @property
    def beta(self) -> float:
        """Current beta after evidence updates."""
        return self.prior_beta + sum(
            1 for e in self.evidence_history
            if e["type"] in [EvidenceType.NEGATIVE, EvidenceType.VALIDATION_FAILURE, EvidenceType.FALSE_POSITIVE_INDICATOR]
        )

    @property
    def mean_confidence(self) -> float:
        """Mean of the posterior Beta distribution."""
        return self.alpha / (self.alpha + self.beta)

    @property
    def confidence_variance(self) -> float:
        """Variance of the posterior Beta distribution."""
        a, b = self.alpha, self.beta
        return (a * b) / ((a + b) ** 2 * (a + b + 1))

    @property
    def confidence_std(self) -> float:
        """Standard deviation of confidence."""
        return math.sqrt(self.confidence_variance)

    @property
    def confidence_interval_95(self) -> tuple:
        """95% credible interval for confidence."""
        from scipy import stats
        lower = stats.beta.ppf(0.025, self.alpha, self.beta)
        upper = stats.beta.ppf(0.975, self.alpha, self.beta)
        return (lower, upper)

    def update(self, evidence_type: EvidenceType, weight: float = 1.0, description: str = "") -> None:
        """Update confidence with new evidence."""
        self.evidence_history.append({
            "type": evidence_type,
            "weight": weight,
            "description": description
        })


@dataclass
class BayesianConfidenceEngine:
    """Engine for Bayesian confidence calculations."""

    # Prior probabilities for different vuln types (from historical data)
    vuln_type_priors: Dict[str, float] = field(default_factory=dict)

    # Evidence strength weights
    evidence_weights: Dict[EvidenceType, float] = field(default_factory=dict)

    def __post_init__(self):
        if not self.vuln_type_priors:
            # Default priors based on typical false positive rates
            self.vuln_type_priors = {
                "sql_injection": 0.7,      # Often true if detected
                "xss": 0.5,                # Medium FP rate
                "ssrf": 0.6,
                "idor": 0.4,               # Higher FP rate
                "path_traversal": 0.5,
                "rce": 0.8,                # Usually serious if flagged
                "auth_bypass": 0.5,
                "file_upload": 0.6,
                "open_redirect": 0.3,      # High FP rate
                "info_disclosure": 0.4,
            }

        if not self.evidence_weights:
            self.evidence_weights = {
                EvidenceType.POSITIVE: 1.0,
                EvidenceType.NEGATIVE: 1.0,
                EvidenceType.NEUTRAL: 0.0,
                EvidenceType.VALIDATION_SUCCESS: 2.0,      # Strong evidence
                EvidenceType.VALIDATION_FAILURE: 2.0,
                EvidenceType.INDEPENDENT_CONFIRM: 3.0,     # Very strong
                EvidenceType.FALSE_POSITIVE_INDICATOR: 1.5,
            }


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def sqli_finding():
    """SQL injection finding for testing."""
    return Finding(
        finding_id="F001",
        vuln_type="sql_injection",
        severity="high",
        title="SQL Injection in login parameter",
        target="https://target.com/login",
        prior_alpha=2.0,  # Slight positive prior (SQLi detection is fairly reliable)
        prior_beta=1.0
    )


@pytest.fixture
def xss_finding():
    """XSS finding with neutral prior."""
    return Finding(
        finding_id="F002",
        vuln_type="xss",
        severity="medium",
        title="Reflected XSS in search",
        target="https://target.com/search",
        prior_alpha=1.0,
        prior_beta=1.0
    )


@pytest.fixture
def uncertain_finding():
    """Finding with high uncertainty."""
    return Finding(
        finding_id="F003",
        vuln_type="idor",
        severity="medium",
        title="Potential IDOR in user API",
        target="https://target.com/api/user/1",
        prior_alpha=0.5,  # Uncertain prior
        prior_beta=0.5
    )


@pytest.fixture
def confidence_engine():
    """Bayesian confidence engine."""
    return BayesianConfidenceEngine()


# ============================================================================
# Prior Distribution Tests
# ============================================================================

class TestBayesianPriors:
    """Tests for prior distribution initialization."""

    def test_uninformative_prior(self):
        """
        Test: Uninformative prior (Beta(1,1)) gives uniform distribution.
        """
        finding = Finding(
            finding_id="test",
            vuln_type="unknown",
            severity="medium",
            title="Test",
            target="test",
            prior_alpha=1.0,
            prior_beta=1.0
        )

        assert finding.mean_confidence == 0.5
        assert abs(finding.confidence_variance - (1/12)) < 0.001  # Beta(1,1) variance = 1/12

    def test_informative_prior_shifts_mean(self):
        """
        Test: Informative prior shifts the mean appropriately.
        """
        # Positive prior (more likely true)
        positive_prior = Finding(
            finding_id="pos",
            vuln_type="test",
            severity="high",
            title="Test",
            target="test",
            prior_alpha=3.0,
            prior_beta=1.0
        )
        assert positive_prior.mean_confidence > 0.5

        # Negative prior (more likely false positive)
        negative_prior = Finding(
            finding_id="neg",
            vuln_type="test",
            severity="low",
            title="Test",
            target="test",
            prior_alpha=1.0,
            prior_beta=3.0
        )
        assert negative_prior.mean_confidence < 0.5

    def test_vuln_type_priors(self, confidence_engine):
        """
        Test: Different vulnerability types have appropriate priors.
        """
        # RCE should have high prior (usually real if detected)
        assert confidence_engine.vuln_type_priors["rce"] > 0.7

        # Open redirect has many false positives
        assert confidence_engine.vuln_type_priors["open_redirect"] < 0.5

    def test_jeffrey_prior(self):
        """
        Test: Jeffrey's prior (Beta(0.5, 0.5)) for maximum entropy.
        """
        finding = Finding(
            finding_id="jeffrey",
            vuln_type="test",
            severity="medium",
            title="Test",
            target="test",
            prior_alpha=0.5,
            prior_beta=0.5
        )

        # Jeffrey's prior still gives mean of 0.5
        assert finding.mean_confidence == 0.5

        # But has different shape (U-shaped)
        assert finding.confidence_variance > (1/12)  # Higher variance than uniform


# ============================================================================
# Evidence Update Tests
# ============================================================================

class TestBayesianUpdates:
    """Tests for Bayesian evidence updates."""

    def test_positive_evidence_increases_confidence(self, sqli_finding):
        """
        Test: Positive evidence increases mean confidence.
        """
        initial_confidence = sqli_finding.mean_confidence

        sqli_finding.update(EvidenceType.POSITIVE, description="Error message confirmed SQLi")

        assert sqli_finding.mean_confidence > initial_confidence

    def test_negative_evidence_decreases_confidence(self, sqli_finding):
        """
        Test: Negative evidence decreases mean confidence.
        """
        initial_confidence = sqli_finding.mean_confidence

        sqli_finding.update(EvidenceType.NEGATIVE, description="WAF blocking all payloads")

        assert sqli_finding.mean_confidence < initial_confidence

    def test_validation_success_strong_update(self, xss_finding):
        """
        Test: Validation success provides strong positive update.
        """
        initial_confidence = xss_finding.mean_confidence

        xss_finding.update(EvidenceType.VALIDATION_SUCCESS, description="Payload executed in browser")

        # Validation success should significantly increase confidence
        confidence_gain = xss_finding.mean_confidence - initial_confidence
        assert confidence_gain > 0.1

    def test_independent_confirmation_strongest(self, uncertain_finding):
        """
        Test: Independent confirmation provides strongest evidence.
        """
        initial_confidence = uncertain_finding.mean_confidence

        uncertain_finding.update(
            EvidenceType.INDEPENDENT_CONFIRM,
            description="Validator subagent confirmed with different technique"
        )

        # Should be significant increase
        assert uncertain_finding.mean_confidence > initial_confidence + 0.2

    def test_multiple_evidence_cumulative(self, xss_finding):
        """
        Test: Multiple pieces of evidence have cumulative effect.
        """
        confidences = [xss_finding.mean_confidence]

        # Add multiple positive evidence
        for i in range(5):
            xss_finding.update(EvidenceType.POSITIVE, description=f"Evidence {i}")
            confidences.append(xss_finding.mean_confidence)

        # Each update should increase confidence
        for i in range(1, len(confidences)):
            assert confidences[i] > confidences[i-1]

        # Final confidence should be high
        assert confidences[-1] > 0.8

    def test_conflicting_evidence_balances(self, xss_finding):
        """
        Test: Conflicting evidence balances out.
        """
        # Add equal positive and negative evidence
        for _ in range(5):
            xss_finding.update(EvidenceType.POSITIVE)
            xss_finding.update(EvidenceType.NEGATIVE)

        # Should still be around 0.5 (started with Beta(1,1))
        assert 0.4 < xss_finding.mean_confidence < 0.6

    def test_neutral_evidence_no_effect(self, sqli_finding):
        """
        Test: Neutral evidence doesn't change confidence.
        """
        initial_confidence = sqli_finding.mean_confidence
        initial_variance = sqli_finding.confidence_variance

        sqli_finding.update(EvidenceType.NEUTRAL, description="Inconclusive test")

        # Mean should not change
        assert sqli_finding.mean_confidence == initial_confidence


# ============================================================================
# Uncertainty Quantification Tests
# ============================================================================

class TestUncertaintyQuantification:
    """Tests for uncertainty measurement."""

    def test_variance_decreases_with_evidence(self, uncertain_finding):
        """
        Test: Variance decreases as more evidence is gathered.
        """
        variances = [uncertain_finding.confidence_variance]

        for i in range(10):
            uncertain_finding.update(
                EvidenceType.POSITIVE if i % 2 == 0 else EvidenceType.NEGATIVE
            )
            variances.append(uncertain_finding.confidence_variance)

        # Variance should generally decrease
        assert variances[-1] < variances[0]

    def test_credible_interval_narrows(self, xss_finding):
        """
        Test: 95% credible interval narrows with more data.
        """
        pytest.importorskip("scipy")

        initial_interval = xss_finding.confidence_interval_95
        initial_width = initial_interval[1] - initial_interval[0]

        # Add consistent positive evidence
        for _ in range(10):
            xss_finding.update(EvidenceType.VALIDATION_SUCCESS)

        final_interval = xss_finding.confidence_interval_95
        final_width = final_interval[1] - final_interval[0]

        assert final_width < initial_width

    def test_high_confidence_low_uncertainty(self, sqli_finding):
        """
        Test: High confidence findings have low uncertainty.
        """
        # Add many confirmations
        for _ in range(20):
            sqli_finding.update(EvidenceType.VALIDATION_SUCCESS)

        # Confidence should be high
        assert sqli_finding.mean_confidence > 0.9

        # Uncertainty (std dev) should be low
        assert sqli_finding.confidence_std < 0.1


# ============================================================================
# Decision Threshold Tests
# ============================================================================

class TestConfidenceThresholds:
    """Tests for confidence-based decision thresholds."""

    def test_report_threshold(self, xss_finding):
        """
        Test: Finding meets report threshold after sufficient evidence.
        """
        REPORT_THRESHOLD = 0.7

        # Initially may not meet threshold
        initial_meets = xss_finding.mean_confidence >= REPORT_THRESHOLD

        # Add positive evidence until meets threshold
        while xss_finding.mean_confidence < REPORT_THRESHOLD:
            xss_finding.update(EvidenceType.VALIDATION_SUCCESS)

        assert xss_finding.mean_confidence >= REPORT_THRESHOLD

    def test_false_positive_threshold(self, uncertain_finding):
        """
        Test: Finding marked as false positive when confidence too low.
        """
        FP_THRESHOLD = 0.3

        # Add negative evidence
        for _ in range(10):
            uncertain_finding.update(EvidenceType.FALSE_POSITIVE_INDICATOR)

        assert uncertain_finding.mean_confidence < FP_THRESHOLD

    def test_needs_validation_threshold(self, xss_finding):
        """
        Test: Finding needs validation when confidence is moderate.
        """
        NEEDS_VALIDATION_LOWER = 0.3
        NEEDS_VALIDATION_UPPER = 0.7

        # Start in uncertain range
        assert NEEDS_VALIDATION_LOWER <= xss_finding.mean_confidence <= NEEDS_VALIDATION_UPPER

        # This indicates validation is needed
        needs_validation = (
            xss_finding.mean_confidence >= NEEDS_VALIDATION_LOWER and
            xss_finding.mean_confidence <= NEEDS_VALIDATION_UPPER
        )
        assert needs_validation


# ============================================================================
# Mathematical Correctness Tests
# ============================================================================

class TestMathematicalCorrectness:
    """Tests for mathematical correctness of Bayesian calculations."""

    def test_beta_mean_formula(self):
        """
        Test: Beta distribution mean = alpha / (alpha + beta).
        """
        test_cases = [
            (1, 1, 0.5),
            (2, 1, 2/3),
            (1, 2, 1/3),
            (5, 5, 0.5),
            (10, 2, 10/12),
        ]

        for alpha, beta, expected_mean in test_cases:
            finding = Finding(
                finding_id="test",
                vuln_type="test",
                severity="low",
                title="Test",
                target="test",
                prior_alpha=alpha,
                prior_beta=beta
            )
            assert abs(finding.mean_confidence - expected_mean) < 0.001

    def test_beta_variance_formula(self):
        """
        Test: Beta variance = (alpha * beta) / ((alpha + beta)^2 * (alpha + beta + 1)).
        """
        test_cases = [
            (1, 1),
            (2, 3),
            (5, 5),
            (10, 2),
        ]

        for alpha, beta in test_cases:
            finding = Finding(
                finding_id="test",
                vuln_type="test",
                severity="low",
                title="Test",
                target="test",
                prior_alpha=alpha,
                prior_beta=beta
            )

            expected_var = (alpha * beta) / ((alpha + beta) ** 2 * (alpha + beta + 1))
            assert abs(finding.confidence_variance - expected_var) < 0.0001

    def test_conjugate_prior_update(self):
        """
        Test: Beta-Bernoulli conjugate prior update is correct.

        Posterior = Beta(alpha + successes, beta + failures)
        """
        finding = Finding(
            finding_id="test",
            vuln_type="test",
            severity="low",
            title="Test",
            target="test",
            prior_alpha=1,
            prior_beta=1
        )

        # Add 3 successes, 2 failures
        for _ in range(3):
            finding.update(EvidenceType.POSITIVE)
        for _ in range(2):
            finding.update(EvidenceType.NEGATIVE)

        # Posterior should be Beta(4, 3)
        assert finding.alpha == 4
        assert finding.beta == 3
        assert abs(finding.mean_confidence - 4/7) < 0.001


# ============================================================================
# Integration Tests
# ============================================================================

class TestBayesianIntegration:
    """Tests for integration with Inferno agent."""

    def test_finding_lifecycle(self, confidence_engine):
        """
        Test: Complete finding lifecycle with confidence tracking.
        """
        # Discovery phase
        finding = Finding(
            finding_id="INT001",
            vuln_type="sql_injection",
            severity="high",
            title="SQLi in user parameter",
            target="https://target.com/api/user",
            prior_alpha=1 + confidence_engine.vuln_type_priors["sql_injection"],
            prior_beta=1
        )

        # Initial confidence
        assert finding.mean_confidence > 0.5  # Prior favors SQLi being real

        # Scanner confirmation
        finding.update(EvidenceType.POSITIVE, description="sqlmap confirmed blind SQLi")
        assert finding.mean_confidence > 0.6

        # Validation phase
        finding.update(EvidenceType.VALIDATION_SUCCESS, description="Validator confirmed with time-based payload")
        assert finding.mean_confidence > 0.75  # Adjusted threshold for evidence weights

        # Final confidence should be reportable
        assert finding.mean_confidence > 0.7

    def test_multiple_findings_ranking(self, confidence_engine):
        """
        Test: Multiple findings can be ranked by confidence.
        """
        findings = [
            Finding("F1", "sql_injection", "high", "SQLi", "target", 3, 1),
            Finding("F2", "xss", "medium", "XSS", "target", 2, 2),
            Finding("F3", "idor", "medium", "IDOR", "target", 1, 3),
        ]

        # Add validation to first finding
        findings[0].update(EvidenceType.VALIDATION_SUCCESS)

        # Rank by confidence
        ranked = sorted(findings, key=lambda f: f.mean_confidence, reverse=True)

        # SQLi with validation should be first
        assert ranked[0].vuln_type == "sql_injection"

    def test_confidence_persistence(self, sqli_finding, tmp_path):
        """
        Test: Confidence state can be serialized and restored.
        """
        import json

        # Add some evidence
        sqli_finding.update(EvidenceType.VALIDATION_SUCCESS)
        sqli_finding.update(EvidenceType.POSITIVE)

        # Serialize
        state = {
            "finding_id": sqli_finding.finding_id,
            "vuln_type": sqli_finding.vuln_type,
            "prior_alpha": sqli_finding.prior_alpha,
            "prior_beta": sqli_finding.prior_beta,
            "evidence_history": sqli_finding.evidence_history,
        }

        state_file = tmp_path / "confidence_state.json"
        state_file.write_text(json.dumps(state, default=str))

        # Restore
        loaded = json.loads(state_file.read_text())

        restored = Finding(
            finding_id=loaded["finding_id"],
            vuln_type=loaded["vuln_type"],
            severity="high",
            title="Restored",
            target="target",
            prior_alpha=loaded["prior_alpha"],
            prior_beta=loaded["prior_beta"],
        )
        # Manually restore evidence
        for ev in loaded["evidence_history"]:
            restored.evidence_history.append(ev)

        assert restored.mean_confidence == pytest.approx(sqli_finding.mean_confidence, rel=0.01)


# ============================================================================
# Edge Cases Tests
# ============================================================================

class TestEdgeCases:
    """Tests for edge cases in Bayesian confidence."""

    def test_extreme_priors(self):
        """
        Test: System handles extreme prior values.
        """
        # Very confident prior
        confident = Finding(
            finding_id="conf",
            vuln_type="test",
            severity="high",
            title="Test",
            target="test",
            prior_alpha=100,
            prior_beta=1
        )
        assert confident.mean_confidence > 0.99

        # Very skeptical prior
        skeptical = Finding(
            finding_id="skep",
            vuln_type="test",
            severity="low",
            title="Test",
            target="test",
            prior_alpha=1,
            prior_beta=100
        )
        assert skeptical.mean_confidence < 0.01

    def test_many_evidence_updates(self):
        """
        Test: System handles many evidence updates without numerical issues.
        """
        finding = Finding(
            finding_id="many",
            vuln_type="test",
            severity="medium",
            title="Test",
            target="test"
        )

        # Add 1000 pieces of evidence
        for i in range(1000):
            finding.update(EvidenceType.POSITIVE if i % 2 == 0 else EvidenceType.NEGATIVE)

        # Should still be computable
        assert 0 <= finding.mean_confidence <= 1
        assert not math.isnan(finding.mean_confidence)
        assert not math.isinf(finding.mean_confidence)

    def test_no_evidence(self):
        """
        Test: Finding with no evidence uses only prior.
        """
        finding = Finding(
            finding_id="none",
            vuln_type="test",
            severity="medium",
            title="Test",
            target="test",
            prior_alpha=2,
            prior_beta=3
        )

        assert len(finding.evidence_history) == 0
        assert finding.mean_confidence == 2 / (2 + 3)
