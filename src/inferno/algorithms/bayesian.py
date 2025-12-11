"""
Bayesian Confidence System for Inferno.

Implements Bayesian inference for vulnerability prediction and
confidence scoring. Uses prior probabilities based on technology
stack and updates beliefs as evidence accumulates.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

from inferno.algorithms.base import AlgorithmState

logger = structlog.get_logger(__name__)


class EvidenceType(str, Enum):
    """Types of evidence that affect vulnerability confidence."""

    # Positive evidence (increases confidence)
    SQL_ERROR = "sql_error"              # Database error in response
    TIMING_DIFF = "timing_diff"          # Response time anomaly
    REFLECTION = "reflection"             # Input reflected in output
    STACK_TRACE = "stack_trace"          # Stack trace exposed
    DEBUG_HEADERS = "debug_headers"      # Debug headers present
    VERSION_LEAK = "version_leak"        # Software version exposed
    PATH_TRAVERSAL = "path_traversal"    # Path traversal indicators
    COMMAND_OUTPUT = "command_output"    # Command execution evidence
    FILE_CONTENT = "file_content"        # Sensitive file content
    AUTH_BYPASS = "auth_bypass"          # Authentication bypassed
    REDIRECT = "redirect"                # Open redirect confirmed
    SSRF_RESPONSE = "ssrf_response"      # SSRF callback received

    # Negative evidence (decreases confidence)
    WAF_BLOCK = "waf_block"              # WAF blocked the request
    RATE_LIMIT = "rate_limit"            # Rate limited
    INPUT_SANITIZED = "input_sanitized"  # Input was sanitized
    NO_CHANGE = "no_change"              # No observable change

    # Neutral/contextual evidence
    TECHNOLOGY = "technology"            # Tech stack detection
    ENDPOINT = "endpoint"                # Endpoint discovered
    PARAMETER = "parameter"              # Parameter found


class VulnerabilityType(str, Enum):
    """Vulnerability types to predict."""

    SQLI = "sqli"
    XSS = "xss"
    RCE = "rce"
    LFI = "lfi"
    SSRF = "ssrf"
    XXE = "xxe"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    OPEN_REDIRECT = "open_redirect"
    INFO_DISCLOSURE = "info_disclosure"
    DESERIALIZE = "deserialize"
    SSTI = "ssti"
    CSRF = "csrf"


class ConfidenceLevel(str, Enum):
    """Confidence levels for findings."""

    CONFIRMED = "confirmed"    # >= 0.9
    HIGH = "high"              # >= 0.7
    MEDIUM = "medium"          # >= 0.5
    LOW = "low"                # >= 0.3
    UNLIKELY = "unlikely"      # < 0.3


@dataclass
class VulnerabilityPrior:
    """Prior probability for a vulnerability type.

    Based on industry statistics (OWASP, CVE data, etc.)
    """
    vuln_type: VulnerabilityType
    base_prior: float  # Base probability without tech context

    # Technology-specific adjustments
    tech_priors: dict[str, float] = field(default_factory=dict)

    def get_prior(self, tech_stack: list[str] | None = None) -> float:
        """Get prior probability adjusted for tech stack."""
        prior = self.base_prior

        if tech_stack:
            for tech in tech_stack:
                tech_key = tech.lower()
                if tech_key in self.tech_priors:
                    # Use maximum of base and tech-specific prior
                    prior = max(prior, self.tech_priors[tech_key])

        return prior


# Industry-derived prior probabilities
VULNERABILITY_PRIORS: dict[VulnerabilityType, VulnerabilityPrior] = {
    VulnerabilityType.SQLI: VulnerabilityPrior(
        vuln_type=VulnerabilityType.SQLI,
        base_prior=0.08,
        tech_priors={
            "php": 0.15,
            "mysql": 0.12,
            "wordpress": 0.18,
            "asp": 0.10,
            "mssql": 0.12,
        }
    ),
    VulnerabilityType.XSS: VulnerabilityPrior(
        vuln_type=VulnerabilityType.XSS,
        base_prior=0.12,
        tech_priors={
            "php": 0.18,
            "javascript": 0.15,
            "react": 0.08,  # Lower due to JSX escaping
            "angular": 0.07,
            "vue": 0.08,
        }
    ),
    VulnerabilityType.RCE: VulnerabilityPrior(
        vuln_type=VulnerabilityType.RCE,
        base_prior=0.03,
        tech_priors={
            "php": 0.08,
            "java": 0.05,
            "python": 0.04,
            "node": 0.04,
        }
    ),
    VulnerabilityType.LFI: VulnerabilityPrior(
        vuln_type=VulnerabilityType.LFI,
        base_prior=0.05,
        tech_priors={
            "php": 0.12,
            "wordpress": 0.10,
            "java": 0.06,
        }
    ),
    VulnerabilityType.SSRF: VulnerabilityPrior(
        vuln_type=VulnerabilityType.SSRF,
        base_prior=0.04,
        tech_priors={
            "java": 0.08,
            "python": 0.06,
            "node": 0.05,
        }
    ),
    VulnerabilityType.XXE: VulnerabilityPrior(
        vuln_type=VulnerabilityType.XXE,
        base_prior=0.03,
        tech_priors={
            "java": 0.12,
            "php": 0.06,
            "dotnet": 0.08,
        }
    ),
    VulnerabilityType.IDOR: VulnerabilityPrior(
        vuln_type=VulnerabilityType.IDOR,
        base_prior=0.10,
        tech_priors={
            "api": 0.15,
            "rest": 0.14,
            "graphql": 0.12,
        }
    ),
    VulnerabilityType.DESERIALIZE: VulnerabilityPrior(
        vuln_type=VulnerabilityType.DESERIALIZE,
        base_prior=0.02,
        tech_priors={
            "java": 0.14,
            "php": 0.08,
            "python": 0.06,
            "dotnet": 0.10,
        }
    ),
    VulnerabilityType.SSTI: VulnerabilityPrior(
        vuln_type=VulnerabilityType.SSTI,
        base_prior=0.03,
        tech_priors={
            "python": 0.10,
            "jinja": 0.15,
            "flask": 0.12,
            "twig": 0.10,
            "php": 0.06,
        }
    ),
}

# Likelihood ratios for evidence types
# P(evidence | vulnerable) / P(evidence | not_vulnerable)
LIKELIHOOD_RATIOS: dict[EvidenceType, dict[VulnerabilityType, float]] = {
    EvidenceType.SQL_ERROR: {
        VulnerabilityType.SQLI: 50.0,
        VulnerabilityType.INFO_DISCLOSURE: 5.0,
    },
    EvidenceType.TIMING_DIFF: {
        VulnerabilityType.SQLI: 20.0,
        VulnerabilityType.RCE: 10.0,
    },
    EvidenceType.REFLECTION: {
        VulnerabilityType.XSS: 30.0,
        VulnerabilityType.SSTI: 15.0,
    },
    EvidenceType.STACK_TRACE: {
        VulnerabilityType.INFO_DISCLOSURE: 40.0,
        VulnerabilityType.RCE: 5.0,
    },
    EvidenceType.PATH_TRAVERSAL: {
        VulnerabilityType.LFI: 40.0,
        VulnerabilityType.RCE: 10.0,
    },
    EvidenceType.COMMAND_OUTPUT: {
        VulnerabilityType.RCE: 100.0,
    },
    EvidenceType.FILE_CONTENT: {
        VulnerabilityType.LFI: 80.0,
        VulnerabilityType.SSRF: 30.0,
    },
    EvidenceType.SSRF_RESPONSE: {
        VulnerabilityType.SSRF: 90.0,
    },
    EvidenceType.AUTH_BYPASS: {
        VulnerabilityType.AUTH_BYPASS: 100.0,
        VulnerabilityType.IDOR: 20.0,
    },
    EvidenceType.WAF_BLOCK: {
        # Decreases confidence (likelihood ratio < 1)
        VulnerabilityType.SQLI: 0.3,
        VulnerabilityType.XSS: 0.3,
        VulnerabilityType.RCE: 0.2,
    },
    EvidenceType.INPUT_SANITIZED: {
        VulnerabilityType.SQLI: 0.2,
        VulnerabilityType.XSS: 0.2,
    },
}


@dataclass
class EvidenceObservation:
    """An observed piece of evidence."""

    evidence_type: EvidenceType
    strength: float = 1.0  # Multiplier for likelihood ratio
    details: str = ""
    endpoint: str = ""
    parameter: str = ""


@dataclass
class VulnerabilityHypothesis:
    """Hypothesis about a vulnerability's existence."""

    vuln_type: VulnerabilityType
    endpoint: str
    parameter: str = ""

    # Bayesian state
    log_prior: float = 0.0
    log_likelihood: float = 0.0
    evidence_history: list[EvidenceObservation] = field(default_factory=list)

    @property
    def log_posterior(self) -> float:
        """Log posterior probability."""
        return self.log_prior + self.log_likelihood

    @property
    def posterior(self) -> float:
        """Posterior probability (0-1)."""
        # Convert from log-odds to probability
        try:
            return 1.0 / (1.0 + math.exp(-self.log_posterior))
        except OverflowError:
            return 1.0 if self.log_posterior > 0 else 0.0

    @property
    def confidence_level(self) -> ConfidenceLevel:
        """Get confidence level from posterior."""
        p = self.posterior
        if p >= 0.9:
            return ConfidenceLevel.CONFIRMED
        elif p >= 0.7:
            return ConfidenceLevel.HIGH
        elif p >= 0.5:
            return ConfidenceLevel.MEDIUM
        elif p >= 0.3:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.UNLIKELY

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "vuln_type": self.vuln_type.value,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "log_prior": self.log_prior,
            "log_likelihood": self.log_likelihood,
            "posterior": self.posterior,
            "confidence_level": self.confidence_level.value,
            "evidence_count": len(self.evidence_history),
        }


class BayesianConfidence:
    """Bayesian confidence system for vulnerability prediction.

    Uses Bayes' theorem to update confidence as evidence accumulates:

        P(vuln | evidence) ∝ P(evidence | vuln) × P(vuln)

    In log space for numerical stability:

        log P(vuln | E) = log P(vuln) + Σ log P(Ei | vuln) - log P(E)

    """

    def __init__(self, tech_stack: list[str] | None = None):
        """Initialize Bayesian confidence system.

        Args:
            tech_stack: Technology stack for prior adjustment
        """
        self._tech_stack = tech_stack or []
        self._hypotheses: dict[str, VulnerabilityHypothesis] = {}

    def _hypothesis_key(
        self,
        vuln_type: VulnerabilityType,
        endpoint: str,
        parameter: str = ""
    ) -> str:
        """Generate unique key for hypothesis."""
        return f"{vuln_type.value}:{endpoint}:{parameter}"

    def create_hypothesis(
        self,
        vuln_type: VulnerabilityType,
        endpoint: str,
        parameter: str = ""
    ) -> VulnerabilityHypothesis:
        """Create a new vulnerability hypothesis.

        Args:
            vuln_type: Type of vulnerability
            endpoint: Target endpoint
            parameter: Optional parameter name

        Returns:
            New or existing hypothesis
        """
        key = self._hypothesis_key(vuln_type, endpoint, parameter)

        if key in self._hypotheses:
            return self._hypotheses[key]

        # Get prior from industry data
        prior_data = VULNERABILITY_PRIORS.get(
            vuln_type,
            VulnerabilityPrior(vuln_type=vuln_type, base_prior=0.05)
        )
        prior_prob = prior_data.get_prior(self._tech_stack)

        # Convert to log-odds
        log_prior = math.log(prior_prob / (1 - prior_prob))

        hypothesis = VulnerabilityHypothesis(
            vuln_type=vuln_type,
            endpoint=endpoint,
            parameter=parameter,
            log_prior=log_prior,
        )

        self._hypotheses[key] = hypothesis

        logger.debug(
            "hypothesis_created",
            vuln_type=vuln_type.value,
            endpoint=endpoint,
            prior=prior_prob,
        )

        return hypothesis

    def update_with_evidence(
        self,
        vuln_type: VulnerabilityType,
        endpoint: str,
        evidence: EvidenceObservation,
        parameter: str = ""
    ) -> VulnerabilityHypothesis:
        """Update hypothesis with new evidence.

        Args:
            vuln_type: Vulnerability type
            endpoint: Target endpoint
            evidence: Observed evidence
            parameter: Optional parameter

        Returns:
            Updated hypothesis
        """
        hypothesis = self.create_hypothesis(vuln_type, endpoint, parameter)

        # Get likelihood ratio for this evidence
        lr = self._get_likelihood_ratio(evidence, vuln_type)

        # Update log-likelihood
        log_lr = math.log(lr * evidence.strength) if lr > 0 else -10.0
        hypothesis.log_likelihood += log_lr
        hypothesis.evidence_history.append(evidence)

        logger.debug(
            "evidence_updated",
            vuln_type=vuln_type.value,
            evidence=evidence.evidence_type.value,
            lr=lr,
            posterior=hypothesis.posterior,
        )

        return hypothesis

    def _get_likelihood_ratio(
        self,
        evidence: EvidenceObservation,
        vuln_type: VulnerabilityType
    ) -> float:
        """Get likelihood ratio for evidence given vulnerability type."""
        ratios = LIKELIHOOD_RATIOS.get(evidence.evidence_type, {})
        return ratios.get(vuln_type, 1.0)  # Default: no change

    def get_hypothesis(
        self,
        vuln_type: VulnerabilityType,
        endpoint: str,
        parameter: str = ""
    ) -> VulnerabilityHypothesis | None:
        """Get existing hypothesis."""
        key = self._hypothesis_key(vuln_type, endpoint, parameter)
        return self._hypotheses.get(key)

    def get_top_hypotheses(
        self,
        min_confidence: float = 0.3,
        limit: int = 10
    ) -> list[VulnerabilityHypothesis]:
        """Get top hypotheses by posterior probability.

        Args:
            min_confidence: Minimum posterior to include
            limit: Maximum number to return

        Returns:
            List of hypotheses sorted by posterior
        """
        filtered = [
            h for h in self._hypotheses.values()
            if h.posterior >= min_confidence
        ]

        sorted_hyps = sorted(filtered, key=lambda h: h.posterior, reverse=True)
        return sorted_hyps[:limit]

    def get_best_attack_targets(
        self,
        vuln_types: list[VulnerabilityType] | None = None
    ) -> list[tuple[str, VulnerabilityType, float]]:
        """Get best attack targets based on posterior probabilities.

        Args:
            vuln_types: Filter to specific vulnerability types

        Returns:
            List of (endpoint, vuln_type, probability) tuples
        """
        targets = []

        for hypothesis in self._hypotheses.values():
            if vuln_types and hypothesis.vuln_type not in vuln_types:
                continue

            targets.append((
                hypothesis.endpoint,
                hypothesis.vuln_type,
                hypothesis.posterior,
            ))

        return sorted(targets, key=lambda x: x[2], reverse=True)

    def calculate_information_gain(
        self,
        evidence_type: EvidenceType,
        endpoint: str,
        vuln_type: VulnerabilityType
    ) -> float:
        """Calculate expected information gain from testing.

        Uses entropy reduction to estimate value of testing.

        Args:
            evidence_type: Type of evidence test would produce
            endpoint: Endpoint to test
            vuln_type: Vulnerability type

        Returns:
            Expected information gain in bits
        """
        hypothesis = self.get_hypothesis(vuln_type, endpoint)
        if not hypothesis:
            hypothesis = self.create_hypothesis(vuln_type, endpoint)

        p = hypothesis.posterior

        # Current entropy
        if p <= 0 or p >= 1:
            return 0.0

        current_entropy = -p * math.log2(p) - (1-p) * math.log2(1-p)

        # Get likelihood ratio
        lr = LIKELIHOOD_RATIOS.get(evidence_type, {}).get(vuln_type, 1.0)

        # Expected posterior if positive evidence
        lr_positive = lr
        p_positive = (lr_positive * p) / (lr_positive * p + (1 - p))

        # Expected posterior if negative evidence
        lr_negative = 1.0 / lr if lr > 0 else 10.0
        p_negative = (lr_negative * p) / (lr_negative * p + (1 - p))

        # Expected entropy after test
        # Assume 50% chance of each outcome for simplicity
        entropy_positive = 0.0
        if 0 < p_positive < 1:
            entropy_positive = -p_positive * math.log2(p_positive) - (1-p_positive) * math.log2(1-p_positive)

        entropy_negative = 0.0
        if 0 < p_negative < 1:
            entropy_negative = -p_negative * math.log2(p_negative) - (1-p_negative) * math.log2(1-p_negative)

        expected_entropy = 0.5 * entropy_positive + 0.5 * entropy_negative

        return current_entropy - expected_entropy

    def set_tech_stack(self, tech_stack: list[str]) -> None:
        """Update technology stack."""
        self._tech_stack = tech_stack

    def get_state(self) -> AlgorithmState:
        """Get persistable state."""
        return AlgorithmState(
            algorithm_name="BayesianConfidence",
            parameters={"tech_stack": self._tech_stack},
            history=[h.to_dict() for h in self._hypotheses.values()],
        )

    def load_state(self, state: AlgorithmState) -> None:
        """Load state from persistence."""
        self._tech_stack = state.parameters.get("tech_stack", [])
        self._hypotheses = {}

        for item in state.history:
            try:
                vuln_type = VulnerabilityType(item["vuln_type"])
                hypothesis = VulnerabilityHypothesis(
                    vuln_type=vuln_type,
                    endpoint=item["endpoint"],
                    parameter=item.get("parameter", ""),
                    log_prior=item.get("log_prior", 0.0),
                    log_likelihood=item.get("log_likelihood", 0.0),
                )
                key = self._hypothesis_key(vuln_type, item["endpoint"], item.get("parameter", ""))
                self._hypotheses[key] = hypothesis
            except (KeyError, ValueError) as e:
                logger.warning("hypothesis_load_failed", error=str(e))


def extract_evidence_from_response(
    response_text: str,
    status_code: int,
    response_time: float,
    baseline_time: float = 0.5
) -> list[EvidenceObservation]:
    """Extract evidence observations from HTTP response.

    Args:
        response_text: Response body text
        status_code: HTTP status code
        response_time: Response time in seconds
        baseline_time: Baseline response time for comparison

    Returns:
        List of extracted evidence observations
    """
    evidence = []
    response_lower = response_text.lower()

    # SQL error patterns
    sql_patterns = [
        "sql syntax", "mysql", "postgresql", "sqlite", "oracle",
        "syntax error", "unclosed quotation", "odbc", "jdbc",
    ]
    if any(pattern in response_lower for pattern in sql_patterns):
        evidence.append(EvidenceObservation(
            evidence_type=EvidenceType.SQL_ERROR,
            strength=1.0,
            details="SQL error pattern detected",
        ))

    # Stack trace patterns
    if any(pattern in response_lower for pattern in [
        "traceback", "stack trace", "exception", "at line",
        "caused by:", "exception in thread",
    ]):
        evidence.append(EvidenceObservation(
            evidence_type=EvidenceType.STACK_TRACE,
            strength=1.0,
            details="Stack trace detected",
        ))

    # Timing analysis
    if response_time > baseline_time * 3:
        strength = min(2.0, (response_time - baseline_time) / baseline_time)
        evidence.append(EvidenceObservation(
            evidence_type=EvidenceType.TIMING_DIFF,
            strength=strength,
            details=f"Response time {response_time:.2f}s vs baseline {baseline_time:.2f}s",
        ))

    # WAF detection
    waf_patterns = [
        "access denied", "blocked", "forbidden", "waf",
        "security", "firewall", "not allowed",
    ]
    if status_code == 403 or any(pattern in response_lower for pattern in waf_patterns):
        evidence.append(EvidenceObservation(
            evidence_type=EvidenceType.WAF_BLOCK,
            strength=1.0,
            details="WAF or security block detected",
        ))

    # File content patterns (LFI)
    if any(pattern in response_text for pattern in [
        "root:", "/bin/bash", "[boot loader]", "<?php",
    ]):
        evidence.append(EvidenceObservation(
            evidence_type=EvidenceType.FILE_CONTENT,
            strength=1.0,
            details="Sensitive file content detected",
        ))

    return evidence
