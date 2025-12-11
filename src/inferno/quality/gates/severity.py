"""
SeverityGate - Validates and adjusts severity ratings.

This gate ensures severity ratings are accurate based on impact,
exploitability, and language used in the finding.
"""

from __future__ import annotations

from typing import Any

from inferno.quality.candidate import FindingCandidate
from inferno.quality.config import QualityConfig
from inferno.quality.gate import QualityGate
from inferno.reporting.models import Severity


class SeverityGate(QualityGate):
    """
    Validates and adjusts severity ratings.

    This gate ensures severity ratings accurately reflect the finding's
    impact and exploitability:
    1. Validates severity against impact criteria
    2. Demotes theoretical findings (those with vague language)
    3. Boosts severity for successful escalations
    4. Applies context-specific severity adjustments

    Severity Criteria:
        CRITICAL:
            - Remote Code Execution (RCE)
            - Authentication bypass
            - Private key/credential exposure
            - Mass data breach

        HIGH:
            - Privilege escalation
            - Access to other user data
            - Admin access
            - SQL injection with data access

        MEDIUM:
            - Sensitive data exposure
            - SSRF to internal network
            - Stored XSS
            - SQL injection (limited impact)

        LOW:
            - Information disclosure (non-sensitive)
            - Reflected XSS
            - CSRF
            - Security misconfigurations

        INFO:
            - Stack traces
            - Version disclosure
            - Error messages
            - Public API documentation

    Gate Properties:
        - Blocking: False (provides guidance but doesn't reject)
        - Weight: 0.15 (moderate importance)
    """

    # Critical severity indicators
    CRITICAL_INDICATORS = [
        "rce",
        "remote code execution",
        "auth bypass",
        "authentication bypass",
        "private key",
        "secret key",
        "aws key",
        "mass breach",
        "database dump",
        "full database",
        "admin takeover",
        "complete compromise",
    ]

    # High severity indicators
    HIGH_INDICATORS = [
        "privilege escalation",
        "privesc",
        "other user data",
        "admin access",
        "sqli",
        "sql injection",
        "xxe",
        "idor",
        "account takeover",
        "password reset",
        "session hijack",
    ]

    # Medium severity indicators
    MEDIUM_INDICATORS = [
        "sensitive data",
        "ssrf",
        "server-side request forgery",
        "stored xss",
        "persistent xss",
        "csrf",
        "cross-site request forgery",
        "open redirect",
        "security misconfiguration",
    ]

    # Low severity indicators
    LOW_INDICATORS = [
        "reflected xss",
        "cors misconfiguration",
        "missing security header",
        "clickjacking",
        "information disclosure",
        "directory listing",
        "path disclosure",
    ]

    # Info severity indicators
    INFO_INDICATORS = [
        "stack trace",
        "version disclosure",
        "error message",
        "debug info",
        "public api",
        "api documentation",
        "swagger",
        "openapi",
    ]

    def __init__(self, config: QualityConfig | None = None) -> None:
        """
        Initialize SeverityGate.

        Args:
            config: Quality configuration (uses default if None)
        """
        super().__init__(
            name="severity_gate",
            weight=0.15,
            is_blocking=False,
            description="Validates and adjusts severity ratings based on impact and exploitability",
        )
        self.config = config or QualityConfig()

    async def evaluate(
        self, candidate: FindingCandidate, target: str, **kwargs: Any
    ) -> tuple[bool, str]:
        """
        Evaluate and adjust finding severity.

        Args:
            candidate: Finding candidate to evaluate
            target: Target URL/hostname (not used in this gate)
            **kwargs: Additional parameters (not used)

        Returns:
            Tuple of (passed: bool, message: str)
        """
        # Start with initial or already-adjusted severity
        current_severity = (
            candidate.adjusted_severity if candidate.adjusted_severity else candidate.initial_severity
        )

        # Validate severity against criteria
        suggested_severity = self._suggest_severity(candidate)

        # Apply theoretical language penalty
        if candidate.has_theoretical_language and self.config.demote_theoretical_findings:
            penalty_levels = self.config.theoretical_severity_demote
            current_severity = self._demote_severity(current_severity, penalty_levels)
            if not candidate.severity_rationale:
                candidate.severity_rationale = (
                    f"Demoted {penalty_levels} level(s) due to theoretical/hypothetical language"
                )

        # Apply escalation success boost
        if candidate.has_successful_escalation:
            # Boost by one level if successful escalation
            current_severity = self._promote_severity(current_severity, 1)
            if candidate.severity_rationale:
                candidate.severity_rationale += " | Increased due to successful escalation"
            else:
                candidate.severity_rationale = "Increased one level due to successful escalation"

        # Use suggested severity if significantly different from current
        if suggested_severity and suggested_severity != current_severity:
            # Only override if suggested is higher or current is clearly wrong
            severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            current_idx = severity_order.index(current_severity)
            suggested_idx = severity_order.index(suggested_severity)

            if suggested_idx > current_idx:
                # Suggested is higher, use it
                current_severity = suggested_severity
                if candidate.severity_rationale:
                    candidate.severity_rationale += f" | Adjusted to {suggested_severity.value} based on impact criteria"
                else:
                    candidate.severity_rationale = f"Adjusted to {suggested_severity.value} based on impact criteria"

        # Update candidate severity if changed
        if current_severity != candidate.initial_severity:
            candidate.adjusted_severity = current_severity

        # Build message
        if candidate.adjusted_severity:
            message = (
                f"Severity adjusted: {candidate.initial_severity.value} -> "
                f"{candidate.adjusted_severity.value} | {candidate.severity_rationale}"
            )
        else:
            message = f"Severity validated: {candidate.initial_severity.value} is appropriate"

        return True, message

    def _suggest_severity(self, candidate: FindingCandidate) -> Severity | None:
        """
        Suggest severity based on impact criteria.

        Args:
            candidate: Finding candidate to analyze

        Returns:
            Suggested severity or None if current is appropriate
        """
        # Combine text for analysis
        text = " ".join(
            [
                candidate.title,
                candidate.description,
                candidate.vuln_type,
                candidate.concrete_impact,
                candidate.attacker_action,
            ]
        ).lower()

        # Check for critical indicators
        if any(indicator in text for indicator in self.CRITICAL_INDICATORS):
            return Severity.CRITICAL

        # Check for high indicators
        if any(indicator in text for indicator in self.HIGH_INDICATORS):
            return Severity.HIGH

        # Check for medium indicators
        if any(indicator in text for indicator in self.MEDIUM_INDICATORS):
            return Severity.MEDIUM

        # Check for low indicators
        if any(indicator in text for indicator in self.LOW_INDICATORS):
            return Severity.LOW

        # Check for info indicators
        if any(indicator in text for indicator in self.INFO_INDICATORS):
            return Severity.INFO

        return None

    def _demote_severity(self, severity: Severity, levels: int) -> Severity:
        """
        Demote severity by specified number of levels.

        Args:
            severity: Current severity
            levels: Number of levels to demote

        Returns:
            Demoted severity (won't go below INFO)
        """
        severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        current_idx = severity_order.index(severity)
        new_idx = max(0, current_idx - levels)
        return severity_order[new_idx]

    def _promote_severity(self, severity: Severity, levels: int) -> Severity:
        """
        Promote severity by specified number of levels.

        Args:
            severity: Current severity
            levels: Number of levels to promote

        Returns:
            Promoted severity (won't go above CRITICAL)
        """
        severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        current_idx = severity_order.index(severity)
        new_idx = min(len(severity_order) - 1, current_idx + levels)
        return severity_order[new_idx]
