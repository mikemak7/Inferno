"""
Generic web technology context for quality gate system.

This module implements generic web application filtering rules to prevent
common false positives and adjust severity ratings appropriately.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from inferno.quality.contexts.base import BaseTechnologyContext
from inferno.reporting.models import Severity

if TYPE_CHECKING:
    from inferno.quality.candidate import ContextAdjustment, FindingCandidate


class GenericWebContext(BaseTechnologyContext):
    """
    Generic web application technology context.

    Provides severity overrides for common web findings that are often
    over-reported or mis-rated:
    - Stack traces → LOW (unless credentials exposed)
    - Version disclosure → INFO
    - X-Powered-By header → INFO
    - Debug mode → LOW (unless credentials exposed)
    - Error messages → INFO
    - Technology disclosure → INFO
    """

    # Pattern definitions
    STACK_TRACE_PATTERNS = [
        re.compile(r"at\s+[\w.$]+\(.*?:\d+:\d+\)", re.IGNORECASE),
        re.compile(r"File\s+[\"'].*?[\"'],\s+line\s+\d+", re.IGNORECASE),
        re.compile(r"Traceback\s+\(most recent call last\)", re.IGNORECASE),
        re.compile(r"Exception\s+in\s+thread", re.IGNORECASE),
        re.compile(r"\.java:\d+\)", re.IGNORECASE),
        re.compile(r"\.php\s+on\s+line\s+\d+", re.IGNORECASE),
    ]

    VERSION_PATTERNS = [
        re.compile(r"(?:version|ver)[:=\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
        re.compile(r"(?:apache|nginx|iis)/([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
        re.compile(r"(?:php|python|ruby|node)/([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
    ]

    HEADER_PATTERNS = {
        "x-powered-by": re.compile(r"x-powered-by:\s*(.+)", re.IGNORECASE),
        "server": re.compile(r"server:\s*(.+)", re.IGNORECASE),
        "x-aspnet-version": re.compile(r"x-aspnet-version:\s*(.+)", re.IGNORECASE),
        "x-aspnetmvc-version": re.compile(r"x-aspnetmvc-version:\s*(.+)", re.IGNORECASE),
    }

    DEBUG_PATTERNS = [
        re.compile(r"debug\s*[:=]\s*true", re.IGNORECASE),
        re.compile(r"debugging\s+enabled", re.IGNORECASE),
        re.compile(r"debug\s+mode", re.IGNORECASE),
        re.compile(r"development\s+mode", re.IGNORECASE),
    ]

    ERROR_MESSAGE_PATTERNS = [
        re.compile(r"error\s*[:=]", re.IGNORECASE),
        re.compile(r"warning\s*[:=]", re.IGNORECASE),
        re.compile(r"exception\s*[:=]", re.IGNORECASE),
        re.compile(r"fatal\s+error", re.IGNORECASE),
    ]

    # Sensitive data patterns (upgrade severity if found)
    CREDENTIAL_PATTERNS = [
        re.compile(r"password\s*[:=]\s*['\"]?([^'\"\s]+)", re.IGNORECASE),
        re.compile(r"api[-_]?key\s*[:=]\s*['\"]?([^'\"\s]+)", re.IGNORECASE),
        re.compile(r"secret\s*[:=]\s*['\"]?([^'\"\s]+)", re.IGNORECASE),
        re.compile(r"token\s*[:=]\s*['\"]?([^'\"\s]+)", re.IGNORECASE),
        re.compile(r"aws[-_]?access[-_]?key", re.IGNORECASE),
        re.compile(r"private[-_]?key", re.IGNORECASE),
    ]

    DATABASE_PATTERNS = [
        re.compile(r"database\s*[:=]", re.IGNORECASE),
        re.compile(r"connection\s+string", re.IGNORECASE),
        re.compile(r"jdbc:", re.IGNORECASE),
        re.compile(r"mongodb://", re.IGNORECASE),
        re.compile(r"mysql://", re.IGNORECASE),
        re.compile(r"postgres://", re.IGNORECASE),
    ]

    def applies_to(self, candidate: FindingCandidate) -> bool:
        """
        This context applies to all web findings.

        It acts as a fallback/default context for generic web security issues.
        """
        return True

    def is_public_by_design(self, candidate: FindingCandidate) -> tuple[bool, str]:
        """
        Check if the finding represents expected web behavior.

        Most generic web findings are not truly "public by design",
        but many are low-impact information disclosure.
        """
        # Generic web findings are rarely filtered completely
        # Instead, we adjust severity
        return False, ""

    def suggest_severity(self, candidate: FindingCandidate) -> Severity | None:
        """
        Suggest severity adjustments for generic web findings.
        """
        evidence = candidate.evidence
        title_lower = candidate.title.lower()
        desc_lower = candidate.description.lower()

        # Check for credentials in evidence (upgrade to HIGH)
        has_credentials = self._contains_credentials(evidence)
        has_database = self._contains_database_info(evidence)

        # Stack trace handling
        if self._is_stack_trace(evidence) or "stack trace" in title_lower:
            if has_credentials or has_database:
                return Severity.HIGH  # Credentials in stack trace is serious
            else:
                return Severity.LOW  # Generic stack trace is low impact

        # Version disclosure
        if any(pattern.search(evidence) for pattern in self.VERSION_PATTERNS) or any(
            keyword in title_lower for keyword in ["version", "disclosure", "banner"]
        ):
            if has_credentials:
                return Severity.HIGH
            else:
                return Severity.INFO  # Version disclosure alone is informational

        # Header disclosure (X-Powered-By, Server, etc.)
        if any(pattern.search(evidence) for pattern in self.HEADER_PATTERNS.values()) or any(
            keyword in title_lower for keyword in ["header", "x-powered-by", "server"]
        ):
            if has_credentials:
                return Severity.HIGH
            else:
                return Severity.INFO  # Header disclosure is informational

        # Debug mode
        if self._is_debug_mode(evidence) or "debug" in title_lower:
            if has_credentials or has_database:
                return Severity.HIGH  # Debug mode exposing secrets is high
            else:
                return Severity.LOW  # Debug mode alone is low

        # Generic error messages
        if self._is_error_message(evidence) or "error message" in title_lower:
            if has_credentials or has_database:
                return Severity.HIGH
            else:
                return Severity.INFO  # Generic error messages are info

        # Technology disclosure
        if any(keyword in title_lower for keyword in ["technology", "framework", "disclosure"]):
            if has_credentials:
                return Severity.HIGH
            else:
                return Severity.INFO

        return None

    def get_context_adjustments(
        self, candidate: FindingCandidate
    ) -> list[ContextAdjustment]:
        """
        Get all generic web context adjustments.
        """
        from inferno.quality.candidate import ContextAdjustment

        adjustments: list[ContextAdjustment] = []

        # Check for severity adjustments
        suggested_severity = self.suggest_severity(candidate)
        if suggested_severity and suggested_severity != candidate.initial_severity:
            reason = self._get_severity_reason(candidate, suggested_severity)

            # Determine context type based on finding characteristics
            context_type = "generic_web"
            if self._is_stack_trace(candidate.evidence):
                context_type = "stack_trace"
            elif self._is_debug_mode(candidate.evidence):
                context_type = "debug_mode"
            elif any(
                pattern.search(candidate.evidence) for pattern in self.VERSION_PATTERNS
            ):
                context_type = "version_disclosure"
            elif self._is_error_message(candidate.evidence):
                context_type = "error_message"

            adjustments.append(
                ContextAdjustment(
                    context_type=context_type,
                    original_severity=candidate.initial_severity,
                    adjusted_severity=suggested_severity,
                    rationale=reason,
                    is_by_design=False,
                )
            )
            candidate.technology_context = context_type

        return adjustments

    def _is_stack_trace(self, text: str) -> bool:
        """Check if text contains a stack trace."""
        return any(pattern.search(text) for pattern in self.STACK_TRACE_PATTERNS)

    def _is_debug_mode(self, text: str) -> bool:
        """Check if text indicates debug mode is enabled."""
        return any(pattern.search(text) for pattern in self.DEBUG_PATTERNS)

    def _is_error_message(self, text: str) -> bool:
        """Check if text contains error messages."""
        return any(pattern.search(text) for pattern in self.ERROR_MESSAGE_PATTERNS)

    def _contains_credentials(self, text: str) -> bool:
        """Check if text contains credentials or secrets."""
        return any(pattern.search(text) for pattern in self.CREDENTIAL_PATTERNS)

    def _contains_database_info(self, text: str) -> bool:
        """Check if text contains database connection information."""
        return any(pattern.search(text) for pattern in self.DATABASE_PATTERNS)

    def _get_severity_reason(
        self, candidate: FindingCandidate, suggested: Severity
    ) -> str:
        """Get explanation for severity adjustment."""
        evidence = candidate.evidence

        has_creds = self._contains_credentials(evidence)
        has_db = self._contains_database_info(evidence)

        if suggested == Severity.HIGH:
            if has_creds:
                return (
                    "Upgraded to HIGH: Credentials or secrets exposed. "
                    "This represents a significant security risk."
                )
            elif has_db:
                return (
                    "Upgraded to HIGH: Database connection information exposed. "
                    "This could lead to data breach."
                )
            else:
                return "Upgraded to HIGH based on sensitive information exposure."

        elif suggested == Severity.LOW:
            if self._is_stack_trace(evidence):
                return (
                    "Downgraded to LOW: Stack trace exposure without sensitive data. "
                    "This is a minor information disclosure."
                )
            elif self._is_debug_mode(evidence):
                return (
                    "Downgraded to LOW: Debug mode enabled but no sensitive data exposed. "
                    "This should be disabled in production."
                )
            else:
                return "Downgraded to LOW: Limited impact information disclosure."

        elif suggested == Severity.INFO:
            if any(pattern.search(evidence) for pattern in self.VERSION_PATTERNS):
                return (
                    "Downgraded to INFO: Version disclosure is common and low-risk. "
                    "Keep software updated to mitigate known vulnerabilities."
                )
            elif any(pattern.search(evidence) for pattern in self.HEADER_PATTERNS.values()):
                return (
                    "Downgraded to INFO: HTTP header disclosure is informational. "
                    "Consider removing unnecessary headers."
                )
            elif self._is_error_message(evidence):
                return (
                    "Downgraded to INFO: Generic error message disclosure. "
                    "Implement proper error handling."
                )
            else:
                return (
                    "Downgraded to INFO: Technology disclosure is informational. "
                    "This is not a vulnerability by itself."
                )

        return f"Severity adjusted to {suggested.value} based on generic web context."
