"""
Base technology context for quality gate system.

This module defines the abstract base class for technology-specific
contexts that help filter false positives and adjust severity ratings
based on technology-specific patterns.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from inferno.reporting.models import Severity

if TYPE_CHECKING:
    from inferno.quality.candidate import ContextAdjustment, FindingCandidate


class BaseTechnologyContext(ABC):
    """
    Abstract base class for technology-specific contexts.

    Implementations should define technology-specific patterns for:
    1. Public-by-design features that should not be reported as vulnerabilities
    2. Severity adjustments based on technology-specific risk factors
    3. Context-specific filtering and validation rules
    """

    def __init__(self) -> None:
        """Initialize the technology context."""
        self.name = self.__class__.__name__
        self.description = self.__doc__ or "No description available"

    @abstractmethod
    def is_public_by_design(self, candidate: FindingCandidate) -> tuple[bool, str]:
        """
        Check if the finding represents a public-by-design feature.

        Args:
            candidate: The finding candidate to evaluate

        Returns:
            Tuple of (is_public, reason):
                - is_public: True if this is a public-by-design feature
                - reason: Explanation of why this is/isn't public-by-design
        """
        pass

    @abstractmethod
    def suggest_severity(self, candidate: FindingCandidate) -> Severity | None:
        """
        Suggest severity adjustment based on technology-specific context.

        Args:
            candidate: The finding candidate to evaluate

        Returns:
            Suggested severity level, or None if no adjustment needed
        """
        pass

    @abstractmethod
    def get_context_adjustments(
        self, candidate: FindingCandidate
    ) -> list[ContextAdjustment]:
        """
        Get all context-specific adjustments for a finding.

        Args:
            candidate: The finding candidate to evaluate

        Returns:
            List of context adjustments to apply
        """
        pass

    def applies_to(self, candidate: FindingCandidate) -> bool:
        """
        Check if this context applies to the given finding.

        Override this method to implement technology detection logic.

        Args:
            candidate: The finding candidate to evaluate

        Returns:
            True if this context should be applied to the finding
        """
        return True

    def evaluate(self, candidate: FindingCandidate) -> ContextAdjustment | None:
        """
        Evaluate a finding and return the primary adjustment.

        This is a convenience method that combines all adjustment logic
        and returns the most significant adjustment.

        Args:
            candidate: The finding candidate to evaluate

        Returns:
            Primary context adjustment, or None if no adjustments needed
        """
        if not self.applies_to(candidate):
            return None

        adjustments = self.get_context_adjustments(candidate)
        if not adjustments:
            return None

        # Return the most significant adjustment
        # Priority: public-by-design > severity change
        for adj in adjustments:
            if adj.is_by_design:
                return adj

        for adj in adjustments:
            if adj.adjusted_severity != candidate.initial_severity:
                return adj

        return adjustments[0] if adjustments else None

    def __repr__(self) -> str:
        """Get string representation."""
        return f"<{self.name}>"
