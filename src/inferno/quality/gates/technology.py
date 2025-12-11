"""
TechnologyContextGate - Applies technology-specific filtering.

This gate uses technology contexts to filter public-by-design features
and adjust severity based on technology-specific risk factors.
"""

from __future__ import annotations

from typing import Any

from inferno.quality.candidate import FindingCandidate
from inferno.quality.config import QualityConfig
from inferno.quality.contexts import (
    APIContext,
    BaseTechnologyContext,
    BlockchainContext,
    GenericWebContext,
)
from inferno.quality.gate import QualityGate


class TechnologyContextGate(QualityGate):
    """
    Applies technology-specific filtering and severity adjustments.

    This gate uses registered technology contexts to:
    1. Detect public-by-design features (blockchain wallet addresses, public API docs, etc.)
    2. Apply context-specific severity adjustments
    3. Filter false positives based on technology-specific patterns

    Registered Contexts:
        - BlockchainContext: Filters public blockchain data
        - APIContext: Filters intentional API documentation
        - GenericWebContext: Adjusts severity for common web findings

    Gate Properties:
        - Blocking: True (findings that are public-by-design are rejected)
        - Weight: 0.20 (important for filtering false positives)
    """

    def __init__(self, config: QualityConfig | None = None) -> None:
        """
        Initialize TechnologyContextGate.

        Args:
            config: Quality configuration (uses default if None)
        """
        super().__init__(
            name="technology_context_gate",
            weight=0.20,
            is_blocking=True,
            description="Applies technology-specific filtering and severity adjustments",
        )
        self.config = config or QualityConfig()

        # Register technology contexts
        self.contexts: list[BaseTechnologyContext] = [
            BlockchainContext(),
            APIContext(),
            GenericWebContext(),
        ]

    def register_context(self, context: BaseTechnologyContext) -> None:
        """
        Register a new technology context.

        Args:
            context: Technology context to register
        """
        if context not in self.contexts:
            self.contexts.append(context)

    async def evaluate(
        self, candidate: FindingCandidate, target: str, **kwargs: Any
    ) -> tuple[bool, str]:
        """
        Evaluate finding against technology contexts.

        Args:
            candidate: Finding candidate to evaluate
            target: Target URL/hostname for context detection
            **kwargs: Additional parameters (not used)

        Returns:
            Tuple of (passed: bool, message: str)
        """
        # Try to detect and apply technology context
        context_applied = False
        rejection_reason: str | None = None

        for context in self.contexts:
            # Check if context applies to this finding
            if not context.applies_to(candidate):
                continue

            context_applied = True
            candidate.technology_context = context.name

            # Check if this is public by design
            is_public, reason = context.is_public_by_design(candidate)
            if is_public:
                candidate.is_public_by_design = True
                candidate.data_intentionally_public = True
                rejection_reason = (
                    f"Finding rejected by {context.name}: {reason} "
                    "This is public-by-design, not a vulnerability."
                )
                break

            # Get context adjustments
            adjustments = context.get_context_adjustments(candidate)
            for adjustment in adjustments:
                candidate.add_context_adjustment(adjustment)

                # If adjustment marks it as public-by-design, reject
                if adjustment.is_by_design:
                    candidate.is_public_by_design = True
                    candidate.data_intentionally_public = True
                    rejection_reason = (
                        f"Finding rejected by {context.name}: {adjustment.rationale}"
                    )
                    break

                # Apply severity adjustment
                if adjustment.adjusted_severity != candidate.initial_severity:
                    candidate.adjusted_severity = adjustment.adjusted_severity
                    candidate.severity_rationale = adjustment.rationale

            if rejection_reason:
                break

        # If rejected due to public-by-design, fail the gate
        if rejection_reason:
            return False, rejection_reason

        # If context was applied but not rejected, pass with context info
        if context_applied:
            message = f"Technology context applied: {candidate.technology_context}"
            if candidate.adjusted_severity:
                message += (
                    f" | Severity adjusted to {candidate.adjusted_severity.value} | "
                    f"{candidate.severity_rationale}"
                )
            return True, message

        # No context applied, pass through
        return True, "No specific technology context detected, using generic validation"
