"""
EscalationGate - Validates escalation attempts.

This gate ensures findings have been properly escalated to demonstrate
maximum impact for Bug Bounty submissions.
"""

from __future__ import annotations

from typing import Any

from inferno.quality.candidate import FindingCandidate
from inferno.quality.config import QualityConfig
from inferno.quality.escalation import (
    BaseEscalationStrategy,
    ChainingStrategy,
    HorizontalEscalation,
    PermissionTestingStrategy,
    VerticalEscalation,
)
from inferno.quality.gate import QualityGate


class EscalationGate(QualityGate):
    """
    Validates escalation attempts for findings.

    This gate ensures that findings have been properly escalated to
    demonstrate maximum impact:
    1. Minimum number of escalation attempts met
    2. Escalation attempts documented with evidence
    3. Appropriate escalation strategies applied
    4. Successful escalations tracked

    Available Escalation Strategies:
        - HorizontalEscalation: Access other user accounts/data
        - VerticalEscalation: Privilege escalation to admin/higher roles
        - ChainingStrategy: Chain multiple findings for greater impact
        - PermissionTestingStrategy: Test all available permissions

    Gate Properties:
        - Blocking: False (non-blocking - provides guidance but doesn't reject)
        - Weight: 0.25 (high importance for quality scoring)
    """

    def __init__(self, config: QualityConfig | None = None) -> None:
        """
        Initialize EscalationGate.

        Args:
            config: Quality configuration (uses default if None)
        """
        super().__init__(
            name="escalation_gate",
            weight=0.25,
            is_blocking=False,
            description="Validates escalation attempts to demonstrate maximum impact",
        )
        self.config = config or QualityConfig()

        # Register escalation strategies
        self.strategies: list[BaseEscalationStrategy] = [
            HorizontalEscalation(),
            VerticalEscalation(),
            ChainingStrategy(),
            PermissionTestingStrategy(),
        ]

    def register_strategy(self, strategy: BaseEscalationStrategy) -> None:
        """
        Register a new escalation strategy.

        Args:
            strategy: Escalation strategy to register
        """
        if strategy not in self.strategies:
            self.strategies.append(strategy)

    async def evaluate(
        self, candidate: FindingCandidate, target: str, **kwargs: Any
    ) -> tuple[bool, str]:
        """
        Evaluate finding escalation attempts.

        Args:
            candidate: Finding candidate to evaluate
            target: Target URL/hostname for escalation
            **kwargs: Additional parameters (not used)

        Returns:
            Tuple of (passed: bool, message: str)
        """
        min_attempts = self.config.min_escalation_attempts
        max_attempts = self.config.max_escalation_attempts

        # Check current escalation count
        current_count = candidate.escalation_count

        # If minimum already met, pass
        if current_count >= min_attempts:
            candidate.escalation_documented = True
            success_count = len(candidate.escalation_successes)
            message = (
                f"Escalation requirement met: {current_count}/{min_attempts} attempts "
                f"({success_count} successful)"
            )
            return True, message

        # Calculate how many more attempts needed
        remaining = min_attempts - current_count

        # Provide guidance on which strategies to try
        suggested_strategies = await self._suggest_strategies(candidate, target)

        message = (
            f"Escalation incomplete: {current_count}/{min_attempts} attempts. "
            f"Need {remaining} more escalation attempt(s). "
            f"Suggested strategies: {', '.join(suggested_strategies[:3])}"
        )

        # Since this is non-blocking, we don't fail the gate
        # Instead, we provide guidance for improvement
        return True, message

    async def _suggest_strategies(
        self, candidate: FindingCandidate, target: str
    ) -> list[str]:
        """
        Suggest applicable escalation strategies for the finding.

        Args:
            candidate: Finding candidate to analyze
            target: Target URL/hostname

        Returns:
            List of suggested strategy names
        """
        from inferno.quality.escalation import FindingCandidate as EscalationCandidate

        # Convert candidate to escalation format
        esc_candidate = EscalationCandidate(
            finding_id=candidate.title,
            vuln_type=candidate.vuln_type,
            severity=candidate.initial_severity.value,
            target_url=target,
            evidence=candidate.evidence,
            metadata={
                "title": candidate.title,
                "description": candidate.description,
                "affected_asset": candidate.affected_asset,
            },
        )

        # Check which strategies are applicable
        suggested: list[str] = []
        for strategy in self.strategies:
            try:
                is_applicable = await strategy.is_applicable(esc_candidate)
                if is_applicable:
                    suggested.append(strategy.name)
            except Exception:
                # If strategy check fails, skip it
                continue

        # If no strategies are applicable, suggest generic ones
        if not suggested:
            suggested = ["HorizontalEscalation", "VerticalEscalation", "ChainingStrategy"]

        return suggested

    async def trigger_escalation(
        self, candidate: FindingCandidate, target: str, strategy_name: str | None = None
    ) -> None:
        """
        Trigger an escalation attempt using specified or best-fit strategy.

        Args:
            candidate: Finding candidate to escalate
            target: Target URL/hostname
            strategy_name: Optional specific strategy name to use

        Raises:
            ValueError: If specified strategy not found
        """
        from inferno.quality.escalation import FindingCandidate as EscalationCandidate

        # Convert candidate to escalation format
        esc_candidate = EscalationCandidate(
            finding_id=candidate.title,
            vuln_type=candidate.vuln_type,
            severity=candidate.initial_severity.value,
            target_url=target,
            evidence=candidate.evidence,
            metadata={
                "title": candidate.title,
                "description": candidate.description,
                "affected_asset": candidate.affected_asset,
            },
        )

        # Find strategy to use
        if strategy_name:
            strategy = next((s for s in self.strategies if s.name == strategy_name), None)
            if not strategy:
                raise ValueError(f"Strategy '{strategy_name}' not found")
        else:
            # Use first applicable strategy
            strategy = None
            for s in self.strategies:
                if await s.is_applicable(esc_candidate):
                    strategy = s
                    break

            if not strategy:
                # Default to horizontal escalation
                strategy = self.strategies[0] if self.strategies else None

        if not strategy:
            return

        # Attempt escalation
        try:
            attempt = await strategy.attempt(esc_candidate, target)

            # Convert to candidate's escalation attempt format
            from inferno.quality.candidate import EscalationAttempt

            candidate_attempt = EscalationAttempt(
                timestamp=attempt.timestamp,
                method=attempt.strategy,
                description=attempt.description,
                payload=attempt.payload or "",
                result=attempt.result.value,
                evidence=attempt.evidence,
                notes=f"Combined with: {', '.join(attempt.combined_with)}"
                if attempt.combined_with
                else "",
            )

            candidate.add_escalation_attempt(candidate_attempt)

            # Track successful escalations
            if attempt.result.value == "success":
                from inferno.quality.candidate import EscalationSuccess

                success = EscalationSuccess(
                    timestamp=attempt.timestamp,
                    from_finding=candidate.vuln_type,
                    to_finding=attempt.description,
                    method=attempt.strategy,
                    severity_increase=f"{candidate.initial_severity.value} -> "
                    f"{candidate.adjusted_severity.value if candidate.adjusted_severity else 'N/A'}",
                    impact_description=attempt.evidence,
                    evidence=attempt.evidence,
                )
                candidate.add_escalation_success(success)

        except Exception:
            # If escalation fails, continue without adding attempt
            pass
