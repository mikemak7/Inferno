"""Base classes and models for finding escalation strategies.

This module provides the foundation for automatically escalating security findings
to demonstrate maximum impact for bug bounty submissions.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EscalationResult(str, Enum):
    """Result of an escalation attempt."""

    SUCCESS = "success"  # Full escalation achieved
    PARTIAL = "partial"  # Some escalation, but not complete
    BLOCKED = "blocked"  # Escalation blocked by security controls
    FAILED = "failed"  # Escalation attempt failed
    NOT_APPLICABLE = "not_applicable"  # Strategy not applicable to this finding


class EscalationAttempt(BaseModel):
    """Record of a single escalation attempt."""

    strategy: str = Field(description="Escalation strategy used")
    description: str = Field(description="Human-readable description of attempt")
    payload: str | None = Field(default=None, description="Payload used if applicable")
    target: str = Field(description="Target URL or endpoint")
    result: EscalationResult = Field(description="Result of the attempt")
    evidence: str = Field(description="Evidence of the result")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    token_tested: str | None = Field(
        default=None, description="Token/credential tested if applicable"
    )
    permissions_discovered: list[str] = Field(
        default_factory=list, description="Permissions discovered during attempt"
    )
    combined_with: list[str] = Field(
        default_factory=list, description="Other findings combined in chain"
    )

    class Config:
        """Pydantic config."""

        json_encoders = {datetime: lambda v: v.isoformat()}


class FindingCandidate(BaseModel):
    """Candidate finding for escalation."""

    finding_id: str
    vuln_type: str
    severity: str
    target_url: str
    evidence: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class BaseEscalationStrategy(ABC):
    """Base class for escalation strategies."""

    def __init__(self) -> None:
        """Initialize the strategy."""
        self._name = self.__class__.__name__

    @property
    def name(self) -> str:
        """Get the strategy name."""
        return self._name

    @abstractmethod
    async def is_applicable(self, candidate: FindingCandidate) -> bool:
        """Check if this strategy applies to the given finding.

        Args:
            candidate: The finding to evaluate

        Returns:
            True if strategy is applicable
        """
        pass

    @abstractmethod
    async def attempt(
        self, candidate: FindingCandidate, target: str | None = None
    ) -> EscalationAttempt:
        """Attempt to escalate the finding.

        Args:
            candidate: The finding to escalate
            target: Optional specific target URL (defaults to candidate.target_url)

        Returns:
            Record of the escalation attempt
        """
        pass

    def _create_attempt(
        self,
        description: str,
        target: str,
        result: EscalationResult,
        evidence: str,
        payload: str | None = None,
        token_tested: str | None = None,
        permissions: list[str] | None = None,
        combined_with: list[str] | None = None,
    ) -> EscalationAttempt:
        """Helper to create an EscalationAttempt.

        Args:
            description: Human-readable description
            target: Target URL
            result: Result of attempt
            evidence: Evidence collected
            payload: Optional payload used
            token_tested: Optional token tested
            permissions: Optional permissions discovered
            combined_with: Optional list of combined findings

        Returns:
            EscalationAttempt instance
        """
        return EscalationAttempt(
            strategy=self.name,
            description=description,
            payload=payload,
            target=target,
            result=result,
            evidence=evidence,
            token_tested=token_tested,
            permissions_discovered=permissions or [],
            combined_with=combined_with or [],
        )
