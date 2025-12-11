"""
Quality gate configuration settings.

This module defines configuration settings for the quality gate system,
including escalation thresholds, validation rules, and environment detection.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pydantic import BaseModel, Field


class QualityConfig(BaseModel):
    """Configuration for quality gate system."""

    # Escalation requirements
    min_escalation_attempts: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Minimum escalation attempts required for findings",
    )
    max_escalation_attempts: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum escalation attempts before giving up",
    )

    # Impact validation
    require_concrete_impact: bool = Field(
        default=True,
        description="Require concrete, demonstrable impact for all findings",
    )
    demote_theoretical_findings: bool = Field(
        default=True,
        description="Demote severity of theoretical/hypothetical findings",
    )

    # Environment detection patterns
    staging_patterns: list[str] = Field(
        default_factory=lambda: [
            r"staging\.",
            r"stg\.",
            r"dev\.",
            r"test\.",
            r"qa\.",
            r"uat\.",
            r"demo\.",
            r"sandbox\.",
            r"preview\.",
            r"-staging\.",
            r"-dev\.",
            r"-test\.",
            r"\.local$",
            r"localhost",
            r"127\.0\.0\.1",
            r"192\.168\.",
            r"10\.",
            r"172\.(1[6-9]|2[0-9]|3[01])\.",
        ],
        description="Regex patterns for detecting staging/dev environments",
    )

    # Technology context validation
    tech_contexts_enabled: list[str] = Field(
        default_factory=lambda: [
            "public_api_endpoint",
            "debug_route",
            "admin_interface",
            "third_party_service",
            "intentional_disclosure",
            "security_headers",
            "cors_policy",
            "rate_limiting",
        ],
        description="Enabled technology context types for validation",
    )

    # Severity adjustment
    theoretical_severity_demote: int = Field(
        default=1,
        ge=0,
        le=3,
        description="Number of severity levels to demote for theoretical findings (0=none, 1=one level, etc.)",
    )

    # Quality scoring
    min_quality_score: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Minimum quality score (0-1) required for report inclusion",
    )
    gate_weight_multiplier: float = Field(
        default=1.0,
        ge=0.1,
        le=10.0,
        description="Multiplier for gate weights in quality score calculation",
    )

    # Pre-report checklist
    require_production_check: bool = Field(
        default=True,
        description="Require explicit production environment verification",
    )
    require_impact_demonstration: bool = Field(
        default=True,
        description="Require demonstrated impact (not just theoretical)",
    )
    require_escalation_documentation: bool = Field(
        default=True,
        description="Require escalation attempts to be documented",
    )

    # False positive prevention
    allow_info_findings: bool = Field(
        default=False,
        description="Allow INFO severity findings in final report",
    )
    allow_low_without_escalation: bool = Field(
        default=False,
        description="Allow LOW severity findings without escalation attempts",
    )

    def is_staging_environment(self, target: str) -> bool:
        """
        Check if target matches staging/dev environment patterns.

        Args:
            target: Target URL or hostname to check

        Returns:
            True if target appears to be staging/dev environment
        """
        import re

        target_lower = target.lower()
        return any(re.search(pattern, target_lower) for pattern in self.staging_patterns)


@dataclass
class GateWeight:
    """Weight configuration for individual gates."""

    gate_name: str
    weight: float = field(default=1.0)
    is_blocking: bool = field(default=False)
    description: str = field(default="")

    def __post_init__(self) -> None:
        """Validate weight is in valid range."""
        if not 0.0 <= self.weight <= 10.0:
            raise ValueError(f"Gate weight must be between 0.0 and 10.0, got {self.weight}")


# Default gate weights for quality scoring
DEFAULT_GATE_WEIGHTS = [
    GateWeight(
        gate_name="so_what_gate",
        weight=3.0,
        is_blocking=True,
        description="Validates concrete impact and exploitability",
    ),
    GateWeight(
        gate_name="environment_gate",
        weight=2.5,
        is_blocking=True,
        description="Ensures finding is on production environment",
    ),
    GateWeight(
        gate_name="escalation_gate",
        weight=2.0,
        is_blocking=True,
        description="Requires escalation attempts for low-severity findings",
    ),
    GateWeight(
        gate_name="technology_context_gate",
        weight=1.5,
        is_blocking=False,
        description="Validates finding against technology-specific context",
    ),
    GateWeight(
        gate_name="theoretical_language_gate",
        weight=1.0,
        is_blocking=False,
        description="Demotes findings with theoretical/hypothetical language",
    ),
]
