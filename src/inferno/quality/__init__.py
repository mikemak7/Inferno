"""
Quality gate system for Bug Bounty finding validation.

This module provides infrastructure for validating security findings through
a multi-stage quality gate system, ensuring findings meet Bug Bounty program
standards before being included in reports.
"""

from __future__ import annotations

from inferno.quality.candidate import (
    ContextAdjustment,
    EscalationAttempt,
    EscalationSuccess,
    FindingCandidate,
)
from inferno.quality.config import QualityConfig
from inferno.quality.contexts import (
    APIContext,
    BaseTechnologyContext,
    BlockchainContext,
    GenericWebContext,
)
from inferno.quality.gate import QualityGate, QualityGateRegistry
from inferno.quality.gates import (
    EscalationGate,
    PreReportChecklistGate,
    SeverityGate,
    SoWhatGate,
    TechnologyContextGate,
)
from inferno.quality.pipeline import QualityGatePipeline

__all__ = [
    # Core models
    "FindingCandidate",
    "EscalationAttempt",
    "EscalationSuccess",
    "ContextAdjustment",
    # Configuration
    "QualityConfig",
    # Gate system
    "QualityGate",
    "QualityGateRegistry",
    "QualityGatePipeline",
    # Quality gates
    "SoWhatGate",
    "TechnologyContextGate",
    "EscalationGate",
    "SeverityGate",
    "PreReportChecklistGate",
    # Technology contexts
    "BaseTechnologyContext",
    "BlockchainContext",
    "APIContext",
    "GenericWebContext",
]
