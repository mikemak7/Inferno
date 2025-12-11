"""
Inferno Agent Package.

This module exports the main agent classes and execution loop
for the Inferno pentesting agent.
"""

from inferno.agent.sdk_executor import SDKAgentExecutor, ExecutionResult, AssessmentConfig
from inferno.agent.prompts import (
    ObjectiveInfo,
    SystemPromptBuilder,
    TargetInfo,
    build_ctf_prompt,
    build_default_prompt,
)

# Import the new unified Runner (CAI-inspired architecture)
from inferno.runner import (
    InfernoRunner,
    RunConfig,
    RunResult,
    NextStep,
    NextStepFinalOutput,
    NextStepHandoff,
    NextStepRunAgain,
    Agent,
    Handoff,
    handoff,
)

# Re-export AgentPersona from prompts for convenience
from inferno.prompts import AgentPersona

__all__ = [
    # New unified Runner (primary)
    "InfernoRunner",
    "RunConfig",
    "RunResult",
    "NextStep",
    "NextStepFinalOutput",
    "NextStepHandoff",
    "NextStepRunAgain",
    "Agent",
    "Handoff",
    "handoff",
    # Legacy executor (will be deprecated)
    "SDKAgentExecutor",
    "AssessmentConfig",
    "ExecutionResult",
    # Prompts
    "AgentPersona",
    "ObjectiveInfo",
    "SystemPromptBuilder",
    "TargetInfo",
    "build_ctf_prompt",
    "build_default_prompt",
]
