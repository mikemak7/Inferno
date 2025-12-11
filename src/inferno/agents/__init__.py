"""
Inferno Agents Package.

This module provides specialized agents for the Inferno penetration testing framework.

Agents:
    - ReasonerAgent: Dedicated reasoning agent for analysis without tool execution.
"""

from inferno.agents.reasoner import (
    ReasonerAgent,
    ReasonerOutput,
    create_reasoner_agent,
    transfer_to_reasoner,
)

__all__ = [
    "ReasonerAgent",
    "ReasonerOutput",
    "create_reasoner_agent",
    "transfer_to_reasoner",
]
