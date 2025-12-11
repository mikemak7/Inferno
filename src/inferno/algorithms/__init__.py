"""
Inferno Algorithms Module - Intelligent Decision Making

This module provides learning algorithms that replace static heuristics
with adaptive, data-driven decision making:

- Multi-Armed Bandits (UCB1, Thompson Sampling) for attack selection
- Monte Carlo Tree Search for attack path discovery
- Bayesian inference for vulnerability confidence
- Q-Learning for action sequencing
- Dynamic budget allocation

All algorithms persist learned parameters across sessions.
"""

from __future__ import annotations

from inferno.algorithms.base import (
    SelectionAlgorithm,
    AlgorithmState,
    OutcomeType,
)
from inferno.algorithms.bandits import (
    UCB1Selector,
    ThompsonSampling,
    ContextualBandit,
    ArmStats,
)
from inferno.algorithms.bayesian import (
    BayesianConfidence,
    VulnerabilityPrior,
    EvidenceType,
    ConfidenceLevel,
)
from inferno.algorithms.qlearning import (
    QLearningAgent,
    PentestState,
    PentestAction,
    RewardFunction,
)
from inferno.algorithms.mcts import (
    MCTSEngine,
    AttackTreeState,
    MCTSNode,
    AttackAction,
    MCTSConfig,
)
from inferno.algorithms.budget import (
    DynamicBudgetAllocator,
    SubagentROI,
    BudgetDecision,
)
from inferno.algorithms.state import (
    AlgorithmStateManager,
    GlobalAlgorithmState,
)
from inferno.algorithms.metrics import (
    MetricsCollector,
    SubagentOutcome,
    TriggerOutcome,
    BranchOutcome,
    AttackOutcome,
)
from inferno.algorithms.manager import (
    AlgorithmManager,
    get_algorithm_manager,
)

__all__ = [
    # Base
    "SelectionAlgorithm",
    "AlgorithmState",
    "OutcomeType",
    # Bandits
    "UCB1Selector",
    "ThompsonSampling",
    "ContextualBandit",
    "ArmStats",
    # Bayesian
    "BayesianConfidence",
    "VulnerabilityPrior",
    "EvidenceType",
    "ConfidenceLevel",
    # Q-Learning
    "QLearningAgent",
    "PentestState",
    "PentestAction",
    "RewardFunction",
    # MCTS
    "MCTSEngine",
    "AttackTreeState",
    "MCTSNode",
    "AttackAction",
    "MCTSConfig",
    # Budget
    "DynamicBudgetAllocator",
    "SubagentROI",
    "BudgetDecision",
    # State
    "AlgorithmStateManager",
    "GlobalAlgorithmState",
    # Metrics
    "MetricsCollector",
    "SubagentOutcome",
    "TriggerOutcome",
    "BranchOutcome",
    "AttackOutcome",
    # Manager
    "AlgorithmManager",
    "get_algorithm_manager",
]
