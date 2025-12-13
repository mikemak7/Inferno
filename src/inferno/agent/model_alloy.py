"""
Model Alloy System for Inferno.

Implements intelligent model switching within a single conversation
to leverage complementary strengths of different models.

Based on XBOW research showing 11%+ improvement by alternating models.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class AlloyStrategy(str, Enum):
    """Model alloy strategies."""

    # Use primary model only (no alloy)
    SINGLE = "single"

    # Random switching with weights
    WEIGHTED_RANDOM = "weighted_random"

    # Switch when stuck or low confidence
    ADAPTIVE = "adaptive"

    # Periodic switching for diversity
    PERIODIC = "periodic"

    # Use secondary model for specific phases
    PHASE_BASED = "phase_based"


@dataclass
class AlloyConfig:
    """Configuration for model alloy."""

    # Primary model (stronger, used most of the time)
    primary_model: str = "claude-opus-4-5-20251101"

    # Secondary model (different perspective)
    secondary_model: str = "claude-opus-4-5-20251101"

    # Strategy for switching
    strategy: AlloyStrategy = AlloyStrategy.ADAPTIVE

    # Weight for primary model (0.0-1.0) in weighted random
    primary_weight: float = 0.8

    # For periodic strategy: switch every N turns
    periodic_interval: int = 5

    # For adaptive strategy: thresholds
    stuck_turn_threshold: int = 3  # Switch if same approach N times
    low_confidence_threshold: int = 40  # Switch if confidence below this

    # Track model usage for analysis
    track_usage: bool = True


@dataclass
class AlloyState:
    """Runtime state for model alloy."""

    current_model: str = ""
    turns_on_current: int = 0
    total_primary_turns: int = 0
    total_secondary_turns: int = 0
    switch_count: int = 0
    last_switch_reason: str = ""

    # Tracking for adaptive strategy
    consecutive_failures: int = 0
    last_confidence: int = 100
    repeated_approaches: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "current_model": self.current_model,
            "turns_on_current": self.turns_on_current,
            "total_primary_turns": self.total_primary_turns,
            "total_secondary_turns": self.total_secondary_turns,
            "switch_count": self.switch_count,
            "last_switch_reason": self.last_switch_reason,
            "primary_ratio": self.primary_ratio,
        }

    @property
    def primary_ratio(self) -> float:
        """Ratio of primary model usage."""
        total = self.total_primary_turns + self.total_secondary_turns
        if total == 0:
            return 1.0
        return self.total_primary_turns / total


class ModelAlloy:
    """
    Intelligent model switching for improved reasoning diversity.

    The key insight from XBOW: different models have different blind spots.
    By alternating models, we get complementary perspectives that together
    find more vulnerabilities than either model alone.

    This implementation uses Opus as primary (stronger overall) but
    strategically brings in Sonnet for diversity without sacrificing quality.
    """

    def __init__(self, config: AlloyConfig | None = None) -> None:
        """Initialize model alloy."""
        self._config = config or AlloyConfig()
        self._state = AlloyState(current_model=self._config.primary_model)

    @property
    def config(self) -> AlloyConfig:
        return self._config

    @property
    def state(self) -> AlloyState:
        return self._state

    @property
    def current_model(self) -> str:
        """Get current model to use."""
        return self._state.current_model

    def select_model(
        self,
        turn: int,
        confidence: int | None = None,
        last_tool_results: list[bool] | None = None,
        current_approach: str | None = None,
        phase: str | None = None,
    ) -> str:
        """
        Select model for the next turn.

        Args:
            turn: Current turn number
            confidence: Current confidence level (0-100)
            last_tool_results: Success/failure of recent tool calls
            current_approach: Description of current approach (for detecting loops)
            phase: Current assessment phase (recon, scan, exploit, etc.)

        Returns:
            Model ID to use
        """
        if self._config.strategy == AlloyStrategy.SINGLE:
            return self._select_single()
        elif self._config.strategy == AlloyStrategy.WEIGHTED_RANDOM:
            return self._select_weighted_random()
        elif self._config.strategy == AlloyStrategy.PERIODIC:
            return self._select_periodic(turn)
        elif self._config.strategy == AlloyStrategy.PHASE_BASED:
            return self._select_phase_based(phase)
        elif self._config.strategy == AlloyStrategy.ADAPTIVE:
            return self._select_adaptive(
                turn, confidence, last_tool_results, current_approach
            )
        else:
            return self._config.primary_model

    def _select_single(self) -> str:
        """Single model - no switching."""
        model = self._config.primary_model
        self._update_state(model, "single_mode")
        return model

    def _select_weighted_random(self) -> str:
        """Random selection with weights favoring primary."""
        if random.random() < self._config.primary_weight:
            model = self._config.primary_model
            reason = "weighted_primary"
        else:
            model = self._config.secondary_model
            reason = "weighted_secondary"

        self._update_state(model, reason)
        return model

    def _select_periodic(self, turn: int) -> str:
        """Switch models periodically for diversity."""
        # Every N turns, use secondary for one turn
        if turn > 0 and turn % self._config.periodic_interval == 0:
            model = self._config.secondary_model
            reason = f"periodic_switch_turn_{turn}"
        else:
            model = self._config.primary_model
            reason = "periodic_primary"

        self._update_state(model, reason)
        return model

    def _select_phase_based(self, phase: str | None) -> str:
        """Select model based on assessment phase."""
        # Use primary (Opus) for complex phases
        complex_phases = {"exploit", "post_exploit", "chain", "bypass"}

        # Use secondary (Sonnet) for routine phases - faster and cheaper
        routine_phases = {"recon", "scan", "enumerate"}

        if phase and phase.lower() in routine_phases:
            model = self._config.secondary_model
            reason = f"phase_{phase}_routine"
        else:
            model = self._config.primary_model
            reason = f"phase_{phase or 'unknown'}_complex"

        self._update_state(model, reason)
        return model

    def _select_adaptive(
        self,
        turn: int,
        confidence: int | None,
        last_tool_results: list[bool] | None,
        current_approach: str | None,
    ) -> str:
        """
        Adaptive selection based on current state.

        Primary model (Opus) is default, but switch to secondary (Sonnet)
        when we might benefit from a different perspective:
        - When stuck (repeated failures)
        - When confidence is low
        - When repeating the same approach
        - Periodically for diversity (every ~10 turns)
        """
        reason = "adaptive_primary"
        model = self._config.primary_model

        # Update tracking
        if confidence is not None:
            self._state.last_confidence = confidence

        if last_tool_results:
            failures = sum(1 for r in last_tool_results[-3:] if not r)
            self._state.consecutive_failures = failures

        if current_approach:
            self._state.repeated_approaches.append(current_approach)
            # Keep last 5
            self._state.repeated_approaches = self._state.repeated_approaches[-5:]

        # Decision logic - switch to secondary for fresh perspective
        should_switch = False

        # 1. Low confidence - need different thinking
        if confidence is not None and confidence < self._config.low_confidence_threshold:
            should_switch = True
            reason = f"adaptive_low_confidence_{confidence}"

        # 2. Consecutive failures - current approach not working
        elif self._state.consecutive_failures >= self._config.stuck_turn_threshold:
            should_switch = True
            reason = f"adaptive_stuck_{self._state.consecutive_failures}_failures"

        # 3. Repeating same approach - need diversity
        elif len(self._state.repeated_approaches) >= 3:
            recent = self._state.repeated_approaches[-3:]
            if len(set(recent)) == 1:  # All same
                should_switch = True
                reason = "adaptive_repeated_approach"

        # 4. Periodic diversity injection (every ~10 turns, 20% chance)
        elif turn > 0 and turn % 10 == 0 and random.random() < 0.2:
            should_switch = True
            reason = f"adaptive_diversity_turn_{turn}"

        # Apply switch if needed, but only if not already on secondary
        if should_switch and self._state.current_model == self._config.primary_model:
            model = self._config.secondary_model
        elif should_switch and self._state.current_model == self._config.secondary_model:
            # Already on secondary, stay for one more turn then switch back
            if self._state.turns_on_current >= 2:
                model = self._config.primary_model
                reason = "adaptive_return_to_primary"
            else:
                model = self._config.secondary_model
                reason = "adaptive_continue_secondary"

        self._update_state(model, reason)
        return model

    def _update_state(self, model: str, reason: str) -> None:
        """Update state after model selection."""
        if model != self._state.current_model:
            self._state.switch_count += 1
            self._state.turns_on_current = 0
            logger.info(
                "model_alloy_switch",
                from_model=self._state.current_model.split("/")[-1] if "/" in self._state.current_model else self._state.current_model.split("-")[1] if "-" in self._state.current_model else self._state.current_model,
                to_model=model.split("/")[-1] if "/" in model else model.split("-")[1] if "-" in model else model,
                reason=reason,
                switch_count=self._state.switch_count,
            )

        self._state.current_model = model
        self._state.turns_on_current += 1
        self._state.last_switch_reason = reason

        if model == self._config.primary_model:
            self._state.total_primary_turns += 1
        else:
            self._state.total_secondary_turns += 1

    def reset_stuck_tracking(self) -> None:
        """Reset stuck tracking after successful progress."""
        self._state.consecutive_failures = 0
        self._state.repeated_approaches = []

    def force_switch(self, reason: str = "manual") -> str:
        """Force a model switch."""
        if self._state.current_model == self._config.primary_model:
            model = self._config.secondary_model
        else:
            model = self._config.primary_model

        self._update_state(model, f"forced_{reason}")
        return model

    def get_stats(self) -> dict[str, Any]:
        """Get alloy statistics."""
        return {
            **self._state.to_dict(),
            "strategy": self._config.strategy.value,
            "primary_model": self._config.primary_model,
            "secondary_model": self._config.secondary_model,
        }


def create_model_alloy(
    primary_model: str = "claude-opus-4-5-20251101",
    secondary_model: str = "claude-opus-4-5-20251101",
    strategy: str = "adaptive",
) -> ModelAlloy:
    """
    Create a model alloy with the specified configuration.

    Args:
        primary_model: Main model (stronger, used most)
        secondary_model: Alternative model (for diversity)
        strategy: Switching strategy (single, weighted_random, adaptive, periodic, phase_based)

    Returns:
        Configured ModelAlloy instance
    """
    config = AlloyConfig(
        primary_model=primary_model,
        secondary_model=secondary_model,
        strategy=AlloyStrategy(strategy),
    )
    return ModelAlloy(config)
