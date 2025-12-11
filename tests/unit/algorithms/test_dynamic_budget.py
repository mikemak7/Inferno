"""
Unit tests for Dynamic Budget Allocation for subagents.

Tests the dynamic budget allocation system that optimizes
resource distribution among subagents based on performance.
"""

import pytest
import numpy as np
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from enum import Enum


# ============================================================================
# Budget Allocation Data Structures
# ============================================================================

class SubagentType(str, Enum):
    """Types of subagents."""

    RECONNAISSANCE = "reconnaissance"
    SCANNER = "scanner"
    EXPLOITER = "exploiter"
    VALIDATOR = "validator"
    POST_EXPLOITATION = "post_exploitation"
    REPORTER = "reporter"


@dataclass
class SubagentPerformance:
    """Performance metrics for a subagent type."""

    agent_type: SubagentType
    total_turns_used: int = 0
    total_turns_allocated: int = 0
    findings_discovered: int = 0
    findings_validated: int = 0
    exploits_successful: int = 0
    exploits_attempted: int = 0
    completion_rate: float = 0.0  # Tasks completed / tasks assigned
    average_time_per_finding: float = 0.0

    @property
    def efficiency(self) -> float:
        """Calculate efficiency score (findings per turn)."""
        if self.total_turns_used == 0:
            return 0.0
        return self.findings_discovered / self.total_turns_used

    @property
    def success_rate(self) -> float:
        """Calculate success rate for exploiters."""
        if self.exploits_attempted == 0:
            return 0.5  # Default when no data
        return self.exploits_successful / self.exploits_attempted

    @property
    def utilization(self) -> float:
        """Calculate utilization (turns used / turns allocated)."""
        if self.total_turns_allocated == 0:
            return 0.0
        return min(1.0, self.total_turns_used / self.total_turns_allocated)


@dataclass
class BudgetAllocation:
    """Budget allocation for a subagent task."""

    agent_type: SubagentType
    allocated_turns: int
    priority: int = 50  # 0-100
    timestamp: datetime = field(default_factory=datetime.now)
    task_description: str = ""
    parent_finding: Optional[str] = None


@dataclass
class BudgetConfig:
    """Configuration for budget allocation."""

    total_budget: int = 500                    # Total turns available
    min_allocation: int = 5                    # Minimum turns per task
    max_allocation: int = 50                   # Maximum turns per task
    reserve_percentage: float = 0.1            # Reserve 10% for emergencies
    reallocation_threshold: float = 0.8        # Reallocate when 80% used

    # Base allocations by phase (percentage)
    phase_budgets: Dict[str, float] = field(default_factory=lambda: {
        "reconnaissance": 0.15,
        "scanning": 0.25,
        "exploitation": 0.35,
        "validation": 0.10,
        "post_exploitation": 0.10,
        "reporting": 0.05,
    })


class DynamicBudgetAllocator:
    """Dynamic budget allocation engine."""

    def __init__(self, config: BudgetConfig = None):
        self.config = config or BudgetConfig()
        self.total_budget = self.config.total_budget
        self.used_budget = 0
        self.reserved_budget = int(self.total_budget * self.config.reserve_percentage)

        self.allocations: List[BudgetAllocation] = []
        self.performance: Dict[SubagentType, SubagentPerformance] = {
            t: SubagentPerformance(agent_type=t) for t in SubagentType
        }

        self.current_phase = "reconnaissance"

    @property
    def remaining_budget(self) -> int:
        """Get remaining available budget."""
        return self.total_budget - self.used_budget - self.reserved_budget

    @property
    def budget_utilization(self) -> float:
        """Get budget utilization percentage."""
        return self.used_budget / self.total_budget

    def allocate(
        self,
        agent_type: SubagentType,
        task_description: str = "",
        priority: int = 50,
        parent_finding: Optional[str] = None,
    ) -> BudgetAllocation:
        """Allocate budget for a subagent task."""
        # Calculate base allocation
        base_allocation = self._calculate_base_allocation(agent_type)

        # Adjust based on performance
        performance_multiplier = self._calculate_performance_multiplier(agent_type)

        # Adjust based on priority
        priority_multiplier = 0.5 + (priority / 100)

        # Calculate final allocation
        allocation = int(base_allocation * performance_multiplier * priority_multiplier)

        # Apply bounds
        allocation = max(self.config.min_allocation, allocation)
        allocation = min(self.config.max_allocation, allocation)
        allocation = min(allocation, self.remaining_budget)

        if allocation < self.config.min_allocation:
            raise ValueError(f"Insufficient budget: {self.remaining_budget} remaining")

        # Create allocation
        budget_allocation = BudgetAllocation(
            agent_type=agent_type,
            allocated_turns=allocation,
            priority=priority,
            task_description=task_description,
            parent_finding=parent_finding,
        )

        self.allocations.append(budget_allocation)
        self.performance[agent_type].total_turns_allocated += allocation

        return budget_allocation

    def _calculate_base_allocation(self, agent_type: SubagentType) -> int:
        """Calculate base allocation based on phase and type."""
        phase_budget = self.config.phase_budgets.get(
            self.current_phase, 0.2
        )
        available_for_phase = self.total_budget * phase_budget

        # Distribute among typical number of agents in phase
        typical_agents_per_phase = {
            "reconnaissance": 2,
            "scanning": 3,
            "exploitation": 4,
            "validation": 2,
            "post_exploitation": 2,
            "reporting": 1,
        }

        agents_in_phase = typical_agents_per_phase.get(self.current_phase, 2)
        base = int(available_for_phase / agents_in_phase)

        return base

    def _calculate_performance_multiplier(self, agent_type: SubagentType) -> float:
        """Calculate performance-based multiplier."""
        perf = self.performance[agent_type]

        if perf.total_turns_used < 10:
            # Not enough data, use neutral multiplier
            return 1.0

        # High efficiency = more budget
        efficiency_factor = min(2.0, 1.0 + perf.efficiency * 2)

        # High completion = more budget
        completion_factor = 0.5 + perf.completion_rate * 0.5

        # High success rate (for exploiters) = more budget
        success_factor = 0.7 + perf.success_rate * 0.6

        return (efficiency_factor + completion_factor + success_factor) / 3

    def record_usage(
        self,
        agent_type: SubagentType,
        turns_used: int,
        findings: int = 0,
        validated: int = 0,
        exploits_attempted: int = 0,
        exploits_successful: int = 0,
        task_completed: bool = True,
    ) -> None:
        """Record subagent performance."""
        perf = self.performance[agent_type]

        perf.total_turns_used += turns_used
        perf.findings_discovered += findings
        perf.findings_validated += validated
        perf.exploits_attempted += exploits_attempted
        perf.exploits_successful += exploits_successful

        # Update completion rate (rolling average)
        completed = 1.0 if task_completed else 0.0
        tasks_count = len([a for a in self.allocations if a.agent_type == agent_type])
        if tasks_count > 0:
            perf.completion_rate = (
                perf.completion_rate * (tasks_count - 1) + completed
            ) / tasks_count

        self.used_budget += turns_used

    def reallocate(self) -> Dict[SubagentType, int]:
        """Reallocate remaining budget based on performance."""
        if self.budget_utilization < self.config.reallocation_threshold:
            return {}  # Too early to reallocate

        remaining = self.remaining_budget + self.reserved_budget  # Include reserve

        # Calculate weights based on performance
        weights = {}
        total_weight = 0

        for agent_type in SubagentType:
            perf = self.performance[agent_type]
            weight = 1.0 + perf.efficiency + perf.success_rate
            weights[agent_type] = weight
            total_weight += weight

        # Distribute remaining budget
        reallocation = {}
        for agent_type, weight in weights.items():
            share = int((weight / total_weight) * remaining)
            reallocation[agent_type] = share

        return reallocation

    def set_phase(self, phase: str) -> None:
        """Set current assessment phase."""
        self.current_phase = phase


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def budget_config():
    """Budget configuration."""
    return BudgetConfig(
        total_budget=500,
        min_allocation=5,
        max_allocation=50,
        reserve_percentage=0.1,
    )


@pytest.fixture
def allocator(budget_config):
    """Budget allocator."""
    return DynamicBudgetAllocator(budget_config)


@pytest.fixture
def high_performance_metrics():
    """High performing subagent metrics."""
    return SubagentPerformance(
        agent_type=SubagentType.SCANNER,
        total_turns_used=100,
        total_turns_allocated=100,
        findings_discovered=20,
        findings_validated=18,
        exploits_attempted=0,
        exploits_successful=0,
        completion_rate=0.9,
    )


@pytest.fixture
def low_performance_metrics():
    """Low performing subagent metrics."""
    return SubagentPerformance(
        agent_type=SubagentType.EXPLOITER,
        total_turns_used=100,
        total_turns_allocated=120,
        findings_discovered=2,
        findings_validated=1,
        exploits_attempted=10,
        exploits_successful=1,
        completion_rate=0.5,
    )


# ============================================================================
# Basic Allocation Tests
# ============================================================================

class TestBasicAllocation:
    """Tests for basic budget allocation."""

    def test_initial_budget(self, allocator):
        """
        Test: Initial budget is correctly set.
        """
        assert allocator.total_budget == 500
        assert allocator.used_budget == 0
        assert allocator.reserved_budget == 50  # 10% of 500

    def test_remaining_budget_calculation(self, allocator):
        """
        Test: Remaining budget is correctly calculated.
        """
        assert allocator.remaining_budget == 450  # 500 - 50 reserve

        allocator.used_budget = 100
        assert allocator.remaining_budget == 350

    def test_allocation_creates_record(self, allocator):
        """
        Test: Allocation creates a proper record.
        """
        allocation = allocator.allocate(
            agent_type=SubagentType.SCANNER,
            task_description="Vulnerability scanning",
            priority=60,
        )

        assert allocation.agent_type == SubagentType.SCANNER
        assert allocation.allocated_turns > 0
        assert allocation.priority == 60
        assert allocation.task_description == "Vulnerability scanning"
        assert len(allocator.allocations) == 1

    def test_allocation_respects_bounds(self, allocator):
        """
        Test: Allocation respects min/max bounds.
        """
        # Very low priority should still get minimum
        low_priority = allocator.allocate(
            agent_type=SubagentType.REPORTER,
            priority=1,
        )
        assert low_priority.allocated_turns >= allocator.config.min_allocation

        # Very high priority should not exceed maximum
        high_priority = allocator.allocate(
            agent_type=SubagentType.EXPLOITER,
            priority=100,
        )
        assert high_priority.allocated_turns <= allocator.config.max_allocation

    def test_allocation_updates_performance_tracking(self, allocator):
        """
        Test: Allocation updates performance tracking.
        """
        initial = allocator.performance[SubagentType.SCANNER].total_turns_allocated

        allocator.allocate(
            agent_type=SubagentType.SCANNER,
            priority=50,
        )

        final = allocator.performance[SubagentType.SCANNER].total_turns_allocated
        assert final > initial


# ============================================================================
# Performance-Based Allocation Tests
# ============================================================================

class TestPerformanceBasedAllocation:
    """Tests for performance-based budget allocation."""

    def test_high_performer_gets_more_budget(self, allocator):
        """
        Test: High performing subagents get more budget.
        """
        # Record good performance for scanner
        allocator.record_usage(
            agent_type=SubagentType.SCANNER,
            turns_used=50,
            findings=15,
            task_completed=True,
        )

        # Record poor performance for exploiter
        allocator.record_usage(
            agent_type=SubagentType.EXPLOITER,
            turns_used=50,
            findings=1,
            exploits_attempted=10,
            exploits_successful=1,
            task_completed=False,
        )

        scanner_allocation = allocator.allocate(
            agent_type=SubagentType.SCANNER,
            priority=50,
        )

        exploiter_allocation = allocator.allocate(
            agent_type=SubagentType.EXPLOITER,
            priority=50,
        )

        # Scanner should get more (better performance)
        assert scanner_allocation.allocated_turns >= exploiter_allocation.allocated_turns

    def test_efficiency_affects_allocation(self, high_performance_metrics, low_performance_metrics):
        """
        Test: Efficiency score correctly calculated.
        """
        # High performer: 20 findings / 100 turns = 0.2 efficiency
        assert high_performance_metrics.efficiency == 0.2

        # Low performer: 2 findings / 100 turns = 0.02 efficiency
        assert low_performance_metrics.efficiency == 0.02

    def test_success_rate_affects_allocation(self, high_performance_metrics, low_performance_metrics):
        """
        Test: Success rate correctly calculated.
        """
        # No exploits attempted
        assert high_performance_metrics.success_rate == 0.5  # Default

        # 1/10 success rate
        assert low_performance_metrics.success_rate == 0.1

    def test_new_subagent_gets_neutral_allocation(self, allocator):
        """
        Test: Subagents with no history get neutral multiplier.
        """
        # No usage recorded yet
        multiplier = allocator._calculate_performance_multiplier(SubagentType.SCANNER)

        # Should be 1.0 (neutral)
        assert multiplier == 1.0


# ============================================================================
# Phase-Based Allocation Tests
# ============================================================================

class TestPhaseBasedAllocation:
    """Tests for phase-based budget allocation."""

    def test_reconnaissance_phase_allocation(self, allocator):
        """
        Test: Reconnaissance phase gets appropriate budget.
        """
        allocator.set_phase("reconnaissance")

        allocation = allocator.allocate(
            agent_type=SubagentType.RECONNAISSANCE,
            priority=50,
        )

        # Recon gets 15% of budget, typically 2 agents
        # Base should be around 500 * 0.15 / 2 = 37.5
        assert 20 <= allocation.allocated_turns <= 50

    def test_exploitation_phase_allocation(self, allocator):
        """
        Test: Exploitation phase gets largest budget.
        """
        allocator.set_phase("exploitation")

        allocation = allocator.allocate(
            agent_type=SubagentType.EXPLOITER,
            priority=50,
        )

        # Exploitation gets 35% of budget
        assert allocation.allocated_turns > 0

    def test_phase_transition_affects_allocation(self, allocator):
        """
        Test: Changing phase affects allocation calculations.
        """
        allocator.set_phase("reconnaissance")
        recon_allocation = allocator.allocate(
            agent_type=SubagentType.SCANNER,
            priority=50,
        )

        allocator.set_phase("exploitation")
        exploit_allocation = allocator.allocate(
            agent_type=SubagentType.SCANNER,
            priority=50,
        )

        # Exploitation phase should allocate more
        assert exploit_allocation.allocated_turns >= recon_allocation.allocated_turns


# ============================================================================
# Budget Exhaustion Tests
# ============================================================================

class TestBudgetExhaustion:
    """Tests for budget exhaustion handling."""

    def test_allocation_limited_by_remaining(self, allocator):
        """
        Test: Allocation cannot exceed remaining budget.
        """
        allocator.used_budget = 440  # Only 10 remaining (minus reserve)

        allocation = allocator.allocate(
            agent_type=SubagentType.SCANNER,
            priority=100,  # High priority
        )

        assert allocation.allocated_turns <= allocator.remaining_budget

    def test_insufficient_budget_raises_error(self, allocator):
        """
        Test: Insufficient budget raises error.
        """
        allocator.used_budget = 495  # Only 5 remaining, but 50 reserved

        with pytest.raises(ValueError, match="Insufficient budget"):
            allocator.allocate(
                agent_type=SubagentType.SCANNER,
                priority=50,
            )

    def test_reserve_budget_available_for_emergency(self, allocator):
        """
        Test: Reserve budget can be tapped during reallocation.
        """
        allocator.used_budget = 400

        reallocation = allocator.reallocate()

        # Should include reserve in reallocation
        total_reallocated = sum(reallocation.values())
        assert total_reallocated <= allocator.remaining_budget + allocator.reserved_budget


# ============================================================================
# Reallocation Tests
# ============================================================================

class TestBudgetReallocation:
    """Tests for budget reallocation."""

    def test_reallocation_triggered_by_threshold(self, allocator):
        """
        Test: Reallocation only occurs after threshold.
        """
        # Below threshold
        allocator.used_budget = 300  # 60%
        early_reallocation = allocator.reallocate()
        assert early_reallocation == {}

        # Above threshold
        allocator.used_budget = 400  # 80%
        late_reallocation = allocator.reallocate()
        assert late_reallocation != {}

    def test_reallocation_favors_high_performers(self, allocator):
        """
        Test: Reallocation gives more to high performers.
        """
        # Record good scanner performance
        allocator.record_usage(
            agent_type=SubagentType.SCANNER,
            turns_used=50,
            findings=20,
            task_completed=True,
        )

        # Record poor exploiter performance
        allocator.record_usage(
            agent_type=SubagentType.EXPLOITER,
            turns_used=50,
            findings=1,
            exploits_attempted=10,
            exploits_successful=0,
            task_completed=False,
        )

        allocator.used_budget = 400  # Trigger reallocation

        reallocation = allocator.reallocate()

        # Scanner should get more
        assert reallocation[SubagentType.SCANNER] > reallocation[SubagentType.EXPLOITER]

    def test_reallocation_distributes_all_remaining(self, allocator):
        """
        Test: Reallocation distributes all remaining budget.
        """
        allocator.used_budget = 400

        reallocation = allocator.reallocate()

        total_reallocated = sum(reallocation.values())
        expected_remaining = allocator.remaining_budget + allocator.reserved_budget

        # Should be close (may have rounding differences)
        assert abs(total_reallocated - expected_remaining) < len(SubagentType)


# ============================================================================
# Usage Recording Tests
# ============================================================================

class TestUsageRecording:
    """Tests for usage recording."""

    def test_usage_updates_metrics(self, allocator):
        """
        Test: Recording usage updates all metrics.
        """
        # Need to allocate first so completion_rate can be calculated
        allocator.allocate(SubagentType.SCANNER, priority=50)

        allocator.record_usage(
            agent_type=SubagentType.SCANNER,
            turns_used=30,
            findings=5,
            validated=4,
            task_completed=True,
        )

        perf = allocator.performance[SubagentType.SCANNER]

        assert perf.total_turns_used == 30
        assert perf.findings_discovered == 5
        assert perf.findings_validated == 4
        assert perf.completion_rate == 1.0

    def test_usage_updates_used_budget(self, allocator):
        """
        Test: Recording usage updates total used budget.
        """
        initial_used = allocator.used_budget

        allocator.record_usage(
            agent_type=SubagentType.SCANNER,
            turns_used=50,
        )

        assert allocator.used_budget == initial_used + 50

    def test_completion_rate_rolling_average(self, allocator):
        """
        Test: Completion rate is calculated as rolling average.
        """
        # First allocation
        allocator.allocate(SubagentType.SCANNER)
        allocator.record_usage(
            SubagentType.SCANNER, turns_used=20, task_completed=True
        )

        # Second allocation
        allocator.allocate(SubagentType.SCANNER)
        allocator.record_usage(
            SubagentType.SCANNER, turns_used=20, task_completed=False
        )

        # Should be 50% (1 completed, 1 failed)
        perf = allocator.performance[SubagentType.SCANNER]
        assert perf.completion_rate == 0.5


# ============================================================================
# Utilization Tests
# ============================================================================

class TestUtilization:
    """Tests for utilization metrics."""

    def test_utilization_calculation(self, high_performance_metrics):
        """
        Test: Utilization is correctly calculated.
        """
        # 100 used / 100 allocated = 100%
        assert high_performance_metrics.utilization == 1.0

    def test_over_utilization_capped(self, low_performance_metrics):
        """
        Test: Utilization is capped at 100%.
        """
        # Set turns used > allocated
        low_performance_metrics.total_turns_used = 150
        low_performance_metrics.total_turns_allocated = 100

        # Should be capped at 1.0
        assert low_performance_metrics.utilization == 1.0

    def test_budget_utilization_tracking(self, allocator):
        """
        Test: Budget utilization percentage is tracked.
        """
        assert allocator.budget_utilization == 0.0

        allocator.used_budget = 250
        assert allocator.budget_utilization == 0.5

        allocator.used_budget = 500
        assert allocator.budget_utilization == 1.0


# ============================================================================
# Integration Tests
# ============================================================================

class TestBudgetIntegration:
    """Tests for integration with Inferno agent."""

    def test_full_assessment_lifecycle(self, allocator):
        """
        Test: Budget allocation through full assessment lifecycle.
        """
        # Reconnaissance phase
        allocator.set_phase("reconnaissance")
        recon_alloc = allocator.allocate(SubagentType.RECONNAISSANCE, priority=70)
        allocator.record_usage(
            SubagentType.RECONNAISSANCE, turns_used=recon_alloc.allocated_turns,
            findings=3, task_completed=True
        )

        # Scanning phase
        allocator.set_phase("scanning")
        scan_alloc = allocator.allocate(SubagentType.SCANNER, priority=60)
        allocator.record_usage(
            SubagentType.SCANNER, turns_used=scan_alloc.allocated_turns,
            findings=8, task_completed=True
        )

        # Exploitation phase
        allocator.set_phase("exploitation")
        exploit_alloc = allocator.allocate(SubagentType.EXPLOITER, priority=80)
        allocator.record_usage(
            SubagentType.EXPLOITER, turns_used=exploit_alloc.allocated_turns,
            exploits_attempted=5, exploits_successful=3, task_completed=True
        )

        # Validation phase
        allocator.set_phase("validation")
        valid_alloc = allocator.allocate(SubagentType.VALIDATOR, priority=90)
        allocator.record_usage(
            SubagentType.VALIDATOR, turns_used=valid_alloc.allocated_turns,
            validated=6, task_completed=True
        )

        # Verify overall metrics
        assert allocator.used_budget > 0
        assert len(allocator.allocations) == 4
        assert allocator.performance[SubagentType.SCANNER].findings_discovered == 8

    def test_budget_persistence(self, allocator, tmp_path):
        """
        Test: Budget state can be saved and loaded.
        """
        import json

        # Make some allocations
        allocator.allocate(SubagentType.SCANNER, priority=50)
        allocator.record_usage(SubagentType.SCANNER, turns_used=30, findings=5)

        # Serialize state
        state = {
            "total_budget": allocator.total_budget,
            "used_budget": allocator.used_budget,
            "current_phase": allocator.current_phase,
            "allocations": [
                {
                    "agent_type": a.agent_type.value,
                    "allocated_turns": a.allocated_turns,
                    "priority": a.priority,
                }
                for a in allocator.allocations
            ],
            "performance": {
                t.value: {
                    "total_turns_used": p.total_turns_used,
                    "findings_discovered": p.findings_discovered,
                }
                for t, p in allocator.performance.items()
            }
        }

        state_file = tmp_path / "budget_state.json"
        state_file.write_text(json.dumps(state))

        # Verify saved
        loaded = json.loads(state_file.read_text())
        assert loaded["used_budget"] == 30
        assert loaded["performance"]["scanner"]["findings_discovered"] == 5


# ============================================================================
# Edge Cases Tests
# ============================================================================

class TestEdgeCases:
    """Tests for edge cases."""

    def test_zero_budget(self):
        """
        Test: System handles zero budget gracefully.
        """
        config = BudgetConfig(total_budget=0)
        allocator = DynamicBudgetAllocator(config)

        with pytest.raises(ValueError):
            allocator.allocate(SubagentType.SCANNER)

    def test_very_small_budget(self):
        """
        Test: System handles very small budget.
        """
        config = BudgetConfig(
            total_budget=20,
            min_allocation=5,
            reserve_percentage=0.1,
        )
        allocator = DynamicBudgetAllocator(config)

        # Should be able to make at least one allocation
        allocation = allocator.allocate(SubagentType.SCANNER)
        assert allocation.allocated_turns >= config.min_allocation

    def test_all_types_can_be_allocated(self, allocator):
        """
        Test: All subagent types can receive allocations.
        """
        for agent_type in SubagentType:
            allocation = allocator.allocate(agent_type, priority=50)
            assert allocation.allocated_turns > 0

    def test_priority_boundaries(self, allocator):
        """
        Test: Priority values at boundaries work correctly.
        """
        # Priority 0
        low = allocator.allocate(SubagentType.SCANNER, priority=0)
        assert low.allocated_turns >= allocator.config.min_allocation

        # Priority 100
        high = allocator.allocate(SubagentType.SCANNER, priority=100)
        assert high.allocated_turns <= allocator.config.max_allocation

        # High priority should get more
        assert high.allocated_turns >= low.allocated_turns
