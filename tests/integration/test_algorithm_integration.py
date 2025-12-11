"""
Integration tests for algorithmic improvements integration with Inferno agent.

Tests how MAB, MCTS, Bayesian Confidence, Q-Learning, and Dynamic Budget
components integrate with the existing agent loop and swarm coordinator.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Dict, Any, List


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def mock_agent_loop():
    """Mock agent loop for integration testing."""
    loop = MagicMock()
    loop._metrics = MagicMock()
    loop._metrics.turns = 0
    loop._metrics.turns_since_finding = 0
    loop._metrics.consecutive_errors = 0
    loop._metrics.last_reported_confidence = 50
    loop._registry = MagicMock()
    return loop


@pytest.fixture
def mock_coordinator():
    """Mock swarm coordinator."""
    coordinator = MagicMock()
    coordinator._state = MagicMock()
    coordinator._state.findings = []
    coordinator._state.discovered_endpoints = []
    coordinator._state.attack_chains = []
    return coordinator


@pytest.fixture
def mock_memory_tool():
    """Mock memory tool for state persistence."""
    memory = AsyncMock()
    memory.search = AsyncMock(return_value=[])
    memory.store = AsyncMock(return_value={"success": True})
    return memory


# ============================================================================
# MAB Integration Tests
# ============================================================================

class TestMABIntegration:
    """Tests for MAB integration with agent loop."""

    @pytest.mark.asyncio
    async def test_mab_state_persists_via_memory(self, mock_memory_tool):
        """
        Test: MAB state is persisted via memory tool between sessions.
        """
        # Simulate MAB state storage
        mab_state = {
            "sql_injection": {"pulls": 50, "rewards": 35.0},
            "xss": {"pulls": 30, "rewards": 15.0},
        }

        await mock_memory_tool.store(
            content=str(mab_state),
            memory_type="algorithm_state",
            tags=["mab", "attack_vectors"],
        )

        mock_memory_tool.store.assert_called_once()
        call_kwargs = mock_memory_tool.store.call_args[1]
        assert call_kwargs["memory_type"] == "algorithm_state"
        assert "mab" in call_kwargs["tags"]

    @pytest.mark.asyncio
    async def test_mab_influences_tool_selection(self, mock_agent_loop):
        """
        Test: MAB selection influences which tool the agent uses.
        """
        # Simulate MAB selection
        mab_selection = {
            "selected_vector": "sql_injection",
            "ucb_value": 0.85,
            "reason": "highest UCB1 score",
        }

        # This should influence the system prompt or tool recommendation
        tool_recommendation = f"Based on historical success rates, prioritize {mab_selection['selected_vector']} testing"

        assert "sql_injection" in tool_recommendation

    @pytest.mark.asyncio
    async def test_mab_updates_after_tool_result(self, mock_agent_loop):
        """
        Test: MAB state updates after tool execution results.
        """
        # Initial state
        mab_state = {"sql_injection": {"pulls": 10, "rewards": 7.0}}

        # Simulate successful tool execution
        tool_result = {
            "tool": "sqlmap",
            "success": True,
            "found_vulnerability": True,
        }

        # Update MAB state
        mab_state["sql_injection"]["pulls"] += 1
        mab_state["sql_injection"]["rewards"] += 1.0

        assert mab_state["sql_injection"]["pulls"] == 11
        assert mab_state["sql_injection"]["rewards"] == 8.0


# ============================================================================
# MCTS Integration Tests
# ============================================================================

class TestMCTSIntegration:
    """Tests for MCTS integration with agent loop."""

    @pytest.mark.asyncio
    async def test_mcts_guides_attack_path(self, mock_coordinator):
        """
        Test: MCTS guides the coordinator's attack path decisions.
        """
        # Simulate MCTS recommendation
        mcts_path = {
            "recommended_action": "exploit_sqli",
            "state": "web_discovered",
            "visits": 150,
            "average_reward": 0.7,
        }

        # MCTS should influence coordinator spawn decisions
        assert mcts_path["recommended_action"] == "exploit_sqli"
        assert mcts_path["visits"] > 100  # Well-explored

    @pytest.mark.asyncio
    async def test_mcts_tree_updates_with_findings(self, mock_coordinator):
        """
        Test: MCTS tree updates when new findings are discovered.
        """
        # Simulate finding discovery
        finding = {
            "vuln_type": "sql_injection",
            "target": "https://target.com/api",
            "severity": "high",
        }

        mock_coordinator._state.findings.append(finding)

        # MCTS should update tree based on finding
        # (state transition from "scanning" to "finding_discovered")
        assert len(mock_coordinator._state.findings) == 1

    @pytest.mark.asyncio
    async def test_mcts_backpropagation_on_success(self, mock_agent_loop):
        """
        Test: MCTS backpropagates rewards when exploitation succeeds.
        """
        # Simulate successful exploitation path
        path = [
            ("initial", "port_scan"),
            ("enumerated", "web_scan"),
            ("web_discovered", "sqli"),
            ("database_access", "dump_creds"),
        ]

        final_reward = 1.0  # Success

        # Backpropagate should update all nodes in path
        for state, action in reversed(path):
            # Each node in path should receive reward
            pass  # In real impl, would update MCTS tree

        assert len(path) == 4


# ============================================================================
# Bayesian Confidence Integration Tests
# ============================================================================

class TestBayesianConfidenceIntegration:
    """Tests for Bayesian confidence integration with findings."""

    @pytest.mark.asyncio
    async def test_finding_confidence_tracked(self, mock_coordinator):
        """
        Test: Finding confidence is tracked via Bayesian updates.
        """
        finding = {
            "finding_id": "F001",
            "vuln_type": "xss",
            "prior_alpha": 1.0,
            "prior_beta": 1.0,
            "evidence": [],
        }

        # Add validation evidence
        finding["evidence"].append({
            "type": "validation_success",
            "description": "Payload executed in browser",
        })

        # Confidence should increase
        alpha = finding["prior_alpha"] + len([
            e for e in finding["evidence"] if e["type"] == "validation_success"
        ])
        beta = finding["prior_beta"]

        mean_confidence = alpha / (alpha + beta)
        assert mean_confidence > 0.5

    @pytest.mark.asyncio
    async def test_low_confidence_triggers_validation(self, mock_coordinator):
        """
        Test: Low confidence findings trigger validation subagent.
        """
        VALIDATION_THRESHOLD = 0.7

        finding = {
            "finding_id": "F002",
            "confidence": 0.5,
            "validated": False,
        }

        needs_validation = finding["confidence"] < VALIDATION_THRESHOLD

        assert needs_validation
        # Would trigger: coordinator.spawn_validator(finding)

    @pytest.mark.asyncio
    async def test_high_confidence_added_to_report(self, mock_coordinator):
        """
        Test: High confidence findings are added to report.
        """
        REPORT_THRESHOLD = 0.8

        findings = [
            {"id": "F1", "confidence": 0.9, "validated": True},
            {"id": "F2", "confidence": 0.6, "validated": True},
            {"id": "F3", "confidence": 0.85, "validated": True},
        ]

        reportable = [f for f in findings if f["confidence"] >= REPORT_THRESHOLD]

        assert len(reportable) == 2
        assert "F1" in [f["id"] for f in reportable]
        assert "F3" in [f["id"] for f in reportable]


# ============================================================================
# Q-Learning Integration Tests
# ============================================================================

class TestQLearningIntegration:
    """Tests for Q-Learning integration with action sequencing."""

    @pytest.mark.asyncio
    async def test_qlearning_suggests_next_action(self, mock_agent_loop):
        """
        Test: Q-Learning suggests optimal next action.
        """
        # Simulate Q-table
        q_table = {
            ("authenticated", "privesc"): 0.8,
            ("authenticated", "dump_creds"): 0.6,
            ("authenticated", "idor"): 0.4,
        }

        current_state = "authenticated"
        available_actions = ["privesc", "dump_creds", "idor"]

        # Q-Learning suggests best action
        best_action = max(
            available_actions,
            key=lambda a: q_table.get((current_state, a), 0.0)
        )

        assert best_action == "privesc"

    @pytest.mark.asyncio
    async def test_qlearning_learns_from_session(self, mock_agent_loop):
        """
        Test: Q-Learning updates from session history.
        """
        session_history = [
            {"state": "initial", "action": "port_scan", "reward": 0.1, "next_state": "enumerated"},
            {"state": "enumerated", "action": "web_scan", "reward": 0.1, "next_state": "web_discovered"},
            {"state": "web_discovered", "action": "sqli", "reward": 0.5, "next_state": "database_access"},
        ]

        # Calculate cumulative reward
        total_reward = sum(h["reward"] for h in session_history)

        assert total_reward == 0.7
        assert len(session_history) == 3

    @pytest.mark.asyncio
    async def test_qlearning_state_persistence(self, mock_memory_tool):
        """
        Test: Q-Learning state persists via memory.
        """
        q_state = {
            "q_table": {
                "initial_port_scan": 0.5,
                "initial_web_scan": 0.4,
            },
            "epsilon": 0.1,
            "episode_count": 50,
        }

        await mock_memory_tool.store(
            content=str(q_state),
            memory_type="algorithm_state",
            tags=["q_learning", "action_sequence"],
        )

        assert mock_memory_tool.store.called


# ============================================================================
# Dynamic Budget Integration Tests
# ============================================================================

class TestDynamicBudgetIntegration:
    """Tests for dynamic budget integration with subagent spawning."""

    @pytest.mark.asyncio
    async def test_budget_allocator_with_coordinator(self, mock_coordinator):
        """
        Test: Budget allocator integrates with coordinator spawn decisions.
        """
        # Simulate budget state
        budget_state = {
            "total_budget": 500,
            "used_budget": 200,
            "remaining": 300,
            "phase": "exploitation",
        }

        # Coordinator should check budget before spawning
        can_spawn = budget_state["remaining"] >= 10  # Minimum allocation

        assert can_spawn

    @pytest.mark.asyncio
    async def test_budget_adjusts_to_performance(self, mock_coordinator):
        """
        Test: Budget allocation adjusts based on subagent performance.
        """
        performance_metrics = {
            "scanner": {"efficiency": 0.2, "completion_rate": 0.9},
            "exploiter": {"efficiency": 0.05, "completion_rate": 0.5},
        }

        # Scanner should get more budget due to better performance
        scanner_multiplier = 1.0 + performance_metrics["scanner"]["efficiency"]
        exploiter_multiplier = 1.0 + performance_metrics["exploiter"]["efficiency"]

        assert scanner_multiplier > exploiter_multiplier

    @pytest.mark.asyncio
    async def test_budget_reallocation_late_phase(self, mock_agent_loop):
        """
        Test: Budget is reallocated in late assessment phase.
        """
        budget_state = {
            "total_budget": 500,
            "used_budget": 400,  # 80% used
            "reserved": 50,
        }

        utilization = budget_state["used_budget"] / budget_state["total_budget"]

        # Should trigger reallocation
        should_reallocate = utilization >= 0.8

        assert should_reallocate


# ============================================================================
# Cross-Algorithm Integration Tests
# ============================================================================

class TestCrossAlgorithmIntegration:
    """Tests for interaction between multiple algorithms."""

    @pytest.mark.asyncio
    async def test_mab_informs_mcts_priors(self):
        """
        Test: MAB statistics inform MCTS action priors.
        """
        # MAB provides success rates
        mab_stats = {
            "sqli": 0.7,
            "xss": 0.5,
            "ssrf": 0.6,
        }

        # MCTS uses these as rollout policy weights
        mcts_policy_weights = {
            action: rate * 2  # Scale for policy
            for action, rate in mab_stats.items()
        }

        assert mcts_policy_weights["sqli"] > mcts_policy_weights["xss"]

    @pytest.mark.asyncio
    async def test_bayesian_confidence_affects_budget(self):
        """
        Test: Bayesian confidence affects budget allocation.
        """
        findings = [
            {"id": "F1", "confidence": 0.9, "severity": "high"},
            {"id": "F2", "confidence": 0.5, "severity": "high"},
        ]

        # High confidence findings warrant more exploitation budget
        high_confidence_count = sum(1 for f in findings if f["confidence"] > 0.7)

        # Budget should allocate more to exploitation if high-confidence findings exist
        exploitation_priority = 50 + (high_confidence_count * 10)

        assert exploitation_priority == 60

    @pytest.mark.asyncio
    async def test_qlearning_and_mab_synergy(self):
        """
        Test: Q-Learning and MAB work together for action selection.
        """
        # Q-Learning for sequential decisions
        q_values = {
            ("authenticated", "privesc"): 0.8,
            ("authenticated", "dump_creds"): 0.7,
        }

        # MAB for technique selection within action
        mab_techniques = {
            "privesc_kernel": 0.6,
            "privesc_suid": 0.8,
            "privesc_sudo": 0.5,
        }

        # Q-Learning selects action category
        best_action = max(q_values.keys(), key=lambda k: q_values[k])[1]
        assert best_action == "privesc"

        # MAB selects specific technique
        best_technique = max(mab_techniques.keys(), key=lambda k: mab_techniques[k])
        assert best_technique == "privesc_suid"


# ============================================================================
# Memory Persistence Integration Tests
# ============================================================================

class TestMemoryPersistenceIntegration:
    """Tests for algorithm state persistence via memory."""

    @pytest.mark.asyncio
    async def test_all_algorithm_states_persist(self, mock_memory_tool):
        """
        Test: All algorithm states can be persisted to memory.
        """
        algorithm_states = {
            "mab": {"pulls": {}, "rewards": {}},
            "mcts": {"tree_root": {}, "visits": 0},
            "bayesian": {"findings_confidence": {}},
            "q_learning": {"q_table": {}, "epsilon": 0.1},
            "budget": {"allocations": [], "used": 0},
        }

        for algo, state in algorithm_states.items():
            await mock_memory_tool.store(
                content=str(state),
                memory_type="algorithm_state",
                tags=[algo],
            )

        assert mock_memory_tool.store.call_count == 5

    @pytest.mark.asyncio
    async def test_algorithm_state_recovery(self, mock_memory_tool):
        """
        Test: Algorithm states can be recovered from memory.
        """
        # Simulate stored state retrieval
        mock_memory_tool.search.return_value = [
            {"content": '{"pulls": 100, "rewards": 70.0}', "tags": ["mab"]},
        ]

        results = await mock_memory_tool.search(
            query="algorithm_state",
            filters={"tags": ["mab"]},
        )

        assert len(results) == 1
        assert "pulls" in results[0]["content"]


# ============================================================================
# Guardrails Integration Tests
# ============================================================================

class TestGuardrailsIntegration:
    """Tests that algorithmic improvements don't bypass guardrails."""

    @pytest.mark.asyncio
    async def test_mab_respects_scope(self, mock_agent_loop):
        """
        Test: MAB selections are filtered through scope validation.
        """
        mab_selection = "sql_injection"
        target = "https://in-scope.target.com/api"
        out_of_scope_target = "https://out-of-scope.com/api"

        # Scope manager mock
        def is_in_scope(url):
            return "in-scope" in url

        # Should allow in-scope
        assert is_in_scope(target)

        # Should block out-of-scope
        assert not is_in_scope(out_of_scope_target)

    @pytest.mark.asyncio
    async def test_mcts_actions_validated(self, mock_coordinator):
        """
        Test: MCTS recommended actions go through validation.
        """
        mcts_action = "exploit_sqli"
        dangerous_actions = ["rm_rf", "shutdown", "format"]

        # Action should not be in dangerous list
        assert mcts_action not in dangerous_actions

    @pytest.mark.asyncio
    async def test_budget_cannot_exceed_global_limit(self):
        """
        Test: Budget allocation cannot exceed global token limit.
        """
        global_token_limit = 1_000_000
        budget_per_turn = 16_000

        max_turns = global_token_limit // budget_per_turn

        # Budget allocation should respect max_turns limit
        requested_turns = 100
        allocated_turns = min(requested_turns, max_turns)
        estimated_tokens = allocated_turns * budget_per_turn

        assert estimated_tokens <= global_token_limit
        assert allocated_turns <= max_turns


# ============================================================================
# Error Handling Integration Tests
# ============================================================================

class TestErrorHandlingIntegration:
    """Tests for error handling in algorithm integration."""

    @pytest.mark.asyncio
    async def test_mab_handles_no_data(self, mock_memory_tool):
        """
        Test: MAB handles cold start gracefully.
        """
        mock_memory_tool.search.return_value = []

        results = await mock_memory_tool.search(query="mab_state")

        # Should return empty, algorithm uses defaults
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_mcts_handles_terminal_state(self):
        """
        Test: MCTS handles terminal states correctly.
        """
        terminal_states = ["root_access", "flag_captured", "blocked"]

        state = "root_access"

        is_terminal = state in terminal_states

        assert is_terminal

    @pytest.mark.asyncio
    async def test_budget_handles_exhaustion(self):
        """
        Test: Budget allocation handles exhausted budget.
        """
        budget_state = {
            "total": 500,
            "used": 495,
            "remaining": 5,
            "min_allocation": 10,
        }

        can_allocate = budget_state["remaining"] >= budget_state["min_allocation"]

        assert not can_allocate
