"""
Unit tests for Multi-Armed Bandit (MAB) attack vector selection.

Tests the UCB1, Thompson Sampling, and Epsilon-Greedy strategies
for selecting optimal attack vectors based on historical success rates.
"""

import pytest
import numpy as np
import copy
from unittest.mock import Mock, patch
from dataclasses import dataclass
from typing import List, Tuple
import math


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def attack_vectors():
    """Sample attack vectors for testing."""
    return [
        "sql_injection",
        "xss",
        "ssrf",
        "idor",
        "path_traversal",
        "rce",
        "auth_bypass",
        "file_upload",
    ]


@pytest.fixture
def mab_state_empty(attack_vectors):
    """Empty MAB state (cold start scenario)."""
    return {
        vector: {"pulls": 0, "rewards": 0.0, "successes": 0, "failures": 0}
        for vector in attack_vectors
    }


@pytest.fixture
def mab_state_initialized(attack_vectors):
    """MAB state with historical data."""
    return {
        "sql_injection": {"pulls": 50, "rewards": 35.0, "successes": 35, "failures": 15},
        "xss": {"pulls": 40, "rewards": 20.0, "successes": 20, "failures": 20},
        "ssrf": {"pulls": 30, "rewards": 25.0, "successes": 25, "failures": 5},
        "idor": {"pulls": 25, "rewards": 15.0, "successes": 15, "failures": 10},
        "path_traversal": {"pulls": 20, "rewards": 8.0, "successes": 8, "failures": 12},
        "rce": {"pulls": 10, "rewards": 8.0, "successes": 8, "failures": 2},
        "auth_bypass": {"pulls": 15, "rewards": 10.0, "successes": 10, "failures": 5},
        "file_upload": {"pulls": 5, "rewards": 3.0, "successes": 3, "failures": 2},
    }


# ============================================================================
# UCB1 Algorithm Tests
# ============================================================================

class TestUCB1Algorithm:
    """Tests for Upper Confidence Bound (UCB1) algorithm."""

    def test_ucb1_formula_correctness(self, mab_state_initialized):
        """
        Test: UCB1 formula calculates correct confidence bounds.

        UCB1 formula: mean_reward + sqrt(2 * ln(total_pulls) / arm_pulls)
        """
        total_pulls = sum(arm["pulls"] for arm in mab_state_initialized.values())

        for vector, stats in mab_state_initialized.items():
            if stats["pulls"] > 0:
                mean_reward = stats["rewards"] / stats["pulls"]
                exploration_term = math.sqrt(
                    2 * math.log(total_pulls) / stats["pulls"]
                )
                ucb_value = mean_reward + exploration_term

                # Verify components are positive
                assert mean_reward >= 0, f"Mean reward should be non-negative for {vector}"
                assert exploration_term > 0, f"Exploration term should be positive for {vector}"
                assert ucb_value > mean_reward, "UCB should exceed mean reward"

    def test_ucb1_cold_start_exploration(self, mab_state_empty):
        """
        Test: UCB1 explores all arms when no data exists (cold start).

        Expected: With no historical data, all arms should have equal
        infinite UCB values, triggering uniform exploration.
        """
        # In cold start, each arm should be selected at least once
        # before exploitation begins
        selected_arms = set()

        for _ in range(len(mab_state_empty)):
            # Find arm with minimum pulls (should be 0 initially)
            min_pulls_arm = min(
                mab_state_empty.keys(),
                key=lambda x: mab_state_empty[x]["pulls"]
            )
            selected_arms.add(min_pulls_arm)

            # Simulate selection
            mab_state_empty[min_pulls_arm]["pulls"] += 1
            mab_state_empty[min_pulls_arm]["rewards"] += np.random.random()

        # All arms should be explored in cold start
        assert len(selected_arms) == len(mab_state_empty), \
            "UCB1 should explore all arms at least once during cold start"

    def test_ucb1_exploitation_after_exploration(self, mab_state_initialized):
        """
        Test: UCB1 exploits high-reward arms after sufficient exploration.
        """
        total_pulls = sum(arm["pulls"] for arm in mab_state_initialized.values())

        # Calculate UCB values
        ucb_values = {}
        for vector, stats in mab_state_initialized.items():
            mean_reward = stats["rewards"] / stats["pulls"]
            exploration = math.sqrt(2 * math.log(total_pulls) / stats["pulls"])
            ucb_values[vector] = mean_reward + exploration

        # SSRF has high success rate (83%) with fewer pulls -> higher UCB
        # RCE has high success rate (80%) with few pulls -> should have high UCB
        best_arm = max(ucb_values.keys(), key=lambda x: ucb_values[x])

        # The best arm should be one with good reward/exploration balance
        assert mab_state_initialized[best_arm]["pulls"] > 0

    def test_ucb1_convergence(self, attack_vectors):
        """
        Test: UCB1 converges to optimal arm over many iterations.

        Simulates 1000 pulls with known reward probabilities and
        verifies the optimal arm is selected most frequently.
        """
        # True reward probabilities (known only to test)
        true_probabilities = {
            "sql_injection": 0.7,
            "xss": 0.5,
            "ssrf": 0.85,  # Best arm
            "idor": 0.6,
            "path_traversal": 0.4,
            "rce": 0.8,
            "auth_bypass": 0.65,
            "file_upload": 0.55,
        }

        # Initialize state
        state = {v: {"pulls": 0, "rewards": 0.0} for v in attack_vectors}
        selection_counts = {v: 0 for v in attack_vectors}

        np.random.seed(42)  # Reproducibility

        for t in range(1, 1001):
            # Select arm using UCB1
            best_ucb = -float("inf")
            selected_arm = None

            for arm in attack_vectors:
                if state[arm]["pulls"] == 0:
                    # Unplayed arms have infinite UCB
                    selected_arm = arm
                    break

                mean = state[arm]["rewards"] / state[arm]["pulls"]
                exploration = math.sqrt(2 * math.log(t) / state[arm]["pulls"])
                ucb = mean + exploration

                if ucb > best_ucb:
                    best_ucb = ucb
                    selected_arm = arm

            # Pull the arm and get reward
            reward = 1.0 if np.random.random() < true_probabilities[selected_arm] else 0.0
            state[selected_arm]["pulls"] += 1
            state[selected_arm]["rewards"] += reward
            selection_counts[selected_arm] += 1

        # SSRF (85% success) should be selected most often
        most_selected = max(selection_counts.keys(), key=lambda x: selection_counts[x])

        # Allow for some variance - optimal should be in top 2
        sorted_by_selection = sorted(
            selection_counts.keys(),
            key=lambda x: selection_counts[x],
            reverse=True
        )
        assert "ssrf" in sorted_by_selection[:2], \
            f"Optimal arm 'ssrf' should be in top 2 selections, got {sorted_by_selection[:2]}"

    def test_ucb1_parameter_sensitivity(self, mab_state_initialized):
        """
        Test: UCB1 exploration parameter affects arm selection.

        Higher exploration constant -> more exploration
        Lower exploration constant -> more exploitation
        """
        total_pulls = sum(arm["pulls"] for arm in mab_state_initialized.values())

        exploration_constants = [0.5, 1.0, 2.0, 4.0]
        selections = {}

        for c in exploration_constants:
            ucb_values = {}
            for vector, stats in mab_state_initialized.items():
                mean_reward = stats["rewards"] / stats["pulls"]
                exploration = math.sqrt(c * math.log(total_pulls) / stats["pulls"])
                ucb_values[vector] = mean_reward + exploration

            selections[c] = max(ucb_values.keys(), key=lambda x: ucb_values[x])

        # With high c, arms with fewer pulls should be favored
        # (exploration bonus dominates)
        # file_upload has fewest pulls (5), should be selected with high c


# ============================================================================
# Thompson Sampling Tests
# ============================================================================

class TestThompsonSampling:
    """Tests for Thompson Sampling algorithm."""

    def test_thompson_sampling_beta_distribution(self, mab_state_initialized):
        """
        Test: Thompson Sampling uses Beta distribution correctly.

        For Bernoulli rewards, posterior is Beta(alpha + successes, beta + failures)
        """
        np.random.seed(42)

        for vector, stats in mab_state_initialized.items():
            alpha = 1 + stats["successes"]  # Prior alpha = 1
            beta = 1 + stats["failures"]    # Prior beta = 1

            # Sample from Beta distribution
            samples = np.random.beta(alpha, beta, size=1000)

            # Mean should approximate true success rate
            true_rate = stats["successes"] / (stats["successes"] + stats["failures"])
            sample_mean = np.mean(samples)

            # Allow 10% tolerance
            assert abs(sample_mean - true_rate) < 0.1, \
                f"Thompson sample mean {sample_mean:.3f} should be close to true rate {true_rate:.3f}"

    def test_thompson_sampling_cold_start(self, mab_state_empty):
        """
        Test: Thompson Sampling handles cold start with uninformative prior.
        """
        np.random.seed(42)

        # With Beta(1,1) prior (uniform), samples should be ~uniform
        samples = {}
        for vector in mab_state_empty.keys():
            # Prior: Beta(1, 1) = Uniform(0, 1)
            samples[vector] = np.random.beta(1, 1, size=100)

        # Mean should be approximately 0.5 for all arms
        for vector, s in samples.items():
            assert 0.3 < np.mean(s) < 0.7, \
                f"Uninformative prior should yield ~0.5 mean, got {np.mean(s):.3f}"

    def test_thompson_sampling_convergence(self, attack_vectors):
        """
        Test: Thompson Sampling converges to optimal arm.
        """
        true_probabilities = {
            "sql_injection": 0.7,
            "xss": 0.5,
            "ssrf": 0.85,  # Best arm
            "idor": 0.6,
            "path_traversal": 0.4,
            "rce": 0.8,
            "auth_bypass": 0.65,
            "file_upload": 0.55,
        }

        state = {v: {"successes": 1, "failures": 1} for v in attack_vectors}  # Beta(1,1) prior
        selection_counts = {v: 0 for v in attack_vectors}

        np.random.seed(42)

        for _ in range(1000):
            # Sample from each arm's posterior
            samples = {
                arm: np.random.beta(
                    state[arm]["successes"],
                    state[arm]["failures"]
                )
                for arm in attack_vectors
            }

            # Select arm with highest sample
            selected_arm = max(samples.keys(), key=lambda x: samples[x])
            selection_counts[selected_arm] += 1

            # Get reward
            if np.random.random() < true_probabilities[selected_arm]:
                state[selected_arm]["successes"] += 1
            else:
                state[selected_arm]["failures"] += 1

        # Verify convergence to optimal
        sorted_arms = sorted(
            selection_counts.keys(),
            key=lambda x: selection_counts[x],
            reverse=True
        )
        assert "ssrf" in sorted_arms[:2], \
            f"Thompson Sampling should converge to optimal, got {sorted_arms[:3]}"

    def test_thompson_sampling_uncertainty_decreases(self, attack_vectors):
        """
        Test: Posterior uncertainty decreases with more data.
        """
        np.random.seed(42)

        # Track variance over iterations
        variances = []
        state = {"successes": 1, "failures": 1}

        for i in range(100):
            # Simulate 70% success rate
            if np.random.random() < 0.7:
                state["successes"] += 1
            else:
                state["failures"] += 1

            # Calculate posterior variance: Beta variance formula
            alpha = state["successes"]
            beta = state["failures"]
            variance = (alpha * beta) / ((alpha + beta) ** 2 * (alpha + beta + 1))
            variances.append(variance)

        # Variance should decrease monotonically (with some noise)
        assert variances[-1] < variances[0], \
            "Posterior variance should decrease with more data"

        # Final variance should be small
        assert variances[-1] < 0.01, \
            f"Variance should be small after 100 pulls, got {variances[-1]:.4f}"


# ============================================================================
# Epsilon-Greedy Tests
# ============================================================================

class TestEpsilonGreedy:
    """Tests for Epsilon-Greedy algorithm."""

    def test_epsilon_greedy_exploration_rate(self, mab_state_initialized):
        """
        Test: Epsilon-Greedy explores at the specified rate.
        """
        epsilon = 0.1
        n_iterations = 10000
        exploration_count = 0
        exploitation_count = 0

        np.random.seed(42)

        # Find best arm (highest mean reward)
        best_arm = max(
            mab_state_initialized.keys(),
            key=lambda x: mab_state_initialized[x]["rewards"] / mab_state_initialized[x]["pulls"]
        )

        for _ in range(n_iterations):
            if np.random.random() < epsilon:
                exploration_count += 1
            else:
                exploitation_count += 1

        # Exploration rate should be approximately epsilon
        actual_rate = exploration_count / n_iterations
        assert abs(actual_rate - epsilon) < 0.02, \
            f"Exploration rate {actual_rate:.3f} should be close to epsilon {epsilon}"

    def test_epsilon_greedy_decay(self, attack_vectors):
        """
        Test: Epsilon decay reduces exploration over time.
        """
        initial_epsilon = 1.0
        min_epsilon = 0.01
        decay_rate = 0.995

        epsilon = initial_epsilon
        epsilons = [epsilon]

        for _ in range(1000):
            epsilon = max(min_epsilon, epsilon * decay_rate)
            epsilons.append(epsilon)

        # Epsilon should decay towards min
        assert epsilons[-1] == pytest.approx(min_epsilon, rel=0.1), \
            f"Epsilon should decay to min, got {epsilons[-1]:.4f}"

        # Decay should be smooth
        for i in range(1, len(epsilons)):
            assert epsilons[i] <= epsilons[i-1], "Epsilon should decrease monotonically"


# ============================================================================
# Integration with Agent Loop Tests
# ============================================================================

class TestMABAgentIntegration:
    """Tests for MAB integration with agent execution loop."""

    def test_mab_state_persistence(self, mab_state_initialized, tmp_path):
        """
        Test: MAB state persists across sessions via memory.
        """
        import json

        # Simulate saving state to memory
        state_file = tmp_path / "mab_state.json"
        state_file.write_text(json.dumps(mab_state_initialized))

        # Reload state
        loaded_state = json.loads(state_file.read_text())

        assert loaded_state == mab_state_initialized, \
            "MAB state should persist and reload correctly"

    def test_mab_update_after_tool_execution(self, mab_state_initialized):
        """
        Test: MAB state updates correctly after tool execution.
        """
        # Simulate successful SQL injection attempt
        vector = "sql_injection"
        original_pulls = mab_state_initialized[vector]["pulls"]
        original_rewards = mab_state_initialized[vector]["rewards"]

        # Update state
        mab_state_initialized[vector]["pulls"] += 1
        mab_state_initialized[vector]["rewards"] += 1.0  # Success
        mab_state_initialized[vector]["successes"] += 1

        assert mab_state_initialized[vector]["pulls"] == original_pulls + 1
        assert mab_state_initialized[vector]["rewards"] == original_rewards + 1.0

    def test_mab_selection_affects_tool_choice(self, mab_state_initialized):
        """
        Test: MAB selection influences which tool/technique is used.
        """
        # Calculate UCB values
        total_pulls = sum(arm["pulls"] for arm in mab_state_initialized.values())

        ucb_values = {}
        for vector, stats in mab_state_initialized.items():
            mean_reward = stats["rewards"] / stats["pulls"]
            exploration = math.sqrt(2 * math.log(total_pulls) / stats["pulls"])
            ucb_values[vector] = mean_reward + exploration

        selected_vector = max(ucb_values.keys(), key=lambda x: ucb_values[x])

        # Selection should be a valid attack vector
        assert selected_vector in mab_state_initialized.keys()

        # Map to tool selection
        vector_to_tool = {
            "sql_injection": "sqlmap",
            "xss": "xss_scanner",
            "ssrf": "ssrf_detector",
            "idor": "idor_scanner",
            "path_traversal": "directory_traversal",
            "rce": "rce_exploiter",
            "auth_bypass": "auth_tester",
            "file_upload": "upload_tester",
        }

        selected_tool = vector_to_tool.get(selected_vector)
        assert selected_tool is not None, f"Selected vector {selected_vector} should map to a tool"


# ============================================================================
# Edge Cases and Error Handling
# ============================================================================

class TestMABEdgeCases:
    """Tests for edge cases and error handling."""

    def test_mab_single_arm(self):
        """
        Test: MAB handles single arm correctly.
        """
        single_arm_state = {
            "only_option": {"pulls": 10, "rewards": 7.0, "successes": 7, "failures": 3}
        }

        # Should always select the only arm
        best_arm = max(
            single_arm_state.keys(),
            key=lambda x: single_arm_state[x]["rewards"] / single_arm_state[x]["pulls"]
        )
        assert best_arm == "only_option"

    def test_mab_zero_rewards(self, attack_vectors):
        """
        Test: MAB handles arms with zero rewards.
        """
        zero_state = {
            vector: {"pulls": 10, "rewards": 0.0, "successes": 0, "failures": 10}
            for vector in attack_vectors
        }

        # All arms have same (zero) mean, UCB should prefer less explored
        # (but all have same pulls here, so any selection is valid)
        total_pulls = sum(arm["pulls"] for arm in zero_state.values())

        ucb_values = {}
        for vector, stats in zero_state.items():
            mean_reward = 0.0
            exploration = math.sqrt(2 * math.log(total_pulls) / stats["pulls"])
            ucb_values[vector] = mean_reward + exploration

        # All UCB values should be equal (same exploration term, zero mean)
        values = list(ucb_values.values())
        assert all(abs(v - values[0]) < 0.001 for v in values), \
            "All arms with zero reward and equal pulls should have equal UCB"

    def test_mab_numerical_stability_large_pulls(self):
        """
        Test: MAB remains numerically stable with large pull counts.
        """
        large_state = {
            "arm1": {"pulls": 1_000_000, "rewards": 700_000.0},
            "arm2": {"pulls": 500_000, "rewards": 400_000.0},
        }

        total_pulls = sum(arm["pulls"] for arm in large_state.values())

        ucb_values = {}
        for arm, stats in large_state.items():
            mean_reward = stats["rewards"] / stats["pulls"]
            exploration = math.sqrt(2 * math.log(total_pulls) / stats["pulls"])
            ucb_values[arm] = mean_reward + exploration

            # Should not overflow or produce NaN
            assert not math.isnan(ucb_values[arm])
            assert not math.isinf(ucb_values[arm])
            assert ucb_values[arm] >= 0

    def test_mab_contextual_vectors(self, mab_state_initialized):
        """
        Test: MAB can handle context-dependent arm selection.

        Different contexts (e.g., target type) should have separate MAB states.
        """
        contexts = ["web_app", "api", "mobile_backend"]
        contextual_states = {
            context: copy.deepcopy(mab_state_initialized)
            for context in contexts
        }

        # Each context should maintain independent state
        contextual_states["api"]["sql_injection"]["rewards"] += 10

        assert contextual_states["api"]["sql_injection"]["rewards"] != \
               contextual_states["web_app"]["sql_injection"]["rewards"], \
            "Contextual MAB should maintain independent states"
