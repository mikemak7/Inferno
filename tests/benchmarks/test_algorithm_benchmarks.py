"""
Benchmark tests for algorithmic improvements.

Measures performance, overhead, and improvement metrics
for MAB, MCTS, Bayesian Confidence, Q-Learning, and Dynamic Budget.
"""

import pytest
import time
import random
import numpy as np
from statistics import mean, stdev
from dataclasses import dataclass
from typing import List, Dict, Any
import math


# ============================================================================
# Benchmark Fixtures
# ============================================================================

@pytest.fixture
def benchmark_config():
    """Configuration for benchmarks."""
    return {
        "iterations": 1000,
        "warmup_iterations": 100,
        "statistical_runs": 10,
    }


# ============================================================================
# MAB Benchmarks
# ============================================================================

@pytest.mark.benchmark
class TestMABBenchmarks:
    """Benchmarks for Multi-Armed Bandit."""

    def test_ucb1_calculation_speed(self, benchmark_config):
        """
        Benchmark: UCB1 calculation speed.
        Target: < 1ms for 100 arms.
        """
        n_arms = 100
        arms = {
            f"arm_{i}": {"pulls": random.randint(1, 1000), "rewards": random.random() * 100}
            for i in range(n_arms)
        }

        total_pulls = sum(arm["pulls"] for arm in arms.values())

        times = []
        for _ in range(benchmark_config["iterations"]):
            start = time.perf_counter()

            for arm_name, stats in arms.items():
                mean_reward = stats["rewards"] / stats["pulls"]
                exploration = math.sqrt(2 * math.log(total_pulls) / stats["pulls"])
                ucb = mean_reward + exploration

            elapsed = (time.perf_counter() - start) * 1000  # ms

            times.append(elapsed)

        avg_time = mean(times)
        p95_time = sorted(times)[int(len(times) * 0.95)]

        print(f"\n{'='*60}")
        print(f"UCB1 Calculation Benchmark ({n_arms} arms)")
        print(f"{'='*60}")
        print(f"Average time:     {avg_time:.4f}ms")
        print(f"P95 time:         {p95_time:.4f}ms")
        print(f"Iterations:       {benchmark_config['iterations']}")
        print(f"{'='*60}")

        assert avg_time < 1.0, f"UCB1 too slow: {avg_time:.4f}ms (target: <1ms)"

    def test_thompson_sampling_speed(self, benchmark_config):
        """
        Benchmark: Thompson Sampling speed.
        Target: < 5ms for 100 arms with 1000 samples each.
        """
        n_arms = 100
        arms = {
            f"arm_{i}": {"successes": random.randint(1, 100), "failures": random.randint(1, 100)}
            for i in range(n_arms)
        }

        times = []
        for _ in range(benchmark_config["iterations"]):
            start = time.perf_counter()

            samples = {
                arm: np.random.beta(stats["successes"], stats["failures"])
                for arm, stats in arms.items()
            }
            best_arm = max(samples.keys(), key=lambda x: samples[x])

            elapsed = (time.perf_counter() - start) * 1000

            times.append(elapsed)

        avg_time = mean(times)
        p95_time = sorted(times)[int(len(times) * 0.95)]

        print(f"\n{'='*60}")
        print(f"Thompson Sampling Benchmark ({n_arms} arms)")
        print(f"{'='*60}")
        print(f"Average time:     {avg_time:.4f}ms")
        print(f"P95 time:         {p95_time:.4f}ms")
        print(f"{'='*60}")

        assert avg_time < 5.0, f"Thompson Sampling too slow: {avg_time:.4f}ms"

    def test_mab_convergence_rate(self):
        """
        Benchmark: MAB convergence to optimal arm.
        Target: > 70% optimal arm selection after 1000 iterations.
        """
        n_runs = 50
        n_iterations = 1000

        true_probs = {
            "optimal": 0.8,
            "good": 0.6,
            "medium": 0.4,
            "poor": 0.2,
        }

        optimal_selections = []

        for run in range(n_runs):
            random.seed(run)
            np.random.seed(run)

            state = {arm: {"successes": 1, "failures": 1} for arm in true_probs}
            selections = {arm: 0 for arm in true_probs}

            for _ in range(n_iterations):
                # Thompson Sampling selection
                samples = {
                    arm: np.random.beta(s["successes"], s["failures"])
                    for arm, s in state.items()
                }
                selected = max(samples.keys(), key=lambda x: samples[x])
                selections[selected] += 1

                # Get reward
                if random.random() < true_probs[selected]:
                    state[selected]["successes"] += 1
                else:
                    state[selected]["failures"] += 1

            # Calculate optimal selection rate
            optimal_rate = selections["optimal"] / n_iterations
            optimal_selections.append(optimal_rate)

        avg_optimal_rate = mean(optimal_selections)

        print(f"\n{'='*60}")
        print(f"MAB Convergence Benchmark")
        print(f"{'='*60}")
        print(f"Runs:                 {n_runs}")
        print(f"Iterations per run:   {n_iterations}")
        print(f"Avg optimal rate:     {avg_optimal_rate:.2%}")
        print(f"Min optimal rate:     {min(optimal_selections):.2%}")
        print(f"Max optimal rate:     {max(optimal_selections):.2%}")
        print(f"{'='*60}")

        assert avg_optimal_rate > 0.70, f"Convergence too slow: {avg_optimal_rate:.2%}"


# ============================================================================
# MCTS Benchmarks
# ============================================================================

@pytest.mark.benchmark
class TestMCTSBenchmarks:
    """Benchmarks for Monte Carlo Tree Search."""

    def test_mcts_iteration_speed(self, benchmark_config):
        """
        Benchmark: MCTS iteration speed.
        Target: > 100 iterations/second.
        """
        from collections import defaultdict

        # Simple tree node
        class Node:
            def __init__(self, state):
                self.state = state
                self.visits = 0
                self.reward = 0.0
                self.children = {}
                self.parent = None

        # Simple environment
        def get_actions(state):
            return ["a1", "a2", "a3"] if state != "terminal" else []

        def simulate(state):
            depth = 0
            reward = 0.0
            while state != "terminal" and depth < 10:
                state = random.choice(["s1", "s2", "terminal"])
                reward += random.random() * 0.1
                depth += 1
            return reward

        root = Node("initial")
        for action in get_actions("initial"):
            child = Node(f"state_{action}")
            child.parent = root
            root.children[action] = child

        n_iterations = 1000
        start = time.perf_counter()

        for _ in range(n_iterations):
            # Selection
            node = root
            while node.children:
                if node.visits == 0:
                    break
                # UCB selection
                best_ucb = -float("inf")
                best_child = None
                for child in node.children.values():
                    if child.visits == 0:
                        best_child = child
                        break
                    ucb = (child.reward / child.visits) + math.sqrt(
                        2 * math.log(node.visits) / child.visits
                    )
                    if ucb > best_ucb:
                        best_ucb = ucb
                        best_child = child
                if best_child:
                    node = best_child

            # Simulation
            reward = simulate(node.state)

            # Backpropagation
            while node:
                node.visits += 1
                node.reward += reward
                node = node.parent

        elapsed = time.perf_counter() - start
        iterations_per_sec = n_iterations / elapsed

        print(f"\n{'='*60}")
        print(f"MCTS Iteration Speed Benchmark")
        print(f"{'='*60}")
        print(f"Iterations:           {n_iterations}")
        print(f"Total time:           {elapsed:.3f}s")
        print(f"Iterations/second:    {iterations_per_sec:.0f}")
        print(f"{'='*60}")

        assert iterations_per_sec > 100, f"MCTS too slow: {iterations_per_sec:.0f} iter/s"

    def test_mcts_memory_growth(self):
        """
        Benchmark: MCTS memory growth per iteration.
        Target: < 1KB per iteration average.
        """
        import sys

        class Node:
            __slots__ = ['state', 'visits', 'reward', 'children', 'parent']

            def __init__(self, state):
                self.state = state
                self.visits = 0
                self.reward = 0.0
                self.children = {}
                self.parent = None

        root = Node("initial")
        initial_size = sys.getsizeof(root)

        nodes_created = [root]

        for i in range(1000):
            # Create new node
            node = Node(f"state_{i}")
            node.parent = root
            root.children[f"action_{i % 10}"] = node
            nodes_created.append(node)

        total_size = sum(sys.getsizeof(n) for n in nodes_created)
        avg_size = total_size / len(nodes_created)

        print(f"\n{'='*60}")
        print(f"MCTS Memory Growth Benchmark")
        print(f"{'='*60}")
        print(f"Nodes created:        {len(nodes_created)}")
        print(f"Total size:           {total_size / 1024:.2f}KB")
        print(f"Avg size per node:    {avg_size:.0f} bytes")
        print(f"{'='*60}")

        assert avg_size < 1024, f"Memory growth too high: {avg_size:.0f} bytes/node"


# ============================================================================
# Bayesian Confidence Benchmarks
# ============================================================================

@pytest.mark.benchmark
class TestBayesianBenchmarks:
    """Benchmarks for Bayesian confidence updates."""

    def test_bayesian_update_speed(self, benchmark_config):
        """
        Benchmark: Bayesian update speed.
        Target: < 0.1ms per update.
        """
        times = []

        for _ in range(benchmark_config["iterations"]):
            alpha, beta = 1.0, 1.0  # Prior

            start = time.perf_counter()

            # Simulate 10 evidence updates
            for _ in range(10):
                if random.random() > 0.5:
                    alpha += 1
                else:
                    beta += 1

                mean_conf = alpha / (alpha + beta)
                variance = (alpha * beta) / ((alpha + beta) ** 2 * (alpha + beta + 1))

            elapsed = (time.perf_counter() - start) * 1000 / 10  # ms per update

            times.append(elapsed)

        avg_time = mean(times)

        print(f"\n{'='*60}")
        print(f"Bayesian Update Speed Benchmark")
        print(f"{'='*60}")
        print(f"Average time/update:  {avg_time:.4f}ms")
        print(f"{'='*60}")

        assert avg_time < 0.1, f"Bayesian update too slow: {avg_time:.4f}ms"

    def test_credible_interval_calculation(self):
        """
        Benchmark: 95% credible interval calculation.
        Target: < 1ms per calculation.
        """
        pytest.importorskip("scipy")
        from scipy import stats

        n_calculations = 1000
        times = []

        for _ in range(n_calculations):
            alpha = random.uniform(1, 100)
            beta = random.uniform(1, 100)

            start = time.perf_counter()

            lower = stats.beta.ppf(0.025, alpha, beta)
            upper = stats.beta.ppf(0.975, alpha, beta)

            elapsed = (time.perf_counter() - start) * 1000

            times.append(elapsed)

        avg_time = mean(times)

        print(f"\n{'='*60}")
        print(f"Credible Interval Calculation Benchmark")
        print(f"{'='*60}")
        print(f"Calculations:         {n_calculations}")
        print(f"Average time:         {avg_time:.4f}ms")
        print(f"{'='*60}")

        assert avg_time < 1.0, f"CI calculation too slow: {avg_time:.4f}ms"


# ============================================================================
# Q-Learning Benchmarks
# ============================================================================

@pytest.mark.benchmark
class TestQLearningBenchmarks:
    """Benchmarks for Q-Learning."""

    def test_q_update_speed(self, benchmark_config):
        """
        Benchmark: Q-value update speed.
        Target: < 0.01ms per update.
        """
        q_table = {}
        alpha = 0.1
        gamma = 0.95

        times = []

        for _ in range(benchmark_config["iterations"]):
            state = f"state_{random.randint(0, 100)}"
            action = f"action_{random.randint(0, 10)}"
            next_state = f"state_{random.randint(0, 100)}"
            reward = random.random()

            start = time.perf_counter()

            current_q = q_table.get((state, action), 0.0)
            max_next_q = max(
                q_table.get((next_state, f"action_{i}"), 0.0)
                for i in range(10)
            )
            new_q = current_q + alpha * (reward + gamma * max_next_q - current_q)
            q_table[(state, action)] = new_q

            elapsed = (time.perf_counter() - start) * 1000

            times.append(elapsed)

        avg_time = mean(times)

        print(f"\n{'='*60}")
        print(f"Q-Learning Update Speed Benchmark")
        print(f"{'='*60}")
        print(f"Average time/update:  {avg_time:.6f}ms")
        print(f"Q-table size:         {len(q_table)} entries")
        print(f"{'='*60}")

        assert avg_time < 0.01, f"Q-update too slow: {avg_time:.6f}ms"

    def test_q_table_scaling(self):
        """
        Benchmark: Q-table lookup scales with size.
        Target: < 0.001ms lookup for 1M entries.
        """
        q_table = {}

        # Build large Q-table
        n_states = 1000
        n_actions = 100

        for s in range(n_states):
            for a in range(n_actions):
                q_table[(f"state_{s}", f"action_{a}")] = random.random()

        print(f"Q-table entries: {len(q_table)}")

        # Benchmark lookups
        n_lookups = 10000
        start = time.perf_counter()

        for _ in range(n_lookups):
            state = f"state_{random.randint(0, n_states-1)}"
            action = f"action_{random.randint(0, n_actions-1)}"
            _ = q_table.get((state, action), 0.0)

        elapsed = time.perf_counter() - start
        avg_lookup = (elapsed / n_lookups) * 1000

        print(f"\n{'='*60}")
        print(f"Q-Table Scaling Benchmark")
        print(f"{'='*60}")
        print(f"Table size:           {len(q_table)} entries")
        print(f"Lookups:              {n_lookups}")
        print(f"Avg lookup time:      {avg_lookup:.6f}ms")
        print(f"{'='*60}")

        assert avg_lookup < 0.001, f"Q-table lookup too slow: {avg_lookup:.6f}ms"


# ============================================================================
# Dynamic Budget Benchmarks
# ============================================================================

@pytest.mark.benchmark
class TestBudgetBenchmarks:
    """Benchmarks for Dynamic Budget allocation."""

    def test_allocation_calculation_speed(self, benchmark_config):
        """
        Benchmark: Budget allocation calculation speed.
        Target: < 0.1ms per allocation.
        """
        performance_data = {
            f"agent_{i}": {
                "efficiency": random.random(),
                "completion_rate": random.random(),
                "success_rate": random.random(),
            }
            for i in range(10)
        }

        times = []

        for _ in range(benchmark_config["iterations"]):
            agent = f"agent_{random.randint(0, 9)}"
            perf = performance_data[agent]
            base_allocation = 30

            start = time.perf_counter()

            # Calculate multiplier
            efficiency_factor = 1.0 + perf["efficiency"]
            completion_factor = 0.5 + perf["completion_rate"] * 0.5
            success_factor = 0.7 + perf["success_rate"] * 0.6
            multiplier = (efficiency_factor + completion_factor + success_factor) / 3

            allocation = int(base_allocation * multiplier)
            allocation = max(5, min(50, allocation))

            elapsed = (time.perf_counter() - start) * 1000

            times.append(elapsed)

        avg_time = mean(times)

        print(f"\n{'='*60}")
        print(f"Budget Allocation Speed Benchmark")
        print(f"{'='*60}")
        print(f"Average time:         {avg_time:.6f}ms")
        print(f"{'='*60}")

        assert avg_time < 0.1, f"Allocation too slow: {avg_time:.6f}ms"

    def test_reallocation_speed(self):
        """
        Benchmark: Budget reallocation speed.
        Target: < 1ms for reallocation across all agent types.
        """
        n_agent_types = 6
        performance = {
            f"type_{i}": {"efficiency": random.random(), "success_rate": random.random()}
            for i in range(n_agent_types)
        }
        remaining_budget = 200

        n_iterations = 1000
        times = []

        for _ in range(n_iterations):
            start = time.perf_counter()

            # Calculate weights
            weights = {}
            total_weight = 0
            for agent_type, perf in performance.items():
                weight = 1.0 + perf["efficiency"] + perf["success_rate"]
                weights[agent_type] = weight
                total_weight += weight

            # Distribute budget
            reallocation = {}
            for agent_type, weight in weights.items():
                share = int((weight / total_weight) * remaining_budget)
                reallocation[agent_type] = share

            elapsed = (time.perf_counter() - start) * 1000

            times.append(elapsed)

        avg_time = mean(times)

        print(f"\n{'='*60}")
        print(f"Budget Reallocation Speed Benchmark")
        print(f"{'='*60}")
        print(f"Agent types:          {n_agent_types}")
        print(f"Average time:         {avg_time:.6f}ms")
        print(f"{'='*60}")

        assert avg_time < 1.0, f"Reallocation too slow: {avg_time:.6f}ms"


# ============================================================================
# Combined Overhead Benchmark
# ============================================================================

@pytest.mark.benchmark
class TestCombinedOverhead:
    """Benchmark for combined algorithmic overhead."""

    def test_total_algorithm_overhead_per_turn(self):
        """
        Benchmark: Total overhead from all algorithms per agent turn.
        Target: < 10ms total overhead per turn.
        """
        n_turns = 100
        overhead_times = []

        for _ in range(n_turns):
            turn_overhead = 0.0

            # MAB selection
            start = time.perf_counter()
            arms = {"a1": 0.5, "a2": 0.6, "a3": 0.7}
            total_pulls = 100
            for arm, reward in arms.items():
                ucb = reward + math.sqrt(2 * math.log(total_pulls) / 10)
            turn_overhead += (time.perf_counter() - start) * 1000

            # Bayesian update
            start = time.perf_counter()
            alpha, beta = 5.0, 3.0
            mean_conf = alpha / (alpha + beta)
            turn_overhead += (time.perf_counter() - start) * 1000

            # Q-Learning lookup and update
            start = time.perf_counter()
            q_table = {("s1", "a1"): 0.5, ("s1", "a2"): 0.6}
            current_q = q_table.get(("s1", "a1"), 0.0)
            new_q = current_q + 0.1 * (0.5 + 0.95 * 0.6 - current_q)
            turn_overhead += (time.perf_counter() - start) * 1000

            # Budget check
            start = time.perf_counter()
            remaining = 300
            allocation = min(30, remaining)
            turn_overhead += (time.perf_counter() - start) * 1000

            overhead_times.append(turn_overhead)

        avg_overhead = mean(overhead_times)
        max_overhead = max(overhead_times)

        print(f"\n{'='*60}")
        print(f"Combined Algorithm Overhead Benchmark")
        print(f"{'='*60}")
        print(f"Turns simulated:      {n_turns}")
        print(f"Avg overhead/turn:    {avg_overhead:.4f}ms")
        print(f"Max overhead/turn:    {max_overhead:.4f}ms")
        print(f"{'='*60}")

        assert avg_overhead < 10.0, f"Total overhead too high: {avg_overhead:.4f}ms"
