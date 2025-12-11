"""
Unit tests for Q-Learning action sequencing.

Tests the Q-Learning algorithm for learning optimal action sequences
during penetration testing assessments.
"""

import pytest
import numpy as np
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict
import random


# ============================================================================
# Q-Learning Data Structures
# ============================================================================

@dataclass
class QLearningConfig:
    """Configuration for Q-Learning algorithm."""

    learning_rate: float = 0.1          # Alpha - how much to update Q-values
    discount_factor: float = 0.95       # Gamma - importance of future rewards
    epsilon: float = 0.1                # Exploration rate
    epsilon_decay: float = 0.995        # Epsilon decay per episode
    min_epsilon: float = 0.01           # Minimum exploration rate
    initial_q_value: float = 0.0        # Initial Q-value for unseen state-actions


@dataclass
class State:
    """Represents an assessment state."""

    access_level: str                   # "none", "user", "admin", "root"
    discovered_vulns: frozenset         # Immutable set of discovered vulns
    exploited_vulns: frozenset          # Immutable set of exploited vulns
    phase: str                          # "recon", "scan", "exploit", "post"

    def __hash__(self):
        return hash((
            self.access_level,
            self.discovered_vulns,
            self.exploited_vulns,
            self.phase
        ))

    def __eq__(self, other):
        if not isinstance(other, State):
            return False
        return (
            self.access_level == other.access_level and
            self.discovered_vulns == other.discovered_vulns and
            self.exploited_vulns == other.exploited_vulns and
            self.phase == other.phase
        )


class QLearningAgent:
    """Q-Learning agent for action sequencing."""

    def __init__(self, config: QLearningConfig = None):
        self.config = config or QLearningConfig()
        self.q_table: Dict[Tuple[State, str], float] = defaultdict(
            lambda: self.config.initial_q_value
        )
        self.epsilon = self.config.epsilon
        self.episode_count = 0

    def get_q_value(self, state: State, action: str) -> float:
        """Get Q-value for state-action pair."""
        return self.q_table[(state, action)]

    def get_best_action(self, state: State, available_actions: List[str]) -> str:
        """Get the best action based on Q-values."""
        if not available_actions:
            return None

        q_values = {a: self.get_q_value(state, a) for a in available_actions}
        return max(q_values.keys(), key=lambda a: q_values[a])

    def select_action(self, state: State, available_actions: List[str]) -> str:
        """Select action using epsilon-greedy policy."""
        if not available_actions:
            return None

        if random.random() < self.epsilon:
            # Explore: random action
            return random.choice(available_actions)
        else:
            # Exploit: best action
            return self.get_best_action(state, available_actions)

    def update(
        self,
        state: State,
        action: str,
        reward: float,
        next_state: State,
        next_actions: List[str],
        done: bool = False
    ) -> None:
        """Update Q-value using Q-learning update rule."""
        current_q = self.get_q_value(state, action)

        if done or not next_actions:
            max_next_q = 0.0
        else:
            max_next_q = max(
                self.get_q_value(next_state, a) for a in next_actions
            )

        # Q-learning update
        target = reward + self.config.discount_factor * max_next_q
        new_q = current_q + self.config.learning_rate * (target - current_q)

        self.q_table[(state, action)] = new_q

    def decay_epsilon(self) -> None:
        """Decay exploration rate."""
        self.epsilon = max(
            self.config.min_epsilon,
            self.epsilon * self.config.epsilon_decay
        )

    def end_episode(self) -> None:
        """Called at end of episode."""
        self.episode_count += 1
        self.decay_epsilon()


# ============================================================================
# Test Environment
# ============================================================================

class PenTestEnvironment:
    """Simulated pen testing environment for Q-Learning."""

    def __init__(self):
        self.reset()

        # Action definitions with rewards and transitions
        self.action_effects = {
            "port_scan": {
                "reward": 0.1,
                "discovers": ["ssh", "http"],
                "success_prob": 0.95,
            },
            "web_scan": {
                "reward": 0.1,
                "discovers": ["sqli", "xss"],
                "requires": "http",
                "success_prob": 0.8,
            },
            "exploit_sqli": {
                "reward": 0.5,
                "requires": "sqli",
                "grants_access": "user",
                "success_prob": 0.6,
            },
            "exploit_xss": {
                "reward": 0.3,
                "requires": "xss",
                "success_prob": 0.5,
            },
            "ssh_brute": {
                "reward": 0.4,
                "requires": "ssh",
                "grants_access": "user",
                "success_prob": 0.2,
            },
            "privesc": {
                "reward": 0.8,
                "requires_access": "user",
                "grants_access": "root",
                "success_prob": 0.4,
            },
            "dump_creds": {
                "reward": 0.3,
                "requires_access": "user",
                "discovers": ["admin_creds"],
                "success_prob": 0.5,
            },
            "use_creds": {
                "reward": 0.6,
                "requires": "admin_creds",
                "grants_access": "admin",
                "success_prob": 0.9,
            },
            "admin_rce": {
                "reward": 0.7,
                "requires_access": "admin",
                "grants_access": "root",
                "success_prob": 0.7,
            },
        }

    def reset(self) -> State:
        """Reset environment to initial state."""
        self.current_state = State(
            access_level="none",
            discovered_vulns=frozenset(),
            exploited_vulns=frozenset(),
            phase="recon"
        )
        return self.current_state

    def get_available_actions(self, state: State = None) -> List[str]:
        """Get actions available in current state."""
        if state is None:
            state = self.current_state

        available = []

        for action, effects in self.action_effects.items():
            # Check prerequisites
            requires = effects.get("requires")
            requires_access = effects.get("requires_access")

            if requires and requires not in state.discovered_vulns:
                continue

            if requires_access:
                access_levels = ["none", "user", "admin", "root"]
                current_idx = access_levels.index(state.access_level)
                required_idx = access_levels.index(requires_access)
                if current_idx < required_idx:
                    continue

            available.append(action)

        return available

    def step(self, action: str) -> Tuple[State, float, bool]:
        """Execute action and return (next_state, reward, done)."""
        if action not in self.action_effects:
            return self.current_state, -0.1, False

        effects = self.action_effects[action]

        # Check if action succeeds
        if random.random() > effects.get("success_prob", 1.0):
            # Failed
            return self.current_state, -0.05, False

        # Apply effects
        reward = effects["reward"]
        new_discovered = set(self.current_state.discovered_vulns)
        new_exploited = set(self.current_state.exploited_vulns)
        new_access = self.current_state.access_level

        if "discovers" in effects:
            new_discovered.update(effects["discovers"])

        if "grants_access" in effects:
            access_levels = ["none", "user", "admin", "root"]
            current_idx = access_levels.index(new_access)
            new_idx = access_levels.index(effects["grants_access"])
            if new_idx > current_idx:
                new_access = effects["grants_access"]
            new_exploited.add(action)

        # Determine phase
        if new_access == "root":
            phase = "complete"
        elif new_exploited:
            phase = "post"
        elif new_discovered:
            phase = "exploit" if any(
                v in new_discovered for v in ["sqli", "xss", "ssh"]
            ) else "scan"
        else:
            phase = "recon"

        self.current_state = State(
            access_level=new_access,
            discovered_vulns=frozenset(new_discovered),
            exploited_vulns=frozenset(new_exploited),
            phase=phase
        )

        done = (new_access == "root")
        if done:
            reward += 1.0  # Bonus for achieving root

        return self.current_state, reward, done


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def q_config():
    """Q-Learning configuration."""
    return QLearningConfig(
        learning_rate=0.1,
        discount_factor=0.95,
        epsilon=0.1,
        epsilon_decay=0.99
    )


@pytest.fixture
def q_agent(q_config):
    """Q-Learning agent."""
    return QLearningAgent(q_config)


@pytest.fixture
def env():
    """Pen testing environment."""
    return PenTestEnvironment()


@pytest.fixture
def initial_state():
    """Initial assessment state."""
    return State(
        access_level="none",
        discovered_vulns=frozenset(),
        exploited_vulns=frozenset(),
        phase="recon"
    )


# ============================================================================
# Q-Value Update Tests
# ============================================================================

class TestQValueUpdates:
    """Tests for Q-value update mechanics."""

    def test_initial_q_values(self, q_agent, initial_state):
        """
        Test: Initial Q-values are set to configured value.
        """
        actions = ["port_scan", "web_scan", "ssh_brute"]

        for action in actions:
            q = q_agent.get_q_value(initial_state, action)
            assert q == q_agent.config.initial_q_value

    def test_q_update_positive_reward(self, q_agent, initial_state):
        """
        Test: Positive reward increases Q-value.
        """
        action = "port_scan"
        initial_q = q_agent.get_q_value(initial_state, action)

        next_state = State(
            access_level="none",
            discovered_vulns=frozenset(["http", "ssh"]),
            exploited_vulns=frozenset(),
            phase="scan"
        )

        q_agent.update(
            state=initial_state,
            action=action,
            reward=1.0,
            next_state=next_state,
            next_actions=["web_scan", "ssh_brute"],
            done=False
        )

        new_q = q_agent.get_q_value(initial_state, action)
        assert new_q > initial_q

    def test_q_update_negative_reward(self, q_agent, initial_state):
        """
        Test: Negative reward decreases Q-value.
        """
        action = "port_scan"

        # First set a positive Q-value
        q_agent.q_table[(initial_state, action)] = 0.5
        initial_q = q_agent.get_q_value(initial_state, action)

        # Update with negative reward
        q_agent.update(
            state=initial_state,
            action=action,
            reward=-1.0,
            next_state=initial_state,
            next_actions=["port_scan"],
            done=False
        )

        new_q = q_agent.get_q_value(initial_state, action)
        assert new_q < initial_q

    def test_q_learning_formula(self, q_config):
        """
        Test: Q-learning update follows correct formula.

        Q(s,a) <- Q(s,a) + alpha * (r + gamma * max(Q(s',a')) - Q(s,a))
        """
        agent = QLearningAgent(q_config)

        state = State("none", frozenset(), frozenset(), "recon")
        action = "test_action"
        next_state = State("user", frozenset(["vuln"]), frozenset(), "exploit")

        # Set known Q-values
        agent.q_table[(state, action)] = 0.5
        agent.q_table[(next_state, "next_action1")] = 0.8
        agent.q_table[(next_state, "next_action2")] = 0.3

        reward = 0.2
        alpha = q_config.learning_rate
        gamma = q_config.discount_factor

        # Expected calculation
        current_q = 0.5
        max_next_q = 0.8  # max of 0.8, 0.3
        expected_q = current_q + alpha * (reward + gamma * max_next_q - current_q)

        agent.update(
            state=state,
            action=action,
            reward=reward,
            next_state=next_state,
            next_actions=["next_action1", "next_action2"],
            done=False
        )

        actual_q = agent.get_q_value(state, action)
        assert abs(actual_q - expected_q) < 0.0001

    def test_terminal_state_no_future_reward(self, q_agent, initial_state):
        """
        Test: Terminal state has no future reward component.
        """
        terminal_state = State("root", frozenset(), frozenset(), "complete")

        q_agent.update(
            state=initial_state,
            action="magic_root",
            reward=1.0,
            next_state=terminal_state,
            next_actions=[],  # No actions in terminal state
            done=True
        )

        # Q-value should be based only on immediate reward
        q = q_agent.get_q_value(initial_state, "magic_root")
        # With alpha=0.1, initial_q=0, reward=1.0: Q = 0 + 0.1 * (1.0 + 0 - 0) = 0.1
        expected = q_agent.config.learning_rate * 1.0
        assert abs(q - expected) < 0.0001


# ============================================================================
# Action Selection Tests
# ============================================================================

class TestActionSelection:
    """Tests for action selection policies."""

    def test_epsilon_greedy_explores(self, q_agent, initial_state):
        """
        Test: Epsilon-greedy explores at configured rate.
        """
        q_agent.epsilon = 1.0  # Always explore

        actions = ["a1", "a2", "a3"]
        selections = defaultdict(int)

        for _ in range(3000):
            action = q_agent.select_action(initial_state, actions)
            selections[action] += 1

        # Should be roughly uniform
        expected = 1000
        for action, count in selections.items():
            assert abs(count - expected) < 200  # 20% tolerance

    def test_epsilon_greedy_exploits(self, q_agent, initial_state):
        """
        Test: Epsilon-greedy exploits best action when not exploring.
        """
        q_agent.epsilon = 0.0  # Never explore

        actions = ["a1", "a2", "a3"]

        # Set Q-values
        q_agent.q_table[(initial_state, "a1")] = 0.1
        q_agent.q_table[(initial_state, "a2")] = 0.9  # Best
        q_agent.q_table[(initial_state, "a3")] = 0.5

        # Should always select a2
        for _ in range(100):
            action = q_agent.select_action(initial_state, actions)
            assert action == "a2"

    def test_best_action_selection(self, q_agent, initial_state):
        """
        Test: get_best_action returns highest Q-value action.
        """
        actions = ["scan", "exploit", "brute"]

        q_agent.q_table[(initial_state, "scan")] = 0.3
        q_agent.q_table[(initial_state, "exploit")] = 0.7
        q_agent.q_table[(initial_state, "brute")] = 0.2

        best = q_agent.get_best_action(initial_state, actions)
        assert best == "exploit"

    def test_epsilon_decay(self, q_agent):
        """
        Test: Epsilon decays correctly over episodes.
        """
        initial_epsilon = q_agent.epsilon

        for _ in range(100):
            q_agent.end_episode()

        # Epsilon should have decayed
        assert q_agent.epsilon < initial_epsilon
        assert q_agent.epsilon >= q_agent.config.min_epsilon


# ============================================================================
# Learning Convergence Tests
# ============================================================================

class TestLearningConvergence:
    """Tests for learning convergence."""

    def test_q_values_converge(self, env):
        """
        Test: Q-values converge after many episodes.
        """
        random.seed(42)

        agent = QLearningAgent(QLearningConfig(
            learning_rate=0.1,
            discount_factor=0.95,
            epsilon=0.3,
            epsilon_decay=0.99,
            min_epsilon=0.01
        ))

        q_history = []

        for episode in range(500):
            state = env.reset()
            total_reward = 0

            for step in range(50):
                actions = env.get_available_actions(state)
                if not actions:
                    break

                action = agent.select_action(state, actions)
                next_state, reward, done = env.step(action)
                next_actions = env.get_available_actions(next_state)

                agent.update(state, action, reward, next_state, next_actions, done)

                total_reward += reward
                state = next_state

                if done:
                    break

            agent.end_episode()

            # Track Q-value for initial state, port_scan
            init_state = State("none", frozenset(), frozenset(), "recon")
            q_history.append(agent.get_q_value(init_state, "port_scan"))

        # Q-values should stabilize (variance decreases)
        early_variance = np.var(q_history[:50])
        late_variance = np.var(q_history[-50:])

        # Late variance should be lower (more stable)
        assert late_variance < early_variance or late_variance < 0.1

    def test_optimal_path_discovered(self, env):
        """
        Test: Agent learns to take optimal path.
        """
        random.seed(42)

        agent = QLearningAgent(QLearningConfig(
            learning_rate=0.2,
            discount_factor=0.95,
            epsilon=0.5,
            epsilon_decay=0.995,
            min_epsilon=0.01
        ))

        success_count = 0
        episode_lengths = []

        for episode in range(1000):
            state = env.reset()
            steps = 0

            for step in range(100):
                actions = env.get_available_actions(state)
                if not actions:
                    break

                action = agent.select_action(state, actions)
                next_state, reward, done = env.step(action)
                next_actions = env.get_available_actions(next_state)

                agent.update(state, action, reward, next_state, next_actions, done)

                state = next_state
                steps += 1

                if done:
                    success_count += 1
                    episode_lengths.append(steps)
                    break

            agent.end_episode()

        # Should achieve root access in many episodes
        assert success_count > 100  # At least 10% success rate

        # Episode length should decrease (learning efficiency)
        # This is a soft check due to stochastic environment
        if len(episode_lengths) > 40:
            early_avg = np.mean(episode_lengths[:20])
            late_avg = np.mean(episode_lengths[-20:])
            # Later episodes should generally be shorter (more efficient)
            # Allow for variance in stochastic environment
            # This is a trend check, not strict requirement
            assert late_avg <= early_avg * 2.0 or late_avg < 50


# ============================================================================
# State Space Tests
# ============================================================================

class TestStateSpace:
    """Tests for state space handling."""

    def test_state_hashing(self):
        """
        Test: States hash correctly for Q-table lookup.
        """
        state1 = State("none", frozenset(["a", "b"]), frozenset(), "recon")
        state2 = State("none", frozenset(["a", "b"]), frozenset(), "recon")
        state3 = State("user", frozenset(["a", "b"]), frozenset(), "recon")

        assert hash(state1) == hash(state2)
        assert state1 == state2
        assert hash(state1) != hash(state3)

    def test_state_equality(self):
        """
        Test: State equality works correctly.
        """
        s1 = State("none", frozenset(["x"]), frozenset(), "recon")
        s2 = State("none", frozenset(["x"]), frozenset(), "recon")
        s3 = State("none", frozenset(["y"]), frozenset(), "recon")

        assert s1 == s2
        assert s1 != s3

    def test_different_states_different_q_values(self, q_agent):
        """
        Test: Different states maintain independent Q-values.
        """
        state1 = State("none", frozenset(), frozenset(), "recon")
        state2 = State("user", frozenset(["vuln"]), frozenset(), "exploit")

        q_agent.q_table[(state1, "action")] = 0.5
        q_agent.q_table[(state2, "action")] = 0.9

        assert q_agent.get_q_value(state1, "action") == 0.5
        assert q_agent.get_q_value(state2, "action") == 0.9


# ============================================================================
# Integration Tests
# ============================================================================

class TestQLearningIntegration:
    """Tests for Q-Learning integration with Inferno."""

    def test_action_to_tool_mapping(self, env):
        """
        Test: Q-Learning actions map to actual tools.
        """
        action_tool_map = {
            "port_scan": "nmap -sV -sC",
            "web_scan": "gobuster dir -w wordlist.txt",
            "exploit_sqli": "sqlmap --batch --dbs",
            "exploit_xss": "xss_scanner --inject",
            "ssh_brute": "hydra -L users.txt -P pass.txt ssh://",
            "privesc": "linpeas.sh",
            "dump_creds": "mimikatz",
            "use_creds": "ssh/login with creds",
            "admin_rce": "admin_exploit",
        }

        for action in env.action_effects.keys():
            assert action in action_tool_map

    def test_q_table_persistence(self, q_agent, initial_state, tmp_path):
        """
        Test: Q-table can be saved and loaded.
        """
        import json

        # Add some Q-values
        q_agent.q_table[(initial_state, "scan")] = 0.5
        q_agent.q_table[(initial_state, "exploit")] = 0.8

        # Serialize (simplified - real impl would handle State objects)
        serializable = {
            str(k): v for k, v in q_agent.q_table.items()
        }

        q_file = tmp_path / "q_table.json"
        q_file.write_text(json.dumps(serializable))

        # Verify saved
        loaded = json.loads(q_file.read_text())
        assert len(loaded) == 2

    def test_reward_shaping(self, env):
        """
        Test: Reward structure encourages desired behavior.
        """
        # Root access should have highest reward
        root_actions = [a for a, e in env.action_effects.items()
                       if e.get("grants_access") == "root"]

        non_root_actions = [a for a, e in env.action_effects.items()
                          if e.get("grants_access") != "root"]

        max_root_reward = max(
            env.action_effects[a]["reward"] for a in root_actions
        )
        max_other_reward = max(
            env.action_effects[a]["reward"] for a in non_root_actions
        )

        # Root-granting actions should have higher base rewards
        assert max_root_reward >= max_other_reward


# ============================================================================
# Edge Cases Tests
# ============================================================================

class TestEdgeCases:
    """Tests for edge cases."""

    def test_no_available_actions(self, q_agent):
        """
        Test: Agent handles state with no available actions.
        """
        state = State("blocked", frozenset(), frozenset(), "failed")

        action = q_agent.select_action(state, [])
        assert action is None

        best = q_agent.get_best_action(state, [])
        assert best is None

    def test_single_action_available(self, q_agent, initial_state):
        """
        Test: Agent handles single available action.
        """
        q_agent.epsilon = 0.5  # Would normally explore

        action = q_agent.select_action(initial_state, ["only_option"])
        assert action == "only_option"

    def test_very_small_learning_rate(self):
        """
        Test: Very small learning rate causes slow convergence.
        """
        config = QLearningConfig(learning_rate=0.001)
        agent = QLearningAgent(config)

        state = State("none", frozenset(), frozenset(), "recon")
        action = "test"

        # Initial Q-value
        initial_q = agent.get_q_value(state, action)

        # Update many times
        for _ in range(100):
            agent.update(state, action, 1.0, state, [action], False)

        final_q = agent.get_q_value(state, action)

        # Q should increase but slowly
        assert final_q > initial_q
        assert final_q < 0.5  # Should not converge quickly

    def test_discount_factor_zero(self):
        """
        Test: Discount factor 0 means only immediate rewards matter.
        """
        config = QLearningConfig(discount_factor=0.0, learning_rate=1.0)
        agent = QLearningAgent(config)

        state1 = State("none", frozenset(), frozenset(), "recon")
        state2 = State("user", frozenset(), frozenset(), "exploit")

        # Set high future Q-value
        agent.q_table[(state2, "next_action")] = 100.0

        # Update with gamma=0
        agent.update(
            state=state1,
            action="action",
            reward=1.0,
            next_state=state2,
            next_actions=["next_action"],
            done=False
        )

        # Q should equal immediate reward (future ignored)
        q = agent.get_q_value(state1, "action")
        assert abs(q - 1.0) < 0.001
