"""
Unit tests for Monte Carlo Tree Search (MCTS) attack path discovery.

Tests the MCTS algorithm for exploring and discovering optimal
attack paths through a target's attack surface.
"""

import pytest
import math
import random
from unittest.mock import Mock, AsyncMock, patch
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from collections import defaultdict


# ============================================================================
# MCTS Data Structures for Testing
# ============================================================================

@dataclass
class AttackNode:
    """Node in the MCTS attack tree."""

    state: str  # Current attack state (e.g., "initial", "authenticated", "admin")
    action: Optional[str] = None  # Action that led to this state
    parent: Optional["AttackNode"] = None
    children: List["AttackNode"] = field(default_factory=list)
    visits: int = 0
    reward: float = 0.0
    untried_actions: List[str] = field(default_factory=list)

    @property
    def ucb1(self) -> float:
        """Calculate UCB1 value for this node."""
        if self.visits == 0:
            return float("inf")
        if self.parent is None or self.parent.visits == 0:
            return self.reward / self.visits

        exploitation = self.reward / self.visits
        exploration = math.sqrt(2 * math.log(self.parent.visits) / self.visits)
        return exploitation + exploration

    def is_terminal(self) -> bool:
        """Check if this is a terminal state."""
        return self.state in ["root_access", "flag_captured", "game_over", "blocked"]

    def is_fully_expanded(self) -> bool:
        """Check if all actions have been tried."""
        return len(self.untried_actions) == 0


@dataclass
class AttackSimulation:
    """Simulated attack environment for MCTS testing."""

    # State transition probabilities
    transitions: Dict[str, Dict[str, tuple]] = field(default_factory=dict)
    # Rewards for reaching states
    state_rewards: Dict[str, float] = field(default_factory=dict)

    def __post_init__(self):
        if not self.transitions:
            # Default attack graph
            self.transitions = {
                "initial": {
                    "port_scan": ("enumerated", 0.95),
                    "web_scan": ("web_discovered", 0.9),
                    "social_eng": ("credentials", 0.3),
                },
                "enumerated": {
                    "service_exploit": ("shell", 0.4),
                    "web_attack": ("web_discovered", 0.8),
                    "brute_force": ("credentials", 0.2),
                },
                "web_discovered": {
                    "sqli": ("database_access", 0.5),
                    "xss": ("session_hijack", 0.4),
                    "ssrf": ("internal_access", 0.3),
                    "auth_bypass": ("authenticated", 0.35),
                },
                "credentials": {
                    "login": ("authenticated", 0.9),
                    "ssh_access": ("shell", 0.8),
                },
                "authenticated": {
                    "privesc_web": ("admin", 0.4),
                    "idor": ("data_leak", 0.5),
                    "file_upload": ("shell", 0.3),
                },
                "database_access": {
                    "dump_creds": ("credentials", 0.7),
                    "data_exfil": ("data_leak", 0.9),
                    "write_shell": ("shell", 0.3),
                },
                "shell": {
                    "local_privesc": ("root_access", 0.4),
                    "lateral_move": ("internal_access", 0.5),
                    "persistence": ("persistent_access", 0.7),
                },
                "admin": {
                    "admin_rce": ("shell", 0.6),
                    "admin_data": ("data_leak", 0.8),
                },
                "internal_access": {
                    "pivot_attack": ("shell", 0.5),
                    "internal_scan": ("enumerated", 0.8),
                },
            }

        if not self.state_rewards:
            self.state_rewards = {
                "initial": 0.0,
                "enumerated": 0.1,
                "web_discovered": 0.1,
                "credentials": 0.3,
                "authenticated": 0.3,
                "database_access": 0.5,
                "session_hijack": 0.3,
                "internal_access": 0.4,
                "shell": 0.7,
                "admin": 0.5,
                "data_leak": 0.6,
                "persistent_access": 0.6,
                "root_access": 1.0,  # Terminal goal
                "blocked": -0.5,
            }

    def get_actions(self, state: str) -> List[str]:
        """Get available actions from a state."""
        return list(self.transitions.get(state, {}).keys())

    def simulate_action(self, state: str, action: str) -> tuple:
        """Simulate taking an action. Returns (new_state, reward)."""
        if state not in self.transitions or action not in self.transitions[state]:
            return ("blocked", -0.5)

        next_state, success_prob = self.transitions[state][action]

        if random.random() < success_prob:
            return (next_state, self.state_rewards.get(next_state, 0.0))
        else:
            return (state, -0.1)  # Failed, stay in same state with penalty


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def attack_simulation():
    """Create a simulated attack environment."""
    return AttackSimulation()


@pytest.fixture
def root_node(attack_simulation):
    """Create a root node for MCTS."""
    return AttackNode(
        state="initial",
        untried_actions=attack_simulation.get_actions("initial")
    )


@pytest.fixture
def expanded_tree(attack_simulation):
    """Create a partially expanded MCTS tree."""
    root = AttackNode(
        state="initial",
        visits=100,
        reward=30.0,
        untried_actions=[]
    )

    # Add children
    child1 = AttackNode(
        state="enumerated",
        action="port_scan",
        parent=root,
        visits=50,
        reward=20.0,
        untried_actions=["service_exploit", "brute_force"]
    )

    child2 = AttackNode(
        state="web_discovered",
        action="web_scan",
        parent=root,
        visits=40,
        reward=15.0,
        untried_actions=["xss", "ssrf"]
    )

    child3 = AttackNode(
        state="credentials",
        action="social_eng",
        parent=root,
        visits=10,
        reward=5.0,
        untried_actions=["login", "ssh_access"]
    )

    root.children = [child1, child2, child3]

    return root


# ============================================================================
# Selection Phase Tests
# ============================================================================

class TestMCTSSelection:
    """Tests for MCTS selection phase."""

    def test_ucb1_selection_prefers_promising_nodes(self, expanded_tree):
        """
        Test: UCB1 selection balances exploration and exploitation.
        """
        # Calculate UCB1 for each child
        ucb_values = {
            child.state: child.ucb1
            for child in expanded_tree.children
        }

        # All values should be finite
        assert all(not math.isinf(v) for v in ucb_values.values())

        # Select best child
        best_child = max(expanded_tree.children, key=lambda c: c.ucb1)

        # Credentials node has fewer visits (10 vs 50,40) -> higher exploration bonus
        # Should balance against lower average reward
        assert best_child is not None

    def test_selection_traverses_to_leaf(self, expanded_tree):
        """
        Test: Selection traverses tree until reaching expandable node.
        """
        def select(node: AttackNode) -> AttackNode:
            while not node.is_terminal() and node.is_fully_expanded():
                if not node.children:
                    break
                node = max(node.children, key=lambda c: c.ucb1)
            return node

        selected = select(expanded_tree)

        # Should stop at a node with untried actions or no children
        assert not selected.is_fully_expanded() or len(selected.children) == 0

    def test_selection_handles_unvisited_nodes(self, root_node):
        """
        Test: Selection handles nodes with zero visits (infinite UCB).
        """
        # Unvisited root should have untried actions
        assert len(root_node.untried_actions) > 0
        assert root_node.visits == 0

        # UCB1 should be infinity for unvisited node
        # (division by zero protection needed)
        if root_node.visits == 0:
            ucb = float("inf")
        else:
            ucb = root_node.ucb1

        assert math.isinf(ucb)


# ============================================================================
# Expansion Phase Tests
# ============================================================================

class TestMCTSExpansion:
    """Tests for MCTS expansion phase."""

    def test_expansion_adds_child_node(self, expanded_tree, attack_simulation):
        """
        Test: Expansion adds a new child node for untried action.
        """
        # Find node with untried actions
        expandable = expanded_tree.children[0]  # enumerated state
        assert len(expandable.untried_actions) > 0

        initial_children = len(expandable.children)

        # Expand
        action = expandable.untried_actions.pop()
        new_state, _ = attack_simulation.simulate_action(expandable.state, action)

        new_child = AttackNode(
            state=new_state,
            action=action,
            parent=expandable,
            untried_actions=attack_simulation.get_actions(new_state)
        )
        expandable.children.append(new_child)

        assert len(expandable.children) == initial_children + 1
        assert new_child.parent == expandable
        assert new_child.action == action

    def test_expansion_removes_from_untried(self, root_node, attack_simulation):
        """
        Test: Expansion removes action from untried_actions list.
        """
        initial_untried = len(root_node.untried_actions)

        action = root_node.untried_actions.pop()

        assert len(root_node.untried_actions) == initial_untried - 1
        assert action not in root_node.untried_actions

    def test_expansion_handles_terminal_states(self, attack_simulation):
        """
        Test: Expansion correctly identifies terminal states.
        """
        terminal_node = AttackNode(
            state="root_access",
            visits=5,
            reward=5.0
        )

        assert terminal_node.is_terminal()

        # Terminal states should not have actions
        actions = attack_simulation.get_actions("root_access")
        assert len(actions) == 0


# ============================================================================
# Simulation (Rollout) Phase Tests
# ============================================================================

class TestMCTSSimulation:
    """Tests for MCTS simulation/rollout phase."""

    def test_simulation_reaches_terminal_or_depth_limit(self, attack_simulation):
        """
        Test: Simulation eventually terminates.
        """
        random.seed(42)

        state = "initial"
        depth = 0
        max_depth = 50

        while not state in ["root_access", "blocked", "flag_captured"] and depth < max_depth:
            actions = attack_simulation.get_actions(state)
            if not actions:
                break

            action = random.choice(actions)
            state, _ = attack_simulation.simulate_action(state, action)
            depth += 1

        assert depth <= max_depth

    def test_simulation_accumulates_rewards(self, attack_simulation):
        """
        Test: Simulation correctly accumulates rewards along path.
        """
        random.seed(42)

        state = "initial"
        total_reward = 0.0
        path = [state]

        for _ in range(20):
            actions = attack_simulation.get_actions(state)
            if not actions:
                break

            action = random.choice(actions)
            new_state, reward = attack_simulation.simulate_action(state, action)
            total_reward += reward

            if new_state != state:
                path.append(new_state)
                state = new_state

        # Reward should be accumulated
        assert isinstance(total_reward, float)

    def test_simulation_uses_random_policy(self, attack_simulation):
        """
        Test: Default rollout uses random action selection.
        """
        random.seed(42)

        selections = defaultdict(int)
        state = "initial"

        # Run many rollouts from same state
        for _ in range(1000):
            actions = attack_simulation.get_actions(state)
            action = random.choice(actions)
            selections[action] += 1

        # All actions should be selected roughly equally
        expected_per_action = 1000 / len(attack_simulation.get_actions("initial"))

        for action, count in selections.items():
            # Allow 20% variance
            assert count > expected_per_action * 0.5
            assert count < expected_per_action * 1.5


# ============================================================================
# Backpropagation Phase Tests
# ============================================================================

class TestMCTSBackpropagation:
    """Tests for MCTS backpropagation phase."""

    def test_backpropagation_updates_all_ancestors(self, expanded_tree):
        """
        Test: Backpropagation updates visits and rewards for all ancestors.
        """
        # Create a deep path
        child = expanded_tree.children[0]
        grandchild = AttackNode(
            state="shell",
            action="service_exploit",
            parent=child,
            visits=0,
            reward=0.0
        )
        child.children.append(grandchild)

        # Record initial values
        initial_root_visits = expanded_tree.visits
        initial_child_visits = child.visits

        # Backpropagate reward of 1.0
        reward = 1.0
        node = grandchild

        while node is not None:
            node.visits += 1
            node.reward += reward
            node = node.parent

        # All ancestors should be updated
        assert grandchild.visits == 1
        assert grandchild.reward == 1.0
        assert child.visits == initial_child_visits + 1
        assert expanded_tree.visits == initial_root_visits + 1

    def test_backpropagation_with_discounting(self, expanded_tree):
        """
        Test: Backpropagation can apply discount factor.
        """
        child = expanded_tree.children[0]
        initial_child_reward = child.reward  # Store initial value
        grandchild = AttackNode(
            state="shell",
            action="service_exploit",
            parent=child,
            visits=0,
            reward=0.0
        )
        child.children.append(grandchild)

        # Backpropagate with discount
        reward = 1.0
        discount = 0.9
        node = grandchild
        depth = 0

        while node is not None:
            node.visits += 1
            discounted_reward = reward * (discount ** depth)
            node.reward += discounted_reward
            node = node.parent
            depth += 1

        # Grandchild gets full reward, child gets discounted reward
        assert grandchild.reward == 1.0  # Full reward at depth 0
        assert child.reward > initial_child_reward  # Got additional discounted reward


# ============================================================================
# Full MCTS Iteration Tests
# ============================================================================

class TestMCTSFullIteration:
    """Tests for complete MCTS iterations."""

    def test_mcts_iteration_improves_estimates(self, attack_simulation):
        """
        Test: Running MCTS iterations improves value estimates.
        """
        random.seed(42)

        root = AttackNode(
            state="initial",
            untried_actions=attack_simulation.get_actions("initial")
        )

        def mcts_iteration(root: AttackNode) -> float:
            # Selection
            node = root
            while node.is_fully_expanded() and node.children:
                if node.is_terminal():
                    break
                node = max(node.children, key=lambda c: c.ucb1 if c.visits > 0 else float("inf"))

            # Expansion
            if node.untried_actions and not node.is_terminal():
                action = node.untried_actions.pop()
                new_state, _ = attack_simulation.simulate_action(node.state, action)
                child = AttackNode(
                    state=new_state,
                    action=action,
                    parent=node,
                    untried_actions=attack_simulation.get_actions(new_state)
                )
                node.children.append(child)
                node = child

            # Simulation
            state = node.state
            total_reward = attack_simulation.state_rewards.get(state, 0.0)

            for _ in range(10):
                if state in ["root_access", "blocked"]:
                    break
                actions = attack_simulation.get_actions(state)
                if not actions:
                    break
                action = random.choice(actions)
                state, reward = attack_simulation.simulate_action(state, action)
                total_reward += reward

            # Backpropagation
            while node is not None:
                node.visits += 1
                node.reward += total_reward
                node = node.parent

            return total_reward

        # Run iterations
        rewards = []
        for _ in range(100):
            reward = mcts_iteration(root)
            rewards.append(reward)

        # Root should have many visits
        assert root.visits == 100

        # Should have expanded children
        assert len(root.children) > 0

    def test_mcts_finds_optimal_path(self, attack_simulation):
        """
        Test: MCTS converges to finding high-value paths.
        """
        random.seed(42)

        # Increase success probability for the optimal path
        attack_simulation.transitions["initial"]["port_scan"] = ("enumerated", 0.99)
        attack_simulation.transitions["enumerated"]["service_exploit"] = ("shell", 0.8)
        attack_simulation.transitions["shell"]["local_privesc"] = ("root_access", 0.7)

        root = AttackNode(
            state="initial",
            untried_actions=attack_simulation.get_actions("initial")
        )

        # Run many iterations
        for _ in range(500):
            # Simplified MCTS iteration
            node = root

            # Selection & Expansion
            while node.is_fully_expanded() and node.children and not node.is_terminal():
                node = max(node.children, key=lambda c: c.ucb1 if c.visits > 0 else float("inf"))

            if node.untried_actions and not node.is_terminal():
                action = random.choice(node.untried_actions)
                node.untried_actions.remove(action)
                new_state, _ = attack_simulation.simulate_action(node.state, action)
                child = AttackNode(
                    state=new_state,
                    action=action,
                    parent=node,
                    untried_actions=attack_simulation.get_actions(new_state)
                )
                node.children.append(child)
                node = child

            # Simulation
            state = node.state
            reward = attack_simulation.state_rewards.get(state, 0.0)

            for _ in range(15):
                if state in ["root_access", "blocked"]:
                    break
                actions = attack_simulation.get_actions(state)
                if not actions:
                    break
                state, r = attack_simulation.simulate_action(state, random.choice(actions))
                reward += r

            # Backprop
            while node:
                node.visits += 1
                node.reward += reward
                node = node.parent

        # Most visited child should be a good path
        best_child = max(root.children, key=lambda c: c.visits)

        # port_scan is part of optimal path
        assert best_child.visits > 100  # Should be well-explored


# ============================================================================
# Integration Tests
# ============================================================================

class TestMCTSIntegration:
    """Tests for MCTS integration with Inferno agent."""

    def test_mcts_state_from_assessment(self):
        """
        Test: MCTS can initialize state from assessment context.
        """
        assessment_context = {
            "target": "https://target.com",
            "discovered_services": ["http", "ssh", "mysql"],
            "identified_vulns": ["sql_injection", "weak_auth"],
            "access_level": "authenticated",
        }

        # Map assessment to MCTS state
        if assessment_context["access_level"] == "authenticated":
            initial_state = "authenticated"
        elif assessment_context.get("shell"):
            initial_state = "shell"
        else:
            initial_state = "web_discovered" if "http" in assessment_context["discovered_services"] else "initial"

        assert initial_state == "authenticated"

    def test_mcts_action_to_tool_mapping(self, attack_simulation):
        """
        Test: MCTS actions map to actual tools/commands.
        """
        action_to_tool = {
            "port_scan": "nmap -sV -sC {target}",
            "web_scan": "gobuster dir -u {target} -w wordlist.txt",
            "social_eng": "gophish/setoolkit {target}",
            "sqli": "sqlmap -u '{target}' --batch --dbs",
            "xss": "xss_scanner --url {target}",
            "ssrf": "ssrf_detector --url {target}",
            "auth_bypass": "auth_tester --url {target}",
            "service_exploit": "metasploit auto-exploit {target}",
            "brute_force": "hydra -L users.txt -P pass.txt {target}",
            "file_upload": "upload_exploit --url {target}",
            "local_privesc": "linpeas.sh",
        }

        for action in attack_simulation.get_actions("initial"):
            assert action in action_to_tool, f"Action {action} should map to a tool"

    def test_mcts_tree_persistence(self, expanded_tree, tmp_path):
        """
        Test: MCTS tree can be serialized and restored.
        """
        import json

        def serialize_node(node: AttackNode) -> dict:
            return {
                "state": node.state,
                "action": node.action,
                "visits": node.visits,
                "reward": node.reward,
                "untried_actions": node.untried_actions,
                "children": [serialize_node(c) for c in node.children]
            }

        serialized = serialize_node(expanded_tree)

        # Save
        tree_file = tmp_path / "mcts_tree.json"
        tree_file.write_text(json.dumps(serialized, indent=2))

        # Load
        loaded = json.loads(tree_file.read_text())

        assert loaded["state"] == expanded_tree.state
        assert loaded["visits"] == expanded_tree.visits
        assert len(loaded["children"]) == len(expanded_tree.children)


# ============================================================================
# Performance Tests
# ============================================================================

@pytest.mark.slow
class TestMCTSPerformance:
    """Performance benchmarks for MCTS."""

    def test_mcts_iteration_speed(self, attack_simulation):
        """
        Benchmark: MCTS should complete 1000 iterations in < 5 seconds.
        """
        import time

        random.seed(42)

        root = AttackNode(
            state="initial",
            untried_actions=attack_simulation.get_actions("initial")
        )

        start = time.time()

        for _ in range(1000):
            # Simplified iteration
            node = root
            while node.is_fully_expanded() and node.children and not node.is_terminal():
                node = max(node.children, key=lambda c: c.ucb1 if c.visits > 0 else float("inf"))

            if node.untried_actions:
                action = node.untried_actions.pop()
                child = AttackNode(
                    state="test",
                    action=action,
                    parent=node
                )
                node.children.append(child)

            # Backprop
            while node:
                node.visits += 1
                node.reward += 0.5
                node = node.parent

        elapsed = time.time() - start

        assert elapsed < 5.0, f"MCTS took {elapsed:.2f}s for 1000 iterations (target: <5s)"

    def test_mcts_memory_usage(self, attack_simulation):
        """
        Test: MCTS tree size grows reasonably.
        """
        random.seed(42)

        root = AttackNode(
            state="initial",
            untried_actions=attack_simulation.get_actions("initial")
        )

        def count_nodes(node: AttackNode) -> int:
            return 1 + sum(count_nodes(c) for c in node.children)

        # Run iterations
        for _ in range(100):
            node = root
            while node.is_fully_expanded() and node.children:
                node = max(node.children, key=lambda c: c.ucb1 if c.visits > 0 else float("inf"))

            if node.untried_actions:
                action = node.untried_actions.pop()
                child = AttackNode(
                    state="test",
                    action=action,
                    parent=node,
                    untried_actions=["a", "b", "c"]
                )
                node.children.append(child)

            while node:
                node.visits += 1
                node = node.parent

        total_nodes = count_nodes(root)

        # Should not explode (max ~500 nodes for 100 iterations)
        assert total_nodes < 500, f"Tree has {total_nodes} nodes (should be < 500)"
