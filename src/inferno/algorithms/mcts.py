"""
Monte Carlo Tree Search for Attack Path Discovery in Inferno.

Implements MCTS with UCT (Upper Confidence bounds for Trees) for
exploring attack paths. The tree represents possible attack sequences,
and MCTS finds optimal paths through simulation and backpropagation.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

from inferno.algorithms.base import AlgorithmState

logger = structlog.get_logger(__name__)


class AccessLevel(int, Enum):
    """Access levels in pentesting."""

    NONE = 0
    ANONYMOUS = 1
    USER = 2
    PRIVILEGED_USER = 3
    LOCAL_ADMIN = 4
    DOMAIN_ADMIN = 5
    ROOT = 6


@dataclass
class AttackTreeState:
    """State representation for MCTS attack tree.

    Captures the current attack surface and access level.
    """
    access_level: AccessLevel = AccessLevel.NONE
    discovered_services: set[str] = field(default_factory=set)
    discovered_vulns: set[str] = field(default_factory=set)
    exploited_vulns: set[str] = field(default_factory=set)
    credentials: set[str] = field(default_factory=set)
    shells: set[str] = field(default_factory=set)  # host:user
    flags_captured: set[str] = field(default_factory=set)

    def clone(self) -> AttackTreeState:
        """Create a deep copy of this state."""
        return AttackTreeState(
            access_level=self.access_level,
            discovered_services=set(self.discovered_services),
            discovered_vulns=set(self.discovered_vulns),
            exploited_vulns=set(self.exploited_vulns),
            credentials=set(self.credentials),
            shells=set(self.shells),
            flags_captured=set(self.flags_captured),
        )

    def is_terminal(self, objective: str = "root") -> bool:
        """Check if state is terminal (objective achieved)."""
        if objective == "root":
            return self.access_level >= AccessLevel.ROOT
        elif objective == "user":
            return self.access_level >= AccessLevel.USER
        elif objective == "flag":
            return len(self.flags_captured) > 0
        return False

    def to_hash(self) -> str:
        """Create hashable representation."""
        return f"{self.access_level.value}:{len(self.exploited_vulns)}:{len(self.shells)}"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "access_level": self.access_level.value,
            "discovered_services": list(self.discovered_services),
            "discovered_vulns": list(self.discovered_vulns),
            "exploited_vulns": list(self.exploited_vulns),
            "credentials": list(self.credentials),
            "shells": list(self.shells),
            "flags_captured": list(self.flags_captured),
        }


@dataclass(frozen=True)
class AttackAction:
    """Immutable action in the attack tree."""

    vector_type: str  # sqli, xss, rce, lfi, etc.
    target: str  # endpoint or service
    payload_class: str = ""  # union, blind, error-based, etc.

    def __str__(self) -> str:
        return f"{self.vector_type}@{self.target}"


@dataclass
class MCTSNode:
    """Node in the MCTS tree."""

    state: AttackTreeState
    action: AttackAction | None = None  # Action that led to this state
    parent: MCTSNode | None = None

    # Statistics
    visits: int = 0
    value: float = 0.0  # Total value (sum of rewards)
    wins: int = 0

    # Children
    children: dict[AttackAction, MCTSNode] = field(default_factory=dict)
    untried_actions: list[AttackAction] = field(default_factory=list)

    @property
    def is_fully_expanded(self) -> bool:
        """Check if all actions have been tried."""
        return len(self.untried_actions) == 0

    @property
    def q_value(self) -> float:
        """Average value (Q-value)."""
        return self.value / self.visits if self.visits > 0 else 0.0

    @property
    def win_rate(self) -> float:
        """Win rate for this node."""
        return self.wins / self.visits if self.visits > 0 else 0.0

    def uct_score(self, exploration_constant: float = 1.414) -> float:
        """Calculate UCT score for node selection.

        UCT = Q(v) / N(v) + c * sqrt(ln(N(parent)) / N(v))

        where:
            Q(v) = total value of node v
            N(v) = visit count of node v
            c = exploration constant (default sqrt(2))
        """
        if self.visits == 0:
            return float("inf")  # Prioritize unexplored nodes

        if self.parent is None:
            return self.q_value

        exploitation = self.q_value
        exploration = exploration_constant * math.sqrt(
            math.log(self.parent.visits) / self.visits
        )
        return exploitation + exploration


@dataclass
class MCTSConfig:
    """Configuration for MCTS engine."""

    max_iterations: int = 1000
    max_depth: int = 20
    exploration_constant: float = 1.414
    simulation_depth: int = 10
    discount_factor: float = 0.95


class MCTSEngine:
    """Monte Carlo Tree Search engine for attack path discovery.

    Phases:
    1. Selection: Traverse tree using UCT until leaf node
    2. Expansion: Add one child to leaf node
    3. Simulation: Random rollout from new node
    4. Backpropagation: Update statistics along path

    Memory Management:
    - Tree is pruned after each search to prevent unbounded growth
    - Only root-level statistics are retained between searches
    - Use reset() to fully clear the tree
    """

    # Maximum tree nodes before forced pruning
    MAX_TREE_NODES = 10000

    def __init__(self, config: MCTSConfig | None = None):
        """Initialize MCTS engine.

        Args:
            config: MCTS configuration
        """
        self.config = config or MCTSConfig()
        self._root: MCTSNode | None = None
        self._total_simulations = 0
        self._node_count = 0  # Track tree size

        # Attack vectors and their base success rates
        self._attack_vectors = {
            "sqli": 0.15,
            "xss": 0.20,
            "rce": 0.05,
            "lfi": 0.10,
            "ssrf": 0.08,
            "auth_bypass": 0.12,
            "idor": 0.15,
            "ssti": 0.06,
            "xxe": 0.04,
        }

    def reset(self) -> None:
        """Fully reset the tree to free memory."""
        if self._root:
            self._clear_node_recursive(self._root)
        self._root = None
        self._node_count = 0
        logger.debug("mcts_tree_reset", total_simulations=self._total_simulations)

    def _clear_node_recursive(self, node: MCTSNode) -> None:
        """Recursively clear node references to help GC."""
        # Clear children first (depth-first)
        for child in list(node.children.values()):
            self._clear_node_recursive(child)
        # Break circular reference
        node.parent = None
        node.children.clear()
        node.untried_actions.clear()

    def prune_tree(self, keep_depth: int = 1) -> int:
        """Prune tree to conserve memory while keeping statistics.

        Args:
            keep_depth: How many levels to keep (1 = only root's direct children)

        Returns:
            Number of nodes pruned
        """
        if self._root is None:
            return 0

        pruned = 0

        def prune_at_depth(node: MCTSNode, current_depth: int) -> int:
            nonlocal pruned
            if current_depth >= keep_depth:
                # Prune all children of this node
                for child in list(node.children.values()):
                    pruned += self._count_and_clear_subtree(child)
                node.children.clear()
                return 0

            # Recurse into children
            for child in node.children.values():
                prune_at_depth(child, current_depth + 1)
            return 0

        prune_at_depth(self._root, 0)
        self._node_count = self._count_nodes(self._root)

        logger.debug(
            "mcts_tree_pruned",
            nodes_pruned=pruned,
            nodes_remaining=self._node_count,
        )
        return pruned

    def _count_and_clear_subtree(self, node: MCTSNode) -> int:
        """Count nodes in subtree and clear references."""
        count = 1
        for child in list(node.children.values()):
            count += self._count_and_clear_subtree(child)
        node.parent = None
        node.children.clear()
        node.untried_actions.clear()
        return count

    def _count_nodes(self, node: MCTSNode | None) -> int:
        """Count total nodes in tree."""
        if node is None:
            return 0
        count = 1
        for child in node.children.values():
            count += self._count_nodes(child)
        return count

    def search(
        self,
        initial_state: AttackTreeState,
        available_actions: list[AttackAction],
        objective: str = "root",
        iterations: int | None = None,
        prune_on_complete: bool = True,
    ) -> AttackAction | None:
        """Run MCTS search from initial state.

        Args:
            initial_state: Starting state
            available_actions: Possible actions from this state
            objective: Search objective ("root", "user", "flag")
            iterations: Number of iterations (defaults to config)
            prune_on_complete: Whether to prune tree after search (saves memory)

        Returns:
            Best action to take, or None if no good action found
        """
        iterations = iterations or self.config.max_iterations

        # Clear previous tree if exists (prevents memory accumulation)
        if self._root is not None:
            self.reset()

        # Initialize root
        self._root = MCTSNode(
            state=initial_state.clone(),
            untried_actions=list(available_actions),
        )
        self._node_count = 1

        for i in range(iterations):
            # Selection
            node = self._select(self._root)

            # Expansion
            if not node.state.is_terminal(objective) and not node.is_fully_expanded:
                node = self._expand(node)

            # Simulation
            reward = self._simulate(node.state, objective)

            # Backpropagation
            self._backpropagate(node, reward)

            self._total_simulations += 1

            # Auto-prune if tree gets too large (prevents OOM)
            if self._node_count > self.MAX_TREE_NODES:
                logger.debug(
                    "mcts_auto_prune_triggered",
                    node_count=self._node_count,
                    iteration=i,
                )
                self.prune_tree(keep_depth=2)

        # Get best action before pruning
        best_action = self._get_best_action()

        # Prune tree to save memory (keep only root-level stats)
        if prune_on_complete:
            self.prune_tree(keep_depth=1)

        return best_action

    def _select(self, node: MCTSNode) -> MCTSNode:
        """Select child node using UCT.

        Traverse down tree selecting children with highest UCT score
        until reaching a node that's not fully expanded.
        """
        current = node

        while current.is_fully_expanded and current.children:
            # Select child with highest UCT score
            best_child = None
            best_score = float("-inf")

            for child in current.children.values():
                score = child.uct_score(self.config.exploration_constant)
                if score > best_score:
                    best_score = score
                    best_child = child

            if best_child is None:
                break

            current = best_child

        return current

    def _expand(self, node: MCTSNode) -> MCTSNode:
        """Expand node by adding one untried action.

        Returns:
            The new child node
        """
        if not node.untried_actions:
            return node

        # Select random untried action
        action = random.choice(node.untried_actions)
        node.untried_actions.remove(action)

        # Create new state by applying action
        new_state = self._apply_action(node.state, action)

        # Generate possible actions from new state
        new_actions = self._get_available_actions(new_state)

        # Create child node
        child = MCTSNode(
            state=new_state,
            action=action,
            parent=node,
            untried_actions=new_actions,
        )

        node.children[action] = child
        self._node_count += 1  # Track tree size for memory management
        return child

    def _simulate(
        self,
        state: AttackTreeState,
        objective: str = "root"
    ) -> float:
        """Simulate random playout from state.

        Returns:
            Reward value from simulation
        """
        current_state = state.clone()
        total_reward = 0.0
        depth = 0

        while depth < self.config.simulation_depth:
            if current_state.is_terminal(objective):
                # Terminal state bonus
                total_reward += 10.0
                break

            # Get possible actions
            actions = self._get_available_actions(current_state)
            if not actions:
                break

            # Random action selection
            action = random.choice(actions)

            # Apply action
            old_state = current_state.clone()
            current_state = self._apply_action(current_state, action)

            # Calculate step reward
            step_reward = self._calculate_step_reward(old_state, current_state, action)
            total_reward += step_reward * (self.config.discount_factor ** depth)

            depth += 1

        return total_reward

    def _backpropagate(self, node: MCTSNode, reward: float) -> None:
        """Backpropagate reward up the tree.

        Updates visit counts and values for all nodes on path to root.
        """
        current = node

        while current is not None:
            current.visits += 1
            current.value += reward

            if reward > 5.0:  # Threshold for "win"
                current.wins += 1

            current = current.parent

    def _apply_action(
        self,
        state: AttackTreeState,
        action: AttackAction
    ) -> AttackTreeState:
        """Apply action to state and return new state.

        Simulates the effect of an attack action.
        """
        new_state = state.clone()

        # Get base success rate for this attack vector
        base_success = self._attack_vectors.get(action.vector_type, 0.1)

        # Adjust success rate based on current state
        if action.target in state.discovered_vulns:
            base_success *= 2.0  # Higher chance if vuln already discovered
        if state.access_level >= AccessLevel.USER:
            base_success *= 1.5  # Easier with some access

        # Cap at 95%
        success_rate = min(0.95, base_success)

        # Simulate attack success
        if random.random() < success_rate:
            # Attack succeeded
            vuln_id = f"{action.vector_type}:{action.target}"
            new_state.exploited_vulns.add(vuln_id)

            # Update access level based on attack type
            if action.vector_type == "rce":
                new_state.access_level = max(
                    new_state.access_level, AccessLevel.USER
                )
                new_state.shells.add(f"{action.target}:user")
            elif action.vector_type in ["auth_bypass", "sqli"]:
                if "admin" in action.target.lower():
                    new_state.access_level = max(
                        new_state.access_level, AccessLevel.LOCAL_ADMIN
                    )
                else:
                    new_state.access_level = max(
                        new_state.access_level, AccessLevel.USER
                    )
            elif action.vector_type == "lfi":
                # LFI might leak credentials
                if random.random() < 0.3:
                    new_state.credentials.add(f"leaked:{action.target}")
        else:
            # Attack failed but we still learned something
            new_state.discovered_vulns.add(f"tested:{action.vector_type}:{action.target}")

        return new_state

    def _get_available_actions(self, state: AttackTreeState) -> list[AttackAction]:
        """Get available actions from state."""
        actions = []

        # Base targets (simplified - in real implementation, would come from discovery)
        targets = ["/login", "/api/users", "/admin", "/upload", "/search"]

        for vector in self._attack_vectors.keys():
            for target in targets:
                action = AttackAction(vector_type=vector, target=target)
                vuln_id = f"{vector}:{target}"

                # Don't repeat already exploited combinations
                if vuln_id not in state.exploited_vulns:
                    actions.append(action)

        return actions

    def _calculate_step_reward(
        self,
        old_state: AttackTreeState,
        new_state: AttackTreeState,
        action: AttackAction
    ) -> float:
        """Calculate reward for a single step."""
        reward = 0.0

        # Access level improvement
        access_diff = new_state.access_level.value - old_state.access_level.value
        reward += access_diff * 5.0

        # New exploitation
        new_exploits = new_state.exploited_vulns - old_state.exploited_vulns
        reward += len(new_exploits) * 2.0

        # New credentials
        new_creds = new_state.credentials - old_state.credentials
        reward += len(new_creds) * 3.0

        # New shells
        new_shells = new_state.shells - old_state.shells
        reward += len(new_shells) * 10.0

        # Small penalty for each step
        reward -= 0.1

        return reward

    def _get_best_action(self) -> AttackAction | None:
        """Get best action from root based on search results."""
        if self._root is None or not self._root.children:
            return None

        # Select child with highest visit count (most robust)
        best_action = None
        best_visits = -1

        for action, child in self._root.children.items():
            if child.visits > best_visits:
                best_visits = child.visits
                best_action = action

        return best_action

    def get_action_ranking(self) -> list[tuple[AttackAction, float, int]]:
        """Get ranking of all explored actions.

        Returns:
            List of (action, q_value, visits) sorted by Q-value
        """
        if self._root is None:
            return []

        ranking = []
        for action, child in self._root.children.items():
            ranking.append((action, child.q_value, child.visits))

        return sorted(ranking, key=lambda x: x[1], reverse=True)

    def get_best_path(self, max_depth: int = 5) -> list[AttackAction]:
        """Get best path from root following highest Q-value children.

        Args:
            max_depth: Maximum path length

        Returns:
            List of actions forming best path
        """
        path = []
        current = self._root

        for _ in range(max_depth):
            if current is None or not current.children:
                break

            # Find best child by Q-value
            best_action = None
            best_q = float("-inf")

            for action, child in current.children.items():
                if child.q_value > best_q:
                    best_q = child.q_value
                    best_action = action

            if best_action is None:
                break

            path.append(best_action)
            current = current.children.get(best_action)

        return path

    def get_state(self) -> AlgorithmState:
        """Get persistable state."""
        # Serialize tree statistics (not full tree to save space)
        action_stats = []
        if self._root:
            for action, child in self._root.children.items():
                action_stats.append({
                    "action": str(action),
                    "vector": action.vector_type,
                    "target": action.target,
                    "visits": child.visits,
                    "value": child.value,
                    "wins": child.wins,
                })

        return AlgorithmState(
            algorithm_name="MCTS",
            parameters={
                "max_iterations": self.config.max_iterations,
                "exploration_constant": self.config.exploration_constant,
                "total_simulations": self._total_simulations,
            },
            history=action_stats,
        )

    def load_state(self, state: AlgorithmState) -> None:
        """Load state from persistence."""
        self.config.max_iterations = state.parameters.get("max_iterations", 1000)
        self.config.exploration_constant = state.parameters.get("exploration_constant", 1.414)
        self._total_simulations = state.parameters.get("total_simulations", 0)

        # Note: We don't fully restore the tree, just statistics
        # The tree will be rebuilt on next search
        logger.info(
            "mcts_state_loaded",
            total_simulations=self._total_simulations,
            action_stats_count=len(state.history),
        )
