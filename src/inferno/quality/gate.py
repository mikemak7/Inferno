"""
Base quality gate infrastructure.

This module defines the abstract QualityGate base class and registry pattern
for implementing quality gates that validate security findings against
Bug Bounty program standards.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from inferno.quality.candidate import FindingCandidate


class QualityGate(ABC):
    """
    Abstract base class for quality gates.

    Quality gates validate specific aspects of security findings and
    can block or adjust findings based on validation results.
    """

    def __init__(
        self,
        name: str,
        weight: float = 1.0,
        is_blocking: bool = False,
        description: str = "",
    ) -> None:
        """
        Initialize quality gate.

        Args:
            name: Unique name for this gate
            weight: Weight for quality score calculation (0-10)
            is_blocking: If True, gate failure blocks report inclusion
            description: Human-readable description of gate purpose
        """
        self.name = name
        self.weight = weight
        self.is_blocking = is_blocking
        self.description = description

        # Validate weight
        if not 0.0 <= weight <= 10.0:
            raise ValueError(f"Gate weight must be between 0.0 and 10.0, got {weight}")

    @abstractmethod
    async def evaluate(
        self, candidate: FindingCandidate, target: str, **kwargs: Any
    ) -> tuple[bool, str]:
        """
        Evaluate finding candidate against this gate.

        Args:
            candidate: Finding candidate to evaluate
            target: Target URL/hostname for environment validation
            **kwargs: Additional gate-specific parameters

        Returns:
            Tuple of (passed: bool, message: str)
            - passed: True if gate validation passed
            - message: Human-readable explanation of result
        """
        pass

    def __repr__(self) -> str:
        """String representation."""
        blocking = "BLOCKING" if self.is_blocking else "NON-BLOCKING"
        return f"{self.__class__.__name__}(name={self.name}, weight={self.weight}, {blocking})"


class QualityGateRegistry:
    """
    Registry for quality gates with singleton pattern.

    Manages registration and retrieval of quality gates for finding validation.
    """

    _instance: QualityGateRegistry | None = None
    _gates: dict[str, QualityGate] = {}

    def __new__(cls) -> QualityGateRegistry:
        """Ensure singleton instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def register(self, gate: QualityGate) -> None:
        """
        Register a quality gate.

        Args:
            gate: QualityGate instance to register

        Raises:
            ValueError: If gate with same name already registered
        """
        if gate.name in self._gates:
            raise ValueError(f"Gate '{gate.name}' already registered")
        self._gates[gate.name] = gate

    def unregister(self, gate_name: str) -> None:
        """
        Unregister a quality gate.

        Args:
            gate_name: Name of gate to unregister
        """
        self._gates.pop(gate_name, None)

    def get(self, gate_name: str) -> QualityGate | None:
        """
        Get a registered gate by name.

        Args:
            gate_name: Name of gate to retrieve

        Returns:
            QualityGate instance or None if not found
        """
        return self._gates.get(gate_name)

    def get_all(self) -> list[QualityGate]:
        """
        Get all registered gates.

        Returns:
            List of all registered QualityGate instances
        """
        return list(self._gates.values())

    def get_blocking_gates(self) -> list[QualityGate]:
        """
        Get all blocking gates.

        Returns:
            List of gates where is_blocking=True
        """
        return [gate for gate in self._gates.values() if gate.is_blocking]

    def get_non_blocking_gates(self) -> list[QualityGate]:
        """
        Get all non-blocking gates.

        Returns:
            List of gates where is_blocking=False
        """
        return [gate for gate in self._gates.values() if not gate.is_blocking]

    def clear(self) -> None:
        """Clear all registered gates (useful for testing)."""
        self._gates.clear()

    def __len__(self) -> int:
        """Get number of registered gates."""
        return len(self._gates)

    def __contains__(self, gate_name: str) -> bool:
        """Check if gate is registered."""
        return gate_name in self._gates

    def __iter__(self):
        """Iterate over registered gates."""
        return iter(self._gates.values())


# Global registry instance
_registry = QualityGateRegistry()


def get_gate_registry() -> QualityGateRegistry:
    """
    Get the global quality gate registry.

    Returns:
        Global QualityGateRegistry singleton instance
    """
    return _registry


def register_gate(gate: QualityGate) -> None:
    """
    Register a gate with the global registry.

    Args:
        gate: QualityGate instance to register
    """
    _registry.register(gate)


def get_gate(gate_name: str) -> QualityGate | None:
    """
    Get a gate from the global registry.

    Args:
        gate_name: Name of gate to retrieve

    Returns:
        QualityGate instance or None if not found
    """
    return _registry.get(gate_name)
