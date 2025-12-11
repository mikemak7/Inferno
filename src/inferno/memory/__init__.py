"""
Inferno Memory Package.

This module provides the memory subsystem for the Inferno agent,
enabling persistent storage and retrieval of assessment data,
findings, and agent knowledge.

The memory system uses Mem0 with Qdrant for vector-based memory
storage, with fallback to simple in-memory storage when Mem0
is not available.

The actual memory tool implementation is in inferno.tools.memory,
and this package provides convenient re-exports.
"""

from inferno.tools.memory import (
    InMemoryStorage,
    MemoryTool,
    MemoryToolWithFallback,
)

__all__ = [
    "InMemoryStorage",
    "MemoryTool",
    "MemoryToolWithFallback",
]
