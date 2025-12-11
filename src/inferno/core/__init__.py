"""
Inferno Core Package.

Core functionality including:
- Scope management for authorized testing
- Shared Knowledge Graph for cross-agent context sharing
- Network Manager for global rate limiting and proxy coordination
- Branch tracking with response pattern detection
- Guardrails for security policies

NOTE: Simplified in rebuild.
- CDN/Geo detection, credential manager, response cache removed
- Diminishing returns, CTF mode features removed
- CORS models removed
"""

from inferno.core.knowledge import (
    KnowledgeEntry,
    KnowledgeGraph,
    KnowledgeType,
    Severity,
    get_knowledge_graph,
)
from inferno.core.network import (
    NetworkManager,
    ProxyConfig,
    ProxyRotator,
    RateLimitConfig,
    RateLimitStrategy,
    UserAgentRotator,
    get_network_manager,
)
from inferno.core.scope import (
    ScopeAction,
    ScopeConfig,
    ScopeManager,
    ScopeRule,
    ScopeViolation,
    check_scope,
    configure_scope,
    get_scope_manager,
)
from inferno.core.branch_tracker import (
    BranchTracker,
    BranchOption,
    ExplorationResult,
    ResponsePatternTracker,
)

__all__ = [
    # Scope Management
    "ScopeAction",
    "ScopeConfig",
    "ScopeManager",
    "ScopeRule",
    "ScopeViolation",
    "check_scope",
    "configure_scope",
    "get_scope_manager",
    # Knowledge Graph
    "KnowledgeGraph",
    "KnowledgeEntry",
    "KnowledgeType",
    "Severity",
    "get_knowledge_graph",
    # Network Manager
    "NetworkManager",
    "RateLimitConfig",
    "RateLimitStrategy",
    "ProxyConfig",
    "ProxyRotator",
    "UserAgentRotator",
    "get_network_manager",
    # Branch Tracking
    "BranchTracker",
    "BranchOption",
    "ExplorationResult",
    "ResponsePatternTracker",
]
