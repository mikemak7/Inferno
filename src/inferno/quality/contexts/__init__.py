"""
Technology context modules for Inferno-AI quality gate system.

This package provides technology-specific contexts for filtering false positives
and adjusting severity ratings based on technology-specific patterns.

Available Contexts:
    - BlockchainContext: Filters public-by-design blockchain features
    - APIContext: Filters intentionally exposed API documentation
    - GenericWebContext: Adjusts severity for common web findings

Example:
    >>> from inferno.quality.contexts import BlockchainContext
    >>> from inferno.quality.candidate import FindingCandidate, ContextAdjustment
    >>> from inferno.reporting.models import Severity
    >>>
    >>> context = BlockchainContext()
    >>> candidate = FindingCandidate(
    ...     title="Wallet Address Disclosure",
    ...     description="Found exposed wallet addresses",
    ...     initial_severity=Severity.MEDIUM,
    ...     evidence="Address: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
    ...     affected_asset="https://example.com/api/wallet",
    ...     vuln_type="information_disclosure"
    ... )
    >>> adjustment = context.evaluate(candidate)
    >>> if adjustment and adjustment.is_by_design:
    ...     print(f"Filtered: {adjustment.rationale}")
"""

from inferno.quality.contexts.api import APIContext
from inferno.quality.contexts.base import BaseTechnologyContext
from inferno.quality.contexts.blockchain import BlockchainContext
from inferno.quality.contexts.generic import GenericWebContext

# Re-export models from candidate module for convenience
# These are TYPE_CHECKING imports in the contexts themselves
__all__ = [
    # Base class
    "BaseTechnologyContext",
    # Context implementations
    "BlockchainContext",
    "APIContext",
    "GenericWebContext",
]
