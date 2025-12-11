"""
Blockchain technology context for quality gate system.

This module implements blockchain-specific filtering rules to prevent
false positives from public-by-design blockchain features.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from inferno.quality.contexts.base import BaseTechnologyContext
from inferno.reporting.models import Severity

if TYPE_CHECKING:
    from inferno.quality.candidate import ContextAdjustment, FindingCandidate


class BlockchainContext(BaseTechnologyContext):
    """
    Blockchain technology context.

    Filters out public-by-design blockchain features that are often
    incorrectly reported as information disclosure vulnerabilities:
    - Wallet addresses (0x prefixed 40 hex characters)
    - Balance information
    - Transaction hashes
    - RPC endpoints (unless admin methods exposed)
    - Contract addresses
    - Gas prices and block numbers
    - On-chain data enumeration
    """

    # Regex patterns for blockchain-specific data
    WALLET_ADDRESS_PATTERN = re.compile(r"0x[a-fA-F0-9]{40}\b")
    TX_HASH_PATTERN = re.compile(r"0x[a-fA-F0-9]{64}\b")
    BLOCK_NUMBER_PATTERN = re.compile(r"\bblock\s*(?:number|height)[:=\s]+(\d+)", re.IGNORECASE)
    GAS_PATTERN = re.compile(r"\b(?:gas|gwei)\b", re.IGNORECASE)
    RPC_PATTERN = re.compile(
        r"(?:eth_|net_|web3_|debug_|personal_|admin_|miner_|txpool_)", re.IGNORECASE
    )

    # Public RPC methods that are safe to expose
    PUBLIC_RPC_METHODS = {
        "eth_blockNumber",
        "eth_call",
        "eth_chainId",
        "eth_estimateGas",
        "eth_gasPrice",
        "eth_getBalance",
        "eth_getBlockByHash",
        "eth_getBlockByNumber",
        "eth_getBlockTransactionCountByHash",
        "eth_getBlockTransactionCountByNumber",
        "eth_getCode",
        "eth_getLogs",
        "eth_getStorageAt",
        "eth_getTransactionByBlockHashAndIndex",
        "eth_getTransactionByBlockNumberAndIndex",
        "eth_getTransactionByHash",
        "eth_getTransactionCount",
        "eth_getTransactionReceipt",
        "eth_getUncleByBlockHashAndIndex",
        "eth_getUncleByBlockNumberAndIndex",
        "eth_getUncleCountByBlockHash",
        "eth_getUncleCountByBlockNumber",
        "eth_protocolVersion",
        "eth_sendRawTransaction",
        "eth_syncing",
        "net_listening",
        "net_peerCount",
        "net_version",
        "web3_clientVersion",
        "web3_sha3",
    }

    # Admin/privileged RPC methods that indicate a real vulnerability
    ADMIN_RPC_METHODS = {
        "admin_",
        "debug_",
        "miner_",
        "personal_unlockAccount",
        "personal_newAccount",
        "personal_importRawKey",
        "personal_listAccounts",
        "personal_sendTransaction",
        "eth_sign",
        "eth_signTransaction",
        "eth_sendTransaction",
        "txpool_",
    }

    # Keywords indicating blockchain context
    BLOCKCHAIN_KEYWORDS = {
        "blockchain",
        "ethereum",
        "web3",
        "metamask",
        "wallet",
        "smart contract",
        "solidity",
        "erc20",
        "erc721",
        "nft",
        "defi",
        "dapp",
        "gwei",
        "wei",
        "gas",
        "mining",
        "consensus",
    }

    def applies_to(self, candidate: FindingCandidate) -> bool:
        """
        Check if this context applies to the finding.

        Returns True if the finding appears to be blockchain-related.
        """
        text = f"{candidate.title} {candidate.description} {candidate.evidence}".lower()

        # Check for blockchain keywords
        if any(keyword in text for keyword in self.BLOCKCHAIN_KEYWORDS):
            return True

        # Check for blockchain-specific patterns
        if (
            self.WALLET_ADDRESS_PATTERN.search(candidate.evidence)
            or self.TX_HASH_PATTERN.search(candidate.evidence)
            or self.RPC_PATTERN.search(candidate.evidence)
        ):
            return True

        return False

    def is_public_by_design(self, candidate: FindingCandidate) -> tuple[bool, str]:
        """
        Check if the finding represents public-by-design blockchain data.

        Blockchain data is inherently public and transparent. Reporting
        wallet addresses, transaction hashes, or on-chain data as
        "information disclosure" is a false positive.
        """
        evidence = candidate.evidence
        title_lower = candidate.title.lower()
        desc_lower = candidate.description.lower()

        # Wallet addresses are public by design
        if self.WALLET_ADDRESS_PATTERN.search(evidence):
            # Check if this looks like an information disclosure finding
            if any(
                keyword in title_lower or keyword in desc_lower
                for keyword in ["wallet", "address", "disclosure", "exposed", "leaked", "found"]
            ):
                return (
                    True,
                    "Wallet addresses are public by design on blockchain. "
                    "This is not information disclosure.",
                )

        # Transaction hashes are public by design
        if self.TX_HASH_PATTERN.search(evidence):
            if any(keyword in title_lower for keyword in ["transaction", "hash", "disclosure"]):
                return (
                    True,
                    "Transaction hashes are publicly visible on blockchain. "
                    "This is expected behavior.",
                )

        # Balance queries are public
        if any(keyword in desc_lower for keyword in ["balance", "getbalance"]):
            return (
                True,
                "Balance queries are public operations on blockchain. "
                "All balances are visible on-chain.",
            )

        # Block numbers and gas prices are public
        if self.BLOCK_NUMBER_PATTERN.search(evidence) or self.GAS_PATTERN.search(evidence):
            return (
                True,
                "Block numbers and gas prices are public blockchain data. "
                "This is not a vulnerability.",
            )

        # Check for public RPC method usage
        rpc_matches = self.RPC_PATTERN.finditer(evidence)
        for match in rpc_matches:
            method = match.group(0)
            # Check if it's a public method
            if any(method.lower().startswith(public.lower()) for public in self.PUBLIC_RPC_METHODS):
                if "rpc" in title_lower and "exposed" in title_lower:
                    return (
                        True,
                        f"RPC method '{method}' is a public read-only method. "
                        "These are safe to expose.",
                    )

        # On-chain data enumeration
        if any(
            keyword in desc_lower for keyword in ["on-chain", "enumerate", "contract address"]
        ):
            return (
                True,
                "Enumeration of on-chain data is expected blockchain behavior. "
                "All data is public by design.",
            )

        return False, ""

    def suggest_severity(self, candidate: FindingCandidate) -> Severity | None:
        """
        Suggest severity adjustments for blockchain findings.

        Admin RPC methods should remain HIGH/CRITICAL.
        Public RPC exposure should be downgraded to INFO.
        """
        evidence = candidate.evidence
        title_lower = candidate.title.lower()
        desc_lower = candidate.description.lower()

        # Check for admin/privileged RPC methods (keep as HIGH/CRITICAL)
        if any(
            admin_method.lower() in evidence.lower() for admin_method in self.ADMIN_RPC_METHODS
        ):
            if candidate.initial_severity in (Severity.LOW, Severity.MEDIUM):
                return Severity.HIGH
            return None  # Already high/critical, no change

        # Public RPC endpoints should be INFO
        if "rpc" in title_lower and any(
            keyword in title_lower for keyword in ["exposed", "accessible", "disclosure"]
        ):
            # Check if it's only public methods
            has_admin = any(
                admin_method.lower() in evidence.lower() for admin_method in self.ADMIN_RPC_METHODS
            )
            if not has_admin:
                return Severity.INFO

        # Wallet/address disclosure should be INFO
        if self.WALLET_ADDRESS_PATTERN.search(evidence) and "disclosure" in title_lower:
            return Severity.INFO

        # Transaction hash disclosure should be INFO
        if self.TX_HASH_PATTERN.search(evidence) and "disclosure" in title_lower:
            return Severity.INFO

        return None

    def get_context_adjustments(
        self, candidate: FindingCandidate
    ) -> list[ContextAdjustment]:
        """
        Get all blockchain-specific context adjustments.
        """
        from inferno.quality.candidate import ContextAdjustment

        adjustments: list[ContextAdjustment] = []

        # Check if public by design
        is_public, public_reason = self.is_public_by_design(candidate)
        if is_public:
            adjustments.append(
                ContextAdjustment(
                    context_type="blockchain",
                    original_severity=candidate.initial_severity,
                    adjusted_severity=Severity.INFO,
                    rationale=public_reason,
                    is_by_design=True,
                )
            )
            # Mark as public by design in the candidate
            candidate.is_public_by_design = True
            candidate.data_intentionally_public = True
            return adjustments

        # Check for severity adjustments
        suggested_severity = self.suggest_severity(candidate)
        if suggested_severity and suggested_severity != candidate.initial_severity:
            reason = self._get_severity_reason(candidate, suggested_severity)
            adjustments.append(
                ContextAdjustment(
                    context_type="blockchain",
                    original_severity=candidate.initial_severity,
                    adjusted_severity=suggested_severity,
                    rationale=reason,
                    is_by_design=False,
                )
            )

        return adjustments

    def _get_severity_reason(
        self, candidate: FindingCandidate, suggested: Severity
    ) -> str:
        """Get explanation for severity adjustment."""
        if suggested == Severity.INFO:
            return (
                "Downgraded to INFO: This is public blockchain data. "
                "While accessible, it represents expected blockchain behavior."
            )
        elif suggested == Severity.HIGH:
            return (
                "Upgraded to HIGH: Admin/privileged RPC methods exposed. "
                "This allows unauthorized blockchain operations."
            )
        return f"Severity adjusted to {suggested.value} based on blockchain context."
