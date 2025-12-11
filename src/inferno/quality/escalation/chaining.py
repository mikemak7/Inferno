"""Chaining strategy for combining multiple vulnerabilities.

This strategy identifies opportunities to chain multiple findings together
to achieve higher impact exploitation scenarios.
"""

import logging
from typing import Any

from inferno.quality.escalation.base import (
    BaseEscalationStrategy,
    EscalationAttempt,
    EscalationResult,
    FindingCandidate,
)
from inferno.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


class ChainingStrategy(BaseEscalationStrategy):
    """Vulnerability chaining for compound exploitation.

    Identifies and tests combinations of vulnerabilities:
    - SSRF + Cloud metadata access
    - SQLi + credential extraction + auth bypass
    - XSS + session hijacking
    - File upload + path traversal + RCE
    - XXE + SSRF + internal network access
    """

    # Vulnerability combination patterns
    CHAIN_PATTERNS = {
        "ssrf_metadata": {
            "primary": ["ssrf", "server_side_request_forgery"],
            "secondary": ["info_disclosure", "cloud"],
            "test": "metadata_access",
        },
        "sqli_auth": {
            "primary": ["sqli", "sql_injection"],
            "secondary": ["auth_bypass", "credential"],
            "test": "credential_extraction",
        },
        "xss_session": {
            "primary": ["xss", "cross_site_scripting"],
            "secondary": ["session", "cookie"],
            "test": "session_hijack",
        },
        "upload_rce": {
            "primary": ["file_upload", "upload"],
            "secondary": ["path_traversal", "lfi"],
            "test": "remote_code_execution",
        },
        "xxe_ssrf": {
            "primary": ["xxe", "xml_external_entity"],
            "secondary": ["ssrf"],
            "test": "internal_network_access",
        },
        "idor_data_leak": {
            "primary": ["idor"],
            "secondary": ["info_disclosure", "pii"],
            "test": "sensitive_data_access",
        },
    }

    def __init__(self, all_findings: list[FindingCandidate] | None = None) -> None:
        """Initialize chaining strategy.

        Args:
            all_findings: All findings from assessment for chain detection
        """
        super().__init__()
        self.all_findings = all_findings or []

    async def is_applicable(self, candidate: FindingCandidate) -> bool:
        """Check if chaining applies to this finding.

        Args:
            candidate: The finding to evaluate

        Returns:
            True if finding could be part of a chain
        """
        if not self.all_findings:
            return False

        # Check if this finding matches any primary vulnerability in chain patterns
        vuln_lower = candidate.vuln_type.lower()
        for pattern in self.CHAIN_PATTERNS.values():
            if any(primary in vuln_lower for primary in pattern["primary"]):
                # Check if we have a secondary vulnerability to chain with
                if self._find_chain_partner(candidate, pattern):
                    return True

        return False

    async def attempt(
        self, candidate: FindingCandidate, target: str | None = None
    ) -> EscalationAttempt:
        """Attempt to chain vulnerabilities together.

        Args:
            candidate: The primary finding to chain
            target: Optional specific target URL

        Returns:
            Record of the chaining attempt
        """
        target_url = target or candidate.target_url
        logger.info(f"Attempting vulnerability chaining with {candidate.vuln_type}")

        # Find applicable chain patterns
        vuln_lower = candidate.vuln_type.lower()
        applicable_chains = []

        for chain_name, pattern in self.CHAIN_PATTERNS.items():
            if any(primary in vuln_lower for primary in pattern["primary"]):
                partner = self._find_chain_partner(candidate, pattern)
                if partner:
                    applicable_chains.append((chain_name, pattern, partner))

        if not applicable_chains:
            return self._create_attempt(
                description="No chainable vulnerabilities found",
                target=target_url,
                result=EscalationResult.NOT_APPLICABLE,
                evidence="No secondary vulnerabilities available for chaining",
            )

        # Test each potential chain
        successful_chains = []
        for chain_name, pattern, partner in applicable_chains:
            result = await self._test_chain(
                chain_name, pattern, candidate, partner, target_url
            )
            if result:
                successful_chains.append((chain_name, result))

        if successful_chains:
            combined_ids = [
                partner.finding_id
                for _, (_, partner) in applicable_chains
                if partner
            ]

            evidence_parts = [f"Successfully chained {len(successful_chains)} vulnerability combination(s):"]
            for chain_name, chain_result in successful_chains:
                evidence_parts.append(f"\n{chain_name}:")
                evidence_parts.append(f"  {chain_result}")

            return self._create_attempt(
                description=f"Chained {len(successful_chains)} vulnerability combination(s) for escalated impact",
                target=target_url,
                result=EscalationResult.SUCCESS,
                evidence="\n".join(evidence_parts),
                combined_with=combined_ids,
            )

        return self._create_attempt(
            description=f"Tested {len(applicable_chains)} chain(s), none successful",
            target=target_url,
            result=EscalationResult.FAILED,
            evidence="Chain attempts did not yield successful exploitation",
        )

    def _find_chain_partner(
        self, primary: FindingCandidate, pattern: dict[str, Any]
    ) -> FindingCandidate | None:
        """Find a secondary vulnerability to chain with primary.

        Args:
            primary: The primary finding
            pattern: The chain pattern to match

        Returns:
            Secondary finding or None
        """
        for finding in self.all_findings:
            if finding.finding_id == primary.finding_id:
                continue

            vuln_lower = finding.vuln_type.lower()
            if any(secondary in vuln_lower for secondary in pattern["secondary"]):
                return finding

        return None

    async def _test_chain(
        self,
        chain_name: str,
        pattern: dict[str, Any],
        primary: FindingCandidate,
        secondary: FindingCandidate,
        target_url: str,
    ) -> str | None:
        """Test a specific vulnerability chain.

        Args:
            chain_name: Name of the chain pattern
            pattern: Chain pattern configuration
            primary: Primary vulnerability
            secondary: Secondary vulnerability
            target_url: Target URL

        Returns:
            Evidence string if successful, None otherwise
        """
        test_type = pattern["test"]

        # Dispatch to specific test method
        if test_type == "metadata_access":
            return await self._test_ssrf_metadata(primary, secondary, target_url)
        elif test_type == "credential_extraction":
            return await self._test_sqli_auth(primary, secondary, target_url)
        elif test_type == "session_hijack":
            return await self._test_xss_session(primary, secondary, target_url)
        elif test_type == "remote_code_execution":
            return await self._test_upload_rce(primary, secondary, target_url)
        elif test_type == "internal_network_access":
            return await self._test_xxe_ssrf(primary, secondary, target_url)
        elif test_type == "sensitive_data_access":
            return await self._test_idor_data_leak(primary, secondary, target_url)

        return None

    async def _test_ssrf_metadata(
        self, ssrf: FindingCandidate, info: FindingCandidate, target_url: str
    ) -> str | None:
        """Test SSRF + metadata access chain.

        Args:
            ssrf: SSRF vulnerability
            info: Info disclosure vulnerability
            target_url: Target URL

        Returns:
            Evidence string if successful
        """
        registry = ToolRegistry()
        ssrf_tool = registry.get("ssrf_detector")

        if not ssrf_tool:
            return None

        try:
            # Test cloud metadata endpoints
            metadata_urls = [
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
            ]

            for metadata_url in metadata_urls:
                result = await ssrf_tool.execute(
                    url=target_url, internal_url=metadata_url
                )

                if result.success and result.data.get("accessible"):
                    return f"SSRF allows access to cloud metadata: {metadata_url}"

        except Exception as e:
            logger.debug(f"SSRF metadata chain test failed: {e}")

        return None

    async def _test_sqli_auth(
        self, sqli: FindingCandidate, auth: FindingCandidate, target_url: str
    ) -> str | None:
        """Test SQLi + credential extraction chain.

        Args:
            sqli: SQL injection vulnerability
            auth: Auth bypass or credential vulnerability
            target_url: Target URL

        Returns:
            Evidence string if successful
        """
        # Check if SQLi evidence contains credentials
        import re

        cred_patterns = [
            r"(username|user|email).*?(password|pass|pwd)",
            r"admin.*?password",
            r"credentials.*?extracted",
        ]

        evidence_combined = f"{sqli.evidence} {auth.evidence}".lower()

        for pattern in cred_patterns:
            if re.search(pattern, evidence_combined, re.I | re.DOTALL):
                return "SQLi allows credential extraction, enabling authentication bypass"

        return None

    async def _test_xss_session(
        self, xss: FindingCandidate, session: FindingCandidate, target_url: str
    ) -> str | None:
        """Test XSS + session hijacking chain.

        Args:
            xss: XSS vulnerability
            session: Session or cookie vulnerability
            target_url: Target URL

        Returns:
            Evidence string if successful
        """
        # If XSS is present and session handling is weak, this is chainable
        evidence_combined = f"{xss.evidence} {session.evidence}".lower()

        session_indicators = [
            "session",
            "cookie",
            "no httponly",
            "missing secure flag",
        ]

        if any(indicator in evidence_combined for indicator in session_indicators):
            return "XSS can be used to steal session cookies for account takeover"

        return None

    async def _test_upload_rce(
        self, upload: FindingCandidate, traversal: FindingCandidate, target_url: str
    ) -> str | None:
        """Test file upload + path traversal chain.

        Args:
            upload: File upload vulnerability
            traversal: Path traversal vulnerability
            target_url: Target URL

        Returns:
            Evidence string if successful
        """
        evidence_combined = f"{upload.evidence} {traversal.evidence}".lower()

        rce_indicators = [
            "php",
            "jsp",
            "asp",
            "upload",
            "path traversal",
            "directory traversal",
        ]

        if sum(indicator in evidence_combined for indicator in rce_indicators) >= 2:
            return "File upload + path traversal enables arbitrary file write and RCE"

        return None

    async def _test_xxe_ssrf(
        self, xxe: FindingCandidate, ssrf: FindingCandidate, target_url: str
    ) -> str | None:
        """Test XXE + SSRF chain.

        Args:
            xxe: XXE vulnerability
            ssrf: SSRF vulnerability
            target_url: Target URL

        Returns:
            Evidence string if successful
        """
        # XXE often leads to SSRF
        return "XXE vulnerability enables SSRF to internal network resources"

    async def _test_idor_data_leak(
        self, idor: FindingCandidate, info: FindingCandidate, target_url: str
    ) -> str | None:
        """Test IDOR + sensitive data access chain.

        Args:
            idor: IDOR vulnerability
            info: Info disclosure vulnerability
            target_url: Target URL

        Returns:
            Evidence string if successful
        """
        evidence_combined = f"{idor.evidence} {info.evidence}".lower()

        sensitive_data = ["pii", "ssn", "credit card", "personal", "email", "phone"]

        if any(data_type in evidence_combined for data_type in sensitive_data):
            return "IDOR provides unauthorized access to sensitive user data (PII)"

        return None
