"""Permission testing strategy for token and credential validation.

This strategy extracts tokens from findings and tests their actual permissions
to document the full scope of access granted.
"""

import logging
import re
from typing import Any

from inferno.quality.escalation.base import (
    BaseEscalationStrategy,
    EscalationAttempt,
    EscalationResult,
    FindingCandidate,
)
from inferno.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


class PermissionTestingStrategy(BaseEscalationStrategy):
    """Test actual permissions of discovered tokens and credentials.

    Extracts tokens from evidence and systematically tests:
    - Read permissions (GET requests)
    - Write permissions (POST/PUT requests)
    - Delete permissions (DELETE requests)
    - Administrative functions
    - Scope of accessible resources
    """

    # Test endpoints for permission validation
    PERMISSION_TESTS = {
        "read": [
            {"path": "/api/users", "method": "GET"},
            {"path": "/api/admin/users", "method": "GET"},
            {"path": "/api/settings", "method": "GET"},
            {"path": "/api/data", "method": "GET"},
        ],
        "write": [
            {"path": "/api/users", "method": "POST"},
            {"path": "/api/settings", "method": "PUT"},
            {"path": "/api/data", "method": "POST"},
        ],
        "delete": [
            {"path": "/api/users/1", "method": "DELETE"},
            {"path": "/api/data/1", "method": "DELETE"},
        ],
    }

    async def is_applicable(self, candidate: FindingCandidate) -> bool:
        """Check if permission testing applies to this finding.

        Args:
            candidate: The finding to evaluate

        Returns:
            True if finding contains extractable tokens
        """
        # Check for JWT tokens
        if re.search(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", candidate.evidence):
            return True

        # Check for API keys
        if re.search(r"api[_-]?key", candidate.evidence, re.I):
            return True

        # Check for bearer tokens
        if re.search(r"bearer\s+[A-Za-z0-9_-]+", candidate.evidence, re.I):
            return True

        # Check for session tokens
        if re.search(r"session[:\s=]+[A-Za-z0-9_-]+", candidate.evidence, re.I):
            return True

        return False

    async def attempt(
        self, candidate: FindingCandidate, target: str | None = None
    ) -> EscalationAttempt:
        """Test permissions of discovered tokens.

        Args:
            candidate: The finding containing tokens
            target: Optional specific target URL

        Returns:
            Record of the permission testing attempt
        """
        target_url = target or candidate.target_url
        logger.info(f"Testing permissions for tokens in {candidate.finding_id}")

        # Extract tokens from evidence
        tokens = self._extract_all_tokens(candidate.evidence)
        if not tokens:
            return self._create_attempt(
                description="No extractable tokens found in evidence",
                target=target_url,
                result=EscalationResult.NOT_APPLICABLE,
                evidence="Could not extract tokens for permission testing",
            )

        # Get HTTP tool
        registry = ToolRegistry()
        http_tool = registry.get("http_request")

        if not http_tool:
            return self._create_attempt(
                description="HTTP tool not available for testing",
                target=target_url,
                result=EscalationResult.FAILED,
                evidence="Cannot perform HTTP requests without http_request tool",
            )

        # Extract base URL
        base_url = self._extract_base_url(target_url)
        if not base_url:
            return self._create_attempt(
                description="Could not extract base URL",
                target=target_url,
                result=EscalationResult.FAILED,
                evidence="Invalid or unparseable target URL",
            )

        # Test each token
        all_permissions = {}
        for token_type, token_value in tokens.items():
            permissions = await self._test_token_permissions(
                http_tool, base_url, token_type, token_value
            )
            if permissions:
                all_permissions[token_type] = permissions

        if all_permissions:
            evidence_parts = ["Token Permission Analysis:"]
            for token_type, perms in all_permissions.items():
                evidence_parts.append(f"\n{token_type}:")
                evidence_parts.append(f"  Permissions: {', '.join(perms)}")

            # Determine result based on permissions
            all_perms = [p for perms in all_permissions.values() for p in perms]
            if "delete" in all_perms or "admin" in all_perms:
                result = EscalationResult.SUCCESS
                description = "Token grants elevated permissions including delete/admin"
            elif "write" in all_perms:
                result = EscalationResult.PARTIAL
                description = "Token grants write permissions"
            else:
                result = EscalationResult.PARTIAL
                description = "Token grants read-only permissions"

            return self._create_attempt(
                description=description,
                target=target_url,
                result=result,
                evidence="\n".join(evidence_parts),
                token_tested=list(tokens.values())[0],  # First token
                permissions=all_perms,
            )

        return self._create_attempt(
            description="No permissions could be validated for extracted tokens",
            target=target_url,
            result=EscalationResult.FAILED,
            evidence=f"Tested {len(tokens)} token(s), no permissions confirmed",
            token_tested=list(tokens.values())[0] if tokens else None,
        )

    def _extract_all_tokens(self, evidence: str) -> dict[str, str]:
        """Extract all tokens from evidence.

        Args:
            evidence: Finding evidence text

        Returns:
            Dictionary mapping token type to value
        """
        tokens = {}

        # JWT token
        jwt_match = re.search(
            r"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)", evidence
        )
        if jwt_match:
            tokens["jwt"] = jwt_match.group(1)

        # API key
        api_key_match = re.search(r"api[_-]?key[:\s=]+([A-Za-z0-9_-]+)", evidence, re.I)
        if api_key_match:
            tokens["api_key"] = api_key_match.group(1)

        # Bearer token
        bearer_match = re.search(r"Bearer\s+([A-Za-z0-9_-]+)", evidence, re.I)
        if bearer_match:
            tokens["bearer"] = bearer_match.group(1)

        # Session token
        session_match = re.search(r"session[:\s=]+([A-Za-z0-9_-]+)", evidence, re.I)
        if session_match:
            tokens["session"] = session_match.group(1)

        return tokens

    def _extract_base_url(self, url: str) -> str | None:
        """Extract base URL from full URL.

        Args:
            url: Full URL

        Returns:
            Base URL (scheme + host) or None
        """
        match = re.match(r"(https?://[^/]+)", url)
        return match.group(1) if match else None

    async def _test_token_permissions(
        self, http_tool: Any, base_url: str, token_type: str, token_value: str
    ) -> list[str]:
        """Test what permissions a token actually has.

        Args:
            http_tool: HTTP tool instance
            base_url: Base URL for testing
            token_type: Type of token (jwt, api_key, etc.)
            token_value: Token value

        Returns:
            List of confirmed permissions
        """
        permissions = []

        # Build auth headers
        headers = self._build_token_headers(token_type, token_value)

        # Test read permissions
        for test in self.PERMISSION_TESTS["read"]:
            url = f"{base_url}{test['path']}"
            try:
                result = await http_tool.execute(
                    url=url, method=test["method"], headers=headers
                )

                if result.success and result.data.get("status_code") == 200:
                    if "read" not in permissions:
                        permissions.append("read")
                    if "/admin/" in test["path"] and "admin" not in permissions:
                        permissions.append("admin")

            except Exception as e:
                logger.debug(f"Read permission test failed for {url}: {e}")

        # Test write permissions
        for test in self.PERMISSION_TESTS["write"]:
            url = f"{base_url}{test['path']}"
            try:
                result = await http_tool.execute(
                    url=url,
                    method=test["method"],
                    headers=headers,
                    data={"test": "value"},
                )

                status = result.data.get("status_code", 0) if result.success else 0
                # 200/201 = success, 403/401 = forbidden, anything else might be success
                if status in [200, 201, 202]:
                    if "write" not in permissions:
                        permissions.append("write")

            except Exception as e:
                logger.debug(f"Write permission test failed for {url}: {e}")

        # Test delete permissions
        for test in self.PERMISSION_TESTS["delete"]:
            url = f"{base_url}{test['path']}"
            try:
                result = await http_tool.execute(
                    url=url, method=test["method"], headers=headers
                )

                status = result.data.get("status_code", 0) if result.success else 0
                if status in [200, 202, 204]:
                    if "delete" not in permissions:
                        permissions.append("delete")

            except Exception as e:
                logger.debug(f"Delete permission test failed for {url}: {e}")

        return permissions

    def _build_token_headers(self, token_type: str, token_value: str) -> dict[str, str]:
        """Build HTTP headers for token authentication.

        Args:
            token_type: Type of token
            token_value: Token value

        Returns:
            Dictionary of HTTP headers
        """
        headers = {}

        if token_type in ["jwt", "bearer"]:
            headers["Authorization"] = f"Bearer {token_value}"
        elif token_type == "api_key":
            headers["X-API-Key"] = token_value
        elif token_type == "session":
            headers["Cookie"] = f"session={token_value}"

        return headers
