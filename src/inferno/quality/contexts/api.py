"""
API technology context for quality gate system.

This module implements API-specific filtering rules to prevent
false positives from intentionally exposed API documentation.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from inferno.quality.contexts.base import BaseTechnologyContext
from inferno.reporting.models import Severity

if TYPE_CHECKING:
    from inferno.quality.candidate import ContextAdjustment, FindingCandidate


class APIContext(BaseTechnologyContext):
    """
    API technology context.

    Filters out public-by-design API documentation that is often
    incorrectly reported as information disclosure:
    - swagger.json, swagger.yaml
    - openapi.json, openapi.yaml
    - /api-docs, /swagger-ui endpoints
    - GraphQL introspection (if explicitly enabled)

    Only flags if INTERNAL/ADMIN endpoints are exposed in documentation.
    """

    # API documentation file patterns
    SWAGGER_PATTERN = re.compile(
        r"swagger\.(json|yaml|yml)|openapi\.(json|yaml|yml)", re.IGNORECASE
    )

    # API documentation endpoint patterns
    DOC_ENDPOINT_PATTERN = re.compile(
        r"/(api[-_]docs?|swagger[-_]ui|redoc|rapidoc|scalar|graphql[-_]playground|graphiql)",
        re.IGNORECASE,
    )

    # GraphQL introspection patterns
    GRAPHQL_INTROSPECTION_PATTERN = re.compile(r"__schema|__type|introspectionQuery", re.IGNORECASE)

    # Internal/admin endpoint indicators
    INTERNAL_INDICATORS = {
        "/admin",
        "/internal",
        "/debug",
        "/private",
        "/test",
        "/dev",
        "/management",
        "/actuator",
        "/metrics",
        "/health",
        "/status",
    }

    ADMIN_KEYWORDS = {
        "admin",
        "internal",
        "debug",
        "private",
        "test",
        "dev",
        "management",
        "actuator",
    }

    # API-related keywords
    API_KEYWORDS = {
        "api",
        "swagger",
        "openapi",
        "graphql",
        "rest",
        "endpoint",
        "documentation",
        "spec",
        "schema",
    }

    def applies_to(self, candidate: FindingCandidate) -> bool:
        """
        Check if this context applies to the finding.

        Returns True if the finding appears to be API-related.
        """
        text = f"{candidate.title} {candidate.description} {candidate.evidence}".lower()

        # Check for API keywords
        if any(keyword in text for keyword in self.API_KEYWORDS):
            return True

        # Check for API documentation patterns
        if (
            self.SWAGGER_PATTERN.search(candidate.evidence)
            or self.DOC_ENDPOINT_PATTERN.search(candidate.evidence)
            or self.GRAPHQL_INTROSPECTION_PATTERN.search(candidate.evidence)
        ):
            return True

        # Check affected asset
        if self.DOC_ENDPOINT_PATTERN.search(candidate.affected_asset):
            return True

        return False

    def is_public_by_design(self, candidate: FindingCandidate) -> tuple[bool, str]:
        """
        Check if the finding represents public-by-design API documentation.

        API documentation endpoints are often intentionally public to help
        developers integrate with the API. This is only a vulnerability if
        internal/admin endpoints are exposed.
        """
        evidence = candidate.evidence
        title_lower = candidate.title.lower()
        desc_lower = candidate.description.lower()
        asset_lower = candidate.affected_asset.lower()

        # Check for API documentation files
        if self.SWAGGER_PATTERN.search(evidence) or self.SWAGGER_PATTERN.search(asset_lower):
            # Check if it contains internal/admin endpoints
            has_internal = self._contains_internal_endpoints(evidence)
            if not has_internal:
                return (
                    True,
                    "API documentation (Swagger/OpenAPI) is intentionally public. "
                    "No internal or admin endpoints detected.",
                )

        # Check for API documentation endpoints
        if self.DOC_ENDPOINT_PATTERN.search(evidence) or self.DOC_ENDPOINT_PATTERN.search(
            asset_lower
        ):
            has_internal = self._contains_internal_endpoints(evidence)
            if not has_internal:
                return (
                    True,
                    "API documentation UI endpoints are commonly exposed for developer access. "
                    "No internal or admin endpoints detected.",
                )

        # Check for GraphQL introspection
        if self.GRAPHQL_INTROSPECTION_PATTERN.search(evidence):
            # GraphQL introspection is often intentionally enabled
            if "introspection" in title_lower and "enabled" in desc_lower:
                has_internal = self._contains_internal_endpoints(evidence)
                if not has_internal:
                    return (
                        True,
                        "GraphQL introspection is commonly enabled for developer tooling. "
                        "This is only a vulnerability if internal mutations/queries are exposed.",
                    )

        # Check if it's just API enumeration without sensitive data or internal endpoints
        if any(
            keyword in title_lower for keyword in ["api", "endpoint", "enumeration", "disclosure"]
        ):
            has_internal = self._contains_internal_endpoints(evidence)
            has_sensitive = self._contains_sensitive_data(evidence)
            if not has_internal and not has_sensitive:
                return (
                    True,
                    "API endpoint enumeration is expected behavior. "
                    "No sensitive data or internal endpoints detected.",
                )

        return False, ""

    def suggest_severity(self, candidate: FindingCandidate) -> Severity | None:
        """
        Suggest severity adjustments for API findings.

        Internal/admin endpoint exposure should remain HIGH.
        Public API documentation should be downgraded to INFO.
        """
        evidence = candidate.evidence
        title_lower = candidate.title.lower()
        desc_lower = candidate.description.lower()

        # Check for internal/admin endpoint exposure
        has_internal = self._contains_internal_endpoints(evidence)

        # Swagger/OpenAPI documentation
        if self.SWAGGER_PATTERN.search(evidence):
            if has_internal:
                # Keep as HIGH if internal endpoints exposed
                if candidate.initial_severity in (Severity.LOW, Severity.MEDIUM):
                    return Severity.HIGH
            else:
                # Downgrade to INFO if only public endpoints
                if candidate.initial_severity in (Severity.MEDIUM, Severity.HIGH):
                    return Severity.INFO

        # API documentation endpoints
        if "api" in title_lower and "doc" in title_lower:
            if has_internal:
                if candidate.initial_severity in (Severity.LOW, Severity.MEDIUM):
                    return Severity.HIGH
            else:
                if candidate.initial_severity in (Severity.MEDIUM, Severity.HIGH):
                    return Severity.INFO

        # GraphQL introspection
        if "graphql" in title_lower and "introspection" in title_lower:
            if has_internal:
                if candidate.initial_severity in (Severity.LOW, Severity.MEDIUM):
                    return Severity.HIGH
            else:
                # GraphQL introspection without sensitive data is LOW
                if candidate.initial_severity == Severity.HIGH:
                    return Severity.LOW

        return None

    def get_context_adjustments(
        self, candidate: FindingCandidate
    ) -> list[ContextAdjustment]:
        """
        Get all API-specific context adjustments.
        """
        from inferno.quality.candidate import ContextAdjustment

        adjustments: list[ContextAdjustment] = []

        # Check if public by design
        is_public, public_reason = self.is_public_by_design(candidate)
        if is_public:
            adjustments.append(
                ContextAdjustment(
                    context_type="api",
                    original_severity=candidate.initial_severity,
                    adjusted_severity=Severity.INFO,
                    rationale=public_reason,
                    is_by_design=True,
                )
            )
            # Mark as public by design in the candidate
            candidate.is_public_by_design = True
            candidate.data_intentionally_public = True
            candidate.technology_context = "public_api_endpoint"
            return adjustments

        # Check for severity adjustments
        suggested_severity = self.suggest_severity(candidate)
        if suggested_severity and suggested_severity != candidate.initial_severity:
            reason = self._get_severity_reason(candidate, suggested_severity)
            has_internal = self._contains_internal_endpoints(candidate.evidence)
            context_type = "internal_api_endpoint" if has_internal else "api_endpoint"

            adjustments.append(
                ContextAdjustment(
                    context_type=context_type,
                    original_severity=candidate.initial_severity,
                    adjusted_severity=suggested_severity,
                    rationale=reason,
                    is_by_design=False,
                )
            )
            candidate.technology_context = context_type

        return adjustments

    def _contains_internal_endpoints(self, text: str) -> bool:
        """
        Check if text contains references to internal/admin endpoints.

        Args:
            text: Text to search for internal endpoint indicators

        Returns:
            True if internal endpoints are detected
        """
        text_lower = text.lower()

        # Check for internal path indicators
        if any(indicator in text_lower for indicator in self.INTERNAL_INDICATORS):
            return True

        # Check for admin keywords in endpoint paths
        # Look for patterns like: /api/admin, /v1/internal, etc.
        endpoint_pattern = re.compile(r"[\"']?/[a-zA-Z0-9/_-]+[\"']?")
        endpoints = endpoint_pattern.findall(text)

        for endpoint in endpoints:
            endpoint_lower = endpoint.lower()
            if any(keyword in endpoint_lower for keyword in self.ADMIN_KEYWORDS):
                return True

        return False

    def _contains_sensitive_data(self, text: str) -> bool:
        """
        Check if text contains sensitive data like credentials or secrets.

        Args:
            text: Text to search for sensitive data

        Returns:
            True if sensitive data is detected
        """
        text_lower = text.lower()

        sensitive_keywords = {
            "password",
            "secret",
            "token",
            "apikey",
            "api_key",
            "credential",
            "private_key",
            "aws_access",
            "auth_token",
        }

        return any(keyword in text_lower for keyword in sensitive_keywords)

    def _get_severity_reason(
        self, candidate: FindingCandidate, suggested: Severity
    ) -> str:
        """Get explanation for severity adjustment."""
        if suggested == Severity.INFO:
            return (
                "Downgraded to INFO: API documentation is intentionally public. "
                "No internal endpoints or sensitive data detected."
            )
        elif suggested == Severity.HIGH:
            return (
                "Upgraded to HIGH: Internal or admin endpoints exposed in API documentation. "
                "This reveals sensitive application structure."
            )
        elif suggested == Severity.LOW:
            return (
                "Downgraded to LOW: While exposed, this API information "
                "does not reveal critical internal structure."
            )
        return f"Severity adjusted to {suggested.value} based on API context."
