"""
PreReportChecklistGate - Final validation before report inclusion.

This gate performs final checks before including a finding in the report,
ensuring production environment, impact demonstration, and escalation documentation.
"""

from __future__ import annotations

import re
from typing import Any

from inferno.quality.candidate import FindingCandidate
from inferno.quality.config import QualityConfig
from inferno.quality.gate import QualityGate


class PreReportChecklistGate(QualityGate):
    """
    Final validation checklist before report inclusion.

    This gate performs critical final checks:
    1. Production environment verification (not staging/dev/test)
    2. Impact demonstration (concrete proof, not theoretical)
    3. Escalation documentation (minimum attempts recorded)
    4. Public-by-design check (not intentionally public data)

    Staging/Dev Environment Patterns:
        - staging., dev., test., sandbox., qa., uat., demo., preview.
        - -staging, -dev, -test
        - .local, localhost, 127.0.0.1
        - Private IPs (192.168.x.x, 10.x.x.x, 172.16-31.x.x)

    Gate Properties:
        - Blocking: True (findings must pass all checks)
        - Weight: 0.10 (final sanity check)
    """

    # Staging/dev environment patterns
    STAGING_PATTERNS = [
        re.compile(r"\bstaging\.", re.IGNORECASE),
        re.compile(r"\bstg\.", re.IGNORECASE),
        re.compile(r"\bdev\.", re.IGNORECASE),
        re.compile(r"\btest\.", re.IGNORECASE),
        re.compile(r"\bqa\.", re.IGNORECASE),
        re.compile(r"\buat\.", re.IGNORECASE),
        re.compile(r"\bdemo\.", re.IGNORECASE),
        re.compile(r"\bsandbox\.", re.IGNORECASE),
        re.compile(r"\bpreview\.", re.IGNORECASE),
        re.compile(r"-staging\b", re.IGNORECASE),
        re.compile(r"-dev\b", re.IGNORECASE),
        re.compile(r"-test\b", re.IGNORECASE),
        re.compile(r"\.local$", re.IGNORECASE),
        re.compile(r"\blocalhost\b", re.IGNORECASE),
        re.compile(r"\b127\.0\.0\.1\b"),
        re.compile(r"\b192\.168\.\d+\.\d+\b"),
        re.compile(r"\b10\.\d+\.\d+\.\d+\b"),
        re.compile(r"\b172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+\b"),
    ]

    def __init__(self, config: QualityConfig | None = None) -> None:
        """
        Initialize PreReportChecklistGate.

        Args:
            config: Quality configuration (uses default if None)
        """
        super().__init__(
            name="pre_report_checklist_gate",
            weight=0.10,
            is_blocking=True,
            description="Final validation checklist before report inclusion",
        )
        self.config = config or QualityConfig()

    async def evaluate(
        self, candidate: FindingCandidate, target: str, **kwargs: Any
    ) -> tuple[bool, str]:
        """
        Perform final validation checks.

        Args:
            candidate: Finding candidate to evaluate
            target: Target URL/hostname for environment validation
            **kwargs: Additional parameters (not used)

        Returns:
            Tuple of (passed: bool, message: str)
        """
        issues: list[str] = []

        # Check 1: Production environment
        if self.config.require_production_check:
            is_production = self._check_production_environment(target, candidate)
            if not is_production:
                issues.append("Not a production environment (detected staging/dev/test patterns)")
            else:
                candidate.is_production = True

        # Check 2: Impact demonstration
        if self.config.require_impact_demonstration:
            has_impact = self._check_impact_demonstrated(candidate)
            if not has_impact:
                issues.append(
                    "Impact not demonstrated (need concrete proof or successful escalation)"
                )
            else:
                candidate.impact_demonstrated = True

        # Check 3: Escalation documentation
        if self.config.require_escalation_documentation:
            has_escalation = self._check_escalation_documented(candidate)
            if not has_escalation:
                min_attempts = self.config.min_escalation_attempts
                current = candidate.escalation_count
                issues.append(
                    f"Escalation not documented ({current}/{min_attempts} attempts required)"
                )
            else:
                candidate.escalation_documented = True

        # Check 4: Not public by design
        if candidate.is_public_by_design or candidate.data_intentionally_public:
            issues.append(
                "Finding is public-by-design or intentionally public data "
                "(should have been filtered by TechnologyContextGate)"
            )

        # Evaluate result
        if issues:
            message = f"Failed pre-report checklist: {'; '.join(issues)}"
            return False, message

        return True, "All pre-report checks passed"

    def _check_production_environment(self, target: str, candidate: FindingCandidate) -> bool:
        """
        Check if target is a production environment.

        Args:
            target: Target URL/hostname
            candidate: Finding candidate (check affected_asset too)

        Returns:
            True if production environment
        """
        # Check target URL
        target_lower = target.lower()
        for pattern in self.STAGING_PATTERNS:
            if pattern.search(target_lower):
                return False

        # Check affected_asset if different from target
        if candidate.affected_asset and candidate.affected_asset.lower() != target_lower:
            asset_lower = candidate.affected_asset.lower()
            for pattern in self.STAGING_PATTERNS:
                if pattern.search(asset_lower):
                    return False

        # Use config's staging check as fallback
        if self.config.is_staging_environment(target):
            return False

        if candidate.affected_asset and self.config.is_staging_environment(
            candidate.affected_asset
        ):
            return False

        return True

    def _check_impact_demonstrated(self, candidate: FindingCandidate) -> bool:
        """
        Check if impact has been demonstrated.

        Args:
            candidate: Finding candidate to check

        Returns:
            True if impact is demonstrated
        """
        # Option 1: Has exploitability proof and concrete impact
        if candidate.exploitability_proof and len(candidate.exploitability_proof.strip()) >= 20:
            if candidate.concrete_impact and len(candidate.concrete_impact.strip()) >= 20:
                return True

        # Option 2: Has successful escalation
        if candidate.has_successful_escalation:
            return True

        # Option 3: Has substantial evidence with no theoretical language
        if candidate.evidence and len(candidate.evidence.strip()) >= 50:
            if not candidate.has_theoretical_language:
                if candidate.concrete_impact and len(candidate.concrete_impact.strip()) >= 20:
                    return True

        return False

    def _check_escalation_documented(self, candidate: FindingCandidate) -> bool:
        """
        Check if escalation attempts are documented.

        Args:
            candidate: Finding candidate to check

        Returns:
            True if escalation is documented
        """
        min_attempts = self.config.min_escalation_attempts

        # Check if minimum attempts met
        if candidate.escalation_count >= min_attempts:
            return True

        # Allow exceptions for certain cases:
        # 1. INFO severity findings don't need escalation
        if candidate.final_severity.value == "info":
            if not self.config.allow_info_findings:
                # INFO findings not allowed anyway
                return False
            return True

        # 2. LOW severity findings may skip escalation if configured
        if candidate.final_severity.value == "low":
            if self.config.allow_low_without_escalation:
                return True

        # 3. CRITICAL findings with concrete proof may skip escalation
        if candidate.final_severity.value == "critical":
            if self._check_impact_demonstrated(candidate):
                return True

        return False
