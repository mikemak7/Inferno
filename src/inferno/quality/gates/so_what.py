"""
SoWhatGate - Validates concrete impact and exploitability.

This gate rejects findings with vague, theoretical language and requires
concrete evidence of impact and exploitability.
"""

from __future__ import annotations

import re
from typing import Any

from inferno.quality.candidate import FindingCandidate
from inferno.quality.config import QualityConfig
from inferno.quality.gate import QualityGate


class SoWhatGate(QualityGate):
    """
    Validates that findings have concrete impact and exploitability.

    This gate answers the "So What?" question by requiring:
    1. No vague/theoretical language ("could", "might", "may", "potentially")
    2. Concrete impact evidence (actual data accessed, commands executed, etc.)
    3. Defined attacker action (what can an attacker actually DO?)
    4. Exploitability proof (evidence of successful exploitation)

    Gate Properties:
        - Blocking: True (findings must pass to be included in report)
        - Weight: 0.30 (highest weight - most important gate)
    """

    # Vague language patterns that indicate theoretical findings
    VAGUE_PATTERNS = [
        re.compile(r"\bcould potentially\b", re.IGNORECASE),
        re.compile(r"\bmight be able to\b", re.IGNORECASE),
        re.compile(r"\btheoretically\b", re.IGNORECASE),
        re.compile(r"\bin theory\b", re.IGNORECASE),
        re.compile(r"\bif an attacker\b", re.IGNORECASE),
        re.compile(r"\bmay allow\b", re.IGNORECASE),
        re.compile(r"\bcould lead to\b", re.IGNORECASE),
        re.compile(r"\bcould be used\b", re.IGNORECASE),
        re.compile(r"\bmight allow\b", re.IGNORECASE),
        re.compile(r"\bpossibly\b", re.IGNORECASE),
        re.compile(r"\bperhaps\b", re.IGNORECASE),
        re.compile(r"\bcould result in\b", re.IGNORECASE),
        re.compile(r"\bmay result in\b", re.IGNORECASE),
    ]

    # Impact evidence patterns that indicate concrete exploitation
    IMPACT_EVIDENCE_PATTERNS = [
        re.compile(r"accessed\s+\d+\s+(?:user|account|record)", re.IGNORECASE),
        re.compile(r"retrieved\s+(?:password|credential|key|token)", re.IGNORECASE),
        re.compile(r"executed\s+(?:command|code|query|script)", re.IGNORECASE),
        re.compile(r"created\s+(?:admin|user|account)", re.IGNORECASE),
        re.compile(r"modified\s+(?:user|account|data|record)", re.IGNORECASE),
        re.compile(r"deleted\s+(?:user|account|data|record)", re.IGNORECASE),
        re.compile(r"extracted\s+(?:\$|data|information|\d+\s+(?:user|record))", re.IGNORECASE),
        re.compile(r"exfiltrated\s+(?:data|information|file)", re.IGNORECASE),
        re.compile(r"bypassed\s+(?:authentication|authorization|access control)", re.IGNORECASE),
        re.compile(r"escalated\s+(?:privilege|permission)", re.IGNORECASE),
        re.compile(r"gained\s+(?:access|control|shell)", re.IGNORECASE),
        re.compile(r"obtained\s+(?:shell|access|credential|token)", re.IGNORECASE),
        re.compile(r"successfully\s+(?:logged in|authenticated|executed)", re.IGNORECASE),
        re.compile(r"compromised\s+(?:server|system|account)", re.IGNORECASE),
        re.compile(r"uploaded\s+(?:file|shell|backdoor)", re.IGNORECASE),
    ]

    def __init__(self, config: QualityConfig | None = None) -> None:
        """
        Initialize SoWhatGate.

        Args:
            config: Quality configuration (uses default if None)
        """
        super().__init__(
            name="so_what_gate",
            weight=0.30,
            is_blocking=True,
            description="Validates concrete impact and exploitability (no theoretical language)",
        )
        self.config = config or QualityConfig()

    async def evaluate(
        self, candidate: FindingCandidate, target: str, **kwargs: Any
    ) -> tuple[bool, str]:
        """
        Evaluate finding for concrete impact and exploitability.

        Args:
            candidate: Finding candidate to evaluate
            target: Target URL/hostname (not used in this gate)
            **kwargs: Additional parameters (not used)

        Returns:
            Tuple of (passed: bool, message: str)
        """
        issues: list[str] = []

        # Check for vague/theoretical language
        has_vague_language = self._check_vague_language(candidate)
        if has_vague_language:
            candidate.has_theoretical_language = True
            issues.append(
                "Finding contains vague/theoretical language "
                "(e.g., 'could', 'might', 'may', 'potentially')"
            )

        # Check for concrete impact evidence
        has_impact_evidence = self._check_impact_evidence(candidate)
        if not has_impact_evidence:
            issues.append(
                "No concrete impact evidence found. "
                "Need proof like 'accessed 100 users' or 'executed command'"
            )

        # Check for defined attacker action
        if not candidate.attacker_action or len(candidate.attacker_action.strip()) < 10:
            issues.append(
                "Attacker action not defined. What can an attacker actually DO with this?"
            )

        # Check for concrete impact description
        if not candidate.concrete_impact or len(candidate.concrete_impact.strip()) < 10:
            issues.append(
                "Concrete impact not defined. "
                "Need specific, measurable business impact (not theoretical)"
            )

        # Check for exploitability proof
        if not candidate.exploitability_proof or len(candidate.exploitability_proof.strip()) < 10:
            issues.append(
                "Exploitability proof not provided. "
                "Need evidence of successful exploitation (not just theory)"
            )

        # Evaluate result
        if issues:
            message = f"Failed 'So What?' validation: {'; '.join(issues)}"
            return False, message

        return True, "Finding has concrete impact and exploitability evidence"

    def _check_vague_language(self, candidate: FindingCandidate) -> bool:
        """
        Check if finding contains vague/theoretical language.

        Args:
            candidate: Finding candidate to check

        Returns:
            True if vague language found
        """
        # Combine all text fields for checking
        text = " ".join(
            [
                candidate.title,
                candidate.description,
                candidate.attacker_action,
                candidate.concrete_impact,
                candidate.exploitability_proof,
            ]
        )

        # Check for vague patterns
        for pattern in self.VAGUE_PATTERNS:
            if pattern.search(text):
                return True

        return False

    def _check_impact_evidence(self, candidate: FindingCandidate) -> bool:
        """
        Check if finding contains concrete impact evidence.

        Args:
            candidate: Finding candidate to check

        Returns:
            True if impact evidence found
        """
        # Combine evidence fields
        evidence_text = " ".join(
            [
                candidate.evidence,
                candidate.concrete_impact,
                candidate.exploitability_proof,
                candidate.attacker_action,
            ]
        )

        # Check for impact evidence patterns
        for pattern in self.IMPACT_EVIDENCE_PATTERNS:
            if pattern.search(evidence_text):
                return True

        # Alternative: Check if concrete_impact is well-defined and doesn't use vague language
        if candidate.concrete_impact:
            # If concrete_impact is defined and has no vague language, consider it valid
            has_vague = any(
                pattern.search(candidate.concrete_impact) for pattern in self.VAGUE_PATTERNS
            )
            # Must be substantial (at least 20 chars) and not vague
            if len(candidate.concrete_impact.strip()) >= 20 and not has_vague:
                return True

        return False
