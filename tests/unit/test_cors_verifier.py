"""
Unit tests for CORS Browser Verification system.

Tests multi-stage verification process including:
- HTTP header detection
- Browser verification (mocked)
- Authentication detection
- Sensitivity analysis
- Proof generation
"""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from inferno.core.cors_models import (
    AuthMechanism,
    BrowserProof,
    ConfidenceLevel,
    CORSFinding,
    CORSMisconfigType,
    SensitivityScore,
)
from inferno.tools.advanced.cors_verifier import CORSVerifier


@pytest.fixture
def temp_output_dir(tmp_path):
    """Create temporary output directory."""
    return tmp_path / "cors_outputs"


@pytest.fixture
def cors_verifier(temp_output_dir):
    """Create CORSVerifier instance."""
    return CORSVerifier(output_dir=temp_output_dir)


@pytest.fixture
def mock_http_client():
    """Create mock HTTP client."""
    client = AsyncMock()
    response = Mock()
    response.status_code = 200
    response.text = '{"sensitive": "data", "email": "test@example.com"}'
    response.headers = {
        "Access-Control-Allow-Origin": "https://evil.com",
        "Access-Control-Allow-Credentials": "true",
        "Content-Type": "application/json",
    }
    client.get.return_value = response
    return client


class TestCORSModels:
    """Test CORS data models."""

    def test_auth_mechanism_enum(self):
        """Test AuthMechanism enum values."""
        assert AuthMechanism.NONE == "none"
        assert AuthMechanism.BEARER_TOKEN == "bearer_token"
        assert AuthMechanism.COOKIE_SESSION == "cookie_session"

    def test_misconfig_type_enum(self):
        """Test CORSMisconfigType enum values."""
        assert CORSMisconfigType.WILDCARD_WITH_CREDENTIALS == "wildcard_with_credentials"
        assert CORSMisconfigType.REFLECTED_ORIGIN == "reflected_origin"
        assert CORSMisconfigType.NULL_ORIGIN == "null_origin"

    def test_confidence_level_enum(self):
        """Test ConfidenceLevel enum values."""
        assert ConfidenceLevel.CONFIRMED == "confirmed"
        assert ConfidenceLevel.HIGH == "high"
        assert ConfidenceLevel.MEDIUM == "medium"
        assert ConfidenceLevel.LOW == "low"
        assert ConfidenceLevel.FALSE_POSITIVE == "false_positive"

    def test_browser_proof_dataclass(self):
        """Test BrowserProof dataclass."""
        proof = BrowserProof(
            success=True,
            response_preview="test data",
            response_length=100,
            data_accessible=True,
        )
        assert proof.success is True
        assert proof.data_accessible is True
        assert proof.response_length == 100

        # Test to_dict
        data = proof.to_dict()
        assert data["success"] is True
        assert data["response_preview"] == "test data"

    def test_sensitivity_score_dataclass(self):
        """Test SensitivityScore dataclass."""
        score = SensitivityScore(
            has_pii=True,
            has_credentials=True,
            detected_patterns=["email: 1 matches", "password: 1 matches"],
            severity_multiplier=2.0,
            explanation="CRITICAL: Contains credentials",
        )
        assert score.has_pii is True
        assert score.has_credentials is True
        assert score.severity_multiplier == 2.0

    def test_cors_finding_dataclass(self):
        """Test CORSFinding dataclass."""
        finding = CORSFinding(
            url="https://api.example.com/user",
            misconfig_type=CORSMisconfigType.REFLECTED_ORIGIN,
            confidence=ConfidenceLevel.CONFIRMED,
            origin_tested="https://evil.com",
            acao_header="https://evil.com",
            acac_header="true",
        )
        assert finding.url == "https://api.example.com/user"
        assert finding.misconfig_type == CORSMisconfigType.REFLECTED_ORIGIN
        assert finding.confidence == ConfidenceLevel.CONFIRMED

    def test_cors_finding_is_exploitable(self):
        """Test is_exploitable method."""
        # Not exploitable without browser proof
        finding = CORSFinding(
            url="https://test.com",
            misconfig_type=CORSMisconfigType.REFLECTED_ORIGIN,
            confidence=ConfidenceLevel.HIGH,
        )
        assert finding.is_exploitable() is False

        # Not exploitable if data not accessible
        finding.browser_proof = BrowserProof(success=True, data_accessible=False)
        assert finding.is_exploitable() is False

        # Exploitable when confirmed and data accessible
        finding.confidence = ConfidenceLevel.CONFIRMED
        finding.browser_proof = BrowserProof(success=True, data_accessible=True)
        assert finding.is_exploitable() is True

    def test_cors_finding_get_summary(self):
        """Test get_summary method."""
        finding = CORSFinding(
            url="https://test.com",
            misconfig_type=CORSMisconfigType.REFLECTED_ORIGIN,
            confidence=ConfidenceLevel.CONFIRMED,
            severity="high",
            requires_auth=True,
            auth_mechanism=AuthMechanism.BEARER_TOKEN,
        )
        finding.browser_proof = BrowserProof(success=True, data_accessible=True)

        summary = finding.get_summary()
        assert "Reflected Origin" in summary
        assert "CONFIRMED" in summary
        assert "HIGH" in summary
        assert "bearer_token" in summary
        assert "BROWSER VERIFIED" in summary


class TestCORSVerifier:
    """Test CORSVerifier tool."""

    @pytest.mark.asyncio
    async def test_initialization(self, temp_output_dir):
        """Test CORSVerifier initialization."""
        verifier = CORSVerifier(output_dir=temp_output_dir)
        assert verifier.name == "cors_verifier"
        assert verifier.output_dir == temp_output_dir
        assert temp_output_dir.exists()

    @pytest.mark.asyncio
    async def test_no_misconfiguration(self, cors_verifier, mock_http_client):
        """Test when no CORS misconfiguration is present."""
        # Setup response with proper CORS
        mock_http_client.get.return_value.headers = {
            "Access-Control-Allow-Origin": "https://trusted.com",
            "Vary": "Origin",
        }
        cors_verifier.http_client = mock_http_client

        result = await cors_verifier.execute(
            url="https://api.example.com/data",
            skip_browser_verification=True,
        )

        assert result.success is True
        assert result.metadata["exploitable"] is False
        assert len(result.metadata["findings"]) == 0

    @pytest.mark.asyncio
    async def test_reflected_origin_detection(self, cors_verifier, mock_http_client):
        """Test detection of reflected origin misconfiguration."""
        cors_verifier.http_client = mock_http_client

        result = await cors_verifier.execute(
            url="https://api.example.com/data",
            test_origins=["https://evil.com"],
            skip_browser_verification=True,
        )

        assert result.success is True
        assert len(result.metadata["findings"]) >= 1

        finding_dict = result.metadata["findings"][0]
        assert finding_dict["misconfig_type"] == "reflected_origin"
        assert finding_dict["acao_header"] == "https://evil.com"
        assert finding_dict["acac_header"] == "true"

    @pytest.mark.asyncio
    async def test_wildcard_with_credentials_detection(self, cors_verifier, mock_http_client):
        """Test detection of wildcard + credentials misconfiguration."""
        # Setup response with wildcard + credentials
        mock_http_client.get.return_value.headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
        cors_verifier.http_client = mock_http_client

        result = await cors_verifier.execute(
            url="https://api.example.com/data",
            skip_browser_verification=True,
        )

        assert result.success is True
        finding_dict = result.metadata["findings"][0]
        assert finding_dict["misconfig_type"] == "wildcard_with_credentials"
        assert finding_dict["confidence"] == "high"

    @pytest.mark.asyncio
    async def test_null_origin_detection(self, cors_verifier, mock_http_client):
        """Test detection of null origin misconfiguration."""
        # Setup response allowing null origin
        mock_http_client.get.return_value.headers = {
            "Access-Control-Allow-Origin": "null",
            "Access-Control-Allow-Credentials": "true",
        }
        cors_verifier.http_client = mock_http_client

        result = await cors_verifier.execute(
            url="https://api.example.com/data",
            test_origins=["null"],
            skip_browser_verification=True,
        )

        assert result.success is True
        finding_dict = result.metadata["findings"][0]
        assert finding_dict["misconfig_type"] == "null_origin"
        assert finding_dict["origin_tested"] == "null"

    @pytest.mark.asyncio
    async def test_authentication_detection_bearer(self, cors_verifier, mock_http_client):
        """Test detection of Bearer token authentication."""
        cors_verifier.http_client = mock_http_client

        result = await cors_verifier.execute(
            url="https://api.example.com/data",
            auth_headers={"Authorization": "Bearer abc123"},
            skip_browser_verification=True,
        )

        assert result.success is True
        finding_dict = result.metadata["findings"][0]
        assert finding_dict["auth_mechanism"] == "bearer_token"
        assert finding_dict["requires_auth"] is True

    @pytest.mark.asyncio
    async def test_authentication_detection_cookie(self, cors_verifier, mock_http_client):
        """Test detection of cookie-based authentication."""
        cors_verifier.http_client = mock_http_client

        result = await cors_verifier.execute(
            url="https://api.example.com/data",
            cookies={"session": "xyz789"},
            skip_browser_verification=True,
        )

        assert result.success is True
        finding_dict = result.metadata["findings"][0]
        assert finding_dict["auth_mechanism"] == "cookie_session"
        assert finding_dict["requires_auth"] is True

    @pytest.mark.asyncio
    async def test_sensitivity_analysis_pii(self, cors_verifier, mock_http_client):
        """Test sensitivity analysis detecting PII."""
        # Create finding with PII in response
        finding = CORSFinding(
            url="https://test.com",
            misconfig_type=CORSMisconfigType.REFLECTED_ORIGIN,
            confidence=ConfidenceLevel.HIGH,
        )
        finding.browser_proof = BrowserProof(
            success=True,
            response_preview='{"email": "user@example.com", "phone": "555-123-4567"}',
            data_accessible=True,
        )

        await cors_verifier._stage4_sensitivity_analysis(finding)

        assert finding.sensitivity is not None
        assert finding.sensitivity.has_pii is True
        assert "email" in [p.split(":")[0] for p in finding.sensitivity.detected_patterns]
        assert finding.sensitivity.severity_multiplier >= 1.5

    @pytest.mark.asyncio
    async def test_sensitivity_analysis_credentials(self, cors_verifier, mock_http_client):
        """Test sensitivity analysis detecting credentials."""
        finding = CORSFinding(
            url="https://test.com",
            misconfig_type=CORSMisconfigType.REFLECTED_ORIGIN,
            confidence=ConfidenceLevel.HIGH,
        )
        finding.browser_proof = BrowserProof(
            success=True,
            response_preview='{"api_key": "sk_live_abc123def456ghi789jkl"}',
            data_accessible=True,
        )

        await cors_verifier._stage4_sensitivity_analysis(finding)

        assert finding.sensitivity is not None
        assert finding.sensitivity.has_api_keys is True
        assert finding.sensitivity.severity_multiplier >= 1.5

    @pytest.mark.asyncio
    async def test_sensitivity_analysis_tokens(self, cors_verifier, mock_http_client):
        """Test sensitivity analysis detecting tokens."""
        finding = CORSFinding(
            url="https://test.com",
            misconfig_type=CORSMisconfigType.REFLECTED_ORIGIN,
            confidence=ConfidenceLevel.HIGH,
        )
        finding.browser_proof = BrowserProof(
            success=True,
            response_preview=(
                '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
                'eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"}'
            ),
            data_accessible=True,
        )

        await cors_verifier._stage4_sensitivity_analysis(finding)

        assert finding.sensitivity is not None
        assert finding.sensitivity.has_tokens is True

    @pytest.mark.asyncio
    async def test_proof_generation(self, cors_verifier, temp_output_dir):
        """Test PoC file generation."""
        finding = CORSFinding(
            url="https://api.example.com/user",
            misconfig_type=CORSMisconfigType.REFLECTED_ORIGIN,
            confidence=ConfidenceLevel.CONFIRMED,
            origin_tested="https://evil.com",
            acao_header="https://evil.com",
            acac_header="true",
        )
        finding.browser_proof = BrowserProof(success=True, data_accessible=True)
        finding.sensitivity = SensitivityScore(explanation="Test data exposure")

        await cors_verifier._stage5_proof_generation(
            finding, auth_headers={"Authorization": "Bearer token"}, cookies=None
        )

        # Check PoC file was created
        assert finding.poc_html_path is not None
        assert finding.poc_html_path.exists()

        # Check PoC content
        poc_content = finding.poc_html_path.read_text()
        assert "CORS" in poc_content
        assert finding.url in poc_content
        assert "executeCORSExploit" in poc_content

        # Check JavaScript snippet
        assert finding.poc_javascript
        assert "XMLHttpRequest" in finding.poc_javascript

        # Check exploit steps
        assert len(finding.exploit_steps) > 0
        assert any("victim" in step.lower() for step in finding.exploit_steps)

        # Check remediation
        assert finding.remediation
        assert "origin" in finding.remediation.lower()

    def test_risk_score_calculation(self, cors_verifier):
        """Test CVSS risk score calculation."""
        # High confidence, no auth, sensitive data
        finding = CORSFinding(
            url="https://test.com",
            misconfig_type=CORSMisconfigType.REFLECTED_ORIGIN,
            confidence=ConfidenceLevel.CONFIRMED,
            requires_auth=False,
        )
        finding.browser_proof = BrowserProof(success=True, data_accessible=True)
        finding.sensitivity = SensitivityScore(
            has_credentials=True, severity_multiplier=2.0
        )

        cors_verifier._calculate_risk_score(finding)

        assert finding.cvss_score > 0
        assert finding.severity in ["low", "medium", "high", "critical"]
        assert finding.exploitability == "high"

    def test_risk_score_with_auth(self, cors_verifier):
        """Test risk score with authentication required."""
        finding = CORSFinding(
            url="https://test.com",
            misconfig_type=CORSMisconfigType.REFLECTED_ORIGIN,
            confidence=ConfidenceLevel.CONFIRMED,
            requires_auth=True,
            auth_mechanism=AuthMechanism.BEARER_TOKEN,
        )
        finding.browser_proof = BrowserProof(success=True, data_accessible=True)

        cors_verifier._calculate_risk_score(finding)

        # Score should be lower with auth required
        assert finding.cvss_score > 0
        # But still exploitable
        assert finding.exploitability == "high"

    def test_javascript_snippet_generation(self, cors_verifier):
        """Test JavaScript exploit snippet generation."""
        finding = CORSFinding(
            url="https://api.example.com/data",
            misconfig_type=CORSMisconfigType.REFLECTED_ORIGIN,
            confidence=ConfidenceLevel.CONFIRMED,
            origin_tested="https://evil.com",
        )

        js_code = cors_verifier._generate_javascript_snippet(
            finding, auth_headers={"Authorization": "Bearer token123"}, cookies=None
        )

        assert "XMLHttpRequest" in js_code
        assert finding.url in js_code
        assert "withCredentials" in js_code
        assert "Bearer token123" in js_code

    def test_remediation_generation_reflected_origin(self, cors_verifier):
        """Test remediation guidance for reflected origin."""
        finding = CORSFinding(
            url="https://test.com",
            misconfig_type=CORSMisconfigType.REFLECTED_ORIGIN,
            confidence=ConfidenceLevel.HIGH,
        )

        remediation = cors_verifier._generate_remediation(finding)

        assert "whitelist" in remediation.lower()
        assert "origin" in remediation.lower()

    def test_remediation_generation_wildcard(self, cors_verifier):
        """Test remediation guidance for wildcard misconfiguration."""
        finding = CORSFinding(
            url="https://test.com",
            misconfig_type=CORSMisconfigType.WILDCARD_WITH_CREDENTIALS,
            confidence=ConfidenceLevel.HIGH,
        )

        remediation = cors_verifier._generate_remediation(finding)

        assert "wildcard" in remediation.lower() or "*" in remediation
        assert "credentials" in remediation.lower()

    def test_summary_generation(self, cors_verifier):
        """Test summary generation."""
        findings = [
            CORSFinding(
                url="https://test1.com",
                misconfig_type=CORSMisconfigType.REFLECTED_ORIGIN,
                confidence=ConfidenceLevel.CONFIRMED,
                severity="high",
            ),
            CORSFinding(
                url="https://test2.com",
                misconfig_type=CORSMisconfigType.NULL_ORIGIN,
                confidence=ConfidenceLevel.MEDIUM,
                severity="medium",
            ),
        ]
        findings[0].browser_proof = BrowserProof(success=True, data_accessible=True)

        summary = cors_verifier._generate_summary(findings)

        assert "2" in summary  # 2 findings
        assert "1" in summary  # 1 exploitable
        assert "high" in summary.lower()
        assert "medium" in summary.lower()

    @pytest.mark.asyncio
    async def test_error_handling(self, cors_verifier):
        """Test error handling in execution.

        Note: When individual origin tests fail (e.g., network errors),
        the exceptions are caught per-origin in _stage1_header_detection,
        and execution continues. This results in no findings being detected,
        not an overall failure.
        """
        # Mock HTTP client that raises exception
        client = AsyncMock()
        client.get.side_effect = Exception("Network error")
        cors_verifier.http_client = client

        result = await cors_verifier.execute(
            url="https://api.example.com/data",
            skip_browser_verification=True,
        )

        # Per-origin errors are caught, resulting in no findings (graceful degradation)
        assert result.success is True
        assert result.metadata["findings"] == []
        assert result.metadata["exploitable"] is False

    @pytest.mark.asyncio
    async def test_multiple_origins(self, cors_verifier, mock_http_client):
        """Test testing multiple origins."""
        cors_verifier.http_client = mock_http_client

        result = await cors_verifier.execute(
            url="https://api.example.com/data",
            test_origins=["https://evil1.com", "https://evil2.com", "null"],
            skip_browser_verification=True,
        )

        # Should get results for each origin
        assert result.success is True
        # At least one finding (could be multiple if all origins are reflected)
        assert len(result.metadata["findings"]) >= 1

    def test_sensitive_pattern_detection(self, cors_verifier):
        """Test sensitive data pattern detection."""
        test_data = """
        {
            "email": "user@example.com",
            "ssn": "123-45-6789",
            "credit_card": "4532-1234-5678-9010",
            "api_key": "api_key: sk_live_abc123def456ghi789jkl",
            "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"
        }
        """

        detected = []
        for pattern_name, pattern_regex in cors_verifier.SENSITIVE_PATTERNS.items():
            import re

            matches = re.findall(pattern_regex, test_data, re.IGNORECASE)
            if matches:
                detected.append(pattern_name)

        assert "email" in detected
        assert "ssn" in detected
        assert "credit_card" in detected
        assert "api_key" in detected
        assert "jwt" in detected


class TestIntegration:
    """Integration tests for full verification flow."""

    @pytest.mark.asyncio
    async def test_full_verification_flow(self, cors_verifier, mock_http_client, temp_output_dir):
        """Test complete verification flow without browser."""
        cors_verifier.http_client = mock_http_client

        result = await cors_verifier.execute(
            url="https://api.example.com/user/profile",
            auth_headers={"Authorization": "Bearer token123"},
            test_origins=["https://evil.com"],
            skip_browser_verification=True,
        )

        # Verify result structure
        assert result.success is True
        assert "findings" in result.metadata
        assert "exploitable" in result.metadata
        assert "summary" in result.metadata

        # Verify finding was detected
        assert len(result.metadata["findings"]) >= 1
        finding = result.metadata["findings"][0]

        # Verify stages completed
        assert finding["misconfig_type"] == "reflected_origin"
        assert finding["auth_mechanism"] == "bearer_token"
        assert finding["cvss_score"] > 0
        assert finding["severity"] in ["low", "medium", "high", "critical"]

    @pytest.mark.asyncio
    async def test_exploitable_finding_with_pii(
        self, cors_verifier, mock_http_client, temp_output_dir
    ):
        """Test exploitable finding with PII data."""
        # Mock response with PII
        mock_http_client.get.return_value.text = json.dumps(
            {
                "user": {
                    "email": "victim@example.com",
                    "phone": "555-123-4567",
                    "ssn": "123-45-6789",
                }
            }
        )
        cors_verifier.http_client = mock_http_client

        result = await cors_verifier.execute(
            url="https://api.example.com/user/profile",
            skip_browser_verification=True,
        )

        assert result.success is True

        # Note: Without browser verification, won't be marked as exploitable
        # but should detect misconfiguration and PII
        finding = result.metadata["findings"][0]
        assert finding["misconfig_type"] == "reflected_origin"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
