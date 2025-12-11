"""
Unit tests for SSRF Detector.

Tests the SSRF detection algorithms, payload generation,
and vulnerability identification logic.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch
from typing import Dict, Any

from inferno.tools.advanced.ssrf_detector import (
    SSRFDetector,
    SSRFType,
    SSRFFinding,
    SSRFPayload,
    SSRF_PAYLOADS,
    RESPONSE_INDICATORS
)


class TestSSRFPayloadGeneration:
    """Test SSRF payload generation and variants."""

    @pytest.fixture
    def detector(self):
        """Create SSRF detector instance."""
        return SSRFDetector()

    @pytest.mark.asyncio
    async def test_generate_localhost_payloads(self, detector):
        """Test generation of localhost targeting payloads."""
        result = await detector.execute(
            operation="generate_payloads",
            categories=["localhost"]
        )

        assert result["success"]
        assert "localhost_payloads" in result["payloads"]
        payloads = result["payloads"]["localhost_payloads"]

        # Should have multiple localhost variations
        assert len(payloads) > 5

        # Check for key payload types
        payload_names = [p["name"] for p in payloads]
        assert "localhost" in payload_names
        assert "127.0.0.1" in payload_names
        assert "ipv6_localhost" in payload_names

    @pytest.mark.asyncio
    async def test_generate_cloud_metadata_payloads(self, detector):
        """Test generation of cloud metadata payloads."""
        result = await detector.execute(
            operation="generate_payloads",
            categories=["cloud_metadata"]
        )

        assert result["success"]
        payloads = result["payloads"]["cloud_metadata_payloads"]

        # Should have AWS, GCP, Azure, etc.
        assert len(payloads) >= 5

        payload_names = [p["name"] for p in payloads]
        assert any("aws" in name for name in payload_names)
        assert any("gcp" in name for name in payload_names)
        assert any("azure" in name for name in payload_names)

    @pytest.mark.asyncio
    async def test_generate_callback_payloads(self, detector):
        """Test generation of callback payloads for blind SSRF."""
        callback_domain = "test.callback.example.com"

        result = await detector.execute(
            operation="generate_payloads",
            callback_domain=callback_domain
        )

        assert result["success"]
        callbacks = result["payloads"]["callback_payloads"]

        # Should have multiple callback variants
        assert len(callbacks) > 0

        # All should include callback domain
        for callback in callbacks:
            assert callback_domain in callback["payload"]
            assert "callback_id" in callback

    @pytest.mark.asyncio
    async def test_payload_encoding_variations(self, detector):
        """Test URL encoding and bypass payloads."""
        result = await detector.execute(
            operation="generate_payloads",
            categories=["url_bypass"]
        )

        assert result["success"]
        payloads = result["payloads"]["bypass_payloads"]

        # Should have encoding bypasses
        assert len(payloads) > 3

        # Check for specific bypass types
        payload_names = [p["name"] for p in payloads]
        assert "url_encoding" in payload_names
        assert "double_encoding" in payload_names


class TestSSRFDetection:
    """Test SSRF vulnerability detection logic."""

    @pytest.fixture
    def detector(self):
        """Create SSRF detector instance."""
        return SSRFDetector()

    @pytest.fixture
    def mock_response(self):
        """Create mock HTTP response."""
        response = Mock()
        response.status = 200
        response.text = AsyncMock(return_value="<html><body>Server response</body></html>")
        return response

    def test_analyze_localhost_access_response(self, detector):
        """Test detection of localhost access in response."""
        # Response with Apache server indicators
        response_text = """
        <!DOCTYPE html>
        <html>
        <head><title>It works!</title></head>
        <body>
        <h1>Apache Web Server</h1>
        <p>If you can see this, the server is working</p>
        </body>
        </html>
        """

        indicators = detector._analyze_response(response_text)

        assert indicators["localhost_success"]
        assert indicators["accessible"]
        assert not indicators["ssrf_blocked"]

    def test_analyze_cloud_metadata_response(self, detector):
        """Test detection of cloud metadata access."""
        # AWS metadata response
        response_text = """
        {
            "ami-id": "ami-0123456789",
            "instance-id": "i-0123456789abcdef0",
            "instance-type": "t2.micro",
            "security-credentials": {
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            }
        }
        """

        indicators = detector._analyze_response(response_text)

        assert indicators["cloud_metadata"]
        assert indicators["accessible"]

    def test_analyze_waf_block_response(self, detector):
        """Test detection of WAF blocking."""
        response_text = """
        <html>
        <head><title>403 Forbidden</title></head>
        <body>
        <h1>Request Blocked by Firewall</h1>
        <p>Your request has been blocked due to security policy</p>
        </body>
        </html>
        """

        indicators = detector._analyze_response(response_text)

        assert indicators["ssrf_blocked"]
        assert not indicators["accessible"]

    def test_analyze_file_access_response(self, detector):
        """Test detection of file access via protocol smuggling."""
        # /etc/passwd content
        response_text = """
        root:x:0:0:root:/root:/bin/bash
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
        www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
        """

        indicators = detector._analyze_response(response_text)

        assert indicators["file_access"]

    def test_analyze_internal_error_response(self, detector):
        """Test detection of internal network errors."""
        response_text = "Connection refused to 192.168.1.100:8080"

        indicators = detector._analyze_response(response_text)

        assert indicators["internal_error"]

    def test_determine_ssrf_type_basic(self, detector):
        """Test SSRF type determination for basic SSRF."""
        payload = SSRFPayload(
            name="test_payload",
            payload="http://localhost/",
            callback_url=None,
            expected_callback=False,
            detection_method="localhost"
        )

        indicators = {"accessible": True}

        ssrf_type = detector._determine_ssrf_type(payload, indicators)

        assert ssrf_type == SSRFType.BASIC

    def test_determine_ssrf_type_blind(self, detector):
        """Test SSRF type determination for blind SSRF."""
        payload = SSRFPayload(
            name="callback_test",
            payload="http://callback.example.com/",
            callback_url="http://callback.example.com/",
            expected_callback=True,
            detection_method="blind"
        )

        indicators = {}

        ssrf_type = detector._determine_ssrf_type(payload, indicators)

        assert ssrf_type == SSRFType.BLIND

    def test_determine_ssrf_type_protocol(self, detector):
        """Test SSRF type determination for protocol smuggling."""
        payload = SSRFPayload(
            name="file_test",
            payload="file:///etc/passwd",
            callback_url=None,
            expected_callback=False,
            detection_method="protocol_smuggling"
        )

        indicators = {"file_access": True}

        ssrf_type = detector._determine_ssrf_type(payload, indicators)

        assert ssrf_type == SSRFType.PROTOCOL


class TestSSRFPayloadInjection:
    """Test payload injection into URLs."""

    @pytest.fixture
    def detector(self):
        """Create SSRF detector instance."""
        return SSRFDetector()

    def test_inject_payload_in_query_param(self, detector):
        """Test injecting SSRF payload into query parameter."""
        url = "http://example.com/fetch?url=http://safe.com"
        parameter = "url"
        payload = "http://localhost/"
        method = "GET"

        result = detector._inject_payload(url, parameter, payload, method)

        assert "http://example.com/fetch" in result
        assert "url=http%3A%2F%2Flocalhost%2F" in result

    def test_inject_payload_post_method(self, detector):
        """Test payload injection for POST method (returns original URL)."""
        url = "http://example.com/api/fetch"
        parameter = "target_url"
        payload = "http://169.254.169.254/"
        method = "POST"

        result = detector._inject_payload(url, parameter, payload, method)

        # For POST, payload goes in body, not URL
        assert result == url

    def test_inject_payload_with_existing_params(self, detector):
        """Test injecting payload with existing query parameters."""
        url = "http://example.com/api?foo=bar&baz=qux"
        parameter = "url"
        payload = "http://192.168.1.1/"
        method = "GET"

        result = detector._inject_payload(url, parameter, payload, method)

        assert "foo=bar" in result
        assert "baz=qux" in result
        assert "url=http%3A%2F%2F192.168.1.1%2F" in result


class TestSSRFValidation:
    """Test SSRF vulnerability validation with real scenarios."""

    @pytest.fixture
    def detector(self):
        """Create SSRF detector instance."""
        return SSRFDetector()

    @pytest.mark.asyncio
    async def test_detect_localhost_ssrf(self, detector):
        """Test detection of localhost SSRF vulnerability."""
        # Mock successful localhost access
        mock_response = Mock()
        mock_response.status = 200
        mock_response.text = "It works! Apache Server"

        with patch.object(detector, 'session') as mock_session:
            mock_session.get = AsyncMock(return_value=Mock(
                __aenter__=AsyncMock(return_value=mock_response),
                __aexit__=AsyncMock()
            ))

            payload = SSRFPayload(
                name="localhost",
                payload="http://localhost/",
                callback_url=None,
                expected_callback=False,
                detection_method="localhost"
            )

            finding = await detector._test_payload(
                url="http://vulnerable.com/fetch?url=http://safe.com",
                parameter="url",
                method="GET",
                payload=payload,
                headers={},
                timeout=10
            )

            # Should detect SSRF
            assert finding is not None
            assert finding.ssrf_type == SSRFType.BASIC
            assert finding.severity in ["high", "critical"]

    @pytest.mark.asyncio
    async def test_no_false_positive_on_blocked_request(self, detector):
        """Test that blocked requests don't trigger false positives."""
        # Mock WAF block response
        mock_response = Mock()
        mock_response.status = 403
        mock_response.text = "Request blocked by firewall"

        with patch.object(detector, 'session') as mock_session:
            mock_session.get = AsyncMock(return_value=Mock(
                __aenter__=AsyncMock(return_value=mock_response),
                __aexit__=AsyncMock()
            ))

            payload = SSRFPayload(
                name="localhost",
                payload="http://localhost/",
                callback_url=None,
                expected_callback=False,
                detection_method="localhost"
            )

            finding = await detector._test_payload(
                url="http://protected.com/fetch?url=http://safe.com",
                parameter="url",
                method="GET",
                payload=payload,
                headers={},
                timeout=10
            )

            # Should NOT detect SSRF (blocked by WAF)
            assert finding is None

    @pytest.mark.asyncio
    async def test_detect_cloud_metadata_access(self, detector):
        """Test detection of cloud metadata SSRF."""
        # Mock AWS metadata response
        mock_response = Mock()
        mock_response.status = 200
        mock_response.text = '{"ami-id": "ami-123", "instance-id": "i-456", "security-credentials": {}}'

        with patch.object(detector, 'session') as mock_session:
            mock_session.get = AsyncMock(return_value=Mock(
                __aenter__=AsyncMock(return_value=mock_response),
                __aexit__=AsyncMock()
            ))

            payload = SSRFPayload(
                name="aws_metadata",
                payload="http://169.254.169.254/latest/meta-data/",
                callback_url=None,
                expected_callback=False,
                detection_method="cloud_metadata"
            )

            finding = await detector._test_payload(
                url="http://vulnerable.com/proxy?url=http://safe.com",
                parameter="url",
                method="GET",
                payload=payload,
                headers={},
                timeout=10
            )

            # Should detect critical SSRF
            assert finding is not None
            assert finding.severity == "critical"
            assert finding.metadata_access


class TestSSRFCallbackGeneration:
    """Test callback ID generation for blind SSRF."""

    @pytest.fixture
    def detector(self):
        """Create SSRF detector instance."""
        return SSRFDetector()

    def test_generate_unique_callback_ids(self, detector):
        """Test that callback IDs are unique."""
        ids = set()
        for _ in range(100):
            callback_id = detector._generate_callback_id()
            ids.add(callback_id)

        # All should be unique
        assert len(ids) == 100

        # All should start with 'inf'
        for callback_id in ids:
            assert callback_id.startswith("inf")
            assert len(callback_id) == 15  # inf + 12 hex chars

    def test_callback_id_format(self, detector):
        """Test callback ID format is valid."""
        callback_id = detector._generate_callback_id()

        # Should be inf + 12 hex characters
        assert callback_id.startswith("inf")
        assert len(callback_id) == 15

        # After 'inf', should be valid hex
        hex_part = callback_id[3:]
        assert all(c in '0123456789abcdef' for c in hex_part)


class TestSSRFResponseIndicators:
    """Test SSRF response indicator patterns."""

    def test_localhost_success_patterns(self):
        """Test localhost success indicator patterns."""
        test_cases = [
            ("It works!", True),
            ("Apache Web Server", True),
            ("nginx/1.18.0", True),
            ("Welcome to nginx!", True),
            ("Index of /", True),
            ("Directory listing for /", True),
            ("Normal page content", False),
        ]

        import re
        patterns = RESPONSE_INDICATORS["localhost_success"]

        for text, should_match in test_cases:
            matched = any(re.search(p, text, re.IGNORECASE) for p in patterns)
            assert matched == should_match, f"Failed for: {text}"

    def test_cloud_metadata_patterns(self):
        """Test cloud metadata indicator patterns."""
        test_cases = [
            ('{"ami-id": "ami-123"}', True),
            ('{"instance-id": "i-456"}', True),
            ('"instance-type": "t2.micro"', True),
            ('"availability-zone": "us-east-1a"', True),
            ('"security-credentials": {}', True),
            ('"access-key-id": "AKIAEXAMPLE"', True),
            ('Regular JSON response', False),
        ]

        import re
        patterns = RESPONSE_INDICATORS["cloud_metadata"]

        for text, should_match in test_cases:
            matched = any(re.search(p, text, re.IGNORECASE) for p in patterns)
            assert matched == should_match, f"Failed for: {text}"

    def test_file_access_patterns(self):
        """Test file access indicator patterns."""
        test_cases = [
            ("root:x:0:0:root:/root:/bin/bash", True),
            ("daemon:x:1:1:daemon:/usr/sbin:/bin/sh", True),
            ("[boot loader]", True),
            ("Windows Registry Editor Version 5.00", True),
            ("Normal text content", False),
        ]

        import re
        patterns = RESPONSE_INDICATORS["file_access"]

        for text, should_match in test_cases:
            matched = any(re.search(p, text, re.IGNORECASE) for p in patterns)
            assert matched == should_match, f"Failed for: {text}"


class TestSSRFEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.fixture
    def detector(self):
        """Create SSRF detector instance."""
        return SSRFDetector()

    @pytest.mark.asyncio
    async def test_timeout_handling(self, detector):
        """Test proper handling of request timeouts."""
        with patch.object(detector, 'session') as mock_session:
            mock_session.get = AsyncMock(side_effect=asyncio.TimeoutError())

            payload = SSRFPayload(
                name="localhost",
                payload="http://localhost/",
                callback_url=None,
                expected_callback=False,
                detection_method="localhost"
            )

            finding = await detector._test_payload(
                url="http://vulnerable.com/fetch?url=http://safe.com",
                parameter="url",
                method="GET",
                payload=payload,
                headers={},
                timeout=10
            )

            # Timeout should not trigger false positive
            assert finding is None

    @pytest.mark.asyncio
    async def test_network_error_handling(self, detector):
        """Test proper handling of network errors."""
        with patch.object(detector, 'session') as mock_session:
            mock_session.get = AsyncMock(side_effect=Exception("Network error"))

            payload = SSRFPayload(
                name="localhost",
                payload="http://localhost/",
                callback_url=None,
                expected_callback=False,
                detection_method="localhost"
            )

            finding = await detector._test_payload(
                url="http://vulnerable.com/fetch?url=http://safe.com",
                parameter="url",
                method="GET",
                payload=payload,
                headers={},
                timeout=10
            )

            # Network error should not trigger false positive
            assert finding is None

    def test_empty_response_handling(self, detector):
        """Test handling of empty responses."""
        indicators = detector._analyze_response("")

        # Empty response should not trigger any indicators
        assert not indicators["localhost_success"]
        assert not indicators["cloud_metadata"]
        assert not indicators["file_access"]
        assert not indicators["accessible"]

    def test_very_large_response_handling(self, detector):
        """Test handling of very large responses."""
        # 10MB of data
        large_response = "A" * (10 * 1024 * 1024)

        # Should not crash
        indicators = detector._analyze_response(large_response)

        # Should still detect if accessible
        assert indicators["accessible"]
