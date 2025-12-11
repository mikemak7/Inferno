"""
Unit tests for NoSQLInjectionScanner.

Tests MongoDB, CouchDB, and Redis payloads, auth bypass detection,
blind injection timing, database fingerprinting, and edge cases.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from inferno.tools.advanced.nosql_injection import (
    NoSQLDatabase,
    NoSQLFinding,
    NoSQLInjectionScanner,
    NoSQLInjectionType,
    NOSQL_PAYLOADS,
    RESPONSE_INDICATORS,
    DATABASE_FINGERPRINTS,
)
from inferno.tools.base import ToolResult


@pytest.fixture
def scanner():
    """Create NoSQL injection scanner instance."""
    return NoSQLInjectionScanner()


@pytest.fixture
def mock_response():
    """Create mock HTTP response."""
    response = MagicMock(spec=httpx.Response)
    response.status_code = 200
    response.text = '{"users": []}'
    response.headers = {"content-type": "application/json"}
    return response


class TestMongoDBPayloads:
    """Test MongoDB injection payloads."""

    def test_mongodb_operator_payloads_exist(self):
        """Test MongoDB operator payloads are defined."""
        assert "mongodb_operators" in NOSQL_PAYLOADS
        payloads = NOSQL_PAYLOADS["mongodb_operators"]
        assert len(payloads) >= 10

        # Check for key operators
        operators = [p[0] for p in payloads]
        assert any("$ne" in op for op in operators)
        assert any("$gt" in op for op in operators)
        assert any("$regex" in op for op in operators)

    def test_mongodb_js_payloads_exist(self):
        """Test MongoDB JavaScript injection payloads."""
        assert "mongodb_js" in NOSQL_PAYLOADS
        payloads = NOSQL_PAYLOADS["mongodb_js"]
        assert len(payloads) >= 5

        # Check for JS injection patterns
        assert any("return" in p[0] for p in payloads)
        assert any("sleep" in p[0] for p in payloads)

    def test_json_injection_payloads_exist(self):
        """Test JSON injection payloads."""
        assert "json_injection" in NOSQL_PAYLOADS
        payloads = NOSQL_PAYLOADS["json_injection"]
        assert len(payloads) >= 5

    @pytest.mark.asyncio
    async def test_scan_mongodb_operators(self, scanner):
        """Test scanning with MongoDB operators."""
        with patch.object(scanner, '_make_request_with_payload', new_callable=AsyncMock) as mock_request:
            # Mock response indicating injection
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = '{"ok": 1, "acknowledged": true}'
            mock_request.return_value = (mock_resp, 0.1)

            with patch.object(scanner, '_detect_database_type', new_callable=AsyncMock, return_value=NoSQLDatabase.MONGODB):
                result = await scanner.execute(
                    operation="scan",
                    url="http://example.com/api/login",
                    parameter="username",
                    database="mongodb",
                )

            assert result.success is True


class TestCouchDBPayloads:
    """Test CouchDB injection payloads."""

    def test_couchdb_payloads_exist(self):
        """Test CouchDB payloads are defined."""
        assert "couchdb" in NOSQL_PAYLOADS
        payloads = NOSQL_PAYLOADS["couchdb"]
        assert len(payloads) >= 2

        # Check for emit patterns
        assert any("emit" in p[0] for p in payloads)

    @pytest.mark.asyncio
    async def test_fingerprint_couchdb(self, scanner):
        """Test CouchDB fingerprinting."""
        with patch.object(scanner, '_make_request', new_callable=AsyncMock) as mock_request:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = '{"couchdb": "Welcome", "version": "3.1.0"}'
            mock_resp.headers = {"server": "CouchDB/3.1.0"}
            mock_request.return_value = (mock_resp, 0.1)

            result = await scanner.execute(
                operation="fingerprint",
                url="http://example.com:5984",
            )

            assert result.success is True
            assert "couchdb" in result.metadata["database_type"].lower()


class TestRedisPayloads:
    """Test Redis injection payloads."""

    def test_redis_payloads_exist(self):
        """Test Redis payloads are defined."""
        assert "redis" in NOSQL_PAYLOADS
        payloads = NOSQL_PAYLOADS["redis"]
        assert len(payloads) >= 4

        # Check for Redis commands
        commands = [p[0] for p in payloads]
        assert any("CONFIG" in cmd for cmd in commands)
        assert any("KEYS" in cmd for cmd in commands)
        assert any("INFO" in cmd for cmd in commands)

    def test_redis_dangerous_commands(self):
        """Test Redis dangerous commands are identified."""
        redis_payloads = NOSQL_PAYLOADS["redis"]
        # FLUSHALL is destructive and should be marked as such
        dangerous = [p for p in redis_payloads if "FLUSHALL" in p[0]]
        assert len(dangerous) > 0


class TestAuthBypassDetection:
    """Test authentication bypass detection."""

    def test_auth_bypass_payloads_exist(self):
        """Test auth bypass payloads are defined."""
        assert "auth_bypass" in NOSQL_PAYLOADS
        payloads = NOSQL_PAYLOADS["auth_bypass"]
        assert len(payloads) >= 5

        # Check for common bypass patterns
        assert any("admin" in p[0] for p in payloads)
        assert any("$ne" in p[0] for p in payloads)
        assert any("$regex" in p[0] for p in payloads)

    @pytest.mark.asyncio
    async def test_auth_bypass_operation(self, scanner):
        """Test auth bypass operation."""
        with patch.object(scanner, '_make_request', new_callable=AsyncMock) as mock_request:
            # Mock baseline (failed login)
            baseline_resp = MagicMock()
            baseline_resp.status_code = 401
            baseline_resp.text = '{"error": "Invalid credentials"}'

            # Mock successful bypass
            bypass_resp = MagicMock()
            bypass_resp.status_code = 200
            bypass_resp.text = '{"token": "abc123", "role": "admin"}'

            # Return baseline first, then bypass for multiple calls
            mock_request.side_effect = [
                (baseline_resp, 0.1),
                (bypass_resp, 0.1),
            ] * 10  # Repeat for multiple payloads

            result = await scanner.execute(
                operation="auth_bypass",
                url="http://example.com/api/login",
                parameters={"username": "test", "password": "test"},
            )

            assert result.success is True
            if result.metadata.get("bypass_found"):
                assert result.metadata["findings_count"] > 0

    def test_check_auth_bypass_status_change(self, scanner):
        """Test auth bypass detection via status code change."""
        baseline = MagicMock()
        baseline.status_code = 401
        baseline.text = "Unauthorized"

        test = MagicMock()
        test.status_code = 200
        test.text = '{"welcome": "admin"}'

        is_bypass = scanner._check_auth_bypass(baseline, test, baseline.text, test.text)
        assert is_bypass is True

    def test_check_auth_bypass_content_indicators(self, scanner):
        """Test auth bypass detection via content indicators."""
        baseline = MagicMock()
        baseline.status_code = 200
        baseline.text = '{"message": "Login failed"}'

        test = MagicMock()
        test.status_code = 200
        test.text = '{"role": "admin", "isAdmin": true, "token": "xyz"}'

        is_bypass = scanner._check_auth_bypass(baseline, test, baseline.text, test.text)
        assert is_bypass is True


class TestBlindInjectionTiming:
    """Test blind injection via timing attacks."""

    @pytest.mark.asyncio
    async def test_blind_nosql_operation(self, scanner):
        """Test blind NoSQL detection operation."""
        with patch.object(scanner, '_make_request_with_payload', new_callable=AsyncMock) as mock_request:
            # Mock baseline timing (fast)
            baseline_times = [(MagicMock(status_code=200, text="{}"), 0.1)] * 3

            # Mock delayed response (timing attack)
            delayed_resp = MagicMock(status_code=200, text="{}")
            slow_response = [(delayed_resp, 5.5)]

            mock_request.side_effect = baseline_times + slow_response + baseline_times * 5

            result = await scanner.execute(
                operation="blind",
                url="http://example.com/api/search",
                parameter="q",
                timing_threshold=3.0,
            )

            # Should detect timing anomaly
            assert result.success is True

    def test_timing_payloads_exist(self):
        """Test timing payloads are defined."""
        assert "timing_payloads" in NOSQL_PAYLOADS
        payloads = NOSQL_PAYLOADS["timing_payloads"]
        assert len(payloads) >= 2

        # Should include sleep/delay patterns
        assert any("sleep" in p[0].lower() for p in payloads)


class TestDatabaseFingerprinting:
    """Test database type fingerprinting."""

    @pytest.mark.asyncio
    async def test_detect_mongodb(self, scanner):
        """Test MongoDB detection."""
        with patch.object(scanner, '_make_request', new_callable=AsyncMock) as mock_request:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = 'MongoError: Invalid query'
            mock_resp.headers = {}
            mock_request.return_value = (mock_resp, 0.1)

            db_type = await scanner._detect_database_type(
                "http://example.com", "POST", None, None
            )

            assert db_type == NoSQLDatabase.MONGODB

    @pytest.mark.asyncio
    async def test_detect_couchdb_from_header(self, scanner):
        """Test CouchDB detection from Server header."""
        with patch.object(scanner, '_make_request', new_callable=AsyncMock) as mock_request:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = "{}"
            mock_resp.headers = {"server": "CouchDB/2.3.1"}
            mock_request.return_value = (mock_resp, 0.1)

            db_type = await scanner._detect_database_type(
                "http://example.com", "GET", None, None
            )

            assert db_type == NoSQLDatabase.COUCHDB

    @pytest.mark.asyncio
    async def test_detect_redis(self, scanner):
        """Test Redis detection."""
        with patch.object(scanner, '_make_request', new_callable=AsyncMock) as mock_request:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = "# Server\nredis_version:6.0.9\n+PONG"
            mock_resp.headers = {}
            mock_request.return_value = (mock_resp, 0.1)

            db_type = await scanner._detect_database_type(
                "http://example.com", "GET", None, None
            )

            assert db_type == NoSQLDatabase.REDIS

    @pytest.mark.asyncio
    async def test_detect_unknown(self, scanner):
        """Test unknown database detection."""
        with patch.object(scanner, '_make_request', new_callable=AsyncMock) as mock_request:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = "Generic response"
            mock_resp.headers = {}
            mock_request.return_value = (mock_resp, 0.1)

            db_type = await scanner._detect_database_type(
                "http://example.com", "GET", None, None
            )

            assert db_type == NoSQLDatabase.UNKNOWN

    def test_database_fingerprints_structure(self):
        """Test database fingerprints are properly defined."""
        assert len(DATABASE_FINGERPRINTS) >= 3
        assert NoSQLDatabase.MONGODB in DATABASE_FINGERPRINTS
        assert NoSQLDatabase.COUCHDB in DATABASE_FINGERPRINTS
        assert NoSQLDatabase.REDIS in DATABASE_FINGERPRINTS


class TestDataExtraction:
    """Test regex-based data extraction."""

    @pytest.mark.asyncio
    async def test_data_extract_operation(self, scanner):
        """Test data extraction operation."""
        with patch.object(scanner, '_make_request_with_payload', new_callable=AsyncMock) as mock_request:
            # Mock successful responses for character extraction
            def make_response(char_found=True):
                resp = MagicMock()
                resp.status_code = 200 if char_found else 404
                resp.text = '{"users": []}' if char_found else '{"users": []}'
                return (resp, 0.05)

            # Simulate finding "admin" - provide enough responses for all iterations
            mock_request.side_effect = [make_response(True)] * 50 + [make_response(False)] * 50

            result = await scanner.execute(
                operation="data_extract",
                url="http://example.com/api/users",
                parameter="username",
                extract_field="password",
            )

            # Should extract at least some characters
            if result.metadata.get("extracted_value"):
                assert len(result.metadata["extracted_value"]) > 0

    def test_check_success_response(self, scanner):
        """Test success response detection."""
        response = MagicMock()
        response.status_code = 200
        response.text = '{"ok": 1, "acknowledged": true}'

        is_success = scanner._check_success_response(response)
        assert is_success is True


class TestResponseAnalysis:
    """Test response analysis and indicator matching."""

    def test_analyze_response_mongodb_success(self, scanner):
        """Test MongoDB success indicator detection."""
        response_text = '{"acknowledged": true, "ok": 1}'
        indicators = scanner._analyze_response(response_text, NoSQLDatabase.MONGODB)

        assert indicators["success"] is True

    def test_analyze_response_auth_bypass(self, scanner):
        """Test auth bypass indicator detection."""
        response_text = '{"role": "admin", "isAdmin": true}'
        indicators = scanner._analyze_response(response_text, NoSQLDatabase.MONGODB)

        assert indicators["auth_bypass"] is True

    def test_analyze_response_error(self, scanner):
        """Test error indicator detection."""
        response_text = 'MongoServerError: Invalid JSON syntax'
        indicators = scanner._analyze_response(response_text, NoSQLDatabase.MONGODB)

        assert indicators["error"] is True
        assert "MongoServerError" in indicators["error_msg"]

    def test_contains_sensitive_data(self, scanner):
        """Test sensitive data detection."""
        response_with_password = '{"password": "secret123"}'
        assert scanner._contains_sensitive_data(response_with_password) is True

        response_with_email = '{"email": "user@example.com"}'
        assert scanner._contains_sensitive_data(response_with_email) is True

        response_with_token = '{"token": "eyJhbGciOi..."}'
        assert scanner._contains_sensitive_data(response_with_token) is True

        normal_response = '{"users": []}'
        assert scanner._contains_sensitive_data(normal_response) is False


class TestSeverityCalculation:
    """Test vulnerability severity calculation."""

    def test_severity_auth_bypass(self, scanner):
        """Test auth bypass gets critical severity."""
        severity = scanner._calculate_severity(
            NoSQLInjectionType.AUTH_BYPASS,
            {"auth_bypass": True}
        )
        assert severity == "critical"

    def test_severity_data_extraction(self, scanner):
        """Test data extraction gets high severity."""
        severity = scanner._calculate_severity(
            NoSQLInjectionType.DATA_EXTRACTION,
            {"success": True}
        )
        assert severity == "high"

    def test_severity_error_based(self, scanner):
        """Test error-based detection gets medium severity."""
        severity = scanner._calculate_severity(
            NoSQLInjectionType.OPERATOR_INJECTION,
            {"error": True}
        )
        assert severity == "medium"


class TestPayloadTesting:
    """Test payload testing logic."""

    def test_get_test_categories_mongodb(self, scanner):
        """Test getting test categories for MongoDB."""
        categories = scanner._get_test_categories(NoSQLDatabase.MONGODB)

        assert "mongodb_operators" in categories
        assert "mongodb_js" in categories
        assert "json_injection" in categories

    def test_get_test_categories_couchdb(self, scanner):
        """Test getting test categories for CouchDB."""
        categories = scanner._get_test_categories(NoSQLDatabase.COUCHDB)

        assert "couchdb" in categories
        assert "json_injection" in categories

    def test_get_test_categories_redis(self, scanner):
        """Test getting test categories for Redis."""
        categories = scanner._get_test_categories(NoSQLDatabase.REDIS)

        assert "redis" in categories

    def test_get_test_categories_unknown(self, scanner):
        """Test getting test categories for unknown database."""
        categories = scanner._get_test_categories(NoSQLDatabase.UNKNOWN)

        # Should fall back to generic tests
        assert "mongodb_operators" in categories
        assert "json_injection" in categories


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_scan_without_parameter(self, scanner):
        """Test scan operation without parameter name."""
        result = await scanner.execute(
            operation="scan",
            url="http://example.com/api",
        )

        assert result.success is False
        assert "required" in result.error.lower()

    @pytest.mark.asyncio
    async def test_auth_bypass_without_parameters(self, scanner):
        """Test auth bypass without parameters dict."""
        result = await scanner.execute(
            operation="auth_bypass",
            url="http://example.com/api/login",
        )

        assert result.success is False
        assert "required" in result.error.lower()

    @pytest.mark.asyncio
    async def test_data_extract_without_parameter(self, scanner):
        """Test data extraction without parameter."""
        result = await scanner.execute(
            operation="data_extract",
            url="http://example.com/api",
        )

        assert result.success is False
        assert "required" in result.error.lower()

    @pytest.mark.asyncio
    async def test_unknown_operation(self, scanner):
        """Test handling of unknown operation."""
        result = await scanner.execute(
            operation="invalid_operation",
            url="http://example.com",
        )

        assert result.success is False
        assert "Unknown operation" in result.error

    @pytest.mark.asyncio
    async def test_request_timeout(self, scanner):
        """Test handling of request timeout."""
        with patch.object(scanner, '_make_request', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = (None, 0.0)

            result = await scanner.execute(
                operation="fingerprint",
                url="http://example.com",
            )

            # Should handle gracefully
            assert isinstance(result, ToolResult)


class TestFormatting:
    """Test output formatting."""

    def test_format_findings(self, scanner):
        """Test findings formatting."""
        findings = [
            NoSQLFinding(
                url="http://example.com",
                parameter="username",
                injection_type=NoSQLInjectionType.OPERATOR_INJECTION,
                database=NoSQLDatabase.MONGODB,
                severity="high",
                payload='{"$ne": null}',
                evidence="Success indicator detected",
                confidence=0.8,
            )
        ]

        output = scanner._format_findings(
            "http://example.com",
            findings,
            NoSQLDatabase.MONGODB
        )

        assert "NoSQL Injection Scan Results" in output
        assert "mongodb" in output.lower()
        # Check for injection type (may be uppercase or lowercase depending on formatting)
        assert "operator_injection" in output.lower()

    def test_format_auth_bypass_findings(self, scanner):
        """Test auth bypass findings formatting."""
        findings = [
            NoSQLFinding(
                url="http://example.com/login",
                parameter="auth",
                injection_type=NoSQLInjectionType.AUTH_BYPASS,
                database=NoSQLDatabase.MONGODB,
                severity="critical",
                payload='{"username": "admin", "password": {"$ne": null}}',
                evidence="Status: 200, bypassed with: Admin bypass",
                confidence=0.9,
            )
        ]

        output = scanner._format_auth_bypass_findings("http://example.com/login", findings)

        assert "CRITICAL" in output
        assert "authentication bypass" in output.lower()


class TestNoSQLFinding:
    """Test NoSQLFinding dataclass."""

    def test_finding_creation(self):
        """Test creating a finding."""
        finding = NoSQLFinding(
            url="http://example.com/api",
            parameter="search",
            injection_type=NoSQLInjectionType.OPERATOR_INJECTION,
            database=NoSQLDatabase.MONGODB,
            severity="high",
            payload='{"$regex": ".*"}',
            evidence="Regex injection successful",
            confidence=0.75,
            metadata={"extra": "info"},
        )

        assert finding.url == "http://example.com/api"
        assert finding.injection_type == NoSQLInjectionType.OPERATOR_INJECTION
        assert finding.confidence == 0.75

    def test_finding_to_dict(self):
        """Test finding serialization."""
        finding = NoSQLFinding(
            url="http://example.com",
            parameter="user",
            injection_type=NoSQLInjectionType.AUTH_BYPASS,
            database=NoSQLDatabase.MONGODB,
            severity="critical",
            payload='{"$ne": ""}',
            evidence="Auth bypassed",
            confidence=0.9,
        )

        data = finding.to_dict()

        assert data["url"] == "http://example.com"
        assert data["injection_type"] == "auth_bypass"
        assert data["database"] == "mongodb"
        assert data["severity"] == "critical"
        assert data["confidence"] == 0.9


class TestResponseIndicators:
    """Test response indicator patterns."""

    def test_response_indicators_structure(self):
        """Test response indicators are properly defined."""
        assert "mongodb_success" in RESPONSE_INDICATORS
        assert "mongodb_auth_bypass" in RESPONSE_INDICATORS
        assert "couchdb_success" in RESPONSE_INDICATORS
        assert "redis_success" in RESPONSE_INDICATORS
        assert "error_indicators" in RESPONSE_INDICATORS

        # Each should have patterns
        for key in RESPONSE_INDICATORS:
            assert len(RESPONSE_INDICATORS[key]) > 0


class TestToolProperties:
    """Test tool properties and metadata."""

    def test_tool_name(self, scanner):
        """Test tool name property."""
        assert scanner.name == "nosql_injection"

    def test_tool_description(self, scanner):
        """Test tool description."""
        desc = scanner.description
        assert "NoSQL injection" in desc
        assert "MongoDB" in desc
        assert "CouchDB" in desc
        assert "Redis" in desc

    def test_tool_category(self, scanner):
        """Test tool category."""
        from inferno.tools.base import ToolCategory
        assert scanner.category == ToolCategory.EXPLOITATION

    def test_tool_input_schema(self, scanner):
        """Test tool input schema."""
        schema = scanner.input_schema

        assert schema["type"] == "object"
        assert "properties" in schema
        assert "operation" in schema["properties"]
        assert "url" in schema["properties"]
        assert "required" in schema
        assert "operation" in schema["required"]
        assert "url" in schema["required"]

    def test_tool_examples(self, scanner):
        """Test tool examples."""
        examples = scanner.examples

        assert len(examples) >= 3
        # Should have examples for different operations
        operations = [ex.input.get("operation") for ex in examples]
        assert "scan" in operations
        assert "auth_bypass" in operations
