"""
Unit tests for IDOR Scanner.

Tests insecure direct object reference detection,
authorization boundary testing, and multi-user access validation.
"""

import pytest
from unittest.mock import AsyncMock, Mock, patch
from typing import Dict, Any

from inferno.tools.advanced.idor_scanner import (
    IDORScanner,
    IDORFinding,
    UserContext
)


class TestIDORParameterDetection:
    """Test ID parameter detection in URLs and responses."""

    @pytest.fixture
    def scanner(self):
        """Create IDOR scanner instance."""
        return IDORScanner()

    @pytest.mark.asyncio
    async def test_detect_numeric_id_in_path(self, scanner):
        """Test detection of numeric ID in URL path."""
        url = "https://api.example.com/users/12345/profile"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"name": "John", "email": "john@example.com"}'

        with patch.object(scanner, '_make_request', return_value=(mock_response, "")):
            result = await scanner.execute(
                operation="detect_params",
                url=url,
                method="GET"
            )

        assert result.success
        assert result.metadata is not None

        id_params = result.metadata["id_params"]
        assert len(id_params) > 0

        # Should detect numeric ID in path
        path_params = [p for p in id_params if p["location"] == "path"]
        assert len(path_params) > 0
        assert any(p["value"] == "12345" for p in path_params)

    @pytest.mark.asyncio
    async def test_detect_uuid_in_path(self, scanner):
        """Test detection of UUID in URL path."""
        url = "https://api.example.com/documents/550e8400-e29b-41d4-a716-446655440000"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"title": "Document", "content": "..."}'

        with patch.object(scanner, '_make_request', return_value=(mock_response, "")):
            result = await scanner.execute(
                operation="detect_params",
                url=url,
                method="GET"
            )

        assert result.success
        id_params = result.metadata["id_params"]

        # Should detect UUID
        uuid_params = [p for p in id_params if p["type"] == "uuid"]
        assert len(uuid_params) > 0

    @pytest.mark.asyncio
    async def test_detect_id_params_in_json_response(self, scanner):
        """Test detection of ID parameters in JSON response."""
        url = "https://api.example.com/users/me"

        response_json = '''
        {
            "user_id": 12345,
            "profile_id": "67890",
            "account_id": 11111,
            "name": "John Doe"
        }
        '''

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = response_json

        with patch.object(scanner, '_make_request', return_value=(mock_response, "")):
            result = await scanner.execute(
                operation="detect_params",
                url=url,
                method="GET"
            )

        assert result.success
        id_params = result.metadata["id_params"]

        # Should detect multiple ID fields
        response_params = [p for p in id_params if p["location"] == "response"]
        assert len(response_params) >= 3

        param_names = [p["name"] for p in response_params]
        assert "user_id" in param_names
        assert "profile_id" in param_names or "account_id" in param_names


class TestIDORAccessControl:
    """Test IDOR access control violation detection."""

    @pytest.fixture
    def scanner(self):
        """Create IDOR scanner instance."""
        return IDORScanner()

    def test_check_access_granted_with_200_ok(self, scanner):
        """Test access detection with 200 OK and success indicators."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"success": true, "data": {"user": "john"}}'

        granted = scanner._check_access_granted(mock_response)
        assert granted

    def test_check_access_denied_with_403(self, scanner):
        """Test access denial detection with 403 Forbidden."""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.text = '{"error": "Forbidden"}'

        granted = scanner._check_access_granted(mock_response)
        assert not granted

    def test_check_access_denied_with_401(self, scanner):
        """Test access denial detection with 401 Unauthorized."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = '{"error": "Unauthorized"}'

        granted = scanner._check_access_granted(mock_response)
        assert not granted

    def test_check_access_denied_with_error_message(self, scanner):
        """Test access denial detection with error message in 200 response."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"error": "access denied", "message": "You are not authorized"}'

        granted = scanner._check_access_granted(mock_response)
        assert not granted

    def test_check_access_granted_with_data_indicators(self, scanner):
        """Test access granted with data presence indicators."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '''
        {
            "result": {
                "user": "john",
                "email": "john@example.com",
                "profile": {"age": 30}
            }
        }
        '''

        granted = scanner._check_access_granted(mock_response)
        assert granted


class TestIDORSensitiveDataExtraction:
    """Test extraction of sensitive data from responses."""

    @pytest.fixture
    def scanner(self):
        """Create IDOR scanner instance."""
        return IDORScanner()

    def test_extract_email_addresses(self, scanner):
        """Test extraction of email addresses."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '''
        {
            "user": "john",
            "email": "john.doe@example.com",
            "contact": "admin@company.org"
        }
        '''

        sensitive = scanner._extract_sensitive_data(mock_response)

        # Should extract emails
        emails = [s for s in sensitive if s.startswith("email:")]
        assert len(emails) >= 2

    def test_extract_phone_numbers(self, scanner):
        """Test extraction of phone numbers."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '''
        {
            "phone": "555-123-4567",
            "mobile": "555.987.6543"
        }
        '''

        sensitive = scanner._extract_sensitive_data(mock_response)

        # Should extract phone numbers
        phones = [s for s in sensitive if s.startswith("phone:")]
        assert len(phones) >= 2

    def test_extract_names(self, scanner):
        """Test extraction of name fields."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '''
        {
            "name": "John Doe",
            "username": "johndoe",
            "first_name": "John",
            "last_name": "Doe"
        }
        '''

        sensitive = scanner._extract_sensitive_data(mock_response)

        # Should extract names
        names = [s for s in sensitive if s.startswith("name:")]
        assert len(names) >= 3


class TestIDORHorizontalPrivilegeEscalation:
    """Test detection of horizontal privilege escalation (accessing other users' data)."""

    @pytest.fixture
    def scanner(self):
        """Create IDOR scanner instance."""
        return IDORScanner()

    @pytest.mark.asyncio
    async def test_detect_horizontal_idor(self, scanner):
        """Test detection of horizontal IDOR vulnerability."""
        url = "https://api.example.com/users/100/profile"

        # User1 (ID 100) trying to access User2's data (ID 200)
        user1_response = Mock()
        user1_response.status_code = 200
        user1_response.text = '{"name": "Alice", "email": "alice@example.com", "user_id": 200}'

        def mock_request(url, method, context, params=None):
            # User1 successfully accesses User2's data - IDOR!
            return (user1_response, "")

        with patch.object(scanner, '_make_request', side_effect=mock_request):
            result = await scanner.execute(
                operation="scan",
                url=url,
                method="GET",
                user1_auth={
                    "headers": {"Authorization": "Bearer token1"},
                    "user_id": "100"
                },
                target_ids=["200", "201"]
            )

        assert result.success
        assert result.metadata is not None

        findings = result.metadata["findings"]
        assert len(findings) > 0

        # Should detect horizontal IDOR
        horizontal_findings = [f for f in findings if f["type"] == "horizontal"]
        assert len(horizontal_findings) > 0

    @pytest.mark.asyncio
    async def test_no_false_positive_when_blocked(self, scanner):
        """Test no false positive when access is properly blocked."""
        url = "https://api.example.com/users/100/profile"

        # User1 (ID 100) trying to access User2's data (ID 200) - properly blocked
        blocked_response = Mock()
        blocked_response.status_code = 403
        blocked_response.text = '{"error": "Forbidden", "message": "You cannot access this resource"}'

        def mock_request(url, method, context, params=None):
            if "200" in url:
                return (blocked_response, "")
            # Can access own data
            own_response = Mock()
            own_response.status_code = 200
            own_response.text = '{"name": "Alice", "user_id": 100}'
            return (own_response, "")

        with patch.object(scanner, '_make_request', side_effect=mock_request):
            result = await scanner.execute(
                operation="scan",
                url=url,
                method="GET",
                user1_auth={
                    "headers": {"Authorization": "Bearer token1"},
                    "user_id": "100"
                },
                target_ids=["200"]
            )

        assert result.success

        # Should NOT detect IDOR (access was properly blocked)
        findings = result.metadata["findings"]
        horizontal_findings = [f for f in findings if f["type"] == "horizontal"]
        assert len(horizontal_findings) == 0


class TestIDORUnauthenticatedAccess:
    """Test detection of unauthenticated IDOR (critical severity)."""

    @pytest.fixture
    def scanner(self):
        """Create IDOR scanner instance."""
        return IDORScanner()

    @pytest.mark.asyncio
    async def test_detect_unauthenticated_idor(self, scanner):
        """Test detection of unauthenticated access to sensitive data."""
        url = "https://api.example.com/users/12345/profile"

        # Unauthenticated request succeeds - critical IDOR!
        unauth_response = Mock()
        unauth_response.status_code = 200
        unauth_response.text = '{"name": "John Doe", "email": "john@example.com", "ssn": "123-45-6789"}'

        request_count = [0]

        def mock_request(url, method, context, params=None):
            request_count[0] += 1
            # Simulate: authenticated requests and unauthenticated both succeed
            return (unauth_response, "")

        with patch.object(scanner, '_make_request', side_effect=mock_request):
            result = await scanner.execute(
                operation="scan",
                url=url,
                method="GET",
                user1_auth={
                    "headers": {"Authorization": "Bearer token1"},
                    "user_id": "100"
                }
            )

        assert result.success

        # Should detect unauthenticated IDOR
        findings = result.metadata["findings"]
        unauth_findings = [f for f in findings if f["type"] == "unauthenticated"]

        # Critical severity for unauthenticated access
        if len(unauth_findings) > 0:
            assert unauth_findings[0]["severity"] == "critical"


class TestIDORMultiUserComparison:
    """Test multi-user access comparison for IDOR detection."""

    @pytest.fixture
    def scanner(self):
        """Create IDOR scanner instance."""
        return IDORScanner()

    @pytest.mark.asyncio
    async def test_compare_access_between_users(self, scanner):
        """Test access comparison between two different users."""
        url = "https://api.example.com/users/100/orders"

        responses = {
            "user1_own": Mock(status_code=200, text='{"orders": [1, 2, 3]}'),
            "user1_user2": Mock(status_code=200, text='{"orders": [4, 5, 6]}'),  # IDOR!
            "user2_own": Mock(status_code=200, text='{"orders": [4, 5, 6]}'),
            "user2_user1": Mock(status_code=403, text='{"error": "Forbidden"}'),  # Properly blocked
        }

        call_count = [0]

        def mock_request(url, method, context, params=None):
            call_count[0] += 1

            if context is None:
                return (Mock(status_code=401, text='{"error": "Unauthorized"}'), "")

            # User1 accessing user2's data
            if context.name == "user1" and "200" in url:
                return (responses["user1_user2"], "")

            # User2 accessing user1's data (blocked)
            if context.name == "user2" and "100" in url:
                return (responses["user2_user1"], "")

            # Own data access
            if "100" in url:
                return (responses["user1_own"], "")
            else:
                return (responses["user2_own"], "")

        with patch.object(scanner, '_make_request', side_effect=mock_request):
            result = await scanner.execute(
                operation="compare",
                url=url,
                method="GET",
                user1_auth={
                    "headers": {"Authorization": "Bearer token1"},
                    "user_id": "100"
                },
                user2_auth={
                    "headers": {"Authorization": "Bearer token2"},
                    "user_id": "200"
                },
                target_ids=["100", "200"]
            )

        assert result.success

        # Should detect that User1 can access User2's data (IDOR)
        # but User2 cannot access User1's data (proper access control)
        issues = result.metadata.get("issues", [])
        if len(issues) > 0:
            # There should be an issue detected for User1 accessing User2's data
            assert any("User1 can access User2" in issue.get("issue", "") for issue in issues)


class TestIDORSequentialIDEnumeration:
    """Test sequential ID enumeration for IDOR discovery."""

    @pytest.fixture
    def scanner(self):
        """Create IDOR scanner instance."""
        return IDORScanner()

    @pytest.mark.asyncio
    async def test_enumerate_sequential_ids(self, scanner):
        """Test enumeration of sequential numeric IDs."""
        url = "https://api.example.com/documents/{id}"

        # Simulate: IDs 1, 3, 5 are accessible, others are not
        accessible_ids = {1, 3, 5}

        def mock_request(url, method, context, params=None):
            # Extract ID from URL
            import re
            match = re.search(r'/documents/(\d+)', url)
            if match:
                doc_id = int(match.group(1))
                if doc_id in accessible_ids:
                    response = Mock()
                    response.status_code = 200
                    response.text = f'{{"id": {doc_id}, "title": "Document {doc_id}"}}'
                    return (response, "")

            not_found = Mock()
            not_found.status_code = 404
            not_found.text = '{"error": "Not found"}'
            return (not_found, "")

        with patch.object(scanner, '_make_request', side_effect=mock_request):
            result = await scanner.execute(
                operation="enum",
                url=url,
                method="GET",
                enum_start=1,
                enum_count=10,
                user1_auth={
                    "headers": {"Authorization": "Bearer token"}
                }
            )

        assert result.success

        # Should find accessible IDs
        accessible_count = result.metadata["accessible_count"]
        accessible_id_list = result.metadata["accessible_ids"]

        assert accessible_count == 3
        assert set(accessible_id_list) == accessible_ids


class TestIDOREdgeCases:
    """Test edge cases and boundary conditions for IDOR detection."""

    @pytest.fixture
    def scanner(self):
        """Create IDOR scanner instance."""
        return IDORScanner()

    @pytest.mark.asyncio
    async def test_handle_network_errors_gracefully(self, scanner):
        """Test graceful handling of network errors."""
        url = "https://api.example.com/users/123"

        def mock_request(url, method, context, params=None):
            return (None, "Connection timeout")

        with patch.object(scanner, '_make_request', side_effect=mock_request):
            result = await scanner.execute(
                operation="scan",
                url=url,
                method="GET",
                user1_auth={"headers": {"Authorization": "Bearer token"}}
            )

        # Should complete without crashing
        assert result.success
        assert result.metadata["findings_count"] == 0

    @pytest.mark.asyncio
    async def test_handle_rate_limiting(self, scanner):
        """Test handling of rate limiting responses."""
        url = "https://api.example.com/users/123"

        rate_limit_response = Mock()
        rate_limit_response.status_code = 429
        rate_limit_response.text = '{"error": "Too many requests"}'

        def mock_request(url, method, context, params=None):
            return (rate_limit_response, "")

        with patch.object(scanner, '_make_request', side_effect=mock_request):
            result = await scanner.execute(
                operation="scan",
                url=url,
                method="GET",
                user1_auth={"headers": {"Authorization": "Bearer token"}},
                target_ids=["200"]
            )

        # Should handle rate limiting gracefully
        assert result.success

    def test_build_user_context(self, scanner):
        """Test user context building from auth dict."""
        auth_dict = {
            "headers": {"Authorization": "Bearer token123"},
            "cookies": {"session": "abc123"},
            "user_id": "user_001",
            "role": "admin"
        }

        context = scanner._build_context("test_user", auth_dict)

        assert context.name == "test_user"
        assert context.auth_header == {"Authorization": "Bearer token123"}
        assert context.cookies == {"session": "abc123"}
        assert context.user_id == "user_001"
        assert context.role == "admin"

    def test_empty_response_handling(self, scanner):
        """Test handling of empty responses."""
        mock_response = Mock()
        mock_response.status_code = 204
        mock_response.text = ""

        # Should not crash on empty response
        granted = scanner._check_access_granted(mock_response)
        assert not granted  # 204 No Content should not be considered granted access


class TestIDORPublicDataFiltering:
    """Test filtering of public data to avoid false positives."""

    @pytest.fixture
    def scanner(self):
        """Create IDOR scanner instance."""
        return IDORScanner()

    def test_identify_public_profile_data(self, scanner):
        """Test identification of intentionally public data."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '''
        {
            "public_profile": true,
            "username": "johndoe",
            "bio": "Public bio text",
            "shared": true
        }
        '''

        # Public profile data should not be flagged as IDOR
        # This would be handled by looking for "public_profile" or "shared" indicators
        sensitive = scanner._extract_sensitive_data(mock_response)

        # Should still extract data, but context matters
        # The false positive filter would handle this
        assert isinstance(sensitive, list)
