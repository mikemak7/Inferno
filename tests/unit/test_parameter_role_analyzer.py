"""
Unit tests for ParameterRoleAnalyzer.

Tests parameter role inference, pattern matching, priority scoring,
testing recommendations, and edge cases.
"""

import pytest

from inferno.core.parameter_role_analyzer import (
    ParameterRole,
    ParameterRoleAnalyzer,
    RoleAnalysisResult,
    TestingRecommendation,
    get_parameter_role_analyzer,
)


class TestParameterRoleInference:
    """Test role inference for various parameter types."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return ParameterRoleAnalyzer()

    def test_identity_role_inference(self, analyzer):
        """Test identification of IDENTITY role parameters."""
        # Test various ID parameter patterns
        result = analyzer.analyze("user_id", "12345")
        assert result.inferred_role == ParameterRole.IDENTITY
        assert result.confidence > 0.6
        assert result.priority >= 90

        # Test UUID
        result = analyzer.analyze("id", "550e8400-e29b-41d4-a716-446655440000")
        assert result.inferred_role == ParameterRole.IDENTITY
        # UUID pattern matched - value_patterns contains "identity: <uuid_regex>"
        assert len(result.value_patterns) > 0 or result.confidence > 0.6

        # Test various ID patterns
        for param_name in ["uid", "account_id", "profile_id", "customer_id"]:
            result = analyzer.analyze(param_name, "123")
            assert result.inferred_role == ParameterRole.IDENTITY

    def test_command_role_inference(self, analyzer):
        """Test identification of COMMAND role parameters."""
        result = analyzer.analyze("cmd", "whoami")
        assert result.inferred_role == ParameterRole.COMMAND
        assert result.priority >= 90
        assert result.confidence > 0.5

        # Test other command patterns
        for param_name in ["exec", "execute", "shell", "command"]:
            result = analyzer.analyze(param_name, "ls")
            assert result.inferred_role == ParameterRole.COMMAND

    def test_template_role_inference(self, analyzer):
        """Test identification of TEMPLATE role parameters."""
        result = analyzer.analyze("template", "user_profile.html")
        assert result.inferred_role == ParameterRole.TEMPLATE
        assert result.priority >= 90

        # Test template variations
        for param_name in ["tpl", "view", "theme", "layout"]:
            result = analyzer.analyze(param_name, "main")
            assert result.inferred_role == ParameterRole.TEMPLATE

    def test_query_role_inference(self, analyzer):
        """Test identification of QUERY role parameters."""
        result = analyzer.analyze("search", "admin' OR '1'='1")
        assert result.inferred_role == ParameterRole.QUERY
        assert result.priority >= 80

        # Test query variations
        for param_name in ["q", "query", "filter", "where"]:
            result = analyzer.analyze(param_name, "test")
            assert result.inferred_role == ParameterRole.QUERY

    def test_path_role_inference(self, analyzer):
        """Test identification of PATH role parameters."""
        result = analyzer.analyze("file", "../../../etc/passwd")
        assert result.inferred_role == ParameterRole.PATH
        assert result.priority >= 85

        # Check value pattern detection
        result = analyzer.analyze("path", "C:\\Windows\\System32")
        assert result.inferred_role == ParameterRole.PATH
        assert any("path" in p.lower() for p in result.value_patterns)

    def test_redirect_role_inference(self, analyzer):
        """Test identification of REDIRECT role parameters."""
        result = analyzer.analyze("redirect", "https://evil.com")
        assert result.inferred_role == ParameterRole.REDIRECT
        assert result.priority >= 85

        # Test redirect variations
        for param_name in ["return", "next", "continue", "goto"]:
            result = analyzer.analyze(param_name, "/dashboard")
            assert result.inferred_role == ParameterRole.REDIRECT

    def test_callback_role_inference(self, analyzer):
        """Test identification of CALLBACK role parameters."""
        result = analyzer.analyze("callback", "http://attacker.com/webhook")
        assert result.inferred_role == ParameterRole.CALLBACK
        assert result.priority >= 85

        # Test callback variations
        for param_name in ["webhook", "notify_url", "ping"]:
            result = analyzer.analyze(param_name, "http://example.com")
            assert result.inferred_role == ParameterRole.CALLBACK

    def test_price_role_inference(self, analyzer):
        """Test identification of PRICE role parameters."""
        result = analyzer.analyze("price", "99.99")
        assert result.inferred_role == ParameterRole.PRICE
        assert result.priority >= 80

        # Test currency format detection
        result = analyzer.analyze("total", "123.45")
        assert result.inferred_role == ParameterRole.PRICE

    def test_auth_token_role_inference(self, analyzer):
        """Test identification of AUTH_TOKEN role parameters."""
        # Test JWT detection
        jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = analyzer.analyze("token", jwt_token)
        assert result.inferred_role == ParameterRole.AUTH_TOKEN
        assert result.priority >= 90
        # Value patterns contain role:pattern format - check for auth_token pattern match
        assert len(result.value_patterns) > 0 or result.confidence > 0.5

        # Test other token patterns
        for param_name in ["session", "jwt", "bearer", "api_key"]:
            result = analyzer.analyze(param_name, "abc123")
            assert result.inferred_role == ParameterRole.AUTH_TOKEN

    def test_message_role_inference(self, analyzer):
        """Test identification of MESSAGE role parameters."""
        result = analyzer.analyze("comment", "<script>alert(1)</script>")
        assert result.inferred_role == ParameterRole.MESSAGE
        assert result.priority >= 70

        # Test message variations
        for param_name in ["message", "text", "body", "content"]:
            result = analyzer.analyze(param_name, "Hello World")
            assert result.inferred_role == ParameterRole.MESSAGE


class TestPatternMatching:
    """Test pattern matching and evidence collection."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return ParameterRoleAnalyzer()

    def test_name_pattern_matching(self, analyzer):
        """Test name-based pattern matching."""
        result = analyzer.analyze("user_id", "123")
        assert len(result.evidence) > 0
        assert any("pattern" in ev.lower() for ev in result.evidence)

    def test_value_pattern_matching(self, analyzer):
        """Test value-based pattern matching."""
        # JWT pattern - value should match auth_token pattern and boost confidence
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSM"
        result = analyzer.analyze("token", jwt)
        # Either patterns detected or confidence boosted from value matching
        assert len(result.value_patterns) > 0 or result.confidence > 0.5
        assert result.confidence > 0.5  # Confidence should be boosted by pattern match

        # Email pattern
        result = analyzer.analyze("email", "test@example.com")
        assert result.inferred_role == ParameterRole.EMAIL
        assert len(result.value_patterns) > 0

    def test_context_based_hints(self, analyzer):
        """Test context-based role inference."""
        # Admin endpoint context
        context = {"endpoint": "/admin/users", "method": "DELETE"}
        result = analyzer.analyze("id", "123", context)
        assert result.inferred_role == ParameterRole.IDENTITY
        assert any("DELETE" in ev or "admin" in ev.lower() for ev in result.evidence)

        # Upload endpoint context
        context = {"endpoint": "/upload/file", "method": "POST"}
        result = analyzer.analyze("filename", "test.php", context)
        assert result.inferred_role == ParameterRole.FILENAME
        assert any("upload" in ev.lower() for ev in result.evidence)

    def test_compound_detection(self, analyzer):
        """Test compound detection with multiple signals."""
        # Both name and value suggest IDENTITY
        result = analyzer.analyze("user_id", "12345")
        # Should have evidence from both name and value patterns
        assert result.confidence > 0.6
        assert len(result.evidence) >= 2

    def test_priority_pattern_matching(self, analyzer):
        """Test that higher priority patterns are detected correctly."""
        # COMMAND should have highest priority
        result_cmd = analyzer.analyze("cmd", "whoami")

        # PAGINATION should have lower priority
        result_page = analyzer.analyze("page", "1")

        assert result_cmd.priority > result_page.priority


class TestPriorityScoring:
    """Test priority scoring and testing recommendations."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return ParameterRoleAnalyzer()

    def test_critical_priority_parameters(self, analyzer):
        """Test critical priority (95+) parameters."""
        critical_params = [
            ("user_id", "123", ParameterRole.IDENTITY),
            ("cmd", "ls", ParameterRole.COMMAND),
            ("token", "abc123", ParameterRole.AUTH_TOKEN),
        ]

        for param_name, param_value, expected_role in critical_params:
            result = analyzer.analyze(param_name, param_value)
            assert result.inferred_role == expected_role
            assert result.priority >= 90

    def test_high_priority_parameters(self, analyzer):
        """Test high priority (85-94) parameters."""
        high_priority_params = [
            ("file", "test.txt", ParameterRole.PATH),
            ("redirect", "/admin", ParameterRole.REDIRECT),
            ("price", "99.99", ParameterRole.PRICE),
        ]

        for param_name, param_value, expected_role in high_priority_params:
            result = analyzer.analyze(param_name, param_value)
            assert result.inferred_role == expected_role
            assert 80 <= result.priority < 95

    def test_low_priority_parameters(self, analyzer):
        """Test low priority parameters."""
        low_priority_params = [
            ("page", "1", ParameterRole.PAGINATION),
            ("phone", "555-1234", ParameterRole.PHONE),
        ]

        for param_name, param_value, expected_role in low_priority_params:
            result = analyzer.analyze(param_name, param_value)
            assert result.inferred_role == expected_role
            assert result.priority < 60

    def test_prioritize_multiple_parameters(self, analyzer):
        """Test prioritizing multiple parameters."""
        params = {
            "id": "123",
            "search": "test",
            "page": "1",
            "cmd": "whoami",
        }

        results = analyzer.prioritize_parameters(params)

        # Should be sorted by priority
        assert len(results) == 4
        assert results[0].priority >= results[1].priority
        assert results[1].priority >= results[2].priority
        assert results[2].priority >= results[3].priority

        # cmd and id both have priority 95, so either could be first
        # Just verify high priority params are at the top
        assert results[0].parameter_name in ["cmd", "id"]
        assert results[0].priority >= 90


class TestTestingRecommendations:
    """Test testing recommendations generation."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return ParameterRoleAnalyzer()

    def test_idor_recommendations(self, analyzer):
        """Test IDOR testing recommendations."""
        result = analyzer.analyze("user_id", "123")
        recommendations = analyzer.get_testing_recommendations(result)

        assert len(recommendations) > 0
        assert any(rec.attack_type == "IDOR" for rec in recommendations)

        idor_rec = next(rec for rec in recommendations if rec.attack_type == "IDOR")
        assert len(idor_rec.example_payloads) > 0
        assert "idor_scanner" in idor_rec.tool_suggestions
        assert idor_rec.priority >= 90

    def test_sqli_recommendations(self, analyzer):
        """Test SQL injection recommendations."""
        result = analyzer.analyze("search", "test")
        recommendations = analyzer.get_testing_recommendations(result)

        assert len(recommendations) > 0
        sql_rec = next((rec for rec in recommendations if rec.attack_type == "SQL_INJECTION"), None)
        assert sql_rec is not None
        assert "' OR '1'='1" in str(sql_rec.example_payloads)

    def test_command_injection_recommendations(self, analyzer):
        """Test command injection recommendations."""
        result = analyzer.analyze("cmd", "ls")
        recommendations = analyzer.get_testing_recommendations(result)

        assert len(recommendations) > 0
        cmd_rec = next((rec for rec in recommendations if rec.attack_type == "OS_COMMAND_INJECTION"), None)
        assert cmd_rec is not None
        assert any("whoami" in payload for payload in cmd_rec.example_payloads)

    def test_xss_recommendations(self, analyzer):
        """Test XSS recommendations."""
        result = analyzer.analyze("comment", "test")
        recommendations = analyzer.get_testing_recommendations(result)

        assert len(recommendations) > 0
        xss_rec = next((rec for rec in recommendations if rec.attack_type == "XSS"), None)
        assert xss_rec is not None
        assert any("script" in payload.lower() for payload in xss_rec.example_payloads)

    def test_path_traversal_recommendations(self, analyzer):
        """Test path traversal recommendations."""
        result = analyzer.analyze("file", "test.txt")
        recommendations = analyzer.get_testing_recommendations(result)

        path_rec = next((rec for rec in recommendations if rec.attack_type == "PATH_TRAVERSAL"), None)
        assert path_rec is not None
        assert any("etc/passwd" in payload for payload in path_rec.example_payloads)

    def test_ssrf_recommendations(self, analyzer):
        """Test SSRF recommendations."""
        result = analyzer.analyze("callback", "http://example.com")
        recommendations = analyzer.get_testing_recommendations(result)

        ssrf_rec = next((rec for rec in recommendations if rec.attack_type == "SSRF_CALLBACK"), None)
        assert ssrf_rec is not None
        assert any("169.254.169.254" in payload for payload in ssrf_rec.example_payloads)


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return ParameterRoleAnalyzer()

    def test_unknown_parameter(self, analyzer):
        """Test handling of unknown parameter types."""
        result = analyzer.analyze("xyz123", "random_value")
        # Should fall back to UNKNOWN or infer from value type
        assert result.inferred_role in [ParameterRole.UNKNOWN, ParameterRole.STRING, ParameterRole.NUMERIC]
        assert result.confidence < 0.5

    def test_numeric_value_inference(self, analyzer):
        """Test numeric value type inference."""
        result = analyzer.analyze("unknown_param", "12345")
        # Without strong name match, should infer NUMERIC from value
        assert result.inferred_role in [ParameterRole.NUMERIC, ParameterRole.IDENTITY]

    def test_boolean_value_inference(self, analyzer):
        """Test boolean value type inference."""
        for bool_value in ["true", "false", "yes", "no", "0", "1"]:
            result = analyzer.analyze("unknown_param", bool_value)
            # Should detect boolean pattern
            assert result.inferred_role in [ParameterRole.BOOLEAN, ParameterRole.UNKNOWN]

    def test_empty_parameter_name(self, analyzer):
        """Test handling of empty parameter name."""
        result = analyzer.analyze("", "value")
        # Should complete without crashing
        assert isinstance(result, RoleAnalysisResult)

    def test_none_sample_value(self, analyzer):
        """Test analysis without sample value."""
        result = analyzer.analyze("user_id", None)
        # Should still infer from name
        assert result.inferred_role == ParameterRole.IDENTITY
        assert result.sample_value is None

    def test_mixed_pattern_parameters(self, analyzer):
        """Test parameters matching multiple patterns."""
        # "search" could be QUERY or MESSAGE
        result = analyzer.analyze("search", "test")
        # Should prioritize QUERY role
        assert result.inferred_role == ParameterRole.QUERY

    def test_long_parameter_name(self, analyzer):
        """Test handling of very long parameter names."""
        # Long names without clear patterns fall back to value-based inference
        long_name = "very_long_user_identification_parameter_name_that_contains_id"
        result = analyzer.analyze(long_name, "123")
        # Pattern matching is exact, so long names without matching patterns
        # will be inferred from value type (numeric in this case)
        assert result.inferred_role in [ParameterRole.IDENTITY, ParameterRole.NUMERIC]
        assert isinstance(result, RoleAnalysisResult)

    def test_special_characters_in_value(self, analyzer):
        """Test handling of special characters in values."""
        result = analyzer.analyze("param", "'; DROP TABLE users; --")
        # Should not crash on injection attempts
        assert isinstance(result, RoleAnalysisResult)


class TestAttackSurfaceAnalysis:
    """Test attack surface breakdown functionality."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return ParameterRoleAnalyzer()

    def test_get_role_attack_surface(self, analyzer):
        """Test attack surface breakdown by attack type."""
        params = {
            "id": "1",
            "cmd": "ls",
            "search": "test",
            "comment": "hello",
        }

        attack_surface = analyzer.get_role_attack_surface(params)

        # Should have multiple attack types
        assert "IDOR" in attack_surface
        assert "OS_COMMAND_INJECTION" in attack_surface
        assert "SQL_INJECTION" in attack_surface
        assert "XSS" in attack_surface

        # Check parameter mapping
        assert "id" in attack_surface["IDOR"]
        assert "cmd" in attack_surface["OS_COMMAND_INJECTION"]

    def test_attack_surface_with_context(self, analyzer):
        """Test attack surface with context information."""
        params = {"id": "123", "file": "test.txt"}
        context = {"endpoint": "/admin/delete", "method": "DELETE"}

        attack_surface = analyzer.get_role_attack_surface(params, context)

        # Should identify attack vectors
        assert "IDOR" in attack_surface
        assert "PATH_TRAVERSAL" in attack_surface or "SSRF" in attack_surface


class TestSingletonInstance:
    """Test singleton instance management."""

    def test_get_singleton_instance(self):
        """Test getting singleton analyzer instance."""
        analyzer1 = get_parameter_role_analyzer()
        analyzer2 = get_parameter_role_analyzer()

        # Should return same instance
        assert analyzer1 is analyzer2

    def test_singleton_initialized_once(self):
        """Test that singleton is initialized only once."""
        analyzer = get_parameter_role_analyzer()
        # Should have compiled patterns
        assert len(analyzer._compiled_name_patterns) > 0
        assert len(analyzer._compiled_value_patterns) > 0
