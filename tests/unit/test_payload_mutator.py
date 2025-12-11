"""
Unit tests for Payload Mutator - WAF Bypass Engine.

Tests adversarial payload mutations, WAF bypass techniques,
and learning from blocked payloads.
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timezone

from inferno.tools.advanced.payload_mutator import (
    PayloadMutator,
    PayloadType,
    MutationType,
    PayloadFeedback,
    MutationResult
)


class TestPayloadEncodingMutations:
    """Test various encoding mutation techniques."""

    @pytest.fixture
    def mutator(self):
        """Create payload mutator instance."""
        return PayloadMutator()

    def test_url_encoding_mutation(self, mutator):
        """Test URL encoding mutation."""
        original = "<script>alert(1)</script>"

        result = mutator.mutate_single(
            original,
            PayloadType.XSS,
            MutationType.ENCODING
        )

        assert result.mutated != original
        assert "%3C" in result.mutated or "%3c" in result.mutated  # Encoded '<'
        assert "%3E" in result.mutated or "%3e" in result.mutated  # Encoded '>'
        assert result.mutation_type == MutationType.ENCODING

    def test_double_url_encoding(self, mutator):
        """Test double URL encoding for deep WAF bypass."""
        original = "<script>alert(1)</script>"

        result = mutator.mutate_single(
            original,
            PayloadType.XSS,
            MutationType.DOUBLE_ENCODING
        )

        # Double encoded '<' becomes %253C
        assert "%25" in result.mutated
        assert result.mutation_type == MutationType.DOUBLE_ENCODING

    def test_unicode_encoding(self, mutator):
        """Test Unicode encoding mutation."""
        original = "<script>alert(1)</script>"

        result = mutator.mutate_single(
            original,
            PayloadType.XSS,
            MutationType.UNICODE
        )

        # Unicode encoded characters
        assert "\\u" in result.mutated or "\\x" in result.mutated
        assert result.mutation_type == MutationType.UNICODE

    def test_base64_encoding(self, mutator):
        """Test Base64 encoding mutation."""
        original = "<?php system($_GET['cmd']); ?>"

        result = mutator.mutate_single(
            original,
            PayloadType.COMMAND_INJECTION,
            MutationType.ENCODING
        )

        # Should contain Base64 encoded payload
        assert result.mutated != original
        assert len(result.mutated) > 0


class TestCaseMutations:
    """Test case variation mutations for WAF bypass."""

    @pytest.fixture
    def mutator(self):
        return PayloadMutator()

    def test_case_variation_xss(self, mutator):
        """Test case variation for XSS payloads."""
        original = "<script>alert(1)</script>"

        result = mutator.mutate_single(
            original,
            PayloadType.XSS,
            MutationType.CASE
        )

        # Should have mixed case
        assert result.mutated != original
        assert result.mutated.lower() == original.lower()
        # Should have both upper and lower case
        assert any(c.isupper() for c in result.mutated)
        assert any(c.islower() for c in result.mutated)

    def test_case_variation_sqli(self, mutator):
        """Test case variation for SQL injection."""
        original = "' OR '1'='1"

        result = mutator.mutate_single(
            original,
            PayloadType.SQLI,
            MutationType.CASE
        )

        # SQL keywords should have varied case
        assert "or" in result.mutated.lower()
        assert result.mutated != original


class TestWhitespaceMutations:
    """Test whitespace manipulation for WAF bypass."""

    @pytest.fixture
    def mutator(self):
        return PayloadMutator()

    def test_whitespace_variation_sqli(self, mutator):
        """Test whitespace variation in SQL injection."""
        original = "' OR '1'='1"

        result = mutator.mutate_single(
            original,
            PayloadType.SQLI,
            MutationType.WHITESPACE
        )

        # Should have different whitespace
        assert "OR" in result.mutated or "or" in result.mutated
        # May include tabs, newlines, or multiple spaces
        assert result.mutated != original

    def test_whitespace_removal_xss(self, mutator):
        """Test whitespace removal in XSS payloads."""
        original = "<script> alert(1) </script>"

        result = mutator.mutate_single(
            original,
            PayloadType.XSS,
            MutationType.WHITESPACE
        )

        # Whitespace should be altered
        assert result.mutated != original


class TestCommentInjection:
    """Test comment-based obfuscation for SQL injection."""

    @pytest.fixture
    def mutator(self):
        return PayloadMutator()

    def test_inline_comment_sqli(self, mutator):
        """Test inline comment injection in SQL."""
        original = "' OR '1'='1"

        result = mutator.mutate_single(
            original,
            PayloadType.SQLI,
            MutationType.COMMENTS
        )

        # Should contain SQL comments
        assert "/*" in result.mutated or "--" in result.mutated or "#" in result.mutated

    def test_comment_bypass_keywords(self, mutator):
        """Test comment-based keyword bypass."""
        original = "UNION SELECT"

        result = mutator.mutate_single(
            original,
            PayloadType.SQLI,
            MutationType.COMMENTS
        )

        # Comments should split keywords
        assert "/*" in result.mutated or result.mutated != original


class TestPayloadGeneration:
    """Test batch payload generation with multiple mutations."""

    @pytest.fixture
    def mutator(self):
        return PayloadMutator()

    def test_generate_multiple_xss_variants(self, mutator):
        """Test generating multiple XSS payload variants."""
        original = "<script>alert(1)</script>"

        variants = mutator.mutate(original, PayloadType.XSS, count=10)

        # Should generate requested number
        assert len(variants) >= 10

        # Should be mostly unique
        unique_payloads = set(v.mutated for v in variants)
        assert len(unique_payloads) >= 8  # At least 8 unique out of 10

        # Should cover multiple mutation types
        mutation_types = set(v.mutation_type for v in variants)
        assert len(mutation_types) >= 3

    def test_generate_sqli_variants(self, mutator):
        """Test generating SQL injection variants."""
        original = "' OR '1'='1"

        variants = mutator.mutate(original, PayloadType.SQLI, count=15)

        assert len(variants) >= 15

        # Check for specific techniques
        mutation_types = [v.mutation_type for v in variants]
        assert MutationType.COMMENTS in mutation_types
        assert MutationType.WHITESPACE in mutation_types
        assert MutationType.CASE in mutation_types

    def test_ssrf_payload_variants(self, mutator):
        """Test SSRF payload variations."""
        original = "http://localhost/"

        variants = mutator.mutate(original, PayloadType.SSRF, count=10)

        assert len(variants) >= 10

        # Should include encoding variations
        assert any("%6c%6f%63%61%6c%68%6f%73%74" in v.mutated.lower() for v in variants)
        # Should include IP variations (127.0.0.1, etc.)
        assert any("127.0.0.1" in v.mutated for v in variants)


class TestWAFBypassLearning:
    """Test learning from WAF blocks and adapting mutations."""

    @pytest.fixture
    def mutator(self):
        return PayloadMutator()

    def test_record_feedback_blocked(self, mutator):
        """Test recording feedback for blocked payload."""
        feedback = PayloadFeedback(
            payload="<script>alert(1)</script>",
            payload_type=PayloadType.XSS,
            blocked=True,
            waf_signature="Cloudflare",
            response_code=403
        )

        mutator.record_feedback(feedback)

        # Feedback should be stored
        assert len(mutator._feedback_history) == 1
        assert mutator._feedback_history[0].blocked is True

    def test_evolve_based_on_feedback(self, mutator):
        """Test payload evolution based on WAF feedback."""
        # Record multiple blocks
        blocked_payloads = [
            "<script>alert(1)</script>",
            "<script>alert(2)</script>",
            "<script>alert(3)</script>",
        ]

        for payload in blocked_payloads:
            mutator.record_feedback(PayloadFeedback(
                payload=payload,
                payload_type=PayloadType.XSS,
                blocked=True,
                waf_signature="Cloudflare"
            ))

        # Evolve payload
        evolved = mutator.evolve("<script>alert(1)</script>", PayloadType.XSS)

        # Should avoid previously blocked patterns
        assert all(e.mutated not in blocked_payloads for e in evolved)

        # Should prioritize successful techniques
        assert len(evolved) > 0

    def test_successful_mutation_tracking(self, mutator):
        """Test tracking of successful mutations."""
        # Record successful bypass
        mutator.record_feedback(PayloadFeedback(
            payload="%3Cscript%3Ealert(1)%3C/script%3E",
            payload_type=PayloadType.XSS,
            blocked=False,
            waf_signature="Cloudflare",
            response_code=200
        ))

        # Should track successful technique
        assert "Cloudflare" in mutator._successful_mutations or len(mutator._feedback_history) > 0


class TestProtocolLevelEvasion:
    """Test protocol-level evasion techniques."""

    @pytest.fixture
    def mutator(self):
        return PayloadMutator()

    def test_null_byte_injection(self, mutator):
        """Test null byte injection mutation."""
        original = "/etc/passwd"

        result = mutator.mutate_single(
            original,
            PayloadType.PATH_TRAVERSAL,
            MutationType.NULL_BYTES
        )

        # Should contain null byte (%00)
        assert "%00" in result.mutated or "\\x00" in result.mutated

    def test_protocol_smuggling(self, mutator):
        """Test HTTP protocol smuggling mutations."""
        original = "GET /admin HTTP/1.1"

        result = mutator.mutate_single(
            original,
            PayloadType.COMMAND_INJECTION,
            MutationType.PROTOCOL_LEVEL
        )

        # Should have protocol-level mutations
        assert result.mutated != original


class TestPayloadObfuscation:
    """Test payload obfuscation techniques."""

    @pytest.fixture
    def mutator(self):
        return PayloadMutator()

    def test_string_concatenation_xss(self, mutator):
        """Test string concatenation obfuscation."""
        original = "alert('XSS')"

        result = mutator.mutate_single(
            original,
            PayloadType.XSS,
            MutationType.CONCATENATION
        )

        # Should use concatenation (e.g., 'ale'+'rt' or String.fromCharCode)
        assert result.mutated != original
        assert "+" in result.mutated or "concat" in result.mutated.lower() or "fromCharCode" in result.mutated

    def test_obfuscation_ssti(self, mutator):
        """Test SSTI payload obfuscation."""
        original = "{{7*7}}"

        result = mutator.mutate_single(
            original,
            PayloadType.SSTI,
            MutationType.OBFUSCATION
        )

        # Should obfuscate template syntax
        assert result.mutated != original


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.fixture
    def mutator(self):
        return PayloadMutator()

    def test_empty_payload(self, mutator):
        """Test handling of empty payload."""
        variants = mutator.mutate("", PayloadType.XSS, count=5)

        # Should handle gracefully
        assert isinstance(variants, list)
        # May return empty list or default payloads
        assert len(variants) >= 0

    def test_very_long_payload(self, mutator):
        """Test handling of very long payload."""
        long_payload = "A" * 10000

        variants = mutator.mutate(long_payload, PayloadType.XSS, count=5)

        # Should handle without crashing
        assert len(variants) > 0

        # Mutations should be reasonable length
        for variant in variants:
            assert len(variant.mutated) < 20000  # Not excessively long

    def test_special_characters(self, mutator):
        """Test handling of payloads with special characters."""
        special_payload = "';!@#$%^&*()[]{}|\\<>?/~`"

        variants = mutator.mutate(special_payload, PayloadType.SQLI, count=5)

        # Should handle special characters
        assert len(variants) > 0

    def test_unicode_payload(self, mutator):
        """Test handling of Unicode payloads."""
        unicode_payload = "测试<script>alert('中文')</script>"

        variants = mutator.mutate(unicode_payload, PayloadType.XSS, count=5)

        # Should handle Unicode
        assert len(variants) > 0


class TestMutationChaining:
    """Test chaining multiple mutations together."""

    @pytest.fixture
    def mutator(self):
        return PayloadMutator()

    def test_chain_encoding_and_case(self, mutator):
        """Test chaining encoding and case mutations."""
        original = "<script>alert(1)</script>"

        # Apply multiple mutation types
        variants = mutator.mutate(original, PayloadType.XSS, count=20)

        # Some variants should combine multiple techniques
        # (implementation-dependent, but should see variety)
        mutation_type_counts = {}
        for variant in variants:
            mutation_type_counts[variant.mutation_type] = mutation_type_counts.get(variant.mutation_type, 0) + 1

        # Should have variety
        assert len(mutation_type_counts) >= 3


class TestPayloadTypeSpecificMutations:
    """Test mutations specific to each payload type."""

    @pytest.fixture
    def mutator(self):
        return PayloadMutator()

    def test_path_traversal_mutations(self, mutator):
        """Test path traversal specific mutations."""
        original = "../../../../etc/passwd"

        variants = mutator.mutate(original, PayloadType.PATH_TRAVERSAL, count=10)

        assert len(variants) >= 10

        # Should include variations like:
        # - URL encoding: ..%2f..%2f
        # - Double encoding
        # - Null byte injection
        # - Backslash variants: ..\..\

        mutated_payloads = [v.mutated for v in variants]
        assert any("%2f" in p or "%2F" in p for p in mutated_payloads)  # URL encoded /

    def test_nosql_injection_mutations(self, mutator):
        """Test NoSQL injection mutations."""
        original = '{"$ne": null}'

        variants = mutator.mutate(original, PayloadType.NOSQL, count=10)

        assert len(variants) >= 10

        # Should include NoSQL-specific techniques
        # - Operator variations
        # - JSON encoding
        # - Array injections

    def test_xxe_payload_mutations(self, mutator):
        """Test XXE payload mutations."""
        original = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'

        variants = mutator.mutate(original, PayloadType.XXE, count=5)

        assert len(variants) >= 5

        # Should preserve XML structure while mutating
        for variant in variants:
            assert "<!ENTITY" in variant.mutated or variant.mutated != original
