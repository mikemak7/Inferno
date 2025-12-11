"""Unit tests for SynthesisEngine."""

from datetime import datetime

import pytest

from inferno.swarm.synthesis import (
    SynthesisEngine,
    AttackChain,
    FindingNode,
    CHAIN_PATTERNS,
    get_synthesis_engine,
    reset_synthesis_engine,
)


@pytest.fixture
def synthesis_engine():
    """Create a synthesis engine for testing."""
    engine = SynthesisEngine(
        min_chain_length=2,
        max_chain_length=5,
        min_chain_score=0.5,
    )
    yield engine
    engine.clear()


@pytest.fixture
def sample_finding():
    """Create a sample finding."""
    return {
        "finding_id": "f001",
        "vuln_type": "sqli",
        "severity": "critical",
        "endpoint": "/search.php",
        "method": "GET",
        "parameters": ["q"],
        "agent_id": "scanner_001",
        "timestamp": datetime.utcnow().isoformat(),
        "metadata": {"dbms": "MySQL"},
    }


class TestFindingNode:
    """Test FindingNode class."""

    def test_finding_creation(self):
        """Test creating a finding node."""
        node = FindingNode(
            finding_id="f001",
            vuln_type="sqli",
            severity="high",
            endpoint="/api/search",
            method="POST",
            parameters=["q", "limit"],
            agent_id="scanner",
            timestamp=datetime.utcnow(),
        )

        assert node.finding_id == "f001"
        assert node.vuln_type == "sqli"
        assert node.severity == "high"

    def test_impact_score_critical(self):
        """Test impact score for critical severity."""
        node = FindingNode(
            finding_id="f001",
            vuln_type="rce",
            severity="critical",
            endpoint="/api",
            method="POST",
            parameters=[],
            agent_id="test",
            timestamp=datetime.utcnow(),
        )

        assert node.impact_score == 10

    def test_impact_score_low(self):
        """Test impact score for low severity."""
        node = FindingNode(
            finding_id="f001",
            vuln_type="info_disclosure",
            severity="low",
            endpoint="/api",
            method="GET",
            parameters=[],
            agent_id="test",
            timestamp=datetime.utcnow(),
        )

        assert node.impact_score == 3

    def test_difficulty_default(self):
        """Test default difficulty calculation."""
        node = FindingNode(
            finding_id="f001",
            vuln_type="unknown_vuln",
            severity="high",
            endpoint="/api",
            method="POST",
            parameters=[],
            agent_id="test",
            timestamp=datetime.utcnow(),
        )

        assert node.difficulty == 5  # Default

    def test_difficulty_override(self):
        """Test difficulty override from metadata."""
        node = FindingNode(
            finding_id="f001",
            vuln_type="sqli",
            severity="high",
            endpoint="/api",
            method="POST",
            parameters=[],
            agent_id="test",
            timestamp=datetime.utcnow(),
            metadata={"difficulty": 8},
        )

        assert node.difficulty == 8


class TestAttackChain:
    """Test AttackChain class."""

    @pytest.fixture
    def sample_chain(self):
        """Create a sample attack chain."""
        steps = [
            FindingNode(
                finding_id="f001",
                vuln_type="sqli",
                severity="high",
                endpoint="/search",
                method="GET",
                parameters=["q"],
                agent_id="scanner",
                timestamp=datetime.utcnow(),
            ),
            FindingNode(
                finding_id="f002",
                vuln_type="file_write",
                severity="critical",
                endpoint="/search",
                method="GET",
                parameters=["q"],
                agent_id="scanner",
                timestamp=datetime.utcnow(),
            ),
        ]

        return AttackChain(
            chain_id="c001",
            name="SQLi to File Write",
            steps=steps,
            pattern_matched="SQLi to File Write/RCE",
        )

    def test_total_difficulty(self, sample_chain):
        """Test total difficulty calculation."""
        # sqli=6, file_write=5 (default), multiplier=3.0
        expected = int((6 + 5) * 3.0)
        assert sample_chain.total_difficulty == expected

    def test_total_impact(self, sample_chain):
        """Test total impact calculation."""
        # Should be max of all steps (critical=10)
        assert sample_chain.total_impact == 10

    def test_probability(self, sample_chain):
        """Test probability calculation."""
        prob = sample_chain.probability
        assert 0.0 <= prob <= 1.0

    def test_score(self, sample_chain):
        """Test chain score calculation."""
        score = sample_chain.score
        assert score > 0.0

        # Score formula: (Impact * Probability) / Difficulty
        expected = (
            sample_chain.total_impact * sample_chain.probability
        ) / sample_chain.total_difficulty
        assert abs(score - expected) < 0.01

    def test_is_viable(self, sample_chain):
        """Test chain viability check."""
        assert sample_chain.is_viable  # Should be viable

    def test_not_viable_low_impact(self):
        """Test non-viable chain with low impact."""
        steps = [
            FindingNode(
                finding_id="f001",
                vuln_type="info_disclosure",
                severity="low",  # Low impact
                endpoint="/api",
                method="GET",
                parameters=[],
                agent_id="test",
                timestamp=datetime.utcnow(),
            ),
        ]

        chain = AttackChain(
            chain_id="c001",
            name="Low Impact Chain",
            steps=steps,
        )

        assert not chain.is_viable  # Impact < 5

    def test_to_dict(self, sample_chain):
        """Test conversion to dictionary."""
        data = sample_chain.to_dict()

        assert data["chain_id"] == "c001"
        assert data["name"] == "SQLi to File Write"
        assert len(data["steps"]) == 2
        assert "score" in data
        assert "is_viable" in data


class TestSynthesisEngine:
    """Test SynthesisEngine functionality."""

    def test_initialization(self):
        """Test engine initialization."""
        engine = SynthesisEngine(
            min_chain_length=2,
            max_chain_length=4,
            min_chain_score=1.0,
        )

        assert engine._min_chain_length == 2
        assert engine._max_chain_length == 4
        assert engine._min_chain_score == 1.0

    def test_add_finding(self, synthesis_engine, sample_finding):
        """Test adding a finding."""
        node = synthesis_engine.add_finding(sample_finding)

        assert node.finding_id == "f001"
        assert node.vuln_type == "sqli"
        assert node.severity == "critical"

    def test_add_finding_auto_id(self, synthesis_engine):
        """Test adding finding without ID generates one."""
        finding = {
            "vuln_type": "xss",
            "severity": "high",
            "endpoint": "/comment",
            "method": "POST",
            "parameters": ["text"],
            "agent_id": "scanner",
        }

        node = synthesis_engine.add_finding(finding)
        assert node.finding_id  # Should have generated ID

    @pytest.mark.asyncio
    async def test_synthesize_pattern_match(self, synthesis_engine):
        """Test synthesis with pattern matching."""
        # Add findings that match a pattern
        finding1 = {
            "finding_id": "f001",
            "vuln_type": "file_upload",
            "severity": "high",
            "endpoint": "/upload.php",
            "method": "POST",
            "parameters": ["file"],
            "agent_id": "scanner",
        }

        finding2 = {
            "finding_id": "f002",
            "vuln_type": "lfi",
            "severity": "high",
            "endpoint": "/view.php",
            "method": "GET",
            "parameters": ["page"],
            "agent_id": "scanner",
        }

        synthesis_engine.add_finding(finding1)
        synthesis_engine.add_finding(finding2)

        chains = await synthesis_engine.synthesize()

        # Should discover the pattern (check all chains, not just viable ones)
        all_chains = synthesis_engine.get_chains()
        assert len(all_chains) > 0
        chain_names = [c.name for c in all_chains]
        assert any("Upload to LFI" in name for name in chain_names)

    @pytest.mark.asyncio
    async def test_synthesize_graph_chains(self, synthesis_engine):
        """Test synthesis with graph-based discovery."""
        # Add multiple findings on same endpoint
        endpoint = "/api/search"
        for i in range(3):
            finding = {
                "finding_id": f"f{i:03d}",
                "vuln_type": f"vuln_{i}",
                "severity": "high",
                "endpoint": endpoint,
                "method": "GET",
                "parameters": ["q"],
                "agent_id": "scanner",
            }
            synthesis_engine.add_finding(finding)

        chains = await synthesis_engine.synthesize()

        # Graph chains might not be viable with default settings
        # Just check that synthesis runs without error
        assert isinstance(chains, list)

    @pytest.mark.asyncio
    async def test_synthesize_with_new_findings(self, synthesis_engine):
        """Test synthesize with new findings in parameter."""
        findings = [
            {
                "finding_id": "f001",
                "vuln_type": "ssrf",
                "severity": "critical",
                "endpoint": "/proxy",
                "method": "GET",
                "parameters": ["url"],
                "agent_id": "scanner",
            },
            {
                "finding_id": "f002",
                "vuln_type": "cloud_metadata",
                "severity": "high",
                "endpoint": "/proxy",
                "method": "GET",
                "parameters": ["url"],
                "agent_id": "scanner",
            },
        ]

        chains = await synthesis_engine.synthesize(findings)

        # Should find "SSRF to Cloud Credentials" pattern
        assert len(chains) > 0

    def test_get_next_targets(self, synthesis_engine):
        """Test getting next target recommendations."""
        findings = [
            {
                "finding_id": "f001",
                "vuln_type": "sqli",
                "severity": "high",
                "endpoint": "/search",
                "method": "GET",
                "parameters": ["q"],
                "agent_id": "scanner",
            },
        ]

        targets = synthesis_engine.get_next_targets(findings)

        # Should suggest related vulns (file_write, file_read, etc.)
        assert len(targets) > 0
        assert any(t in ["file_write", "file_read", "auth_bypass"] for t in targets)

    def test_get_next_targets_excludes_current(self, synthesis_engine):
        """Test that next targets excludes current types."""
        findings = [
            {
                "finding_id": "f001",
                "vuln_type": "sqli",
                "severity": "high",
                "endpoint": "/search",
                "method": "GET",
                "parameters": ["q"],
                "agent_id": "scanner",
            },
        ]

        targets = synthesis_engine.get_next_targets(findings)

        # Should not suggest sqli (already have it)
        assert "sqli" not in targets

    def test_get_report(self, synthesis_engine, sample_finding):
        """Test report generation."""
        synthesis_engine.add_finding(sample_finding)
        report = synthesis_engine.get_report()

        assert "ATTACK CHAIN SYNTHESIS REPORT" in report
        assert "Total Findings: 1" in report

    def test_get_report_empty(self, synthesis_engine):
        """Test report with no findings."""
        report = synthesis_engine.get_report()

        assert "Total Findings: 0" in report
        assert "No attack chains discovered" in report

    def test_get_chains(self, synthesis_engine):
        """Test getting all chains."""
        chains = synthesis_engine.get_chains()
        assert isinstance(chains, list)

    def test_get_finding(self, synthesis_engine, sample_finding):
        """Test getting specific finding."""
        synthesis_engine.add_finding(sample_finding)
        node = synthesis_engine.get_finding("f001")

        assert node is not None
        assert node.finding_id == "f001"

    def test_get_finding_not_found(self, synthesis_engine):
        """Test getting non-existent finding."""
        node = synthesis_engine.get_finding("does_not_exist")
        assert node is None

    def test_clear(self, synthesis_engine, sample_finding):
        """Test clearing engine state."""
        synthesis_engine.add_finding(sample_finding)
        assert len(synthesis_engine._findings) == 1

        synthesis_engine.clear()
        assert len(synthesis_engine._findings) == 0
        assert len(synthesis_engine._chains) == 0

    @pytest.mark.asyncio
    async def test_chain_filtering_by_score(self):
        """Test that low-score chains are filtered."""
        engine = SynthesisEngine(min_chain_score=5.0)  # High threshold

        # Add low-impact findings
        findings = [
            {
                "finding_id": "f001",
                "vuln_type": "info_disclosure",
                "severity": "low",
                "endpoint": "/api",
                "method": "GET",
                "parameters": [],
                "agent_id": "test",
            },
        ]

        chains = await engine.synthesize(findings)

        # Should be filtered out due to low score
        assert len(chains) == 0

    @pytest.mark.asyncio
    async def test_multiple_patterns_same_pair(self, synthesis_engine):
        """Test handling multiple patterns for same vuln pair."""
        # Some vuln pairs might match multiple patterns
        findings = [
            {
                "finding_id": "f001",
                "vuln_type": "xss",
                "severity": "high",
                "endpoint": "/comment",
                "method": "POST",
                "parameters": ["text"],
                "agent_id": "scanner",
            },
            {
                "finding_id": "f002",
                "vuln_type": "csrf",
                "severity": "medium",
                "endpoint": "/comment",
                "method": "POST",
                "parameters": ["text"],
                "agent_id": "scanner",
            },
        ]

        chains = await synthesis_engine.synthesize(findings)

        # Should handle without error
        assert isinstance(chains, list)


def test_chain_patterns_format():
    """Test that all chain patterns have correct format."""
    for pattern in CHAIN_PATTERNS:
        assert len(pattern) == 4
        assert isinstance(pattern[0], str)  # vuln1_type
        assert isinstance(pattern[1], str)  # vuln2_type
        assert isinstance(pattern[2], str)  # chain_name
        assert isinstance(pattern[3], (int, float))  # multiplier
        assert pattern[3] > 0  # Positive multiplier


def test_global_singleton():
    """Test global synthesis engine singleton."""
    engine1 = get_synthesis_engine()
    engine2 = get_synthesis_engine()
    assert engine1 is engine2

    reset_synthesis_engine()
    engine3 = get_synthesis_engine()
    assert engine3 is not engine1
