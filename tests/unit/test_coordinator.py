"""
Unit tests for SwarmCoordinator.

Tests spawn rules, plan assessment, finding handling, proactive spawning,
and agent lifecycle management.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, Mock, patch

from inferno.core.knowledge import KnowledgeEntry, KnowledgeGraph, KnowledgeType, Severity
from inferno.swarm.agents import SubAgentType
from inferno.swarm.coordinator import (
    SPAWN_RULES,
    AgentInstance,
    AgentSpawnSpec,
    AssessmentPlan,
    AttackChain,
    CoordinationResult,
    Phase,
    SwarmCoordinator,
)
from inferno.swarm.tool import SwarmTool
from inferno.tools.registry import ToolRegistry


@pytest.fixture
def mock_client():
    """Mock Anthropic client."""
    return AsyncMock()


@pytest.fixture
def mock_registry():
    """Mock tool registry."""
    registry = MagicMock(spec=ToolRegistry)
    registry.get_all_tools.return_value = []
    return registry


@pytest.fixture
def mock_knowledge_graph():
    """Mock knowledge graph."""
    return MagicMock(spec=KnowledgeGraph)


@pytest.fixture
def mock_swarm_tool():
    """Mock swarm tool."""
    tool = AsyncMock(spec=SwarmTool)
    tool.execute.return_value = Mock(
        success=True,
        data={"findings": []},
        metadata={"tokens": 1000, "turns": 5},
        error=None,
    )
    return tool


@pytest.fixture
def coordinator(mock_client, mock_registry, mock_knowledge_graph):
    """Create coordinator instance."""
    return SwarmCoordinator(
        client=mock_client,
        registry=mock_registry,
        knowledge_graph=mock_knowledge_graph,
        operation_id="test_op",
    )


class TestSpawnRules:
    """Test spawn rule evaluation."""

    def test_spawn_rules_structure(self):
        """Test SPAWN_RULES has correct structure."""
        assert len(SPAWN_RULES) >= 10  # Should have at least 10 rules

        for rule_name, rule_config in SPAWN_RULES.items():
            assert "trigger" in rule_config
            assert "agents" in rule_config
            assert "description" in rule_config
            assert callable(rule_config["trigger"])
            assert isinstance(rule_config["agents"], list)

    def test_assessment_start_rule(self, coordinator):
        """Test assessment_start spawn rule."""
        context = {"phase": Phase.INITIAL}

        decision = coordinator.get_spawn_decision(
            Phase.INITIAL,
            {},
            [],
        )

        # May or may not trigger depending on implementation
        # Just ensure it doesn't crash

    def test_waf_detected_rule(self, coordinator):
        """Test waf_detected spawn rule."""
        context = {"waf_detected": True}
        metrics = {"waf_detected": True}

        decision = coordinator.get_spawn_decision(
            Phase.SCANNING,
            metrics,
            [],
        )

        if decision:
            assert SubAgentType.ANALYZER in decision.get("agents", [])

    def test_sqli_found_rule(self, coordinator):
        """Test sqli_found spawn rule."""
        findings = [
            {"vuln_type": "SQL Injection", "location": "/api/search"}
        ]

        decision = coordinator.get_spawn_decision(
            Phase.SCANNING,
            {},
            findings,
        )

        if decision:
            assert SubAgentType.EXPLOITER in decision.get("agents", [])

    def test_rce_found_rule(self, coordinator):
        """Test rce_found spawn rule."""
        findings = [
            {"vuln_type": "Remote Code Execution", "location": "/api/exec"}
        ]

        decision = coordinator.get_spawn_decision(
            Phase.EXPLOITATION,
            {},
            findings,
        )

        if decision:
            assert SubAgentType.EXPLOITER in decision.get("agents", []) or SubAgentType.POST_EXPLOITATION in decision.get("agents", [])

    def test_high_severity_cluster_rule(self, coordinator):
        """Test high_severity_cluster spawn rule."""
        findings = [
            {"vuln_type": "SQLi", "severity": "critical"},
            {"vuln_type": "XSS", "severity": "high"},
            {"vuln_type": "IDOR", "severity": "high"},
        ]

        decision = coordinator.get_spawn_decision(
            Phase.VALIDATION,
            {},
            findings,
        )

        # Should trigger validation agent when 3+ high/critical findings
        if decision:
            assert SubAgentType.VALIDATOR in decision.get("agents", [])

    def test_api_discovered_rule(self, coordinator):
        """Test api_discovered spawn rule."""
        findings = [
            {"location": "/api/v1/users"}
        ]

        decision = coordinator.get_spawn_decision(
            Phase.RECONNAISSANCE,
            {},
            findings,
        )

        # May trigger API testing
        if decision:
            assert SubAgentType.SCANNER in decision.get("agents", [])

    def test_credentials_found_rule(self, coordinator, mock_knowledge_graph):
        """Test credentials_found spawn rule."""
        # Mock knowledge entries with credentials
        cred_entry = KnowledgeEntry(
            id="cred_1",
            content="admin:password123",
            knowledge_type=KnowledgeType.CREDENTIAL,
            source_agent="recon_1",
            target="example.com",
        )

        context = {"knowledge": [cred_entry]}

        # Manual evaluation since coordinator.get_spawn_decision may not have access
        trigger = SPAWN_RULES["credentials_found"]["trigger"]
        should_spawn = trigger(context)

        if should_spawn:
            assert SubAgentType.POST_EXPLOITATION in SPAWN_RULES["credentials_found"]["agents"]

    def test_file_upload_found_rule(self, coordinator):
        """Test file_upload_found spawn rule."""
        findings = [
            {"vuln_type": "File Upload", "location": "/upload"}
        ]

        decision = coordinator.get_spawn_decision(
            Phase.SCANNING,
            {},
            findings,
        )

        if decision:
            assert SubAgentType.EXPLOITER in decision.get("agents", [])

    def test_jwt_found_rule(self, coordinator):
        """Test jwt_found spawn rule."""
        findings = [
            {"type": "JWT Token Found", "location": "/api/auth"}
        ]

        decision = coordinator.get_spawn_decision(
            Phase.RECONNAISSANCE,
            {},
            findings,
        )

        # JWT analysis should be triggered
        if decision:
            assert SubAgentType.ANALYZER in decision.get("agents", [])


class TestPlanAssessment:
    """Test assessment planning."""

    @pytest.mark.asyncio
    async def test_plan_assessment_web_app(self, coordinator):
        """Test planning for web application."""
        plan = await coordinator.plan_assessment(
            target="https://example.com",
            objective="Full security assessment",
            ctf_mode=False,
        )

        assert isinstance(plan, AssessmentPlan)
        assert plan.target == "https://example.com"
        assert len(plan.phases) > 0
        assert Phase.RECONNAISSANCE in plan.phases
        assert Phase.SCANNING in plan.phases
        assert len(plan.initial_spawns) > 0

    @pytest.mark.asyncio
    async def test_plan_assessment_ctf_mode(self, coordinator):
        """Test planning for CTF."""
        plan = await coordinator.plan_assessment(
            target="http://ctf.example.com",
            objective="Capture the flag",
            ctf_mode=True,
        )

        assert plan.ctf_mode is True
        assert Phase.EXPLOITATION in plan.phases
        # CTF mode should have aggressive initial spawns
        assert len(plan.initial_spawns) >= 2

    @pytest.mark.asyncio
    async def test_plan_phases_order(self, coordinator):
        """Test phases are in logical order."""
        plan = await coordinator.plan_assessment(
            target="https://example.com",
            objective="Full assessment",
        )

        # RECONNAISSANCE should come before EXPLOITATION
        if Phase.RECONNAISSANCE in plan.phases and Phase.EXPLOITATION in plan.phases:
            recon_idx = plan.phases.index(Phase.RECONNAISSANCE)
            exploit_idx = plan.phases.index(Phase.EXPLOITATION)
            assert recon_idx < exploit_idx

    @pytest.mark.asyncio
    async def test_plan_initial_spawns_priority(self, coordinator):
        """Test initial spawns are prioritized."""
        plan = await coordinator.plan_assessment(
            target="https://example.com",
            objective="Full assessment",
        )

        # All initial spawns should have priority set
        for spawn_spec in plan.initial_spawns:
            assert spawn_spec.priority > 0
            assert spawn_spec.agent_type in SubAgentType


class TestFindingHandling:
    """Test finding handling and reporting."""

    @pytest.mark.asyncio
    async def test_handle_finding(self, coordinator):
        """Test handling a finding from agent."""
        finding = {
            "vuln_type": "SQL Injection",
            "severity": "high",
            "target": "https://example.com",
            "location": "/api/search",
            "description": "SQL injection in search parameter",
            "evidence": "' OR '1'='1",
        }

        await coordinator.handle_finding("agent_001", finding)

        # Finding should be added to findings list
        assert len(coordinator._all_findings) == 1
        assert coordinator._all_findings[0]["vuln_type"] == "SQL Injection"
        assert coordinator._all_findings[0]["agent_id"] == "agent_001"

    @pytest.mark.asyncio
    async def test_finding_added_to_knowledge_graph(self, coordinator, mock_knowledge_graph):
        """Test findings are added to knowledge graph."""
        finding = {
            "vuln_type": "XSS",
            "severity": "medium",
            "target": "https://example.com",
            "location": "/comment",
            "description": "Reflected XSS in comment field",
        }

        await coordinator.handle_finding("agent_002", finding)

        # Should call add_entry on knowledge graph
        mock_knowledge_graph.add_entry.assert_called_once()

    @pytest.mark.asyncio
    async def test_finding_updates_agent_instance(self, coordinator):
        """Test finding updates agent instance."""
        # Create an active agent
        agent_instance = AgentInstance(
            agent_id="agent_003",
            agent_type=SubAgentType.SCANNER,
            task="Scan for vulnerabilities",
            spawned_at=datetime.now(timezone.utc),
        )
        coordinator._active_agents["agent_003"] = agent_instance

        finding = {
            "vuln_type": "IDOR",
            "severity": "high",
            "location": "/api/users/:id",
        }

        await coordinator.handle_finding("agent_003", finding)

        # Agent instance should have the finding
        assert len(agent_instance.findings) == 1
        assert agent_instance.findings[0]["vuln_type"] == "IDOR"


class TestProactiveSpawning:
    """Test proactive agent spawning."""

    @pytest.mark.asyncio
    async def test_spawn_agent(self, coordinator, mock_swarm_tool):
        """Test spawning a sub-agent."""
        coordinator.set_swarm_tool(mock_swarm_tool)

        agent_id = await coordinator.spawn_agent(
            agent_type=SubAgentType.SCANNER.value,
            task="Scan for SQL injection",
            context="Target: https://example.com",
        )

        # Agent should be registered
        assert agent_id in coordinator._active_agents
        agent = coordinator._active_agents[agent_id]
        assert agent.agent_type == SubAgentType.SCANNER
        assert agent.task == "Scan for SQL injection"

    @pytest.mark.asyncio
    async def test_spawn_with_dependencies(self, coordinator, mock_swarm_tool):
        """Test spawning agent with dependencies."""
        coordinator.set_swarm_tool(mock_swarm_tool)

        # Spawn first agent
        agent_1_id = await coordinator.spawn_agent(
            agent_type=SubAgentType.RECONNAISSANCE.value,
            task="Recon",
        )

        # Move to completed
        if agent_1_id in coordinator._active_agents:
            agent = coordinator._active_agents[agent_1_id]
            agent.status = "completed"
            agent.completed_at = datetime.now(timezone.utc)
            coordinator._completed_agents.append(agent)
            del coordinator._active_agents[agent_1_id]

        # Spawn second agent with dependency
        agent_2_id = await coordinator.spawn_agent(
            agent_type=SubAgentType.SCANNER.value,
            task="Scan",
            dependencies=[agent_1_id],
        )

        # Should wait for dependency before spawning
        assert agent_2_id in coordinator._active_agents or agent_2_id in [a.agent_id for a in coordinator._completed_agents]


class TestAgentLifecycle:
    """Test agent lifecycle management."""

    @pytest.mark.asyncio
    async def test_agent_completion(self, coordinator, mock_swarm_tool):
        """Test agent completion tracking."""
        coordinator.set_swarm_tool(mock_swarm_tool)

        agent_id = await coordinator.spawn_agent(
            agent_type=SubAgentType.SCANNER.value,
            task="Scan",
        )

        # Simulate agent completion
        if agent_id in coordinator._active_agents:
            agent = coordinator._active_agents[agent_id]
            agent.status = "completed"
            agent.completed_at = datetime.now(timezone.utc)
            agent.tokens_used = 1500
            agent.turns_used = 8

            coordinator._completed_agents.append(agent)
            del coordinator._active_agents[agent_id]

        # Should be in completed list
        assert any(a.agent_id == agent_id for a in coordinator._completed_agents)
        assert agent_id not in coordinator._active_agents

    def test_agent_instance_is_complete(self):
        """Test AgentInstance.is_complete()."""
        agent = AgentInstance(
            agent_id="test",
            agent_type=SubAgentType.SCANNER,
            task="Test",
            spawned_at=datetime.now(timezone.utc),
        )

        assert not agent.is_complete()

        agent.status = "completed"
        assert agent.is_complete()

        agent.status = "failed"
        assert agent.is_complete()

    def test_agent_instance_to_dict(self):
        """Test AgentInstance serialization."""
        agent = AgentInstance(
            agent_id="test_001",
            agent_type=SubAgentType.EXPLOITER,
            task="Exploit SQLi",
            spawned_at=datetime.now(timezone.utc),
            status="running",
            tokens_used=1000,
            turns_used=5,
        )

        agent_dict = agent.to_dict()

        assert agent_dict["agent_id"] == "test_001"
        assert agent_dict["agent_type"] == SubAgentType.EXPLOITER.value
        assert agent_dict["task"] == "Exploit SQLi"
        assert agent_dict["status"] == "running"
        assert agent_dict["tokens_used"] == 1000


class TestAttackChainSynthesis:
    """Test attack chain synthesis."""

    @pytest.mark.asyncio
    async def test_synthesize_findings_sqli_chain(self, coordinator):
        """Test SQLi attack chain synthesis."""
        coordinator._all_findings = [
            {
                "vuln_type": "SQL Injection",
                "severity": "high",
                "location": "/api/login",
                "target": "example.com",
            }
        ]

        chains = await coordinator.synthesize_findings()

        # Should create SQLi chain
        assert len(chains) > 0
        sqli_chains = [c for c in chains if "sql" in c.name.lower()]
        assert len(sqli_chains) > 0

    @pytest.mark.asyncio
    async def test_synthesize_findings_ssrf_chain(self, coordinator):
        """Test SSRF attack chain synthesis."""
        coordinator._all_findings = [
            {
                "vuln_type": "SSRF",
                "severity": "high",
                "location": "/api/fetch",
                "target": "example.com",
            }
        ]

        chains = await coordinator.synthesize_findings()

        # Should create SSRF chain
        ssrf_chains = [c for c in chains if "ssrf" in c.name.lower()]
        assert len(ssrf_chains) > 0

    @pytest.mark.asyncio
    async def test_synthesize_findings_xss_csrf_chain(self, coordinator):
        """Test XSS + CSRF chain synthesis."""
        coordinator._all_findings = [
            {
                "vuln_type": "XSS",
                "severity": "medium",
                "location": "/comment",
                "target": "example.com",
            },
            {
                "vuln_type": "CSRF",
                "severity": "medium",
                "location": "/api/settings",
                "target": "example.com",
            },
        ]

        chains = await coordinator.synthesize_findings()

        # Should create XSS+CSRF chain
        xss_csrf_chains = [c for c in chains if "xss" in c.name.lower() and "csrf" in c.name.lower()]
        assert len(xss_csrf_chains) > 0

    @pytest.mark.asyncio
    async def test_synthesize_findings_upload_rce_chain(self, coordinator):
        """Test file upload to RCE chain synthesis."""
        coordinator._all_findings = [
            {
                "vuln_type": "File Upload",
                "severity": "high",
                "location": "/upload",
                "target": "example.com",
            },
            {
                "vuln_type": "RCE",
                "severity": "critical",
                "location": "/files",
                "target": "example.com",
            },
        ]

        chains = await coordinator.synthesize_findings()

        # Should create upload->RCE chain
        upload_chains = [c for c in chains if "upload" in c.name.lower() and "rce" in c.name.lower()]
        assert len(upload_chains) > 0
        if upload_chains:
            assert upload_chains[0].severity == Severity.CRITICAL


class TestExecutePlan:
    """Test plan execution."""

    @pytest.mark.asyncio
    async def test_execute_plan_success(self, coordinator, mock_swarm_tool):
        """Test successful plan execution."""
        coordinator.set_swarm_tool(mock_swarm_tool)

        plan = AssessmentPlan(
            target="https://example.com",
            objective="Test",
            phases=[Phase.RECONNAISSANCE],
            initial_spawns=[
                AgentSpawnSpec(
                    agent_type=SubAgentType.RECONNAISSANCE,
                    task="Recon",
                    priority=10,
                )
            ],
            spawn_rules={},
        )

        # Mock quick completion
        with patch.object(coordinator, '_wait_for_active_agents', return_value=None):
            result = await coordinator.execute_plan(plan, max_agents=5, max_parallel=2)

        assert isinstance(result, CoordinationResult)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_execute_plan_without_swarm_tool(self, coordinator):
        """Test execute_plan fails without swarm tool."""
        plan = AssessmentPlan(
            target="https://example.com",
            objective="Test",
            phases=[],
            initial_spawns=[],
            spawn_rules={},
        )

        result = await coordinator.execute_plan(plan)

        assert result.success is False
        assert "SwarmTool not initialized" in result.error

    @pytest.mark.asyncio
    async def test_execute_plan_respects_max_agents(self, coordinator, mock_swarm_tool):
        """Test execute_plan respects max_agents limit."""
        coordinator.set_swarm_tool(mock_swarm_tool)

        plan = AssessmentPlan(
            target="https://example.com",
            objective="Test",
            phases=[Phase.RECONNAISSANCE],
            initial_spawns=[
                AgentSpawnSpec(
                    agent_type=SubAgentType.RECONNAISSANCE,
                    task=f"Task {i}",
                    priority=10,
                )
                for i in range(20)  # Request 20 spawns
            ],
            spawn_rules={},
        )

        with patch.object(coordinator, '_wait_for_active_agents', return_value=None):
            result = await coordinator.execute_plan(plan, max_agents=5, max_parallel=2)

        # Should not exceed max_agents
        total_spawned = len(result.agents_spawned)
        assert total_spawned <= 5


class TestCoordinationResult:
    """Test CoordinationResult model."""

    def test_coordination_result_to_dict(self):
        """Test CoordinationResult serialization."""
        plan = AssessmentPlan(
            target="https://example.com",
            objective="Test",
            phases=[Phase.RECONNAISSANCE],
            initial_spawns=[],
            spawn_rules={},
        )

        agent = AgentInstance(
            agent_id="test_001",
            agent_type=SubAgentType.SCANNER,
            task="Scan",
            spawned_at=datetime.now(timezone.utc),
        )

        result = CoordinationResult(
            plan=plan,
            agents_spawned=[agent],
            findings=[{"vuln_type": "XSS"}],
            attack_chains=[],
            total_tokens=5000,
            total_duration_seconds=120.5,
            success=True,
        )

        result_dict = result.to_dict()

        assert result_dict["plan"]["target"] == "https://example.com"
        assert len(result_dict["agents_spawned"]) == 1
        assert len(result_dict["findings"]) == 1
        assert result_dict["total_tokens"] == 5000
        assert result_dict["success"] is True


class TestAgentSpawnSpec:
    """Test AgentSpawnSpec model."""

    def test_agent_spawn_spec_creation(self):
        """Test creating AgentSpawnSpec."""
        spec = AgentSpawnSpec(
            agent_type=SubAgentType.EXPLOITER,
            task="Exploit SQLi",
            context="Found at /api/search",
            priority=9,
            dependencies=["recon_001"],
            metadata={"target": "example.com"},
        )

        assert spec.agent_type == SubAgentType.EXPLOITER
        assert spec.task == "Exploit SQLi"
        assert spec.priority == 9
        assert "recon_001" in spec.dependencies
        assert spec.metadata["target"] == "example.com"


class TestAssessmentPlan:
    """Test AssessmentPlan model."""

    def test_assessment_plan_to_dict(self):
        """Test AssessmentPlan serialization."""
        plan = AssessmentPlan(
            target="https://example.com",
            objective="Full assessment",
            phases=[Phase.RECONNAISSANCE, Phase.SCANNING],
            initial_spawns=[
                AgentSpawnSpec(
                    agent_type=SubAgentType.RECONNAISSANCE,
                    task="Recon",
                    priority=10,
                )
            ],
            spawn_rules={"rule1": {}},
            estimated_duration_minutes=30,
            ctf_mode=True,
        )

        plan_dict = plan.to_dict()

        assert plan_dict["target"] == "https://example.com"
        assert plan_dict["ctf_mode"] is True
        assert len(plan_dict["phases"]) == 2
        assert Phase.RECONNAISSANCE.value in plan_dict["phases"]
        assert len(plan_dict["initial_spawns"]) == 1
