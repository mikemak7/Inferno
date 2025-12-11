"""
Unit tests for SwarmCoordinator.

Tests the intelligent agent orchestration system including:
- Assessment planning based on target analysis
- Proactive spawn rule evaluation
- Attack chain synthesis
- Agent instance tracking
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from inferno.core.knowledge import KnowledgeEntry, KnowledgeType, Severity as KnowledgeSeverity
from inferno.reporting.models import Finding, Severity
from inferno.swarm.agents import SubAgentType
from inferno.swarm.coordinator import (
    AgentInstance,
    AgentSpawnSpec,
    AssessmentPlan,
    AttackChain,
    CoordinationResult,
    Phase,
    SwarmCoordinator,
    SPAWN_RULES,
)
from inferno.tools.base import ToolResult


@pytest.fixture
def mock_client():
    """Create a mock Anthropic client."""
    client = MagicMock()
    return client


@pytest.fixture
def mock_registry():
    """Create a mock tool registry."""
    registry = MagicMock()
    return registry


@pytest.fixture
def mock_knowledge_graph():
    """Create a mock knowledge graph."""
    kg = MagicMock()
    kg.add_entry = AsyncMock()
    return kg


@pytest.fixture
def coordinator(mock_client, mock_registry, mock_knowledge_graph):
    """Create a SwarmCoordinator instance."""
    return SwarmCoordinator(
        client=mock_client,
        registry=mock_registry,
        knowledge_graph=mock_knowledge_graph,
        operation_id="test_op_001",
    )


@pytest.fixture
def mock_swarm_tool():
    """Create a mock SwarmTool."""
    tool = MagicMock()
    tool.execute = AsyncMock(
        return_value=ToolResult(
            success=True,
            output="Agent completed successfully",
            metadata={"tokens": 5000, "turns": 10},
        )
    )
    return tool


class TestAssessmentPlanning:
    """Test assessment planning functionality."""

    @pytest.mark.asyncio
    async def test_plan_web_assessment(self, coordinator):
        """Test planning for web application assessment."""
        plan = await coordinator.plan_assessment(
            target="https://example.com",
            objective="Full security assessment of web application",
            ctf_mode=False,
        )

        assert isinstance(plan, AssessmentPlan)
        assert plan.target == "https://example.com"
        assert plan.objective == "Full security assessment of web application"
        assert Phase.RECONNAISSANCE in plan.phases
        assert Phase.SCANNING in plan.phases
        assert Phase.VALIDATION in plan.phases
        assert len(plan.initial_spawns) > 0
        assert plan.ctf_mode is False

    @pytest.mark.asyncio
    async def test_plan_ctf_assessment(self, coordinator):
        """Test planning for CTF mode (aggressive, parallel)."""
        plan = await coordinator.plan_assessment(
            target="http://ctf.example.com",
            objective="Capture the flag quickly",
            ctf_mode=True,
        )

        assert plan.ctf_mode is True
        # CTF mode should spawn both recon and scanner in parallel
        assert len(plan.initial_spawns) >= 2
        agent_types = [spec.agent_type for spec in plan.initial_spawns]
        assert SubAgentType.RECONNAISSANCE in agent_types
        assert SubAgentType.SCANNER in agent_types
        # CTF should have shorter estimated duration
        assert plan.estimated_duration_minutes <= 30

    @pytest.mark.asyncio
    async def test_plan_subdomain_enumeration(self, coordinator):
        """Test planning when subdomain enumeration is requested."""
        plan = await coordinator.plan_assessment(
            target="example.com",
            objective="Enumerate all subdomains and test them",
            ctf_mode=False,
        )

        # Should have custom subdomain rule
        assert "immediate_subdomain" in plan.spawn_rules
        rule = plan.spawn_rules["immediate_subdomain"]
        assert SubAgentType.RECONNAISSANCE in rule["agents"]

    @pytest.mark.asyncio
    async def test_plan_comprehensive_assessment(self, coordinator):
        """Test planning for comprehensive assessment (longer duration)."""
        plan = await coordinator.plan_assessment(
            target="https://example.com",
            objective="Comprehensive full-scope security assessment",
            ctf_mode=False,
        )

        # Comprehensive should have longer duration
        assert plan.estimated_duration_minutes >= 60


class TestSpawnDecisions:
    """Test spawn decision logic."""

    def test_get_spawn_decision_waf_detected(self, coordinator):
        """Test spawn decision when WAF is detected."""
        metrics = {"waf_detected": True}
        decision = coordinator.get_spawn_decision(
            current_phase=Phase.SCANNING,
            metrics=metrics,
            recent_findings=[],
        )

        assert decision is not None
        assert decision["rule"] == "waf_detected"
        assert SubAgentType.ANALYZER in decision["agents"]

    def test_get_spawn_decision_sqli_found(self, coordinator):
        """Test spawn decision when SQL injection found."""
        findings = [
            {
                "vuln_type": "sql_injection",
                "severity": "high",
                "location": "/login",
            }
        ]

        decision = coordinator.get_spawn_decision(
            current_phase=Phase.SCANNING,
            metrics={},
            recent_findings=findings,
        )

        assert decision is not None
        assert decision["rule"] == "sqli_found"
        assert SubAgentType.EXPLOITER in decision["agents"]

    def test_get_spawn_decision_rce_found(self, coordinator):
        """Test spawn decision when RCE found."""
        findings = [
            {
                "vuln_type": "command_injection_rce",
                "severity": "critical",
                "location": "/exec",
            }
        ]

        decision = coordinator.get_spawn_decision(
            current_phase=Phase.EXPLOITATION,
            metrics={},
            recent_findings=findings,
        )

        assert decision is not None
        assert decision["rule"] == "rce_found"
        assert SubAgentType.EXPLOITER in decision["agents"]
        assert SubAgentType.POST_EXPLOITATION in decision["agents"]

    def test_get_spawn_decision_high_severity_cluster(self, coordinator):
        """Test spawn decision when multiple high-severity findings exist."""
        findings = [
            {"vuln_type": "xss", "severity": "high"},
            {"vuln_type": "auth_bypass", "severity": "critical"},
            {"vuln_type": "idor", "severity": "high"},
        ]

        decision = coordinator.get_spawn_decision(
            current_phase=Phase.SCANNING,
            metrics={},
            recent_findings=findings,
        )

        assert decision is not None
        assert decision["rule"] == "high_severity_cluster"
        assert SubAgentType.VALIDATOR in decision["agents"]

    def test_get_spawn_decision_no_match(self, coordinator):
        """Test spawn decision returns None when no rules match."""
        decision = coordinator.get_spawn_decision(
            current_phase=Phase.RECONNAISSANCE,
            metrics={},
            recent_findings=[],
        )

        # No rules should trigger with empty context
        assert decision is None


class TestAgentSpawning:
    """Test agent spawning functionality."""

    @pytest.mark.asyncio
    async def test_spawn_agent(self, coordinator, mock_swarm_tool):
        """Test spawning a single agent."""
        coordinator.set_swarm_tool(mock_swarm_tool)

        agent_id = await coordinator.spawn_agent(
            agent_type=SubAgentType.RECONNAISSANCE.value,
            task="Enumerate subdomains of example.com",
            context="Initial reconnaissance phase",
        )

        assert agent_id is not None
        assert agent_id.startswith("reconnaissance_")
        # Agent should be in active agents initially
        assert agent_id in coordinator._active_agents

    @pytest.mark.asyncio
    async def test_spawn_agent_with_dependencies(self, coordinator, mock_swarm_tool):
        """Test spawning agent with dependencies."""
        coordinator.set_swarm_tool(mock_swarm_tool)

        # Spawn first agent
        agent1_id = await coordinator.spawn_agent(
            agent_type=SubAgentType.RECONNAISSANCE.value,
            task="Initial recon",
        )

        # Manually complete first agent
        coordinator._active_agents[agent1_id].status = "completed"
        coordinator._completed_agents.append(coordinator._active_agents[agent1_id])
        del coordinator._active_agents[agent1_id]

        # Spawn second agent with dependency
        agent2_id = await coordinator.spawn_agent(
            agent_type=SubAgentType.SCANNER.value,
            task="Scan discovered endpoints",
            dependencies=[agent1_id],
        )

        assert agent2_id is not None

    @pytest.mark.asyncio
    async def test_spawn_agent_without_swarm_tool(self, coordinator):
        """Test spawning agent fails gracefully without SwarmTool."""
        with pytest.raises(RuntimeError, match="SwarmTool not initialized"):
            await coordinator.spawn_agent(
                agent_type=SubAgentType.RECONNAISSANCE.value,
                task="Test task",
            )


class TestFindingHandling:
    """Test finding handling and tracking."""

    @pytest.mark.asyncio
    async def test_handle_finding(self, coordinator, mock_knowledge_graph):
        """Test handling a reported finding."""
        agent_id = "test_agent_001"
        finding = {
            "vuln_type": "xss",
            "severity": "high",
            "target": "https://example.com",
            "description": "Reflected XSS in search parameter",
            "location": "/search?q=",
            "evidence": "Payload: <script>alert(1)</script>",
        }

        # Create agent instance
        coordinator._active_agents[agent_id] = AgentInstance(
            agent_id=agent_id,
            agent_type=SubAgentType.SCANNER,
            task="Scan for vulnerabilities",
            spawned_at=datetime.now(timezone.utc),
        )

        await coordinator.handle_finding(agent_id, finding)

        # Finding should be added to all findings
        assert len(coordinator._all_findings) == 1
        assert coordinator._all_findings[0]["vuln_type"] == "xss"
        assert coordinator._all_findings[0]["agent_id"] == agent_id

        # Finding should be added to agent instance
        assert len(coordinator._active_agents[agent_id].findings) == 1

        # Finding should be added to knowledge graph
        mock_knowledge_graph.add_entry.assert_called_once()
        entry = mock_knowledge_graph.add_entry.call_args[0][0]
        assert isinstance(entry, KnowledgeEntry)
        assert entry.knowledge_type == KnowledgeType.FINDING

    @pytest.mark.asyncio
    async def test_handle_multiple_findings(self, coordinator, mock_knowledge_graph):
        """Test handling multiple findings from different agents."""
        agent1 = "scanner_001"
        agent2 = "exploiter_001"

        coordinator._active_agents[agent1] = AgentInstance(
            agent_id=agent1,
            agent_type=SubAgentType.SCANNER,
            task="Scan",
            spawned_at=datetime.now(timezone.utc),
        )
        coordinator._active_agents[agent2] = AgentInstance(
            agent_id=agent2,
            agent_type=SubAgentType.EXPLOITER,
            task="Exploit",
            spawned_at=datetime.now(timezone.utc),
        )

        finding1 = {"vuln_type": "sqli", "severity": "high", "target": "https://example.com"}
        finding2 = {"vuln_type": "xss", "severity": "medium", "target": "https://example.com"}

        await coordinator.handle_finding(agent1, finding1)
        await coordinator.handle_finding(agent2, finding2)

        assert len(coordinator._all_findings) == 2
        assert coordinator._all_findings[0]["agent_id"] == agent1
        assert coordinator._all_findings[1]["agent_id"] == agent2


class TestAttackChainSynthesis:
    """Test attack chain synthesis."""

    @pytest.mark.asyncio
    async def test_synthesize_sqli_chain(self, coordinator):
        """Test synthesizing SQL injection attack chain."""
        coordinator._all_findings = [
            {
                "vuln_type": "sql_injection",
                "severity": "high",
                "location": "/login",
                "target": "https://example.com/login",
                "title": "SQL Injection in Login",
                "description": "Boolean-based blind SQLi",
                "evidence": "Payload: ' OR '1'='1",
                "remediation": "Use parameterized queries",
            }
        ]

        chains = await coordinator.synthesize_findings()

        assert len(chains) > 0
        sqli_chain = next((c for c in chains if "SQL Injection" in c.name), None)
        assert sqli_chain is not None
        assert sqli_chain.severity == Severity.HIGH
        assert len(sqli_chain.steps) == 1

    @pytest.mark.asyncio
    async def test_synthesize_upload_rce_chain(self, coordinator):
        """Test synthesizing file upload to RCE chain."""
        coordinator._all_findings = [
            {
                "vuln_type": "file_upload",
                "severity": "high",
                "location": "/upload",
                "target": "https://example.com/upload",
                "title": "Unrestricted File Upload",
                "description": "No file type validation",
                "evidence": "Uploaded shell.php successfully",
                "remediation": "Validate file types",
            },
            {
                "vuln_type": "command_injection",
                "severity": "critical",
                "location": "/uploads/shell.php",
                "target": "https://example.com/uploads/shell.php",
                "title": "RCE via Uploaded File",
                "description": "Executed PHP code",
                "evidence": "Ran system commands",
                "remediation": "Restrict execution permissions",
            },
        ]

        chains = await coordinator.synthesize_findings()

        upload_rce_chain = next((c for c in chains if "Upload to RCE" in c.name), None)
        assert upload_rce_chain is not None
        assert upload_rce_chain.severity == Severity.CRITICAL
        assert len(upload_rce_chain.steps) == 2
        assert upload_rce_chain.estimated_exploitability >= 0.8

    @pytest.mark.asyncio
    async def test_synthesize_xss_csrf_chain(self, coordinator):
        """Test synthesizing XSS + CSRF attack chain."""
        coordinator._all_findings = [
            {
                "vuln_type": "xss",
                "severity": "high",
                "location": "/profile",
                "target": "https://example.com/profile",
                "title": "Stored XSS",
                "description": "XSS in profile bio",
                "evidence": "<script>alert(1)</script>",
                "remediation": "Sanitize user input",
            },
            {
                "vuln_type": "csrf",
                "severity": "medium",
                "location": "/change-password",
                "target": "https://example.com/change-password",
                "title": "CSRF in Password Change",
                "description": "No CSRF token",
                "evidence": "Changed password without token",
                "remediation": "Implement CSRF tokens",
            },
        ]

        chains = await coordinator.synthesize_findings()

        xss_csrf_chain = next((c for c in chains if "XSS + CSRF" in c.name), None)
        assert xss_csrf_chain is not None
        assert xss_csrf_chain.severity == Severity.HIGH
        assert xss_csrf_chain.requires_interaction is True
        assert len(xss_csrf_chain.steps) == 2

    @pytest.mark.asyncio
    async def test_synthesize_no_findings(self, coordinator):
        """Test synthesis with no findings."""
        coordinator._all_findings = []

        chains = await coordinator.synthesize_findings()

        assert len(chains) == 0


class TestPlanExecution:
    """Test assessment plan execution."""

    @pytest.mark.asyncio
    async def test_execute_plan_without_swarm_tool(self, coordinator):
        """Test executing plan fails gracefully without SwarmTool."""
        plan = await coordinator.plan_assessment(
            target="https://example.com",
            objective="Test",
        )

        result = await coordinator.execute_plan(plan)

        assert result.success is False
        assert "SwarmTool not initialized" in result.error

    @pytest.mark.asyncio
    async def test_execute_plan_with_initial_spawns(self, coordinator, mock_swarm_tool):
        """Test executing plan with initial spawns."""
        coordinator.set_swarm_tool(mock_swarm_tool)

        plan = AssessmentPlan(
            target="https://example.com",
            objective="Test assessment",
            phases=[Phase.INITIAL, Phase.RECONNAISSANCE],
            initial_spawns=[
                AgentSpawnSpec(
                    agent_type=SubAgentType.RECONNAISSANCE,
                    task="Recon task",
                    priority=10,
                )
            ],
            spawn_rules={},
        )

        # Execute with short timeout
        with patch.object(coordinator, "_wait_for_active_agents", new_callable=AsyncMock):
            result = await coordinator.execute_plan(plan, max_agents=1, max_parallel=1)

        assert result.success is True
        assert len(result.agents_spawned) > 0


class TestMetrics:
    """Test metrics collection."""

    def test_get_current_metrics(self, coordinator):
        """Test getting current assessment metrics."""
        # Add some test data
        coordinator._active_agents["agent1"] = AgentInstance(
            agent_id="agent1",
            agent_type=SubAgentType.SCANNER,
            task="Scan",
            spawned_at=datetime.now(timezone.utc),
        )
        coordinator._completed_agents.append(
            AgentInstance(
                agent_id="agent2",
                agent_type=SubAgentType.RECONNAISSANCE,
                task="Recon",
                spawned_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
                status="completed",
            )
        )
        coordinator._all_findings.append(
            {"vuln_type": "xss", "severity": "high", "type": "xss_finding"}
        )
        coordinator._current_phase = Phase.SCANNING

        metrics = coordinator._get_current_metrics()

        assert metrics["active_agents"] == 1
        assert metrics["completed_agents"] == 1
        assert metrics["total_findings"] == 1
        assert metrics["current_phase"] == Phase.SCANNING.value
        assert metrics["waf_detected"] is False


class TestSpawnRules:
    """Test spawn rule configuration."""

    def test_spawn_rules_structure(self):
        """Test that spawn rules have proper structure."""
        for rule_name, rule_config in SPAWN_RULES.items():
            assert "trigger" in rule_config
            assert callable(rule_config["trigger"])
            assert "agents" in rule_config
            assert isinstance(rule_config["agents"], list)
            assert "parallel" in rule_config
            assert "priority" in rule_config
            assert "description" in rule_config

    def test_spawn_rules_trigger_execution(self):
        """Test that spawn rule triggers execute without errors."""
        test_context = {
            "phase": Phase.SCANNING,
            "waf_detected": False,
            "findings": [],
            "knowledge": [],
        }

        for rule_name, rule_config in SPAWN_RULES.items():
            trigger_fn = rule_config["trigger"]
            try:
                result = trigger_fn(test_context)
                assert isinstance(result, bool)
            except Exception as e:
                pytest.fail(f"Rule {rule_name} trigger failed: {e}")
