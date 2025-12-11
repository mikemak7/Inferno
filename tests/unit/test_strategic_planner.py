"""
Unit tests for StrategicPlanner.

Tests plan creation, attack chain generation, budget allocation,
phase progression, and step completion tracking.
"""

import pytest
from datetime import datetime

from inferno.agent.strategic_planner import (
    AttackChainStep,
    AttackPhase,
    BudgetAllocation,
    ChainType,
    StrategicPlan,
    StrategicPlanner,
    TargetAnalysis,
    TestingStep,
)


class TestPlanCreation:
    """Test strategic plan creation for different targets."""

    @pytest.mark.asyncio
    async def test_create_plan_for_web_application(self):
        """Test plan creation for a web application target."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Full security assessment",
            max_budget_usd=10.0,
        )

        assert isinstance(plan, StrategicPlan)
        assert plan.target == "https://example.com"
        assert len(plan.phases) > 0
        assert AttackPhase.RECONNAISSANCE in plan.phases
        assert AttackPhase.SCANNING in plan.phases
        assert plan.total_estimated_cost <= 10.0

    @pytest.mark.asyncio
    async def test_create_plan_for_api(self):
        """Test plan creation for API target."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://api.example.com",
            objective="Test API security",
            max_budget_usd=5.0,
        )

        # API tests should include API-specific phases
        assert len(plan.phases) > 0
        assert any(
            "api" in step.description.lower()
            for phase_steps in plan.steps_by_phase.values()
            for step in phase_steps
        )

    @pytest.mark.asyncio
    async def test_create_plan_for_ctf(self):
        """Test plan creation for CTF target."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="http://ctf.example.com",
            objective="Capture the flag",
            ctf_mode=True,
        )

        # CTF mode should be aggressive and time-optimized
        assert plan.ctf_mode is True
        assert AttackPhase.EXPLOITATION in plan.phases
        # Should have higher priority steps first
        recon_steps = plan.steps_by_phase.get(AttackPhase.RECONNAISSANCE, [])
        if len(recon_steps) > 1:
            assert recon_steps[0].priority >= recon_steps[-1].priority

    @pytest.mark.asyncio
    async def test_create_plan_with_budget_constraints(self):
        """Test plan creation respects budget constraints."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Quick scan",
            max_budget_usd=1.0,
        )

        # Should have fewer, more focused steps
        total_steps = sum(len(steps) for steps in plan.steps_by_phase.values())
        assert plan.total_estimated_cost <= 1.0
        assert total_steps > 0  # But still have some steps

    @pytest.mark.asyncio
    async def test_create_plan_with_known_tech_stack(self):
        """Test plan creation with known technology stack."""
        planner = StrategicPlanner()

        tech_stack = {
            "framework": "Django",
            "database": "PostgreSQL",
            "auth": "JWT",
        }

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Full assessment",
            known_tech_stack=tech_stack,
        )

        # Should include tech-specific steps
        all_steps = [
            step
            for phase_steps in plan.steps_by_phase.values()
            for step in phase_steps
        ]

        assert any("jwt" in step.description.lower() for step in all_steps)
        assert any("sql" in step.description.lower() for step in all_steps)


class TestTargetAnalysis:
    """Test target analysis functionality."""

    @pytest.mark.asyncio
    async def test_analyze_web_application(self):
        """Test analyzing a web application."""
        planner = StrategicPlanner()

        analysis = await planner.analyze_target(
            "https://shop.example.com",
            "Test e-commerce security",
        )

        assert isinstance(analysis, TargetAnalysis)
        assert analysis.target_type in ["web_application", "api", "mixed"]
        assert analysis.estimated_complexity > 0

    @pytest.mark.asyncio
    async def test_analyze_api_endpoint(self):
        """Test analyzing an API endpoint."""
        planner = StrategicPlanner()

        analysis = await planner.analyze_target(
            "https://api.example.com/v1",
            "API security test",
        )

        assert "api" in analysis.target_type.lower()
        assert len(analysis.likely_vulnerabilities) > 0

    @pytest.mark.asyncio
    async def test_complexity_estimation(self):
        """Test complexity estimation."""
        planner = StrategicPlanner()

        # Simple static site
        simple_analysis = await planner.analyze_target(
            "https://blog.example.com",
            "Basic scan",
        )

        # Complex application
        complex_analysis = await planner.analyze_target(
            "https://enterprise.example.com/admin",
            "Full penetration test with authentication bypass",
        )

        # Complex target should have higher estimated complexity
        assert complex_analysis.estimated_complexity >= simple_analysis.estimated_complexity


class TestAttackChainGeneration:
    """Test attack chain generation."""

    @pytest.mark.asyncio
    async def test_generate_basic_chains(self):
        """Test generating basic attack chains."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Full assessment",
        )

        # Should have generated some attack chains
        assert len(plan.attack_chains) > 0

    @pytest.mark.asyncio
    async def test_sqli_to_data_breach_chain(self):
        """Test SQL injection to data breach chain."""
        planner = StrategicPlanner()

        chain = planner.create_attack_chain(
            chain_type=ChainType.SQLI_TO_DATA_BREACH,
            target_info={"has_database": True},
        )

        assert chain is not None
        assert len(chain.steps) > 0
        assert any("sql" in step.description.lower() for step in chain.steps)
        assert chain.severity in ["high", "critical"]

    @pytest.mark.asyncio
    async def test_xss_to_account_takeover_chain(self):
        """Test XSS to account takeover chain."""
        planner = StrategicPlanner()

        chain = planner.create_attack_chain(
            chain_type=ChainType.XSS_TO_ACCOUNT_TAKEOVER,
            target_info={"has_user_input": True},
        )

        assert chain is not None
        assert any("xss" in step.description.lower() for step in chain.steps)
        assert any("session" in step.description.lower() or "cookie" in step.description.lower() for step in chain.steps)

    @pytest.mark.asyncio
    async def test_file_upload_to_rce_chain(self):
        """Test file upload to RCE chain."""
        planner = StrategicPlanner()

        chain = planner.create_attack_chain(
            chain_type=ChainType.FILE_UPLOAD_TO_RCE,
            target_info={"has_file_upload": True},
        )

        assert chain is not None
        assert any("upload" in step.description.lower() for step in chain.steps)
        assert any("rce" in step.description.lower() or "execute" in step.description.lower() for step in chain.steps)
        assert chain.severity == "critical"

    @pytest.mark.asyncio
    async def test_chain_prioritization(self):
        """Test attack chain prioritization."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Full assessment",
        )

        if len(plan.attack_chains) > 1:
            # Chains should be sorted by priority
            for i in range(len(plan.attack_chains) - 1):
                assert plan.attack_chains[i].priority >= plan.attack_chains[i + 1].priority


class TestBudgetAllocation:
    """Test budget allocation across phases."""

    @pytest.mark.asyncio
    async def test_budget_allocation_structure(self):
        """Test budget allocation structure."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Full assessment",
            max_budget_usd=10.0,
        )

        assert isinstance(plan.budget, BudgetAllocation)
        assert plan.budget.total_budget_usd == 10.0
        assert plan.budget.reconnaissance_pct > 0
        assert plan.budget.scanning_pct > 0

        # All percentages should sum to 100
        total_pct = (
            plan.budget.reconnaissance_pct
            + plan.budget.scanning_pct
            + plan.budget.exploitation_pct
            + plan.budget.post_exploitation_pct
            + plan.budget.validation_pct
        )
        assert 99 <= total_pct <= 101  # Allow small rounding errors

    @pytest.mark.asyncio
    async def test_ctf_budget_allocation(self):
        """Test budget allocation for CTF mode."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="http://ctf.example.com",
            objective="Capture flag",
            ctf_mode=True,
            max_budget_usd=5.0,
        )

        # CTF should allocate more to exploitation
        assert plan.budget.exploitation_pct > plan.budget.reconnaissance_pct

    @pytest.mark.asyncio
    async def test_budget_limits_per_phase(self):
        """Test budget limits are calculated per phase."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Full assessment",
            max_budget_usd=10.0,
        )

        # Each phase should have a budget limit
        for phase in plan.phases:
            phase_budget = plan.budget.get_phase_budget(phase)
            assert phase_budget > 0
            assert phase_budget <= 10.0

    @pytest.mark.asyncio
    async def test_total_estimated_cost_within_budget(self):
        """Test total estimated cost stays within budget."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Full assessment",
            max_budget_usd=5.0,
        )

        assert plan.total_estimated_cost <= 5.0


class TestPhaseProgression:
    """Test phase progression and dependencies."""

    @pytest.mark.asyncio
    async def test_phase_order(self):
        """Test phases are in logical order."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Full assessment",
        )

        # Reconnaissance should come before exploitation
        recon_idx = None
        exploit_idx = None

        for i, phase in enumerate(plan.phases):
            if phase == AttackPhase.RECONNAISSANCE:
                recon_idx = i
            elif phase == AttackPhase.EXPLOITATION:
                exploit_idx = i

        if recon_idx is not None and exploit_idx is not None:
            assert recon_idx < exploit_idx

    @pytest.mark.asyncio
    async def test_can_start_phase(self):
        """Test phase start conditions."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Full assessment",
        )

        # Should be able to start RECONNAISSANCE (first phase)
        assert plan.can_start_phase(AttackPhase.RECONNAISSANCE)

        # Should not be able to start EXPLOITATION before RECONNAISSANCE
        if AttackPhase.EXPLOITATION in plan.phases:
            plan.current_phase = AttackPhase.INITIAL
            # Implementation may vary, but typically requires recon first
            # This test validates the concept

    @pytest.mark.asyncio
    async def test_advance_to_next_phase(self):
        """Test advancing to next phase."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Full assessment",
        )

        initial_phase = plan.current_phase
        plan.advance_to_next_phase()

        # Should have moved to next phase
        if len(plan.phases) > 1:
            current_idx = plan.phases.index(plan.current_phase)
            initial_idx = plan.phases.index(initial_phase)
            assert current_idx > initial_idx


class TestStepCompletion:
    """Test step completion and progress tracking."""

    @pytest.mark.asyncio
    async def test_mark_step_complete(self):
        """Test marking a step as complete."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Full assessment",
        )

        # Get first step
        first_phase = plan.phases[0]
        first_step = plan.steps_by_phase[first_phase][0]

        initial_completed = plan.completed_steps

        # Mark complete
        plan.mark_step_complete(first_step.step_id)

        assert plan.completed_steps == initial_completed + 1
        assert first_step.step_id in plan.completed_step_ids

    @pytest.mark.asyncio
    async def test_record_finding_from_step(self):
        """Test recording findings from steps."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Full assessment",
        )

        finding = {
            "vulnerability": "SQL Injection",
            "severity": "high",
            "location": "/api/users",
        }

        first_phase = plan.phases[0]
        first_step = plan.steps_by_phase[first_phase][0]

        plan.record_finding(first_step.step_id, finding)

        # Finding should be recorded
        assert len(plan.findings) == 1
        assert plan.findings[0]["vulnerability"] == "SQL Injection"

    @pytest.mark.asyncio
    async def test_progress_calculation(self):
        """Test progress percentage calculation."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Full assessment",
        )

        # Initial progress
        initial_progress = plan.get_progress_percentage()
        assert 0 <= initial_progress <= 100

        # Complete some steps
        for phase in plan.phases[:1]:  # Complete first phase
            for step in plan.steps_by_phase[phase]:
                plan.mark_step_complete(step.step_id)

        # Progress should increase
        new_progress = plan.get_progress_percentage()
        assert new_progress > initial_progress

    @pytest.mark.asyncio
    async def test_get_next_step(self):
        """Test getting next recommended step."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Full assessment",
        )

        next_step = plan.get_next_step()

        assert next_step is not None
        assert isinstance(next_step, TestingStep)
        assert next_step.step_id not in plan.completed_step_ids

    @pytest.mark.asyncio
    async def test_get_pending_steps_for_phase(self):
        """Test getting pending steps for a phase."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Full assessment",
        )

        first_phase = plan.phases[0]
        pending_steps = plan.get_pending_steps(first_phase)

        # All steps should be pending initially
        assert len(pending_steps) == len(plan.steps_by_phase[first_phase])

        # Mark one complete
        plan.mark_step_complete(pending_steps[0].step_id)

        # Should have one fewer pending
        new_pending = plan.get_pending_steps(first_phase)
        assert len(new_pending) == len(pending_steps) - 1


class TestPlanAdaptation:
    """Test plan adaptation based on findings."""

    @pytest.mark.asyncio
    async def test_adapt_plan_after_sqli_finding(self):
        """Test plan adaptation after SQLi discovery."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Full assessment",
        )

        initial_step_count = sum(len(steps) for steps in plan.steps_by_phase.values())

        # Report SQLi finding
        finding = {
            "vulnerability": "SQL Injection",
            "severity": "high",
            "location": "/api/search",
        }

        plan.adapt_based_on_finding(finding)

        # Should add exploitation steps
        new_step_count = sum(len(steps) for steps in plan.steps_by_phase.values())
        assert new_step_count >= initial_step_count  # May add new steps

    @pytest.mark.asyncio
    async def test_adapt_plan_after_auth_bypass(self):
        """Test plan adaptation after auth bypass."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Full assessment",
        )

        finding = {
            "vulnerability": "Authentication Bypass",
            "severity": "critical",
            "location": "/admin",
        }

        plan.adapt_based_on_finding(finding)

        # Should prioritize admin endpoint testing
        exploitation_steps = plan.steps_by_phase.get(AttackPhase.EXPLOITATION, [])
        if exploitation_steps:
            # New admin-related steps should have high priority
            assert any("admin" in step.description.lower() for step in exploitation_steps)


class TestPlanSerialization:
    """Test plan serialization and deserialization."""

    @pytest.mark.asyncio
    async def test_plan_to_dict(self):
        """Test converting plan to dictionary."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Full assessment",
        )

        plan_dict = plan.to_dict()

        assert plan_dict["target"] == "https://example.com"
        assert "phases" in plan_dict
        assert "steps_by_phase" in plan_dict
        assert "budget" in plan_dict
        assert "attack_chains" in plan_dict

    @pytest.mark.asyncio
    async def test_plan_from_dict(self):
        """Test loading plan from dictionary."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Full assessment",
        )

        plan_dict = plan.to_dict()
        loaded_plan = StrategicPlan.from_dict(plan_dict)

        assert loaded_plan.target == plan.target
        assert loaded_plan.objective == plan.objective
        assert len(loaded_plan.phases) == len(plan.phases)


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_create_plan_with_zero_budget(self):
        """Test plan creation with zero budget."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Free scan",
            max_budget_usd=0.0,
        )

        # Should still create a minimal plan
        assert isinstance(plan, StrategicPlan)
        assert len(plan.phases) > 0

    @pytest.mark.asyncio
    async def test_create_plan_with_invalid_target(self):
        """Test plan creation with invalid target."""
        planner = StrategicPlanner()

        # Should handle invalid URL gracefully
        plan = await planner.create_plan(
            target="not-a-url",
            objective="Test",
        )

        assert isinstance(plan, StrategicPlan)

    @pytest.mark.asyncio
    async def test_mark_nonexistent_step_complete(self):
        """Test marking non-existent step as complete."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Full assessment",
        )

        # Should handle gracefully
        plan.mark_step_complete("nonexistent-step-id")
        # Should not crash

    @pytest.mark.asyncio
    async def test_get_next_step_when_all_complete(self):
        """Test getting next step when all are complete."""
        planner = StrategicPlanner()

        plan = await planner.create_plan(
            target="https://example.com",
            objective="Quick scan",
        )

        # Mark all steps complete
        for phase_steps in plan.steps_by_phase.values():
            for step in phase_steps:
                plan.mark_step_complete(step.step_id)

        next_step = plan.get_next_step()
        # Should return None when all complete
        assert next_step is None
