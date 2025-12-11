"""
SwarmCoordinator Usage Example.

Demonstrates how to use the SwarmCoordinator for intelligent agent orchestration.
"""

import asyncio
from anthropic import AsyncAnthropic

from inferno.config.settings import InfernoSettings
from inferno.swarm import SwarmCoordinator, SwarmTool
from inferno.tools.registry import ToolRegistry


async def main():
    """Example usage of SwarmCoordinator."""

    # Initialize settings and client
    settings = InfernoSettings()
    client = AsyncAnthropic(api_key=settings.anthropic_api_key)

    # Create tool registry
    registry = ToolRegistry()

    # Create coordinator
    coordinator = SwarmCoordinator(
        client=client,
        registry=registry,
        operation_id="example_op_001",
    )

    # Create and attach SwarmTool
    swarm_tool = SwarmTool(
        client=client,
        parent_registry=registry,
        operation_id="example_op_001",
        target="https://example.com",
    )
    coordinator.set_swarm_tool(swarm_tool)

    # Plan assessment
    print("Planning assessment...")
    plan = await coordinator.plan_assessment(
        target="https://example.com",
        objective="Full security assessment",
        ctf_mode=False,
    )

    print(f"Assessment plan created:")
    print(f"  - Target: {plan.target}")
    print(f"  - Phases: {[p.value for p in plan.phases]}")
    print(f"  - Initial spawns: {len(plan.initial_spawns)}")
    print(f"  - Spawn rules: {len(plan.spawn_rules)}")
    print(f"  - Estimated duration: {plan.estimated_duration_minutes} minutes")
    print()

    # Simulate some findings to trigger spawn rules
    print("Simulating finding reporting...")
    await coordinator.handle_finding(
        agent_id="test_scanner_001",
        finding={
            "vuln_type": "sql_injection",
            "severity": "high",
            "target": "https://example.com/login",
            "location": "/login",
            "title": "SQL Injection in Login Form",
            "description": "Boolean-based blind SQLi vulnerability",
            "evidence": "Payload: ' OR '1'='1",
            "remediation": "Use parameterized queries",
        }
    )

    # Check spawn decisions
    print("Checking spawn decisions...")
    decision = coordinator.get_spawn_decision(
        current_phase=plan.phases[2],  # SCANNING phase
        metrics=coordinator._get_current_metrics(),
        recent_findings=coordinator._all_findings,
    )

    if decision:
        print(f"Spawn decision triggered:")
        print(f"  - Rule: {decision['rule']}")
        print(f"  - Agents: {[a.value for a in decision['agents']]}")
        print(f"  - Task: {decision['task']}")
        print(f"  - Priority: {decision['priority']}")
    print()

    # Synthesize attack chains
    print("Synthesizing attack chains...")
    chains = await coordinator.synthesize_findings()

    print(f"Found {len(chains)} attack chain(s):")
    for chain in chains:
        print(f"  - {chain.name}")
        print(f"    Severity: {chain.severity.value}")
        print(f"    Steps: {len(chain.steps)}")
        print(f"    Impact: {chain.impact}")
        print(f"    Exploitability: {chain.estimated_exploitability:.1%}")
    print()

    # Example: CTF mode planning
    print("Planning CTF assessment...")
    ctf_plan = await coordinator.plan_assessment(
        target="http://ctf.example.com",
        objective="Capture the flag",
        ctf_mode=True,
    )

    print(f"CTF Assessment plan:")
    print(f"  - CTF mode: {ctf_plan.ctf_mode}")
    print(f"  - Initial spawns: {len(ctf_plan.initial_spawns)} (parallel)")
    print(f"  - Phases: {[p.value for p in ctf_plan.phases]}")
    print(f"  - Estimated duration: {ctf_plan.estimated_duration_minutes} minutes")

    # Show initial spawn details
    print("\nInitial spawns:")
    for spec in ctf_plan.initial_spawns:
        print(f"  - {spec.agent_type.value}")
        print(f"    Task: {spec.task}")
        print(f"    Priority: {spec.priority}")


if __name__ == "__main__":
    asyncio.run(main())
