#!/usr/bin/env python3
"""
Demo of MessageBus and SynthesisEngine working together.

This example shows how multiple agents can:
1. Communicate findings via MessageBus
2. Have SynthesisEngine correlate findings into attack chains
3. Get recommendations for next targets
"""

import asyncio
from datetime import datetime

from inferno.swarm import (
    get_message_bus,
    get_synthesis_engine,
    MessageType,
    AgentMessage,
)


async def recon_agent_handler(message: AgentMessage) -> None:
    """Handler for reconnaissance agent."""
    print(f"[RECON] Received {message.message_type}: {message.payload}")


async def scanner_agent_handler(message: AgentMessage) -> None:
    """Handler for scanner agent."""
    print(f"[SCANNER] Received {message.message_type}: {message.payload}")


async def exploiter_agent_handler(message: AgentMessage) -> None:
    """Handler for exploiter agent."""
    print(f"[EXPLOITER] Received {message.message_type}: {message.payload}")


async def main():
    """Run the demo."""
    # Initialize components
    bus = get_message_bus()
    synthesis = get_synthesis_engine()

    await bus.start()

    # Subscribe agents
    await bus.subscribe("recon_001", recon_agent_handler)
    await bus.subscribe("scanner_001", scanner_agent_handler)
    await bus.subscribe("exploiter_001", exploiter_agent_handler)

    print("=" * 80)
    print("SWARM COORDINATION DEMO")
    print("=" * 80)

    # Simulate agent discovering findings
    print("\n[1] Recon agent discovers file upload vulnerability...")
    finding1 = {
        "finding_id": "f001",
        "vuln_type": "file_upload",
        "severity": "high",
        "endpoint": "/upload.php",
        "method": "POST",
        "parameters": ["file", "path"],
        "agent_id": "recon_001",
        "timestamp": datetime.utcnow().isoformat(),
        "metadata": {"file_types_allowed": ["*"]},
    }
    await bus.broadcast_finding("recon_001", finding1, priority=75)
    synthesis.add_finding(finding1)

    await asyncio.sleep(0.5)

    print("\n[2] Scanner agent discovers LFI vulnerability...")
    finding2 = {
        "finding_id": "f002",
        "vuln_type": "lfi",
        "severity": "high",
        "endpoint": "/view.php",
        "method": "GET",
        "parameters": ["page"],
        "agent_id": "scanner_001",
        "timestamp": datetime.utcnow().isoformat(),
        "metadata": {"filter_bypass": "..%2f"},
    }
    await bus.broadcast_finding("scanner_001", finding2, priority=75)
    synthesis.add_finding(finding2)

    await asyncio.sleep(0.5)

    print("\n[3] Recon agent discovers SSRF vulnerability...")
    finding3 = {
        "finding_id": "f003",
        "vuln_type": "ssrf",
        "severity": "critical",
        "endpoint": "/proxy.php",
        "method": "GET",
        "parameters": ["url"],
        "agent_id": "recon_001",
        "timestamp": datetime.utcnow().isoformat(),
        "metadata": {"internal_access": True},
    }
    await bus.broadcast_finding("recon_001", finding3, priority=90)
    synthesis.add_finding(finding3)

    await asyncio.sleep(0.5)

    print("\n[4] Scanner agent discovers SQLi vulnerability...")
    finding4 = {
        "finding_id": "f004",
        "vuln_type": "sqli",
        "severity": "critical",
        "endpoint": "/search.php",
        "method": "GET",
        "parameters": ["q"],
        "agent_id": "scanner_001",
        "timestamp": datetime.utcnow().isoformat(),
        "metadata": {"dbms": "MySQL", "injectable_param": "q"},
    }
    await bus.broadcast_finding("scanner_001", finding4, priority=90)
    synthesis.add_finding(finding4)

    await asyncio.sleep(0.5)

    # Synthesize attack chains
    print("\n[5] Synthesizing attack chains...")
    chains = await synthesis.synthesize()

    print(f"\nDiscovered {len(chains)} attack chains:")
    for chain in chains[:5]:  # Show top 5
        print(
            f"  - {chain.name} | Score: {chain.score:.2f} | "
            f"Difficulty: {chain.total_difficulty} | Impact: {chain.total_impact}"
        )

    # Get recommendations for next targets
    print("\n[6] Getting recommendations for next targets...")
    current_findings = [finding1, finding2, finding3, finding4]
    next_targets = synthesis.get_next_targets(current_findings)

    print(f"\nRecommended vulnerability types to search for:")
    for target in next_targets:
        print(f"  - {target}")

    # Generate report
    print("\n[7] Generating synthesis report...")
    print("\n" + synthesis.get_report())

    # Test request/response pattern
    print("\n[8] Testing context request between agents...")
    try:
        # This would timeout since we don't have a real handler responding
        # But it demonstrates the API
        context_request = asyncio.create_task(
            bus.request_context(
                requester="exploiter_001",
                target_agent="scanner_001",
                context_type="sql_injection_details",
                timeout_seconds=2.0,
            )
        )

        # In a real scenario, scanner_001 would respond with a RESPONSE message
        # For demo, we'll just let it timeout
        try:
            await context_request
        except asyncio.TimeoutError:
            print("  (Timeout expected - no handler responding)")

    except Exception as e:
        print(f"  Error: {e}")

    # Show message bus stats
    print("\n[9] Message Bus Statistics:")
    stats = bus.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")

    # Cleanup
    await bus.stop()
    synthesis.clear()

    print("\n" + "=" * 80)
    print("DEMO COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
