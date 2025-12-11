"""
Example: Using CTF Mode with Diminishing Returns for HackTheBox/CTF challenges.

This example shows how to use Inferno-AI in CTF mode with aggressive flag detection
and diminishing returns tracking to quickly solve CTF challenges.
"""

import asyncio
from pathlib import Path

from inferno.agent.sdk_executor import SDKAgentExecutor, AssessmentConfig
from inferno.config.settings import InfernoSettings


async def solve_htb_challenge():
    """Solve a HackTheBox web challenge using CTF mode."""

    # Configure for CTF mode
    config = AssessmentConfig(
        target="http://10.10.11.97",  # HTB target IP
        objective="Find the user and root flags",
        mode="ctf",  # Enable CTF mode (aggressive, fast)
        target_type="web",
        max_turns=100,  # Lower for CTF speed

        # CTF-specific settings
        ctf_mode=True,  # Explicit CTF mode
        enable_diminishing_returns=True,  # Auto-pivot when stuck
        diminishing_returns_window=10,
        diminishing_returns_threshold=0.3,

        # Speed optimizations
        auto_continue=True,
        max_continuations=3,  # Fewer continuations for CTF

        # Disable slower features
        auto_validate_findings=False,  # Skip validation in CTF
        enable_branch_tracking=True,  # Keep for systematic exploration
        enable_chain_enumeration=True,  # Keep for exploit chaining
    )

    # Initialize executor with settings
    settings = InfernoSettings()
    executor = SDKAgentExecutor(settings=settings)

    # Add callback to see flags as they're found
    def on_message(msg: str):
        if "FLAG!" in msg or "flag{" in msg.lower():
            print(f"\n🚩 POTENTIAL FLAG: {msg}\n")

    executor.on_message(on_message)

    # Run assessment
    print("🎯 Starting HackTheBox challenge in CTF mode...")
    print("⚡ Aggressive mode enabled - speed over stealth")
    print("🔄 Diminishing returns tracking - auto-pivot when stuck")
    print("🚩 Auto flag detection - all responses scanned\n")

    result = await executor.run(config)

    # Print results
    print("\n" + "="*60)
    print("CTF CHALLENGE RESULTS")
    print("="*60)
    print(f"Objective Met: {result.objective_met}")
    print(f"Stop Reason: {result.stop_reason}")
    print(f"Total Turns: {result.turns}")
    print(f"Total Cost: ${result.total_cost_usd:.4f}")
    print(f"Duration: {result.duration_seconds:.1f}s")

    if result.flags_found:
        print(f"\n🚩 FLAGS FOUND ({len(result.flags_found)}):")
        for i, flag in enumerate(result.flags_found, 1):
            print(f"  {i}. {flag}")
    else:
        print("\n⚠️  No flags found")

    print(f"\nArtifacts: {result.artifacts_dir}")
    print("="*60 + "\n")

    return result


async def solve_ctf_web_challenge():
    """Solve a CTF web challenge with custom success criteria."""

    config = AssessmentConfig(
        target="http://ctf.example.com:8080/challenge",
        objective="Find the flag",
        mode="ctf",
        target_type="web",
        max_turns=50,

        # Success criteria
        success_criteria=[
            "Find and extract the flag",
            "Document the vulnerability that led to the flag",
        ],

        # Rules for this CTF
        rules=[
            "Do NOT perform DoS attacks",
            "Do NOT attempt to compromise other teams",
            "Time limit: 2 hours",
        ],

        # CTF mode
        ctf_mode=True,
        enable_diminishing_returns=True,
    )

    executor = SDKAgentExecutor()

    # Callback for live progress
    def on_turn(turn: int, tokens: int, cost: float):
        print(f"Turn {turn}: {tokens:,} tokens, ${cost:.4f}")

    def on_finding(title: str, severity: str, location: str):
        print(f"📝 Finding: [{severity}] {title} @ {location}")

    executor.on_turn(on_turn)
    executor.on_finding(on_finding)

    result = await executor.run(config)

    if result.flags_found:
        print(f"\n✅ SUCCESS! Found {len(result.flags_found)} flag(s)")
        for flag in result.flags_found:
            print(f"   🚩 {flag}")
    else:
        print("\n❌ No flag found")

    return result


async def solve_with_payload_blasting():
    """Example using the CTFPayloadBlaster directly for targeted payload testing."""

    from inferno.core.ctf_mode import CTFPayloadBlaster, FlagDetector
    from inferno.tools.http import HTTPTool

    # Initialize tools
    blaster = CTFPayloadBlaster(max_concurrent=10)
    http_tool = HTTPTool()

    # SQL injection payloads
    sqli_payloads = [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "admin'--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1' AND 1=1--",
        "1' AND 1=2--",
        "' OR 'a'='a",
    ]

    print("🚀 Blasting SQL injection payloads...")

    # Test login form
    results = await blaster.blast_payloads(
        base_url="http://ctf.example.com/login",
        parameter="username",
        payloads=sqli_payloads,
        http_tool=http_tool,
        method="POST",
    )

    print(f"\n📊 Results:")
    print(f"   Total tested: {results['total_tested']}")
    print(f"   Successful: {results['successful']}")
    print(f"   Unique responses: {results['unique_responses']}")
    print(f"   Flags found: {len(results['found_flags'])}")

    if results['best_flag']:
        print(f"\n🚩 Best Flag: {results['best_flag'].flag}")
        print(f"   Confidence: {results['best_flag'].confidence:.1%}")
        print(f"   Source: {results['best_flag'].source}")

    return results


async def main():
    """Run examples."""

    print("="*60)
    print("CTF MODE EXAMPLES")
    print("="*60 + "\n")

    # Example 1: HackTheBox challenge
    print("\n📌 Example 1: HackTheBox Challenge")
    print("-" * 60)
    # await solve_htb_challenge()

    # Example 2: General CTF web challenge
    print("\n📌 Example 2: General CTF Web Challenge")
    print("-" * 60)
    # await solve_ctf_web_challenge()

    # Example 3: Direct payload blasting
    print("\n📌 Example 3: Direct Payload Blasting")
    print("-" * 60)
    # await solve_with_payload_blasting()

    print("\n✅ Examples complete!")


if __name__ == "__main__":
    # Uncomment the example you want to run
    asyncio.run(main())
