"""
Example: Using Diminishing Returns Tracking for Bug Bounty Assessments.

This example shows how to use the diminishing returns tracking system to
automatically detect when the agent is stuck and should pivot to a different
attack vector, saving time and finding more bugs faster.
"""

import asyncio

from inferno.agent.sdk_executor import SDKAgentExecutor, AssessmentConfig
from inferno.config.settings import InfernoSettings
from inferno.core.diminishing_returns import DiminishingReturnsTracker


async def bug_bounty_with_auto_pivot():
    """Run a bug bounty assessment with automatic pivot detection."""

    config = AssessmentConfig(
        target="https://example.com",
        objective="Find high-severity vulnerabilities for bug bounty",
        mode="web",
        max_turns=200,

        # Enable diminishing returns tracking
        enable_diminishing_returns=True,
        diminishing_returns_window=10,  # Analyze last 10 attempts
        diminishing_returns_threshold=0.3,  # Pivot if success drops below 30%

        # Other features
        enable_branch_tracking=True,
        enable_chain_enumeration=True,
        auto_validate_findings=True,  # Validate findings for bug bounty
    )

    executor = SDKAgentExecutor()

    # Track diminishing returns warnings
    warnings_received = []

    def on_message(msg: str):
        if "DIMINISHING RETURNS DETECTED" in msg:
            warnings_received.append(msg)
            print("\n" + "="*60)
            print("⚠️  DIMINISHING RETURNS WARNING")
            print("="*60)
            print(msg)
            print("="*60 + "\n")

    executor.on_message(on_message)

    print("🎯 Starting bug bounty assessment...")
    print("🔄 Diminishing returns tracking enabled")
    print("⚡ Auto-pivot when stuck on failing approaches\n")

    result = await executor.run(config)

    # Print results
    print("\n" + "="*60)
    print("BUG BOUNTY ASSESSMENT RESULTS")
    print("="*60)
    print(f"Objective Met: {result.objective_met}")
    print(f"Findings: {result.findings_summary}")
    print(f"Total Turns: {result.turns}")
    print(f"Warnings Received: {len(warnings_received)}")
    print(f"Duration: {result.duration_seconds/60:.1f} minutes")
    print(f"Cost: ${result.total_cost_usd:.4f}")
    print("="*60 + "\n")

    return result


async def manual_diminishing_returns_tracking():
    """Example of using DiminishingReturnsTracker directly."""

    tracker = DiminishingReturnsTracker(
        window_size=10,
        threshold_ratio=0.3,
        min_samples=5,
    )

    print("📊 Simulating SQLi testing with diminishing returns...\n")

    # Simulate 20 SQLi attempts
    for i in range(20):
        # First 8 succeed, rest fail (simulating WAF kicking in)
        success = i < 8

        # Generate response signature
        if success:
            signature = f"response_success_{i}"
        else:
            signature = "blocked_by_waf"  # Same response when blocked

        tracker.record_attempt(
            category="sqli",
            success=success,
            response_signature=signature,
            details={
                "attempt": i + 1,
                "payload": f"' OR 1={i}--",
            }
        )

        print(f"Attempt {i+1}: {'✅ Success' if success else '❌ Failed'}")

        # Check for diminishing returns every 5 attempts
        if (i + 1) % 5 == 0:
            result = tracker.check_diminishing_returns("sqli")

            print(f"\n--- Analysis after {i+1} attempts ---")
            print(f"Overall success rate: {result.overall_rate:.1%}")
            print(f"Recent success rate: {result.recent_rate:.1%}")

            if result.diminishing:
                print(f"⚠️  DIMINISHING RETURNS: {result.reason}")
                print(f"📝 Recommendation: {result.recommendation}")
                print("\n🔄 PIVOT TO DIFFERENT APPROACH!")
                break
            else:
                print("✅ Continue current approach")

            print()

    # Get overall statistics
    stats = tracker.get_all_stats()
    print("\n" + "="*60)
    print("FINAL STATISTICS")
    print("="*60)
    print(f"Total attempts: {stats['total_attempts']}")
    print(f"Total successes: {stats['total_successes']}")
    print(f"Blocked categories: {', '.join(stats['blocked_categories']) or 'None'}")
    print(f"Recommended: {', '.join(stats['recommended_categories']) or 'None'}")
    print("="*60 + "\n")

    return tracker


async def multi_category_tracking():
    """Example showing tracking multiple attack categories."""

    tracker = DiminishingReturnsTracker()

    print("📊 Testing multiple attack vectors...\n")

    # Simulate different attack categories
    categories = {
        "sqli": [True, True, True, False, False, False, False, False],  # Declining
        "xss": [True, True, True, True, True, True, True, True],  # Consistent success
        "ssrf": [False, False, False, False, False, False],  # Never works
        "path_traversal": [True, False, True, False, True, True, True],  # Mixed
    }

    for category, results in categories.items():
        print(f"\n🎯 Testing {category.upper()}...")

        for i, success in enumerate(results):
            tracker.record_attempt(
                category=category,
                success=success,
                response_signature=f"{category}_{'success' if success else 'fail'}_{i}",
            )

            print(f"  Attempt {i+1}: {'✅' if success else '❌'}")

    print("\n" + "="*60)
    print("MULTI-CATEGORY ANALYSIS")
    print("="*60)

    # Check each category
    for category in categories:
        result = tracker.check_diminishing_returns(category)

        print(f"\n📌 {category.upper()}")
        print(f"   Overall: {result.overall_rate:.1%}")
        print(f"   Recent: {result.recent_rate:.1%}")
        print(f"   Status: {'⚠️  DIMINISHING' if result.diminishing else '✅ CONTINUE'}")

        if result.diminishing:
            print(f"   Reason: {result.reason}")

    # Get recommendations
    print("\n" + "-"*60)
    recommended = tracker.get_recommended_categories()
    blocked = tracker.get_blocked_categories()

    print("\n🚀 RECOMMENDED (highest success rate):")
    for cat in recommended:
        print(f"   ✅ {cat}")

    print("\n🚫 BLOCKED (diminishing returns):")
    for cat in blocked:
        print(f"   ❌ {cat}")

    print("\n💡 PIVOT SUGGESTION:")
    print(f"   {tracker.generate_pivot_suggestion()}")
    print("="*60 + "\n")

    return tracker


async def real_world_scenario():
    """Simulate a real-world assessment scenario."""

    tracker = DiminishingReturnsTracker(
        window_size=8,
        threshold_ratio=0.4,  # 40% threshold (less aggressive)
        min_samples=5,
    )

    print("🎯 Real-World Scenario: E-commerce Web Application\n")
    print("Target: https://shop.example.com")
    print("Objective: Find authentication bypass or payment vulnerabilities\n")

    scenarios = [
        {
            "phase": "1. Initial Reconnaissance",
            "category": "enumeration",
            "attempts": [True, True, True, True, True],
            "description": "Enumerating endpoints and technologies"
        },
        {
            "phase": "2. SQL Injection Testing",
            "category": "sqli",
            "attempts": [True, True, True, False, False, False, False, False, False, False],
            "description": "SQLi payloads - WAF detected and blocked after 3 attempts"
        },
        {
            "phase": "3. XSS Testing",
            "category": "xss",
            "attempts": [True, False, True, False, False],
            "description": "XSS payloads - some sanitization but bypasses possible"
        },
        {
            "phase": "4. Business Logic Testing",
            "category": "business_logic",
            "attempts": [True, True, True, True, True, True],
            "description": "Testing cart manipulation and payment logic"
        },
    ]

    for scenario in scenarios:
        print(f"\n{scenario['phase']}")
        print(f"📝 {scenario['description']}")
        print("-" * 60)

        for i, success in enumerate(scenario['attempts'], 1):
            tracker.record_attempt(
                category=scenario['category'],
                success=success,
                response_signature=f"{scenario['category']}_resp_{i}",
            )

            status = "✅ Success" if success else "❌ Failed"
            print(f"   Attempt {i}: {status}")

        # Check for diminishing returns
        result = tracker.check_diminishing_returns(scenario['category'])

        print(f"\n   Analysis:")
        print(f"   - Overall success: {result.overall_rate:.1%}")
        print(f"   - Recent success: {result.recent_rate:.1%}")

        if result.diminishing:
            print(f"   - ⚠️  Status: DIMINISHING RETURNS ({result.reason})")
            print(f"   - 💡 Action: {result.recommendation}")
            print(f"   - 🔄 PIVOT to different approach!")
        else:
            print(f"   - ✅ Status: Continue exploring")

    # Final analysis
    print("\n" + "="*60)
    print("FINAL ASSESSMENT ANALYSIS")
    print("="*60)

    recommended = tracker.get_recommended_categories()
    blocked = tracker.get_blocked_categories()

    print("\n🎯 Most Promising Attack Vectors:")
    for i, cat in enumerate(recommended[:3], 1):
        stats = tracker.get_category_stats(cat)
        print(f"   {i}. {cat.upper()}")
        print(f"      - Success rate: {stats['success_rate']:.1%}")
        print(f"      - Attempts: {stats['total_attempts']}")

    print("\n🚫 Ineffective/Blocked Vectors:")
    for cat in blocked:
        stats = tracker.get_category_stats(cat)
        print(f"   - {cat.upper()}")
        print(f"      - Success rate: {stats['success_rate']:.1%}")
        print(f"      - Last attempt: Recent")

    print("\n💡 Recommended Focus:")
    pivot = tracker.generate_pivot_suggestion()
    print(f"   {pivot}")
    print("="*60 + "\n")

    return tracker


async def main():
    """Run examples."""

    print("="*60)
    print("DIMINISHING RETURNS EXAMPLES")
    print("="*60 + "\n")

    # Example 1: Bug bounty with auto-pivot
    print("\n📌 Example 1: Bug Bounty with Auto-Pivot")
    print("-" * 60)
    # Uncomment to run real assessment
    # await bug_bounty_with_auto_pivot()

    # Example 2: Manual tracking
    print("\n📌 Example 2: Manual Diminishing Returns Tracking")
    print("-" * 60)
    await manual_diminishing_returns_tracking()

    # Example 3: Multi-category tracking
    print("\n📌 Example 3: Multi-Category Tracking")
    print("-" * 60)
    await multi_category_tracking()

    # Example 4: Real-world scenario
    print("\n📌 Example 4: Real-World Scenario")
    print("-" * 60)
    await real_world_scenario()

    print("\n✅ All examples complete!")


if __name__ == "__main__":
    asyncio.run(main())
