"""
Think Tool for Inferno.

Forces explicit reasoning before action. Based on research showing that
explicit "think" steps improve agent decision-making and reduce wasted turns.

The think tool doesn't execute anything - it just logs the thought and returns it.
This forces the model to pause, reflect, and strategize before acting.
"""

from __future__ import annotations

from typing import Any

import structlog

from inferno.tools.base import CoreTool, ToolCategory, ToolResult

logger = structlog.get_logger(__name__)


class ThinkTool(CoreTool):
    """
    Tool for explicit reasoning and strategic planning.

    Use this tool to:
    - Analyze the current situation before taking action
    - Plan your next steps strategically
    - Evaluate why an approach isn't working
    - Consider alternative attack vectors
    - Reflect on findings and their implications
    - Decide whether to pivot or persist

    This tool doesn't retrieve new information or modify anything.
    It simply logs your thought process and returns it, forcing
    deliberate reasoning before action.

    Best used:
    - Before starting a new attack vector
    - After multiple failed attempts (to avoid loops)
    - When confidence is low
    - Before reporting a finding (to validate it mentally)
    - When stuck or unsure what to do next
    """

    @property
    def name(self) -> str:
        return "think"

    @property
    def description(self) -> str:
        return """Use this tool to think through your approach before acting.

WHEN TO USE:
- Before starting a new attack vector
- After 2-3 failed attempts (avoid loops!)
- When unsure what to do next
- Before reporting a finding (validate your reasoning)
- When you need to prioritize between options

WHAT TO THINK ABOUT:
- What have I tried so far? What worked/didn't work?
- What's the most likely vulnerability given the target's profile?
- Am I stuck in a loop? Should I pivot?
- What evidence supports this finding?
- What's the highest-value next action?

This tool doesn't execute anything - it just records your reasoning.
Use it to force yourself to strategize before acting."""

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "thought": {
                    "type": "string",
                    "description": "Your reasoning, analysis, or strategic thinking. Be specific about what you're considering and why.",
                },
                "thought_type": {
                    "type": "string",
                    "enum": [
                        "situation_analysis",  # Analyzing current state
                        "strategy",            # Planning next steps
                        "reflection",          # Looking back at what happened
                        "hypothesis",          # Forming a hypothesis about a vuln
                        "pivot_decision",      # Deciding to change approach
                        "validation",          # Validating a finding mentally
                        "prioritization",      # Choosing between options
                    ],
                    "description": "Type of thinking being done. Helps categorize the thought.",
                    "default": "strategy",
                },
                "confidence": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 100,
                    "description": "Your current confidence level (0-100) in making progress toward the objective. Report this honestly - low confidence triggers helpful subagent deployment.",
                },
            },
            "required": ["thought"],
        }

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.CORE

    @property
    def defer_loading(self) -> bool:
        """Think tool is always available - core tool."""
        return False

    async def execute(self, **kwargs: Any) -> ToolResult:
        """
        Record and return the thought.

        This doesn't do anything except log and return the thought,
        forcing the agent to explicitly reason before acting.

        If confidence is provided and low, the system may recommend
        spawning subagents to help make progress.
        """
        thought = kwargs.get("thought", "")
        thought_type = kwargs.get("thought_type", "strategy")
        confidence = kwargs.get("confidence")  # Optional 0-100

        if not thought:
            return ToolResult(
                success=False,
                output="",
                error="Thought cannot be empty. What are you thinking about?",
            )

        # Log the thought for tracing/debugging
        logger.info(
            "agent_think",
            thought_type=thought_type,
            thought_length=len(thought),
            confidence=confidence,
            thought_preview=thought[:200] + "..." if len(thought) > 200 else thought,
        )

        # Format response based on thought type
        type_prompts = {
            "situation_analysis": "Situation analyzed. What action does this analysis suggest?",
            "strategy": "Strategy formed. Execute your plan.",
            "reflection": "Reflection complete. What will you do differently?",
            "hypothesis": "Hypothesis noted. How will you test it?",
            "pivot_decision": "Pivot decision made. Proceed with new approach.",
            "validation": "Validation complete. Is the finding confirmed?",
            "prioritization": "Priorities set. Start with the highest-value action.",
        }

        follow_up = type_prompts.get(thought_type, "Thought recorded. Proceed.")

        # Build output
        output_parts = [f"[{thought_type.upper()}]", thought, ""]

        # Add confidence-based guidance
        if confidence is not None:
            output_parts.append(f"Confidence: {confidence}%")
            if confidence < 40:
                output_parts.append(
                    "\n⚠️ LOW CONFIDENCE DETECTED. Consider deploying a subagent "
                    "to help explore with fresh context. Use the swarm tool."
                )
            elif confidence < 60:
                output_parts.append(
                    "\n💡 Moderate confidence. If stuck for 5+ more turns, "
                    "consider spawning a focused subagent."
                )

        output_parts.append(f"\n{follow_up}")

        return ToolResult(
            success=True,
            output="\n".join(output_parts),
            metadata={
                "thought_type": thought_type,
                "thought_length": len(thought),
                "confidence": confidence,
            },
        )
