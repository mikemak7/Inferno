"""
Base prompt system for Inferno.

This module provides the foundation for modular, composable prompts
that can be assembled based on the assessment context.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PromptPriority(int, Enum):
    """Priority levels for prompt modules (lower = higher priority)."""

    CRITICAL = 0  # Safety rules, ethical guidelines
    HIGH = 10  # Core methodology
    MEDIUM = 20  # Technique-specific guidance
    LOW = 30  # Tips and optimizations
    OPTIONAL = 40  # Nice-to-have context


class AgentPersona(str, Enum):
    """Agent personas that affect behavior and approach."""

    THOROUGH = "thorough"  # Comprehensive, methodical
    AGGRESSIVE = "aggressive"  # Fast, exploits quickly
    STEALTHY = "stealthy"  # Evades detection
    EDUCATIONAL = "educational"  # Explains as it goes
    CTF = "ctf"  # CTF competition mode


@dataclass
class PromptModule:
    """
    A modular prompt component that can be composed with others.

    Prompt modules are building blocks that combine to form the
    complete system prompt based on the assessment context.
    """

    name: str
    content: str
    priority: PromptPriority = PromptPriority.MEDIUM
    requires: list[str] = field(default_factory=list)  # Required modules
    conflicts: list[str] = field(default_factory=list)  # Incompatible modules
    tags: list[str] = field(default_factory=list)  # For filtering
    enabled: bool = True

    def render(self, context: dict[str, Any] | None = None) -> str:
        """
        Render the prompt with optional context variables.

        Uses safe string template substitution that ignores
        unmatched placeholders (e.g., JSON content with braces).

        Args:
            context: Variables to substitute in the prompt.

        Returns:
            Rendered prompt string.
        """
        if context:
            from string import Template

            # Use Template with safe_substitute to avoid KeyError on
            # content that contains braces (like JSON examples)
            # First, convert {var} style to $var style for Template
            content = self.content
            for key in context:
                content = content.replace("{" + key + "}", "${" + key + "}")

            try:
                template = Template(content)
                return template.safe_substitute(context)
            except (KeyError, ValueError):
                # If any error, return original content
                return self.content
        return self.content


class PromptModuleProvider(ABC):
    """Abstract base class for prompt module providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name."""
        ...

    @abstractmethod
    def get_modules(self) -> list[PromptModule]:
        """Get all prompt modules from this provider."""
        ...

    def get_module(self, name: str) -> PromptModule | None:
        """Get a specific module by name."""
        for module in self.get_modules():
            if module.name == name:
                return module
        return None


@dataclass
class PromptContext:
    """Context for prompt assembly."""

    target: str
    objective: str
    scope: str = "as provided"
    persona: AgentPersona = AgentPersona.THOROUGH
    assessment_type: str = "general"  # web, network, code, ctf
    rules: list[str] = field(default_factory=list)
    additional_context: dict[str, Any] = field(default_factory=dict)


class PromptAssembler:
    """
    Assembles complete system prompts from modular components.

    The assembler collects modules from various providers, resolves
    dependencies and conflicts, and combines them into a coherent
    system prompt.
    """

    def __init__(self) -> None:
        """Initialize the prompt assembler."""
        self._providers: list[PromptModuleProvider] = []
        self._overrides: dict[str, PromptModule] = {}

    def register_provider(self, provider: PromptModuleProvider) -> None:
        """Register a prompt module provider."""
        self._providers.append(provider)

    def override_module(self, module: PromptModule) -> None:
        """Override a module by name."""
        self._overrides[module.name] = module

    def get_all_modules(self) -> list[PromptModule]:
        """Get all available modules from all providers."""
        modules: dict[str, PromptModule] = {}

        # Collect from providers
        for provider in self._providers:
            for module in provider.get_modules():
                modules[module.name] = module

        # Apply overrides
        modules.update(self._overrides)

        return list(modules.values())

    def assemble(
        self,
        context: PromptContext,
        include_tags: list[str] | None = None,
        exclude_tags: list[str] | None = None,
    ) -> str:
        """
        Assemble a complete system prompt from modules.

        Args:
            context: The prompt context.
            include_tags: Only include modules with these tags.
            exclude_tags: Exclude modules with these tags.

        Returns:
            Complete assembled system prompt.
        """
        modules = self.get_all_modules()

        # Filter by enabled status
        modules = [m for m in modules if m.enabled]

        # Filter by tags
        if include_tags:
            modules = [
                m for m in modules
                if any(tag in m.tags for tag in include_tags)
            ]
        if exclude_tags:
            modules = [
                m for m in modules
                if not any(tag in m.tags for tag in exclude_tags)
            ]

        # Resolve dependencies and conflicts
        modules = self._resolve_dependencies(modules)

        # Sort by priority
        modules.sort(key=lambda m: m.priority.value)

        # Build context dict for rendering
        render_context = {
            "target": context.target,
            "objective": context.objective,
            "scope": context.scope,
            "persona": context.persona.value,
            "assessment_type": context.assessment_type,
            "rules": "\n".join(f"- {r}" for r in context.rules) if context.rules else "None specified",
            **context.additional_context,
        }

        # Render and combine
        parts = []
        for module in modules:
            rendered = module.render(render_context)
            if rendered.strip():
                parts.append(rendered)

        return "\n\n".join(parts)

    def _resolve_dependencies(
        self,
        modules: list[PromptModule],
    ) -> list[PromptModule]:
        """Resolve module dependencies and remove conflicts."""
        module_names = {m.name for m in modules}
        result = []

        for module in modules:
            # Check if required modules are present
            missing = [r for r in module.requires if r not in module_names]
            if missing:
                continue  # Skip module with missing dependencies

            # Check for conflicts
            has_conflict = any(c in module_names for c in module.conflicts)
            if has_conflict:
                continue  # Skip conflicting module

            result.append(module)

        return result
