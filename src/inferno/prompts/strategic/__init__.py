"""Strategic prompt templates for Inferno-AI.

This module contains Mako-based templates for injecting rich contextual intelligence
into agent prompts. Templates provide actionable guidance based on:
- Application model understanding
- Attack plan progress and prioritization
- Parameter role-based testing strategies
- Attack chain discovery and exploitation

Templates are designed to be rendered by MakoEngine with appropriate context objects.
"""

from pathlib import Path

# Template directory for easy reference
STRATEGIC_TEMPLATES_DIR = Path(__file__).parent

# Available template files
TEMPLATES = {
    "application_model": "application_model_context.md",
    "attack_plan": "attack_plan_context.md",
    "parameter_roles": "parameter_role_guidance.md",
    "chain_discovery": "chain_discovery_context.md",
}


def get_template_path(template_name: str) -> Path:
    """Get the full path to a strategic template.

    Args:
        template_name: Name of the template (key from TEMPLATES dict)

    Returns:
        Path object pointing to the template file

    Raises:
        KeyError: If template_name is not recognized
        FileNotFoundError: If template file doesn't exist
    """
    if template_name not in TEMPLATES:
        available = ", ".join(TEMPLATES.keys())
        raise KeyError(
            f"Unknown template '{template_name}'. Available templates: {available}"
        )

    template_path = STRATEGIC_TEMPLATES_DIR / TEMPLATES[template_name]

    if not template_path.exists():
        raise FileNotFoundError(f"Template file not found: {template_path}")

    return template_path


__all__ = [
    "STRATEGIC_TEMPLATES_DIR",
    "TEMPLATES",
    "get_template_path",
]
