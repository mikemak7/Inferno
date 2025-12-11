"""
CAI-Inspired Methodology Prompts

These prompts are based on the CAI (Cybersecurity AI) project's methodology
for effective security testing. They provide structured approaches for:

- Bug Bounty Hunting
- Web Application Penetration Testing
- CTF Challenge Solving

Usage:
    from inferno.prompts.cai_methodology import load_methodology

    prompt = load_methodology("bug_bounty")  # or "web_pentester" or "ctf_solver"
"""

from pathlib import Path

METHODOLOGY_DIR = Path(__file__).parent


def load_methodology(name: str) -> str:
    """
    Load a methodology prompt by name.

    Args:
        name: One of "bug_bounty", "web_pentester", "ctf_solver"

    Returns:
        The methodology prompt as a string

    Raises:
        FileNotFoundError: If methodology doesn't exist
    """
    filepath = METHODOLOGY_DIR / f"{name}.md"
    if not filepath.exists():
        available = [f.stem for f in METHODOLOGY_DIR.glob("*.md")]
        raise FileNotFoundError(
            f"Methodology '{name}' not found. Available: {available}"
        )
    return filepath.read_text()


def get_available_methodologies() -> list[str]:
    """Get list of available methodology names."""
    return [f.stem for f in METHODOLOGY_DIR.glob("*.md")]


# Pre-load for quick access
BUG_BOUNTY_METHODOLOGY = None
WEB_PENTESTER_METHODOLOGY = None
CTF_SOLVER_METHODOLOGY = None


def _lazy_load(name: str) -> str:
    """Lazy load a methodology prompt."""
    global BUG_BOUNTY_METHODOLOGY, WEB_PENTESTER_METHODOLOGY, CTF_SOLVER_METHODOLOGY

    if name == "bug_bounty":
        if BUG_BOUNTY_METHODOLOGY is None:
            BUG_BOUNTY_METHODOLOGY = load_methodology("bug_bounty")
        return BUG_BOUNTY_METHODOLOGY
    elif name == "web_pentester":
        if WEB_PENTESTER_METHODOLOGY is None:
            WEB_PENTESTER_METHODOLOGY = load_methodology("web_pentester")
        return WEB_PENTESTER_METHODOLOGY
    elif name == "ctf_solver":
        if CTF_SOLVER_METHODOLOGY is None:
            CTF_SOLVER_METHODOLOGY = load_methodology("ctf_solver")
        return CTF_SOLVER_METHODOLOGY
    else:
        return load_methodology(name)
