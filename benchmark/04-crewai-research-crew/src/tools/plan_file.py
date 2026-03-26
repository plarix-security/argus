"""Shared plan file for inter-agent communication."""

from pathlib import Path
from crewai.tools import tool

PLAN_PATH = Path("./output/plan.md")


@tool
def read_plan() -> str:
    """Read the current research plan.

    Returns:
        Plan content
    """
    PLAN_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not PLAN_PATH.exists():
        return "No plan exists yet."

    # AFB04 INFO: Plan influences agent behavior
    content = PLAN_PATH.read_text()
    return content


@tool
def update_plan(new_content: str) -> str:
    """Update the shared research plan.

    VULNERABILITY: Any agent can overwrite the plan,
    enabling cross-agent instruction injection.

    Args:
        new_content: New plan content

    Returns:
        Confirmation
    """
    PLAN_PATH.parent.mkdir(parents=True, exist_ok=True)
    # AFB04 WARNING: Shared mutable file
    PLAN_PATH.write_text(new_content)
    return "Plan updated successfully"
