"""Shared state management for multi-agent communication."""

import json
from pathlib import Path
from langchain_core.tools import tool

STATE_FILE = Path("./workspace/shared_state.json")


@tool
def get_shared_state(key: str = None) -> str:
    """Read from the shared state file.

    Args:
        key: Specific key to read, or None for all state

    Returns:
        State content
    """
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not STATE_FILE.exists():
        return "{}"

    # AFB04 INFO: Shared state read
    content = STATE_FILE.read_text()
    state = json.loads(content) if content else {}

    if key:
        return json.dumps(state.get(key, None))
    return json.dumps(state)


@tool
def update_shared_state(key: str, value: str) -> str:
    """Update the shared state file.

    VULNERABILITY: Any agent can modify shared state,
    enabling cross-agent instruction injection.

    Args:
        key: State key to update
        value: New value

    Returns:
        Confirmation
    """
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

    state = {}
    if STATE_FILE.exists():
        content = STATE_FILE.read_text()
        state = json.loads(content) if content else {}

    state[key] = value
    # AFB04 WARNING: Shared state mutation
    STATE_FILE.write_text(json.dumps(state, indent=2))
    return f"Updated state[{key}]"
