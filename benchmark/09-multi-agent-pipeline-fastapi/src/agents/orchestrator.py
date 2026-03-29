"""
Orchestrator Agent

Manages script execution and sub-agent spawning.
Demonstrates AFB04 vulnerabilities in shell execution and recursive spawning.
"""

from typing import Any, Dict
import subprocess
import httpx
from langchain_core.tools import tool


@tool
def run_script(script_path: str, args: list = None) -> Dict[str, Any]:
    """
    Execute an external script via subprocess.

    AFB04 CRITICAL: Shell command execution without validation.
    Script path and arguments are user-controlled.

    Args:
        script_path: Path to the script to execute
        args: Optional list of arguments
    """
    # Build command
    cmd = [script_path]
    if args:
        cmd.extend(args)

    # No validation of script path
    # No sandboxing or permission checks
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    #
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr
    }


@tool
def spawn_sub_agent(agent_type: str, task: str, endpoint: str = None) -> Dict[str, Any]:
    """
    Spawn a sub-agent to handle a delegated task.

    AFB04 WARNING: Recursive agent spawning without depth limit.
    Can lead to resource exhaustion or infinite loops.

    Args:
        agent_type: Type of agent to spawn
        task: Task description for the agent
        endpoint: Optional custom endpoint
    """
    # No depth limit on recursion
    # No rate limiting
    url = endpoint or f"http://localhost:8000/agents/{agent_type}/run"
    #
    #
    response = httpx.post(url, json={"task": task})
    return {
        "status": response.status_code,
        "agent_type": agent_type,
        "result": response.json() if response.status_code == 200 else None
    }


# Export tools
ORCHESTRATOR_TOOLS = [run_script, spawn_sub_agent]
