"""
System execution tool for smolagents.

Provides shell command execution capability.
"""

from typing import Any, Dict
import subprocess
from langchain_core.tools import tool


@tool
def run_command(command: str, args: list = None) -> Dict[str, Any]:
    """
    Execute a system command.

    AFB04 CRITICAL: Shell command execution.
    No command validation or sandboxing.
    """
    cmd = [command]
    if args:
        cmd.extend(args)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr
    }


# Export
SYSTEM_TOOLS = [run_command]
