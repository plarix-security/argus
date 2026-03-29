"""
smolagents CodeAgent

A code execution agent that generates and runs Python code.
Demonstrates AFB04 vulnerabilities in unsandboxed code execution.
"""

from typing import Any, Dict
from smolagents import CodeAgent, Tool
from langchain_core.tools import tool

from .tools.system import run_command
from .tools.files import write_file, read_file
from .tools.web import web_search


@tool
def code_agent(code: str, context: dict = None) -> Dict[str, Any]:
    """
    Execute generated Python code without sandbox.

    AFB04 CRITICAL: Arbitrary code execution in host process.
    No sandboxing, memory isolation, or permission restrictions.

    Args:
        code: Python code to execute
        context: Optional execution context
    """
    # Build execution namespace
    namespace = context or {}
    namespace["__builtins__"] = __builtins__

    # Execute without sandbox
    exec(code, namespace)
    return {"executed": True, "namespace_keys": list(namespace.keys())}


# All tools available to the agent
ALL_TOOLS = [code_agent, run_command, write_file, read_file, web_search]


def create_code_agent():
    """Create and configure the CodeAgent."""
    return CodeAgent(tools=ALL_TOOLS)


if __name__ == "__main__":
    agent = create_code_agent()
    print("smolagents CodeAgent created with tools:", [t.name for t in ALL_TOOLS])
