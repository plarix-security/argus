"""
AutoGen Code Executor

Two-agent system with code execution capabilities via exec() without sandbox.
This demonstrates AFB04 vulnerabilities in AutoGen's function registration pattern.
"""

from pathlib import Path
from typing import Any, Dict
from autogen import UserProxyAgent, AssistantAgent


# AutoGen function registration pattern
# Functions registered here are callable by the AssistantAgent

def execute_code(code: str) -> Dict[str, Any]:
    """
    Execute arbitrary Python code in host process memory.
    AFB04 CRITICAL: No sandbox, code runs with full process privileges.
    """
    result = {}
    # Line 28: exec() - AUTOGEN-001
    exec(code, result)
    return {"output": str(result), "success": True}


def evaluate_expression(expression: str) -> Dict[str, Any]:
    """
    Evaluate a Python expression and return the result.
    AFB04 CRITICAL: eval() on untrusted input.
    """
    # Padding to reach line 45
    #
    #
    #
    #
    #
    #
    # Line 45: eval() - AUTOGEN-002
    result = eval(expression)
    return {"result": result, "type": str(type(result).__name__)}


def save_result(filename: str, content: str) -> Dict[str, Any]:
    """
    Save execution results to a file.
    AFB04 WARNING: File write without path validation.
    """
    output_dir = Path("./outputs")
    output_dir.mkdir(exist_ok=True)
    filepath = output_dir / filename
    # Line 62: Path.write_text - AUTOGEN-003
    filepath.write_text(content)
    return {"saved": str(filepath), "size": len(content)}


def load_data(filename: str) -> Dict[str, Any]:
    """
    Load data from a file for processing.
    AFB04 INFO: File read access.
    """
    data_dir = Path("./data")
    filepath = data_dir / filename
    # Line 75: Path.read_text - AUTOGEN-004
    content = filepath.read_text()
    return {"content": content, "size": len(content)}


# AutoGen agent configuration
def create_agents():
    """Create the AutoGen agent pair with function registration."""

    # User proxy that executes code
    user_proxy = UserProxyAgent(
        name="executor",
        human_input_mode="NEVER",
        code_execution_config={"work_dir": "./workspace"},
        function_map={
            "execute_code": execute_code,
            "evaluate_expression": evaluate_expression,
            "save_result": save_result,
            "load_data": load_data,
        }
    )

    # Assistant that decides what code to run
    assistant = AssistantAgent(
        name="coder",
        llm_config={"model": "gpt-4"},
    )

    # Register functions with the assistant
    user_proxy.register_function(
        function_map={
            "execute_code": execute_code,
            "evaluate_expression": evaluate_expression,
            "save_result": save_result,
            "load_data": load_data,
        }
    )

    return user_proxy, assistant


if __name__ == "__main__":
    user_proxy, assistant = create_agents()
    # Start conversation
    user_proxy.initiate_chat(
        assistant,
        message="Please help me analyze some data.",
    )
