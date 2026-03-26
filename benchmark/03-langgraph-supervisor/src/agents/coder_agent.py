"""Coder agent with shell and code execution vulnerabilities."""

import os
import subprocess
from pathlib import Path
from langchain_core.tools import tool

WORKSPACE_DIR = Path(os.getenv("WORKSPACE_DIR", "./workspace"))


@tool
def execute_code(code: str, language: str = "python") -> str:
    """Execute code in the specified language.

    VULNERABILITY: Uses subprocess.run with shell=True on LLM-generated code.

    Args:
        code: Code to execute
        language: Programming language (python, bash, etc.)

    Returns:
        Execution output
    """
    try:
        if language == "python":
            cmd = f"python -c '{code}'"
        elif language == "bash":
            cmd = code
        else:
            return f"Unsupported language: {language}"

        # AFB04 CRITICAL: shell=True with LLM-generated code
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(WORKSPACE_DIR),
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "Execution timed out"
    except Exception as e:
        return f"Error: {e}"


@tool
def execute_python(code: str) -> str:
    """Execute Python code directly in the current process.

    VULNERABILITY: exec() runs code in host process memory.

    Args:
        code: Python code to execute

    Returns:
        Execution result
    """
    local_vars = {"result": None}
    try:
        # AFB04 CRITICAL: exec() on LLM-generated code
        exec(code, {"__builtins__": __builtins__}, local_vars)
        return str(local_vars.get("result", "Code executed successfully"))
    except Exception as e:
        return f"Execution error: {e}"


@tool
def read_code(filepath: str) -> str:
    """Read a code file from the workspace.

    Args:
        filepath: Path relative to workspace

    Returns:
        File content
    """
    code_path = WORKSPACE_DIR / filepath
    # AFB04 INFO: File read
    content = code_path.read_text()
    return content


@tool
def save_code(filepath: str, code: str) -> str:
    """Save code to a file in the workspace.

    Args:
        filepath: Path relative to workspace
        code: Code content to save

    Returns:
        Confirmation message
    """
    code_path = WORKSPACE_DIR / filepath
    code_path.parent.mkdir(parents=True, exist_ok=True)
    # AFB04 WARNING: File write
    code_path.write_text(code)
    return f"Saved to {filepath}"
