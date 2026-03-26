"""Calculator tool with intentional code execution vulnerabilities.

This module demonstrates AFB04 violations through unsafe eval() usage
and subprocess execution of LLM-generated expressions.
"""

import subprocess
from typing import Any


def calculate(expression: str) -> str:
    """Evaluate a mathematical expression.

    VULNERABILITY: Uses eval() directly on the expression string.
    This allows arbitrary code execution if the LLM generates
    malicious input like: __import__('os').system('rm -rf /')

    Args:
        expression: Mathematical expression to evaluate (e.g., "2 + 2")

    Returns:
        String representation of the result
    """
    try:
        # AFB04 CRITICAL: eval() on untrusted input
        result = eval(expression)
        return str(result)
    except Exception as e:
        return f"Error evaluating expression: {e}"


def calculate_subprocess(expression: str) -> str:
    """Evaluate expression using Python subprocess as fallback.

    VULNERABILITY: Executes Python code via subprocess with shell access.
    Even more dangerous than eval() as it runs in a separate process.

    Args:
        expression: Python expression to evaluate

    Returns:
        String output from subprocess
    """
    try:
        # AFB04 CRITICAL: subprocess execution of LLM-generated code
        result = subprocess.run(
            ["python", "-c", f"print({expression})"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return f"Error: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: Calculation timed out"
    except Exception as e:
        return f"Error: {e}"


# Tool definitions for OpenAI function calling
CALCULATOR_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "calculate",
            "description": "Evaluate a mathematical expression and return the result",
            "parameters": {
                "type": "object",
                "properties": {
                    "expression": {
                        "type": "string",
                        "description": "The mathematical expression to evaluate (e.g., '2 + 2', '10 * 5')",
                    }
                },
                "required": ["expression"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "calculate_subprocess",
            "description": "Evaluate a complex mathematical expression using Python subprocess",
            "parameters": {
                "type": "object",
                "properties": {
                    "expression": {
                        "type": "string",
                        "description": "The Python expression to evaluate",
                    }
                },
                "required": ["expression"],
            },
        },
    },
]
