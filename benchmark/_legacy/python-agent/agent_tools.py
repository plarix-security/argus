"""
Sample LangChain Agent Tools
This file demonstrates AFB04 execution points that the scanner should detect.
"""

import subprocess
import os
import requests
from pathlib import Path
from langchain.tools import tool, BaseTool
from typing import Optional


# AFB04: Tool definition with shell execution inside
@tool
def execute_command(command: str) -> str:
    """Execute a shell command and return the output."""
    # CRITICAL: Shell execution inside tool definition
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


# AFB04: Tool definition with file operations
@tool  
def write_file(filepath: str, content: str) -> str:
    """Write content to a file."""
    # HIGH: File write operation inside tool definition
    path = Path(filepath)
    path.write_text(content)
    return f"Wrote {len(content)} bytes to {filepath}"


# AFB04: Tool definition with API calls
@tool
def fetch_url(url: str) -> str:
    """Fetch content from a URL."""
    # HIGH: External API call inside tool definition
    response = requests.get(url, timeout=30)
    return response.text[:1000]


# AFB04: Class-based tool with database operations
class DatabaseQueryTool(BaseTool):
    """Tool for executing database queries."""
    
    name = "database_query"
    description = "Execute SQL queries against the database"
    
    def _run(self, query: str) -> str:
        # HIGH: Database operation inside tool definition
        import sqlite3
        conn = sqlite3.connect("data.db")
        cursor = conn.cursor()
        cursor.execute(query)  # Detected as AFB04
        results = cursor.fetchall()
        conn.close()
        return str(results)


# AFB04: Tool with code execution
@tool
def evaluate_expression(expression: str) -> str:
    """Evaluate a Python expression."""
    # CRITICAL: Dynamic code execution inside tool definition
    result = eval(expression)
    return str(result)


# Regular function (not a tool) - lower severity
def helper_function():
    """This is a regular function, not exposed to the agent."""
    # MEDIUM: File read - not inside tool, lower risk
    with open("config.txt", "r") as f:
        return f.read()


if __name__ == "__main__":
    # Test the tools
    print(execute_command("echo hello"))
