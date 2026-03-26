"""File operations tool with intentional path traversal vulnerability.

This module demonstrates AFB04 violations through unsanitized file paths.
"""

import os
from pathlib import Path
from typing import Optional


def write_file(filepath: str, content: str) -> str:
    """Write content to a file at the specified path.

    VULNERABILITY: No path validation - allows path traversal.
    Attack: write_file("../../../etc/cron.d/backdoor", "malicious content")

    Args:
        filepath: Path where file should be written
        content: Content to write to the file

    Returns:
        Success message or error
    """
    try:
        filepath = Path(filepath)

        # AFB04 WARNING: Creates parent directories without validation
        filepath.parent.mkdir(parents=True, exist_ok=True)

        # AFB04 WARNING: Writes to arbitrary path without validation
        filepath.write_text(content)

        return f"Successfully wrote {len(content)} bytes to {filepath}"
    except Exception as e:
        return f"Error writing file: {e}"


def read_file(filepath: str) -> str:
    """Read content from a file.

    VULNERABILITY: No path validation - can read sensitive files.

    Args:
        filepath: Path to read from

    Returns:
        File content or error message
    """
    try:
        filepath = Path(filepath)
        # AFB04 INFO: Reads arbitrary files without validation
        content = filepath.read_text()
        return content
    except Exception as e:
        return f"Error reading file: {e}"


def list_files(directory: str, pattern: str = "*") -> str:
    """List files in a directory matching a pattern.

    Args:
        directory: Directory to list
        pattern: Glob pattern to match (default: *)

    Returns:
        List of matching files
    """
    try:
        base_path = Path(directory)
        # AFB04 INFO: Directory enumeration
        files = list(base_path.glob(pattern))
        return "\n".join(str(f) for f in files[:50])  # Limit output
    except Exception as e:
        return f"Error listing files: {e}"


FILE_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write content to a file at the specified path",
            "parameters": {
                "type": "object",
                "properties": {
                    "filepath": {"type": "string", "description": "Path to write to"},
                    "content": {"type": "string", "description": "Content to write"},
                },
                "required": ["filepath", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read content from a file",
            "parameters": {
                "type": "object",
                "properties": {
                    "filepath": {"type": "string", "description": "Path to read from"},
                },
                "required": ["filepath"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": "List files in a directory",
            "parameters": {
                "type": "object",
                "properties": {
                    "directory": {"type": "string", "description": "Directory to list"},
                    "pattern": {"type": "string", "description": "Glob pattern (default: *)"},
                },
                "required": ["directory"],
            },
        },
    },
]
