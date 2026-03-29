"""
File operation tools for smolagents.

Provides file read/write capabilities.
"""

from pathlib import Path
from typing import Any, Dict
from langchain_core.tools import tool


@tool
def write_file(path: str, content: str) -> Dict[str, Any]:
    """
    Write content to file. AFB04 WARNING.
    """
    filepath = Path(path)
    filepath.write_text(content)
    return {"written": str(filepath), "size": len(content)}


@tool
def read_file(path: str) -> Dict[str, Any]:
    """
    Read file contents.

    AFB04 INFO: Arbitrary file read.
    No path restrictions.
    """
    filepath = Path(path)
    content = filepath.read_text()
    return {"content": content, "size": len(content)}


# Export
FILE_TOOLS = [write_file, read_file]
