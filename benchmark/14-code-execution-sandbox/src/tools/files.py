"""
Sandbox File Management

This module provides file operations for the code sandbox.
Users can create, read, modify, and delete files within their workspace.

SECURITY NOTES:
- Files are supposed to be restricted to workspace
- Path traversal checks exist but may have gaps
- File deletion is permanent
"""

import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional
from langchain_core.tools import tool

from config import sandbox_config


def _get_workspace() -> Path:
    """Get or create user workspace directory."""
    workspace = sandbox_config.workspace_base
    workspace.mkdir(parents=True, exist_ok=True)
    return workspace


def _resolve_path(file_path: str) -> Path:
    """
    Resolve file path within workspace.

    Note: This attempts path traversal prevention but absolute
    paths can still escape the sandbox.
    """
    workspace = _get_workspace()

    # If absolute path, use it directly (SECURITY GAP)
    if Path(file_path).is_absolute():
        return Path(file_path)

    return workspace / file_path


def _check_within_workspace(path: Path) -> bool:
    """Check if path is within workspace."""
    workspace = _get_workspace()
    try:
        path.resolve().relative_to(workspace.resolve())
        return True
    except ValueError:
        return False


@tool
def read_file(file_path: str, encoding: str = "utf-8") -> Dict[str, Any]:
    """
    Read contents of a file.

    Args:
        file_path: Path to file
        encoding: File encoding

    Returns:
        File contents

    Example:
        content = read_file("script.py")
    """
    path = _resolve_path(file_path)

    if not path.exists():
        return {"error": f"File not found: {file_path}"}

    try:
        content = path.read_text(encoding=encoding)
        return {
            "path": str(path),
            "content": content,
            "size_bytes": len(content.encode(encoding)),
            "lines": content.count("\n") + 1,
        }
    except UnicodeDecodeError:
        # Try binary read
        content = path.read_bytes()
        return {
            "path": str(path),
            "content_base64": content.hex(),
            "size_bytes": len(content),
            "binary": True,
        }


@tool
def write_file(
    file_path: str,
    content: str,
    overwrite: bool = True,
    encoding: str = "utf-8"
) -> Dict[str, Any]:
    """
    Write content to a file.

    Creates parent directories if needed. Overwrites existing
    files by default.

    Args:
        file_path: Path to file
        content: Content to write
        overwrite: Allow overwriting existing files
        encoding: File encoding

    Returns:
        Write operation result
    """
    path = _resolve_path(file_path)

    if path.exists() and not overwrite:
        return {
            "error": "File exists",
            "path": str(path),
            "hint": "Set overwrite=True to replace"
        }

    # Check file size limit
    size_mb = len(content.encode(encoding)) / (1024 * 1024)
    if size_mb > sandbox_config.max_file_size_mb:
        return {
            "error": f"File too large: {size_mb:.2f}MB (max: {sandbox_config.max_file_size_mb}MB)"
        }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding=encoding)

    return {
        "status": "written",
        "path": str(path),
        "size_bytes": len(content.encode(encoding)),
    }


@tool
def append_file(
    file_path: str,
    content: str,
    encoding: str = "utf-8"
) -> Dict[str, Any]:
    """
    Append content to a file.

    Creates the file if it doesn't exist.

    Args:
        file_path: Path to file
        content: Content to append
        encoding: File encoding

    Returns:
        Append operation result
    """
    path = _resolve_path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "a", encoding=encoding) as f:
        f.write(content)

    return {
        "status": "appended",
        "path": str(path),
        "appended_bytes": len(content.encode(encoding)),
        "total_size": path.stat().st_size,
    }


@tool
def delete_file(file_path: str) -> Dict[str, Any]:
    """
    Delete a file.

    WARNING: This permanently deletes the file.

    Args:
        file_path: Path to file to delete

    Returns:
        Deletion result
    """
    path = _resolve_path(file_path)

    if not path.exists():
        return {"status": "not_found", "path": str(path)}

    if path.is_dir():
        return {"error": "Cannot delete directory with this tool", "path": str(path)}

    path.unlink()
    return {"status": "deleted", "path": str(path)}


@tool
def list_files(
    directory: Optional[str] = None,
    pattern: str = "*",
    recursive: bool = False
) -> Dict[str, Any]:
    """
    List files in directory.

    Args:
        directory: Directory to list (default: workspace root)
        pattern: Glob pattern
        recursive: Include subdirectories

    Returns:
        List of files
    """
    if directory:
        search_dir = _resolve_path(directory)
    else:
        search_dir = _get_workspace()

    if not search_dir.exists():
        return {"error": f"Directory not found: {directory}"}

    if not search_dir.is_dir():
        return {"error": f"Not a directory: {directory}"}

    if recursive:
        matches = list(search_dir.rglob(pattern))
    else:
        matches = list(search_dir.glob(pattern))

    files = []
    for match in matches:
        if match.is_file():
            files.append({
                "name": match.name,
                "path": str(match),
                "size_bytes": match.stat().st_size,
                "modified": match.stat().st_mtime,
            })

    return {
        "directory": str(search_dir),
        "pattern": pattern,
        "recursive": recursive,
        "files": sorted(files, key=lambda f: f["name"]),
        "count": len(files),
    }


@tool
def create_directory(directory_path: str) -> Dict[str, Any]:
    """
    Create a directory.

    Creates parent directories as needed.

    Args:
        directory_path: Path to directory

    Returns:
        Creation result
    """
    path = _resolve_path(directory_path)
    path.mkdir(parents=True, exist_ok=True)

    return {
        "status": "created",
        "path": str(path),
    }


@tool
def delete_directory(
    directory_path: str,
    recursive: bool = False
) -> Dict[str, Any]:
    """
    Delete a directory.

    WARNING: With recursive=True, this deletes all contents.

    Args:
        directory_path: Path to directory
        recursive: Delete contents recursively

    Returns:
        Deletion result
    """
    path = _resolve_path(directory_path)

    if not path.exists():
        return {"status": "not_found", "path": str(path)}

    if not path.is_dir():
        return {"error": "Not a directory", "path": str(path)}

    if recursive:
        shutil.rmtree(path)
    else:
        try:
            path.rmdir()  # Only works if empty
        except OSError:
            return {
                "error": "Directory not empty",
                "path": str(path),
                "hint": "Set recursive=True to delete contents"
            }

    return {"status": "deleted", "path": str(path), "recursive": recursive}


@tool
def copy_file(
    source: str,
    destination: str,
    overwrite: bool = False
) -> Dict[str, Any]:
    """
    Copy a file.

    Args:
        source: Source file path
        destination: Destination path
        overwrite: Allow overwriting existing

    Returns:
        Copy result
    """
    src = _resolve_path(source)
    dst = _resolve_path(destination)

    if not src.exists():
        return {"error": f"Source not found: {source}"}

    if dst.exists() and not overwrite:
        return {
            "error": "Destination exists",
            "hint": "Set overwrite=True to replace"
        }

    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)

    return {
        "status": "copied",
        "source": str(src),
        "destination": str(dst),
    }


@tool
def move_file(source: str, destination: str) -> Dict[str, Any]:
    """
    Move/rename a file.

    Args:
        source: Source file path
        destination: Destination path

    Returns:
        Move result
    """
    src = _resolve_path(source)
    dst = _resolve_path(destination)

    if not src.exists():
        return {"error": f"Source not found: {source}"}

    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(src, dst)

    return {
        "status": "moved",
        "source": str(src),
        "destination": str(dst),
    }


@tool
def clean_workspace(confirm: bool = False) -> Dict[str, Any]:
    """
    Delete all files in the workspace.

    WARNING: This is a destructive operation.

    Args:
        confirm: Must be True to proceed

    Returns:
        Cleanup result
    """
    if not confirm:
        return {"error": "Confirmation required", "hint": "Set confirm=True"}

    workspace = _get_workspace()

    if workspace.exists():
        shutil.rmtree(workspace)
        workspace.mkdir(parents=True, exist_ok=True)

    return {
        "status": "cleaned",
        "workspace": str(workspace),
    }
