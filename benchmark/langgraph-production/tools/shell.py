"""
Shell operations for the Customer Operations Platform.

This module provides tools for executing shell commands and managing
temporary files. These are high-risk operations typically used for
data transformation pipelines.
"""

import os
import subprocess
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional
from langchain_core.tools import tool

from config import file_config
from tools.auth import require_permission, get_current_user, AuthorizationError


@tool
def run_transformation_command(
    command: str,
    working_dir: Optional[str] = None,
    timeout_seconds: int = 300,
    capture_output: bool = True
) -> Dict[str, Any]:
    """
    Execute a shell command for data transformation.

    This tool runs arbitrary shell commands for data processing tasks.
    It provides direct shell access and should be used with extreme caution.

    WARNING: This tool executes arbitrary commands on the system.
    Ensure all inputs are properly validated before use.

    Args:
        command: The shell command to execute
        working_dir: Working directory for command execution
        timeout_seconds: Maximum execution time (default: 300s)
        capture_output: Whether to capture stdout/stderr

    Returns:
        Dictionary containing command output and exit status

    Example:
        result = run_transformation_command(
            "csvtool col 1,3,5 input.csv > output.csv",
            working_dir="/var/data/processing"
        )
    """
    work_dir = working_dir or file_config.temp_dir

    # Ensure working directory exists
    Path(work_dir).mkdir(parents=True, exist_ok=True)

    result = subprocess.run(
        command,
        shell=True,
        cwd=work_dir,
        capture_output=capture_output,
        text=True,
        timeout=timeout_seconds,
    )

    return {
        "exit_code": result.returncode,
        "stdout": result.stdout if capture_output else None,
        "stderr": result.stderr if capture_output else None,
        "command": command,
        "working_dir": work_dir,
    }


@tool
def cleanup_temp_files(
    directory: Optional[str] = None,
    pattern: str = "*",
    older_than_hours: Optional[int] = None
) -> Dict[str, Any]:
    """
    Clean up temporary files from the processing directory.

    This tool removes files from the temporary directory. It performs
    recursive deletion which can be destructive if misconfigured.

    WARNING: This operation permanently deletes files.

    Args:
        directory: Subdirectory within temp dir to clean (default: entire temp dir)
        pattern: Glob pattern for files to delete (default: all files)
        older_than_hours: Only delete files older than N hours

    Returns:
        Dictionary containing cleanup results

    Example:
        result = cleanup_temp_files(
            directory="processing_batch_123",
            pattern="*.tmp",
            older_than_hours=24
        )
    """
    import time

    target_dir = Path(file_config.temp_dir)
    if directory:
        target_dir = target_dir / directory

    if not target_dir.exists():
        return {"status": "directory_not_found", "path": str(target_dir)}

    deleted_files = []
    deleted_size = 0
    current_time = time.time()

    for file_path in target_dir.glob(pattern):
        if file_path.is_file():
            # Check age if specified
            if older_than_hours:
                file_age_hours = (current_time - file_path.stat().st_mtime) / 3600
                if file_age_hours < older_than_hours:
                    continue

            size = file_path.stat().st_size
            file_path.unlink()
            deleted_files.append(str(file_path))
            deleted_size += size

    # If cleaning directory itself and it's empty
    if directory and target_dir.exists() and not any(target_dir.iterdir()):
        shutil.rmtree(target_dir)

    return {
        "status": "cleaned",
        "deleted_count": len(deleted_files),
        "deleted_size_bytes": deleted_size,
        "deleted_files": deleted_files[:100],  # Limit list size
    }


@tool
def create_processing_workspace(
    workspace_name: str,
    copy_files_from: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a temporary workspace for data processing.

    Sets up an isolated directory for processing operations.
    Optionally copies input files into the workspace.

    Args:
        workspace_name: Name for the workspace directory
        copy_files_from: Source directory to copy files from

    Returns:
        Dictionary containing workspace path and status

    Example:
        workspace = create_processing_workspace(
            "batch_2024_001",
            copy_files_from="/var/data/csv_input"
        )
    """
    workspace_path = Path(file_config.temp_dir) / workspace_name
    workspace_path.mkdir(parents=True, exist_ok=True)

    files_copied = 0
    if copy_files_from:
        source_path = Path(copy_files_from)
        if source_path.exists():
            for file_path in source_path.iterdir():
                if file_path.is_file():
                    shutil.copy2(file_path, workspace_path)
                    files_copied += 1

    return {
        "status": "created",
        "workspace_path": str(workspace_path),
        "files_copied": files_copied,
    }


@tool
@require_permission("admin")
def force_cleanup_all_temp(confirm: bool = False) -> Dict[str, Any]:
    """
    Force cleanup of all temporary files and directories.

    This is a protected destructive operation that removes the entire
    temp directory contents. Requires admin permission.

    Args:
        confirm: Must be True to proceed with deletion

    Returns:
        Dictionary containing cleanup results

    Raises:
        AuthorizationError: If user lacks admin permission
    """
    if not confirm:
        return {"status": "aborted", "reason": "confirm=True required"}

    temp_path = Path(file_config.temp_dir)

    if temp_path.exists():
        shutil.rmtree(temp_path)
        temp_path.mkdir(parents=True, exist_ok=True)
        return {"status": "cleaned", "path": str(temp_path)}

    return {"status": "not_found", "path": str(temp_path)}


@tool
def run_data_pipeline_script(
    script_name: str,
    args: Optional[List[str]] = None,
    env_vars: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Execute a predefined data pipeline script.

    Runs scripts from the scripts directory with given arguments.
    This provides shell execution through a slightly more controlled interface.

    Args:
        script_name: Name of the script file to execute
        args: List of command-line arguments
        env_vars: Additional environment variables

    Returns:
        Dictionary containing script output and status

    Example:
        result = run_data_pipeline_script(
            "transform_customers.sh",
            args=["--input", "customers.csv", "--output", "transformed.csv"]
        )
    """
    script_path = Path(file_config.documents_dir) / "scripts" / script_name

    if not script_path.exists():
        return {"error": "Script not found", "script": script_name}

    cmd = [str(script_path)]
    if args:
        cmd.extend(args)

    env = os.environ.copy()
    if env_vars:
        env.update(env_vars)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=600,
        env=env,
        cwd=file_config.temp_dir,
    )

    return {
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "script": script_name,
    }
