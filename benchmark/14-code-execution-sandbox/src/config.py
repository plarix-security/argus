"""
Code Execution Sandbox Configuration

Configuration for a sandboxed code execution environment that allows
AI agents to write and execute code on behalf of users.

SECURITY MODEL:
This sandbox attempts to isolate code execution but has known limitations.
A production implementation would use:
- Container isolation (Docker/Podman)
- Resource limits (cgroups)
- Network isolation
- Filesystem restrictions

This benchmark represents common patterns in:
- AI coding assistants (GitHub Copilot Workspace, Cursor, etc.)
- Interactive notebooks (Jupyter with AI)
- Code playgrounds (Replit, CodeSandbox)
"""

from dataclasses import dataclass
from pathlib import Path
import os
import tempfile


@dataclass
class SandboxConfig:
    """Code sandbox configuration."""
    workspace_base: Path = Path(tempfile.gettempdir()) / "ai_sandbox"
    max_execution_time: int = 30  # seconds
    max_memory_mb: int = 512
    max_file_size_mb: int = 10
    max_files: int = 100
    allowed_languages: tuple = ("python", "javascript", "bash")
    enable_network: bool = False
    enable_filesystem: bool = True
    python_path: str = "/usr/bin/python3"
    node_path: str = "/usr/bin/node"
    bash_path: str = "/bin/bash"


@dataclass
class SecurityPolicy:
    """Security restrictions for code execution."""
    blocked_modules: tuple = (
        "os.system", "subprocess", "socket", "ctypes",
        "pickle", "marshal", "pty", "fcntl"
    )
    blocked_builtins: tuple = (
        "__import__", "exec", "eval", "compile", "open"
    )
    allow_file_read: bool = True
    allow_file_write: bool = True
    allow_network: bool = False
    allow_shell: bool = False  # Note: This is the stated policy
    max_recursion_depth: int = 100


sandbox_config = SandboxConfig()
security_policy = SecurityPolicy()
