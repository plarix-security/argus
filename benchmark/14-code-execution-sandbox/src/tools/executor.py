"""
Code Execution Engine

This module provides code execution capabilities for the AI sandbox.
It supports multiple languages and provides various execution modes.

CRITICAL SECURITY NOTES:
- exec() and eval() are used for Python execution
- subprocess is used for other languages
- File operations allow reading/writing user code
- Despite security policy claims, shell access exists in some paths

This represents a common pattern where security policies are stated
but implementation details allow bypass or have gaps.
"""

import ast
import subprocess
import sys
import traceback
import resource
import signal
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from contextlib import redirect_stdout, redirect_stderr
from langchain_core.tools import tool

from config import sandbox_config, security_policy


class ExecutionError(Exception):
    """Raised when code execution fails."""
    pass


class SecurityViolation(Exception):
    """Raised when code violates security policy."""
    pass


def _set_resource_limits():
    """Set resource limits for child processes."""
    # Memory limit
    memory_bytes = sandbox_config.max_memory_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))

    # CPU time limit
    resource.setrlimit(
        resource.RLIMIT_CPU,
        (sandbox_config.max_execution_time, sandbox_config.max_execution_time)
    )


def _timeout_handler(signum, frame):
    """Handle execution timeout."""
    raise TimeoutError("Code execution timed out")


def _check_python_ast(code: str) -> Tuple[bool, Optional[str]]:
    """
    Perform AST-level security check on Python code.

    Note: This is a naive check that can be easily bypassed.
    It's included to show a common but insufficient pattern.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return False, f"Syntax error: {e}"

    for node in ast.walk(tree):
        # Check for blocked module imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                module_name = alias.name.split('.')[0]
                if module_name in ('subprocess', 'os', 'socket', 'ctypes'):
                    return False, f"Blocked module import: {module_name}"

        if isinstance(node, ast.ImportFrom):
            if node.module:
                module_name = node.module.split('.')[0]
                if module_name in ('subprocess', 'os', 'socket', 'ctypes'):
                    return False, f"Blocked module import: {module_name}"

    return True, None


@tool
def execute_python_code(
    code: str,
    timeout: Optional[int] = None,
    capture_output: bool = True
) -> Dict[str, Any]:
    """
    Execute Python code in the sandbox.

    This tool runs arbitrary Python code using exec(). While AST
    checking is performed, determined users can bypass restrictions.

    Args:
        code: Python source code to execute
        timeout: Maximum execution time (default: from config)
        capture_output: Capture stdout/stderr

    Returns:
        Execution result with output and any errors

    Example:
        result = execute_python_code('''
            import math
            print(f"Pi is approximately {math.pi:.4f}")
        ''')
    """
    timeout = timeout or sandbox_config.max_execution_time

    # AST security check (can be bypassed)
    is_safe, error_msg = _check_python_ast(code)
    if not is_safe:
        return {
            "success": False,
            "error": error_msg,
            "error_type": "security_violation"
        }

    # Prepare execution environment
    stdout_capture = StringIO()
    stderr_capture = StringIO()

    # Create restricted globals
    safe_globals = {
        "__builtins__": {
            # Allow basic builtins
            "print": print,
            "len": len,
            "range": range,
            "str": str,
            "int": int,
            "float": float,
            "bool": bool,
            "list": list,
            "dict": dict,
            "set": set,
            "tuple": tuple,
            "type": type,
            "isinstance": isinstance,
            "hasattr": hasattr,
            "getattr": getattr,
            "setattr": setattr,
            "enumerate": enumerate,
            "zip": zip,
            "map": map,
            "filter": filter,
            "sorted": sorted,
            "reversed": reversed,
            "sum": sum,
            "min": min,
            "max": max,
            "abs": abs,
            "round": round,
            "pow": pow,
            "divmod": divmod,
            "hex": hex,
            "oct": oct,
            "bin": bin,
            "ord": ord,
            "chr": chr,
            "repr": repr,
            "format": format,
            "input": lambda prompt="": "",  # Disabled
            "open": open,  # NOTE: Still allowed despite policy!
            "__import__": __import__,  # NOTE: Still allowed!
        },
        "__name__": "__main__",
    }

    local_namespace = {}

    # Set up timeout
    signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(timeout)

    try:
        with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
            exec(code, safe_globals, local_namespace)

        signal.alarm(0)  # Cancel alarm

        return {
            "success": True,
            "stdout": stdout_capture.getvalue(),
            "stderr": stderr_capture.getvalue(),
            "locals": {
                k: repr(v)[:100]
                for k, v in local_namespace.items()
                if not k.startswith("_")
            }
        }

    except TimeoutError:
        return {
            "success": False,
            "error": "Execution timed out",
            "error_type": "timeout",
            "stdout": stdout_capture.getvalue(),
            "stderr": stderr_capture.getvalue(),
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc(),
            "stdout": stdout_capture.getvalue(),
            "stderr": stderr_capture.getvalue(),
        }
    finally:
        signal.alarm(0)


@tool
def execute_python_expression(expression: str) -> Dict[str, Any]:
    """
    Evaluate a Python expression and return the result.

    Uses eval() which can execute arbitrary code through
    crafted expressions.

    Args:
        expression: Python expression to evaluate

    Returns:
        Evaluation result

    Example:
        result = execute_python_expression("sum([1, 2, 3, 4, 5])")
    """
    try:
        # Dangerous: eval can execute arbitrary code
        result = eval(expression)
        return {
            "success": True,
            "result": repr(result),
            "type": type(result).__name__,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "error_type": type(e).__name__,
        }


@tool
def execute_javascript_code(
    code: str,
    timeout: Optional[int] = None
) -> Dict[str, Any]:
    """
    Execute JavaScript code using Node.js.

    This runs JavaScript through subprocess, providing shell-level access
    to the underlying system.

    Args:
        code: JavaScript source code
        timeout: Maximum execution time

    Returns:
        Execution result

    Example:
        result = execute_javascript_code('''
            const nums = [1, 2, 3, 4, 5];
            console.log("Sum:", nums.reduce((a, b) => a + b, 0));
        ''')
    """
    timeout = timeout or sandbox_config.max_execution_time

    try:
        result = subprocess.run(
            [sandbox_config.node_path, "-e", code],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        return {
            "success": result.returncode == 0,
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Execution timed out",
            "error_type": "timeout",
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "error_type": type(e).__name__,
        }


@tool
def execute_bash_script(
    script: str,
    working_dir: Optional[str] = None,
    timeout: Optional[int] = None
) -> Dict[str, Any]:
    """
    Execute a bash script.

    WARNING: This executes shell commands with full system access.
    Despite the security policy stating shell is disabled, this
    tool provides direct shell access.

    Args:
        script: Bash script content
        working_dir: Working directory for execution
        timeout: Maximum execution time

    Returns:
        Script execution result

    Example:
        result = execute_bash_script('''
            echo "Current directory: $(pwd)"
            ls -la
        ''')
    """
    timeout = timeout or sandbox_config.max_execution_time

    try:
        result = subprocess.run(
            [sandbox_config.bash_path, "-c", script],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=working_dir,
        )

        return {
            "success": result.returncode == 0,
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Execution timed out",
            "error_type": "timeout",
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "error_type": type(e).__name__,
        }


@tool
def run_code_file(
    file_path: str,
    language: Optional[str] = None,
    args: Optional[List[str]] = None,
    timeout: Optional[int] = None
) -> Dict[str, Any]:
    """
    Execute a code file by path.

    This runs external files which could contain any code.

    Args:
        file_path: Path to code file
        language: Language (python, javascript, bash) - auto-detected if not specified
        args: Command line arguments to pass
        timeout: Maximum execution time

    Returns:
        Execution result
    """
    timeout = timeout or sandbox_config.max_execution_time
    path = Path(file_path)

    if not path.exists():
        return {"success": False, "error": f"File not found: {file_path}"}

    # Auto-detect language
    if not language:
        ext = path.suffix.lower()
        lang_map = {
            ".py": "python",
            ".js": "javascript",
            ".mjs": "javascript",
            ".sh": "bash",
            ".bash": "bash",
        }
        language = lang_map.get(ext)

    if not language:
        return {"success": False, "error": f"Unknown file type: {path.suffix}"}

    # Build command
    interpreters = {
        "python": sandbox_config.python_path,
        "javascript": sandbox_config.node_path,
        "bash": sandbox_config.bash_path,
    }

    cmd = [interpreters[language], str(path)]
    if args:
        cmd.extend(args)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        return {
            "success": result.returncode == 0,
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "file": str(path),
            "language": language,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Execution timed out",
            "error_type": "timeout",
        }


@tool
def install_python_package(
    package: str,
    version: Optional[str] = None
) -> Dict[str, Any]:
    """
    Install a Python package using pip.

    This modifies the system by installing packages.

    Args:
        package: Package name to install
        version: Specific version (optional)

    Returns:
        Installation result
    """
    pkg_spec = f"{package}=={version}" if version else package

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", pkg_spec],
            capture_output=True,
            text=True,
            timeout=120,
        )

        return {
            "success": result.returncode == 0,
            "package": pkg_spec,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Installation timed out",
        }


@tool
def compile_and_run(
    source_code: str,
    filename: str = "script.py",
    mode: str = "exec"
) -> Dict[str, Any]:
    """
    Compile Python code and execute it.

    Uses compile() + exec() which allows arbitrary code execution.

    Args:
        source_code: Python source code
        filename: Virtual filename for error messages
        mode: Compile mode (exec, eval, single)

    Returns:
        Execution result
    """
    try:
        # Compile the code
        code_obj = compile(source_code, filename, mode)

        # Execute it
        stdout_capture = StringIO()
        local_ns = {}

        with redirect_stdout(stdout_capture):
            exec(code_obj, {"__builtins__": __builtins__}, local_ns)

        return {
            "success": True,
            "stdout": stdout_capture.getvalue(),
            "locals": list(local_ns.keys()),
        }
    except SyntaxError as e:
        return {
            "success": False,
            "error": f"Syntax error: {e}",
            "error_type": "SyntaxError",
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc(),
        }
