"""
Code Sandbox Agent Orchestrator

This module implements an AI coding assistant agent that can write,
execute, and debug code on behalf of users.

ARCHITECTURE:
The agent uses CrewAI for orchestration, demonstrating a different
framework pattern from the Kubernetes agent.

CAPABILITIES:
- Write and execute Python, JavaScript, and Bash code
- Manage files in a sandboxed workspace
- Install packages
- Debug execution errors

This represents real-world AI coding assistants.
"""

from typing import Any, Dict, List, Optional
from crewai import Agent, Task, Crew
from crewai_tools import tool as crewai_tool

from tools.executor import (
    execute_python_code,
    execute_python_expression,
    execute_javascript_code,
    execute_bash_script,
    run_code_file,
    install_python_package,
    compile_and_run,
)
from tools.files import (
    read_file,
    write_file,
    append_file,
    delete_file,
    list_files,
    create_directory,
    delete_directory,
    copy_file,
    move_file,
    clean_workspace,
)


# Wrap LangChain tools for CrewAI
@crewai_tool("Execute Python Code")
def cc_execute_python(code: str) -> str:
    """Execute Python code and return the result."""
    result = execute_python_code.invoke({"code": code})
    return str(result)


@crewai_tool("Execute Expression")
def cc_eval_expression(expression: str) -> str:
    """Evaluate a Python expression."""
    result = execute_python_expression.invoke({"expression": expression})
    return str(result)


@crewai_tool("Run JavaScript")
def cc_run_javascript(code: str) -> str:
    """Execute JavaScript code."""
    result = execute_javascript_code.invoke({"code": code})
    return str(result)


@crewai_tool("Run Bash Script")
def cc_run_bash(script: str) -> str:
    """Execute a Bash script."""
    result = execute_bash_script.invoke({"script": script})
    return str(result)


@crewai_tool("Read File")
def cc_read_file(path: str) -> str:
    """Read content from a file."""
    result = read_file.invoke({"file_path": path})
    return str(result)


@crewai_tool("Write File")
def cc_write_file(path: str, content: str) -> str:
    """Write content to a file."""
    result = write_file.invoke({"file_path": path, "content": content})
    return str(result)


@crewai_tool("Delete File")
def cc_delete_file(path: str) -> str:
    """Delete a file."""
    result = delete_file.invoke({"file_path": path})
    return str(result)


@crewai_tool("List Files")
def cc_list_files(directory: str = "") -> str:
    """List files in a directory."""
    result = list_files.invoke({"directory": directory if directory else None})
    return str(result)


@crewai_tool("Install Package")
def cc_install_package(package: str) -> str:
    """Install a Python package."""
    result = install_python_package.invoke({"package": package})
    return str(result)


# Define specialized agents
code_writer = Agent(
    role="Code Writer",
    goal="Write clean, efficient, and well-documented code",
    backstory="""You are an expert software developer who writes
    high-quality code. You understand multiple programming languages
    and follow best practices for code organization.""",
    tools=[cc_write_file, cc_read_file, cc_list_files],
    verbose=True,
)

code_executor = Agent(
    role="Code Executor",
    goal="Execute code and analyze the results",
    backstory="""You are a code execution specialist who runs code
    in a sandboxed environment. You can execute Python, JavaScript,
    and Bash scripts safely.""",
    tools=[
        cc_execute_python,
        cc_eval_expression,
        cc_run_javascript,
        cc_run_bash,
        cc_install_package,
    ],
    verbose=True,
)

file_manager = Agent(
    role="File Manager",
    goal="Manage files and workspace organization",
    backstory="""You manage the workspace filesystem, organizing
    files and directories for the coding environment.""",
    tools=[
        cc_read_file,
        cc_write_file,
        cc_delete_file,
        cc_list_files,
    ],
    verbose=True,
)


def create_coding_task(description: str) -> Task:
    """Create a coding task for the crew."""
    return Task(
        description=description,
        expected_output="Code or execution result",
        agent=code_writer,
    )


def create_execution_task(code_path: str) -> Task:
    """Create an execution task."""
    return Task(
        description=f"Execute the code at {code_path} and report results",
        expected_output="Execution output or error details",
        agent=code_executor,
    )


def run_coding_session(task_description: str) -> Dict[str, Any]:
    """
    Run a coding session with the agent crew.

    Args:
        task_description: What the user wants to accomplish

    Returns:
        Session results
    """
    crew = Crew(
        agents=[code_writer, code_executor, file_manager],
        tasks=[create_coding_task(task_description)],
        verbose=True,
    )

    result = crew.kickoff()

    return {
        "status": "completed",
        "result": str(result),
        "task": task_description,
    }


def execute_and_debug(code: str, language: str = "python") -> Dict[str, Any]:
    """
    Execute code and provide debugging assistance.

    This workflow:
    1. Writes code to a file
    2. Executes it
    3. If error, analyzes and suggests fixes

    Args:
        code: Source code to execute
        language: Programming language

    Returns:
        Execution and debugging results
    """
    results = {"steps": []}

    # Step 1: Write code
    ext = {"python": ".py", "javascript": ".js", "bash": ".sh"}[language]
    filename = f"temp_script{ext}"

    write_result = write_file.invoke({
        "file_path": filename,
        "content": code,
    })
    results["steps"].append({"action": "write", "result": write_result})

    # Step 2: Execute
    if language == "python":
        exec_result = execute_python_code.invoke({"code": code})
    elif language == "javascript":
        exec_result = execute_javascript_code.invoke({"code": code})
    else:
        exec_result = execute_bash_script.invoke({"script": code})

    results["steps"].append({"action": "execute", "result": exec_result})
    results["success"] = exec_result.get("success", False)

    # Cleanup
    delete_file.invoke({"file_path": filename})

    return results
