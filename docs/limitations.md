# Limitations

This page documents what WyScan cannot do. Understanding these limitations helps you interpret scan results correctly.

## TypeScript/JavaScript Not Supported

**The TypeScript/JavaScript detector is disabled.**

WyScan will scan `.ts`, `.tsx`, `.js`, and `.jsx` files but will return no findings. The detector was disabled to avoid false positives from pattern matching.

If you have TypeScript agent code, WyScan will not detect any issues in it. Use other tools for TypeScript security scanning.

## Single-Level Cross-File Resolution

WyScan resolves imports only one level deep.

**Detected:**

```python
# tools.py
from helpers import do_stuff

@tool
def my_tool():
    do_stuff()  # Traced to helpers.py
```

**Not Detected:**

```python
# tools.py calls helpers.py calls utils.py calls subprocess.run
# The path from tools.py to subprocess.run may not be detected
```

If your tool calls a helper that calls another helper that calls a dangerous operation, WyScan may not trace the full path.

## External Packages Not Traced

WyScan only analyzes files in your project. It does not trace calls into third-party packages.

**Not Detected:**

```python
from some_library import dangerous_wrapper

@tool
def my_tool():
    dangerous_wrapper()  # Internally calls subprocess.run
```

If a third-party package wraps dangerous operations, WyScan will not detect the risk.

## AFB04 Only

This version detects **AFB04 (Unauthorized Action)** boundaries only.

**Not Detected:**

- **AFB01 (Instruction Injection):** Prompt injection attacks
- **AFB02 (Context Poisoning):** Tainted RAG context
- **AFB03 (Constraint Bypass):** Business logic violations

These require semantic analysis that is not yet implemented.

## Call Graph Depth Limit

The call graph is traced to a maximum depth of 10 levels to prevent infinite loops and stack overflow.

Very deep call chains may not be fully traced.

## Dynamic Tool Registration

WyScan detects tool registrations through static patterns. If tools are registered dynamically at runtime, they may not be detected.

**Detected:**

```python
@tool
def my_tool():
    pass
```

**May Not Be Detected:**

```python
tools = []
for func in get_functions():
    tools.append(Tool(func=func))
```

## Framework-Specific Authorization

Some frameworks have built-in authorization mechanisms that WyScan does not recognize.

**May Report False Positive:**

```python
# LangChain with built-in approval callback
agent = create_agent(tools=tools, require_approval=True)
```

WyScan checks for explicit policy gates in code, not framework configuration.

## What To Do About These Limitations

1. **Manual review:** For critical paths, manually verify that authorization is in place
2. **Multiple tools:** Use WyScan alongside Semgrep, Bandit, or manual code review
3. **Defense in depth:** Do not rely solely on static analysis for security
