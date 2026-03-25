# Limitations

This page documents what WyScan cannot do. Understanding these limitations helps you interpret scan results correctly.

## TypeScript/JavaScript Not Supported

**The TypeScript/JavaScript detector is gated.**

WyScan will scan `.ts`, `.tsx`, `.js`, and `.jsx` files and emit an INFO-level notice, but will return no findings. The detector is gated to avoid false positives from pattern matching without proper call graph analysis.

If you have TypeScript agent code, WyScan will not detect any issues in it. Use other tools for TypeScript security scanning.

## Cross-File Resolution Limited to Depth 3

WyScan resolves imports transitively up to 3 levels deep.

**Detected:**

```python
# tools.py -> helpers.py -> utils.py (3 levels)
from helpers import do_stuff

@tool
def my_tool():
    do_stuff()  # Traced through 3 levels of imports
```

**Not Detected:**

```python
# tools.py -> a.py -> b.py -> c.py -> d.py (4+ levels)
# The path beyond depth 3 may not be fully traced
```

If your tool calls through more than 3 levels of helper functions across files, WyScan may not trace the full path.

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

WyScan recognizes some framework-level authorization mechanisms (added in v1.0.0):

**Recognized:**

```python
# LangChain with human_in_the_loop
AgentExecutor(agent=agent, tools=tools, human_in_the_loop=True)

# AutoGen with approval
register_function(func, human_input_mode="ALWAYS")
```

**May Still Miss:**

```python
# Framework-specific config in separate files
# Authorization set via environment variables
# Runtime-configured approval mechanisms
```

WyScan checks for explicit policy gates in code and some framework configuration patterns, but may not catch all authorization mechanisms.

## What To Do About These Limitations

1. **Manual review:** For critical paths, manually verify that authorization is in place
2. **Multiple tools:** Use WyScan alongside Semgrep, Bandit, or manual code review
3. **Defense in depth:** Do not rely solely on static analysis for security
