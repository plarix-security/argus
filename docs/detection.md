# What WyScan Detects

WyScan detects AFB04 (Unauthorized Action) boundaries in Python agent codebases.

## Overview

WyScan traces from tool registration points to dangerous operations. If there is no policy gate in the call path, it reports a finding.

## CEE Severity Model

WyScan uses the **CEE (Comprehensive Exposure Evaluation)** severity model which considers three factors:

1. **Reversibility**: Irreversible operations (delete, rmtree, eval) are always CRITICAL
2. **Data Sensitivity**: Operations touching passwords, secrets, credentials, tokens, or PII are elevated one level
3. **Validation Helpers**: Call paths through sanitize*, validate*, check_*, verify* functions are downgraded one level (heuristic-based)

The base severity is determined by operation type, then adjusted based on these factors.

## Severity Levels

### CRITICAL

Irreversible destruction, exfiltration, or arbitrary execution.

| Category | Operations |
|----------|-----------|
| Shell execution | `subprocess.run`, `subprocess.Popen`, `subprocess.call`, `os.system`, `os.popen`, `os.exec*`, `asyncio.create_subprocess_*` |
| Code execution | `eval`, `exec` |
| File deletion | `shutil.rmtree`, `os.remove`, `os.unlink`, `os.rmdir`, `Path.unlink`, `Path.rmdir` |

### WARNING

Recoverable but consequential state modification.

| Category | Operations |
|----------|-----------|
| File writes | `Path.write_text`, `Path.write_bytes`, `file.write`, `Path.mkdir`, `shutil.copy`, `shutil.move`, `os.rename`, `os.makedirs` |
| HTTP mutations | `requests.post`, `requests.put`, `requests.patch`, `requests.delete`, `httpx.*`, `aiohttp.*` |
| Database writes | `session.add`, `session.delete`, `session.commit`, `session.flush`, `model.save`, `model.create` |
| Email | `smtp.send_message`, `smtp.sendmail` |

### INFO

Read-only access to sensitive data or external systems.

| Category | Operations |
|----------|-----------|
| File reads | `open()`, `Path.read_text`, `Path.read_bytes` |
| HTTP reads | `requests.get`, `httpx.get`, `urllib.request.*` |
| Database reads | `cursor.execute` (SELECT), `cursor.fetchall`, `cursor.fetchone` |
| Environment | `os.getenv`, `os.environ` |

## Supported Frameworks

WyScan detects tool registrations in these frameworks:

| Framework | Detection Patterns |
|-----------|-------------------|
| LangChain | `@tool`, `BaseTool`, `StructuredTool`, `Tool()`, `create_react_agent`, `AgentExecutor` |
| CrewAI | `@task`, `@agent`, `crewai.tool`, `CrewAITool` |
| AutoGen | `register_function`, `function_map`, `UserProxyAgent`, `AssistantAgent` |
| LlamaIndex | `FunctionTool`, `QueryEngineTool`, `ToolOutput` |
| MCP | `mcp.server`, `@server.tool`, `tool_handler`, `ToolProvider` |
| OpenAI | `tools=[...]`, `function_call`, `tool_choice` |

## Policy Gate Detection

WyScan recognizes these as structural policy gates that protect a call path:

**Authorization exceptions:**
- `PermissionError`
- `AuthorizationError`
- `AccessDeniedError`
- `UnauthorizedError`

**Known decorators:**
- `@require_permission`
- `@permission_required`
- `@login_required`
- `@authenticated`
- `@require_role`
- `@role_required`
- `@user_passes_test`

**Structural patterns:**
- Functions with conditional branches that check parameters
- Functions that raise exceptions when authorization fails
- Functions with early returns based on authorization checks

If a recognized policy gate exists in the call path between a tool and a dangerous operation, the finding is not reported.

## How Detection Works

1. Parse Python source with tree-sitter to build an AST
2. Find all tool registrations using framework patterns
3. Build a call graph from each tool
4. Trace paths to dangerous operations
5. Check each path for policy gates
6. Report unprotected paths with severity based on operation type
