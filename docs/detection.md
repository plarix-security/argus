# Detection Model

WyScan currently reports AFB04-style unauthorized action exposure in Python code.

The shipped detector does this:

1. Parse Python source with tree-sitter.
2. Detect tool registrations using framework and decorator patterns.
3. Build call paths within the analyzed file.
4. Match reachable operations against the current operation table.
5. Credit a policy gate only when the analyzed path contains recognized structural authorization logic.

## Severity Model

Severity is based on matched operations, then adjusted by limited heuristics already present in the implementation.

- Irreversible operations are forced to `CRITICAL`.
- Sensitive-data naming heuristics can elevate severity by one level.
- Validation-helper naming heuristics can downgrade severity by one level.

These adjustments are heuristic only.

## Current Operation Buckets

`CRITICAL`

- Shell execution
- Dynamic code execution and unsafe deserialization
- File or directory deletion
- `cursor.executescript()` and Redis flush operations

`WARNING`

- File writes and directory creation
- HTTP mutation calls such as `post`, `put`, `patch`, and `delete`
- HTTP GET calls currently matched by the shipped detector
- Common ORM and NoSQL write-style calls
- Email sends

`INFO`

- File reads
- Generic database reads such as `.execute()`, `.fetchone()`, `.fetchall()`, and `.query()`
- Redis `get` and `keys`
- Directory listing and glob-like operations

## Framework Labels

Framework labels are pattern-based and Python-only. They indicate that WyScan matched a registration pattern, not that it modeled the full runtime behavior of that framework.

The current detector includes labels for patterns associated with LangChain, CrewAI, AutoGen, OpenAI tool schemas and dispatch maps, LlamaIndex, MCP, and generic Python decorator-style tool registration.

## Policy Gates

WyScan credits a policy gate when the analyzed path contains code it recognizes as structural authorization logic, such as:

- Conditional checks on parameters
- Authorization-like exceptions raised on denied paths
- Decorators that are structurally analyzed as wrappers that can prevent execution
- Known authorization decorator names

Validation helpers such as `validate_*` or `sanitize_*` are not credited as gates by themselves.
