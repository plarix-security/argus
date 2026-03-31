# Detection Model

WyScan currently reports AFB04-style unauthorized action exposure in Python code.

The shipped detector does this:

1. Parse Python source with tree-sitter.
2. Resolve tool registrations from framework-specific code structure when available.
3. Fall back to framework or decorator patterns only when semantic resolution is incomplete.
4. Build call paths across the analyzed Python file set.
5. Match reachable operations against the current operation table.
6. Credit a policy gate only when the analyzed path contains structural authorization logic.

## Severity Model

Severity is based on matched operations. Limited heuristics still exist, but they only adjust fallback-classified paths where structural or semantic proof was incomplete.

- Irreversible operations are forced to `CRITICAL`.
- Sensitive-data naming heuristics can elevate fallback-classified paths by one level.
- Validation-helper naming heuristics can downgrade fallback-classified paths by one level.

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

Framework labels are Python-only. They prefer semantic extraction from code structure, helper-returned bundles, and dispatch maps, then fall back to matched registration patterns when semantic resolution is incomplete.

The current detector includes semantic handling for LangGraph/LangChain tool lists, helper-returned tool bundles, CrewAI agent tool lists, AutoGen `function_map` registrations, imported tool decorators, OpenAI tool schemas and dispatch maps, plus fallback labels for generic Python decorator-style tool registration.

## Policy Gates

WyScan credits a policy gate when the analyzed path contains code it recognizes as structural authorization logic, such as:

- Conditional checks on parameters
- Authorization-like exceptions raised on denied paths
- Decorators that are structurally analyzed as wrappers that can prevent execution
- Imported decorators whose wrapper logic is structurally analyzed as gates

Validation helpers such as `validate_*` or `sanitize_*` are not credited as gates by themselves. Authorization-like decorator names are treated as heuristic evidence, not full gate proof, when no structural gate is found.
