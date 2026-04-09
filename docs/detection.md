# Detection Model

WyScan reports AFB04-style unauthorized action exposure in Python, TypeScript, and JavaScript code.

The shipped detector does this:

1. Parse source with tree-sitter (Python, TypeScript, and JavaScript).
2. Resolve tool registrations from framework-specific code structure when available.
3. Fall back to framework or decorator patterns only when semantic resolution is incomplete.
4. Build call paths across the analyzed file set (batched by language for cross-file analysis).
5. Match reachable operations against the current operation table.
6. Credit a policy gate only when the analyzed path contains structural authorization logic.

## Supported Languages

- **Python**: Broad static-analysis support with semantic framework extraction, but still non-comprehensive.
- **TypeScript**: Broad static-analysis support for common Node.js agent patterns, but non-comprehensive.
- **JavaScript**: Uses the same static-analysis engine as TypeScript, with the same non-comprehensive limits.

## Severity Model

Severity is based on matched operations. Limited heuristics still exist, but they only adjust fallback-classified paths where structural or semantic proof was incomplete.

- Irreversible operations are forced to `CRITICAL`.
- Sensitive-data naming heuristics can elevate fallback-classified paths by one level.
- Validation-helper naming heuristics can downgrade fallback-classified paths by one level.

These adjustments are heuristic only.

## Current Operation Buckets

`CRITICAL`

- Shell execution (subprocess, child_process, execa, shelljs)
- Dynamic code execution (eval, exec, vm.runInContext, page.evaluate)
- File or directory deletion (unlink, rm, rimraf, fs-extra remove)
- Raw SQL execution and Redis flush operations

`WARNING`

- File writes and directory creation
- HTTP mutation calls such as `post`, `put`, `patch`, and `delete`
- ORM operations (Prisma, TypeORM, Sequelize, Knex, Drizzle)
- Email sends (nodemailer, SendGrid)
- Browser automation (Playwright page.goto, page.fill)

`INFO`

- File reads
- Generic database reads
- HTTP GET calls
- Directory listing and glob-like operations

## Framework Labels

### Python Frameworks

The current detector includes semantic handling for:
- LangGraph/LangChain tool lists and decorators
- Helper-returned tool bundles
- CrewAI agent tool lists
- AutoGen `function_map` registrations
- OpenAI tool schemas and dispatch maps
- Generic Python decorator-style tool registration

### TypeScript/JavaScript Frameworks

The current detector includes semantic handling for:
- OpenAI SDK (chat.completions.create with tools)
- LangChain.js (DynamicStructuredTool, @tool decorator)
- LangGraph.js (createReactAgent, StateGraph)
- Vercel AI SDK (tool() definitions, streamText/generateText)
- MCP SDK (server.tool() registrations)
- Mastra (createTool definitions)
- Playwright/Puppeteer browser automation
- Generic tools arrays and tool registration patterns

## Policy Gates

WyScan credits a policy gate when the analyzed path contains code it recognizes as structural authorization logic, such as:

- Conditional checks on parameters
- Authorization-like exceptions raised on denied paths (PermissionError, UnauthorizedError, ForbiddenException, etc.)
- Decorators that are structurally analyzed as wrappers that can prevent execution
- Imported decorators whose wrapper logic is structurally analyzed as gates

Validation helpers such as `validate_*` or `sanitize_*` are not credited as gates by themselves. Authorization-like decorator names are treated as heuristic evidence, not full gate proof, when no structural gate is found.

Note: Generic `Error` exceptions are not treated as authorization gates to avoid false negatives.
