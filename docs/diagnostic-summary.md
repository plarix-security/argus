# DIAGNOSTIC SUMMARY: Why elizaos/eliza produces only ~4 CEEs

## Root Cause Analysis

### Problem 1: `hasAgenticContext` misses ElizaOS imports (semantic-index.ts:848-864)

Current implementation only checks for:
`agent`, `plugin`, `tool`, `runtime`, `langchain`, `langgraph`, `mastra`, `modelcontextprotocol`, `openai`, `/ai`

ElizaOS imports `@elizaos/core`, which contains none of these tokens.
Therefore `hasAgenticContext` returns `false` for virtually all ElizaOS files.

### Problem 2: `isLikelyAgenticActionObject` requires too many combined signals (semantic-index.ts:814-846)

The logic requires:
- A primary execution prop (handler/execute/run/action) - usually satisfied
- AND one of:
  - `hasTypeToken` (type annotation contains Action/Tool/etc) - often not captured by AST
  - `hasTargetToken && (hasNameToken || hasAgenticImport)` - both target name AND context
  - `hasNameToken && hasAgenticImport` - name token AND agentic import

Since `hasAgenticImport` (= `hasAgenticContext`) returns false for ElizaOS files, and type annotations
are not always captured, the combined condition fails for most objects.

### Problem 3: No dedicated ElizaOS extractor

There is no `extractElizaOSTools` function. ElizaOS uses:
- Exported const objects with `handler:` property typed as `Action`
- Plugin objects with `actions: Action[]` arrays
These are the primary tool registration patterns, but none of the extractors handle them correctly.

### Problem 4: CEE emission requires dangerous operation match (detector.ts:154-165)

CEEs are only emitted when `callGraph.exposedPaths` contains entries. Exposed paths only exist when
a root function's call graph traversal reaches a `DANGEROUS_OPERATION_PATTERNS` match.

If traversal finds no match (because ElizaOS uses `runtime.fetch()` not `fetch()`, or because the
tool just calls `runtime.createMemory()` which is not in any pattern), zero CEEs are emitted.

### Problem 5: ElizaOS runtime methods missing from DANGEROUS_OPERATION_PATTERNS

ElizaOS handlers commonly call:
- `runtime.fetch()` - HTTP request via runtime
- `runtime.useModel()` - LLM invocation
- `runtime.createMemory()` - memory write
- `runtime.updateMemory()` - memory write
- `runtime.generateText()` - LLM call
- `runtime.call()` - arbitrary tool invocation

None of these are in `SEMANTIC_DANGEROUS_OPERATION_PATTERNS` or `DANGEROUS_OPERATION_PATTERNS`.

### Problem 6: `extractPluginArrayPatterns` doesn't cross file boundaries for imports (semantic-index.ts:875-980)

ElizaOS plugins export `{ name: string, actions: Action[] }` where actions are imported from other files.
The current code resolves function references via `resolveFunctionReference` but this only works within
the same file or via the `files` map. When actions are re-exported through index.ts files, the
resolution fails silently.

### Problem 7: `extractActionObjectPatterns` inline function nodeId mismatch (semantic-index.ts:762-780)

When `{ handler: async () => {...} }` is found, the synthetic function name is `${assignment.target}.${prop.key}`
(e.g., `myAction.handler`). But the AST parser (ast-parser.ts) may not extract inline arrow functions
as named functions with that synthetic name, causing the nodeId to not match any node in the call graph.

### Problem 8: Call graph traversal for cross-file hops

The `buildCallGraph` function in call-graph.ts traverses cross-file edges, but for ElizaOS plugins
where the handler is imported from a different file, the import resolution chain must be correct.
If any resolution step fails, traversal silently stops.

## Summary Table

| Problem | Location | Impact |
|---------|----------|--------|
| hasAgenticContext misses @elizaos/core | semantic-index.ts:848 | All ElizaOS files get no agentic context |
| isLikelyAgenticActionObject too strict | semantic-index.ts:814 | Most action objects rejected |
| No ElizaOS extractor | semantic-index.ts | No dedicated ElizaOS pattern extraction |
| CEE requires dangerous op match | detector.ts:154 | Tools with no traced op produce 0 CEEs |
| ElizaOS runtime methods missing | call-graph.ts | runtime.fetch() etc not detected |
| Cross-file plugin array traversal | semantic-index.ts:875 | Imported actions not followed |
| Inline function nodeId mismatch | semantic-index.ts:762 | Inline handlers not in call graph |
| Generic traversal depth | call-graph.ts | May cut short on deep call chains |
