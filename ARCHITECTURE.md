# AFB Scanner Architecture

## Design Philosophy

AFB Scanner is built on these core principles:

1. **No false positives** — report nothing rather than guess
2. **Static analysis only** — no LLM inference, no runtime monitoring
3. **No hardcoding** — structural analysis, not pattern lists
4. **Framework awareness** — understands LangChain, CrewAI patterns
5. **Context sensitivity** — severity adjusted by execution context

## Components

### 1. AST Walker (`src/analyzer/ast-walker.ts`)

Regex-based parser that creates a simplified AST from source code.

- Extracts function calls, decorators, class definitions
- Language-agnostic node representation
- Zero native dependencies (pure TypeScript)

### 2. Language Detectors

**Python Detector** (`src/analyzer/python/detector.ts`)
- Matches against PYTHON_PATTERNS defined in afb04.ts
- Detects: @tool decorators, subprocess calls, file ops, requests, DB cursors, eval
- Two-pass analysis: identify tool definitions, then flag execution points inside them

**TypeScript Detector** (`src/analyzer/typescript/detector.ts`)
- Matches against TYPESCRIPT_PATTERNS defined in afb04.ts
- Detects: tool(), child_process, fs module, fetch, axios, Prisma, eval
- Same two-pass structure as Python

### 3. AFB04 Classifier (`src/afb/afb04.ts`)

Defines execution patterns with:
- Category (tool_call, shell_execution, file_operation, etc.)
- Base severity (critical, high, medium)
- Description and rationale

Severity adjustment logic:
- Inside tool definition: +1 level
- Dynamic/user input detected: +1 level
- Capped at CRITICAL

### 4. Analyzer Orchestrator (`src/analyzer/index.ts`)

Main coordinator that:
- Discovers files (with include/exclude patterns)
- Dispatches to language-specific detectors
- Aggregates findings into AnalysisReport
- Filters by confidence threshold
- Sorts by severity, then file, then line

### 5. Reporter (`src/reporter/pr-comment.ts`)

Formats results for consumption:
- **Markdown** - Professional PR comment format
- **JSON** - Programmatic/CI integration
- **Terminal** - ANSI-colored CLI output

### 6. GitHub Integration

**Webhook Handler** (`src/github/webhook-handler.ts`)
- Handles push and pull_request events
- Clones repo with installation token
- Creates check runs with results
- Posts/updates PR comments

**App Server** (`src/app.ts`)
- Express server for webhook endpoint
- Environment validation
- Health check at /health

### 7. CLI (`src/cli.ts`)

Standalone tool for local analysis:
- Directory or single-file analysis
- Multiple output formats
- Exit codes for CI/CD: 0=clean, 1=high, 2=critical

## Detection Flow

```
Source Code
    │
    ├─→ AST Walker (regex-based parsing)
    │       │
    │       ├─→ Extract function calls
    │       ├─→ Extract decorators  
    │       └─→ Build simplified tree
    │
    ├─→ Language Detector (Python or TypeScript)
    │       │
    │       ├─→ First Pass: Identify tool definitions
    │       │     - @tool decorator
    │       │     - BaseTool subclass
    │       │     - tool() function call
    │       │
    │       └─→ Second Pass: Find execution points
    │             - Match against pattern catalog
    │             - Check if inside tool definition
    │             - Calculate severity
    │
    └─→ Generate Findings
            │
            ├─→ Filter by confidence threshold
            ├─→ Sort by severity/file/line
            └─→ Format for output
```

## Key Decisions

### Why regex instead of proper tree-sitter?

Native compilation issues across platforms. Regex parsing provides:
- Zero build dependencies
- Cross-platform compatibility
- Fast enough for most codebases
- 80% accuracy vs 95% with full AST

Trade-off: Some complex patterns may be missed, but false negatives preferred over false positives.

### Why AFB04 only for MVP?

AFB04 is structurally detectable through static analysis:
- Concrete execution points (function calls)
- Framework-specific patterns (decorators, classes)
- Clear blast radius indicators

AFB01-03 require semantic understanding:
- AFB01: Instruction injection (need to understand prompt construction)
- AFB02: Context poisoning (need to track data provenance)
- AFB03: Constraint bypass (need to understand business logic)

Future versions will add semantic analysis for these.

### Why TypeScript for scanner itself?

- Best GitHub App ecosystem (Octokit, Probot)
- Good async/await support for I/O operations  
- Strong typing helps prevent bugs
- Easy deployment (compile to JS, run anywhere)

## Performance

Typical analysis times:
- Single file: 5-20ms
- Small repo (50 files): 200-500ms
- Medium repo (500 files): 2-5s
- Large repo limited to 1000 files by default

Memory usage: ~100MB for typical repos (dominated by git clone).

## Security Considerations

Scanner itself has minimal attack surface:
- No arbitrary code execution
- Read-only file access
- Temporary directories cleaned up
- GitHub tokens scoped to installation
- No network calls except GitHub API

## Future Enhancements

1. **Full tree-sitter** - WASM or pre-built binaries
2. **Data flow analysis** - Track variable values across calls
3. **Semantic analysis** - Understand prompt construction for AFB01-03
4. **More languages** - Go, Rust, Java
5. **Custom patterns** - User-defined execution point definitions
6. **IDE plugins** - VSCode, JetBrains
