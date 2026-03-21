# AFB Scanner

**Agent Failure Boundary Scanner** - Detects AFB04 (Unauthorized Action) boundaries in agentic AI codebases through static analysis.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## What is AFB04?

AFB04 represents the **Agent → Act** boundary from the [AFB Taxonomy](https://github.com/plarix-security/afb-spec) — the critical transition point where an AI agent attempts to perform an action that affects world state.

This includes:
- **Tool invocations** exposed to agent reasoning (LangChain, CrewAI, custom tools)
- **Shell command execution** (subprocess, os.system, child_process)
- **File system operations** (read, write, delete)
- **External API calls** (requests, fetch, axios)
- **Database operations** (SQL queries, ORM writes)
- **Dynamic code execution** (eval, exec)

These execution points require careful authorization and validation to prevent unintended actions driven by adversarial inputs or compromised reasoning.

## Why AFB Scanner?

Traditional security scanners miss agent-specific risks:
- They don't understand tool-calling patterns
- They can't identify agent execution boundaries
- They don't distinguish between direct user code and agent-accessible code

AFB Scanner is purpose-built for agentic AI security:
- **Framework-aware**: Recognizes LangChain, CrewAI, and custom agent patterns
- **Context-sensitive**: Distinguishes code inside tool definitions (higher risk) from regular code
- **No hardcoding**: Uses AST analysis, not regex matching
- **Zero false-positive tolerance**: Reports nothing rather than fabricating findings

## Quick Start

### Installation

```bash
npm install
npm run build
```

### CLI Usage

```bash
# Analyze a directory
npm run analyze ./path/to/agent-project

# JSON output for CI/CD
npm run analyze ./project -- --json

# Analyze specific files
npm run analyze ./project -- --files tools.py agent.ts

# Higher confidence threshold
npm run analyze ./project -- --confidence 0.8
```

### GitHub App

Deploy as a GitHub App to automatically scan PRs and pushes:

1. Create a GitHub App with these permissions:
   - Pull requests: Read & Write (for comments)
   - Contents: Read (for cloning)
   - Commit statuses: Read & Write

2. Subscribe to events:
   - Pull request
   - Push

3. Configure environment variables:
```bash
GITHUB_APP_ID=your-app-id
GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n..."
GITHUB_WEBHOOK_SECRET=your-webhook-secret
PORT=3000
```

4. Start the server:
```bash
npm start
```

5. Set your GitHub App webhook URL to `https://your-domain/webhook`

## What It Detects

### Python Patterns

| Category | Examples | Severity |
|----------|----------|----------|
| Tool Definitions | `@tool` decorator, `BaseTool` subclass, `StructuredTool()` | HIGH |
| Shell Execution | `subprocess.run()`, `os.system()`, `os.popen()` | CRITICAL |
| File Operations | `open()`, `Path.write_text()`, `shutil.rmtree()` | MEDIUM-HIGH |
| API Calls | `requests.post()`, `httpx.get()`, `aiohttp` | HIGH |
| Database | `cursor.execute()`, SQLAlchemy `session.execute()` | HIGH |
| Code Execution | `eval()`, `exec()`, `compile()` | CRITICAL |

### TypeScript/JavaScript Patterns

| Category | Examples | Severity |
|----------|----------|----------|
| Tool Definitions | `tool()`, `DynamicTool`, `DynamicStructuredTool` | HIGH |
| Shell Execution | `exec()`, `spawn()`, `execSync()` | CRITICAL |
| File Operations | `fs.writeFile()`, `fs.rm()`, `fs.unlink()` | MEDIUM-HIGH |
| API Calls | `fetch()`, `axios.post()`, `http.request()` | HIGH |
| Database | Prisma operations, `query()`, `execute()` | HIGH |
| Code Execution | `eval()`, `new Function()` | CRITICAL |

## Sample Report

```
AFB Scanner v1.0.0
===================================

⚠️  5 AFB04 boundaries detected.

Summary:
  Critical: 1
  High:     3
  Medium:   1

Findings:

🔴 CRITICAL [TOOL]
   File: tools/shell_tool.py:15
   Category: shell_execution
   Operation: Subprocess execution
   Code: subprocess.run(command, shell=True, capture_output=True)

🔴 HIGH [TOOL]
   File: tools/api_tool.py:23
   Category: api_call
   Operation: HTTP request via requests library
   Code: requests.post(url, json=data)

🔴 HIGH
   File: agent.py:45
   Category: tool_call
   Operation: LangChain/CrewAI tool definition
   Code: @tool\ndef execute_query(query: str):

🔴 HIGH
   File: tools/db_tool.py:31
   Category: database_operation
   Operation: Database cursor execute
   Code: cursor.execute(query, params)

🟡 MEDIUM
   File: utils/file_handler.py:12
   Category: file_operation
   Operation: File open operation
   Code: open(filepath, 'r')

---
Files analyzed: 15
Analysis time: 234ms
```

## Scope & Limitations

### MVP Scope (v1.0)

**Included:**
- AFB04 (Unauthorized Action) detection only
- Python and TypeScript/JavaScript codebases
- LangChain and CrewAI framework recognition
- CLI tool for local analysis
- GitHub App for PR/push analysis

**Not Included (Future Versions):**
- AFB01 (Instruction Boundary) - requires semantic analysis
- AFB02 (Context Boundary) - requires data flow analysis
- AFB03 (Constraint Boundary) - requires policy specification
- Other languages (Go, Rust, Java)
- IDE plugins

### Detection Accuracy

- **No false positives by design**: We report nothing rather than guess
- **High confidence for framework patterns**: 0.9+ for recognized tools
- **Medium confidence for generic patterns**: 0.7-0.8 for common libraries
- **Context elevation**: Findings inside tool definitions get higher severity

## Architecture

```
afb-scanner/
├── src/
│   ├── app.ts                 # GitHub App entry point
│   ├── cli.ts                 # CLI tool
│   ├── analyzer/
│   │   ├── index.ts           # Main orchestrator
│   │   ├── ast-walker.ts      # Tree-sitter AST utilities
│   │   ├── python/
│   │   │   └── detector.ts    # Python pattern matching
│   │   └── typescript/
│   │       └── detector.ts    # TS/JS pattern matching
│   ├── afb/
│   │   └── afb04.ts           # AFB04 patterns & classification
│   ├── github/
│   │   └── webhook-handler.ts # GitHub App webhooks
│   ├── reporter/
│   │   └── pr-comment.ts      # Report formatters
│   └── types/
│       └── index.ts           # Type definitions
├── package.json
├── tsconfig.json
└── README.md
```

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Run CLI in development
npm run analyze ./test-project

# Start server in development
npm run dev
```

## Contributing

Contributions welcome! Please read the [AFB Specification](https://github.com/plarix-security/afb-spec) before contributing.

Priority areas:
1. Additional framework support (AutoGen, Semantic Kernel)
2. More language parsers (Go, Rust)
3. Data flow analysis for AFB02/AFB03
4. IDE integrations

## License

MIT

## References

- [AFB Taxonomy Specification](https://github.com/plarix-security/afb-spec)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [LangChain Security](https://python.langchain.com/docs/security/)
