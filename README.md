# WyScan

**Static analyzer for agentic AI codebases that detects unsafe tool boundaries.**

wyscan finds places in your agent code where tools can execute dangerous operations, like shell commands, file deletion, or external API calls, without authorization checks. It analyzes Python and TypeScript/JavaScript codebases to identify **AFB04 (Unauthorized Action)** boundaries: the execution paths where an AI agent's actions can affect systems or data.

```
wyscan  v0.6.0  by Plarix
AFB Scanner — github.com/plarix-security/wyscan

Scanning: /path/to/agent-project
──────────────────────────────────────────────────

CRITICAL  agent_tools.py:47
shutil.rmtree(agent_dir) — file operation reachable from @tool
(langchain), no policy gate in call path.
Agent can delete arbitrary directories without authorization.

WARNING   api_client.py:83
requests.post(url, data=payload) — external API call reachable
from @tool (langchain), no policy gate in call path.
Agent can transmit data externally without authorization.

──────────────────────────────────────────────────
2 critical  3 warning  5 info  34 files  1.2s
```

## What It Does

**wyscan scans your agent codebase and reports:**

- Tool functions exposed to LLM reasoning that can execute shell commands
- File system operations (delete, write, move) reachable from agent tools
- External API calls (HTTP POST/PUT/DELETE) without policy gates
- Database write operations accessible from tool definitions
- Dynamic code execution (eval, exec) in agent-callable functions

**It does NOT:**
- Execute your code (static analysis only)
- Require you to change your code to run
- Use LLMs or inference (pure AST-based detection)
- Produce false positives from pattern matching (proper call graph analysis)

## Why This Matters

In agentic systems, the boundary between AI reasoning and code execution is a critical security point. A tool decorated with `@tool` becomes callable by the LLM. If that tool can reach `subprocess.run()`, `shutil.rmtree()`, or `requests.post()` without authorization checks, the agent has unrestricted access to those capabilities.

wyscan helps you find these boundaries early so you can:
- Add policy gates before deployment
- Review which capabilities agents actually need
- Audit authorization coverage across tool definitions
- Prevent agents from performing unauthorized actions

## Quick Start

### Install

**Option 1: Link locally (development)**
```bash
cd wyscan
npm install
npm run build
npm link
```

**Option 2: Global install (when published)**
```bash
npm install -g @plarix/wyscan
```

**Option 3: Direct usage (no install)**
```bash
npm run wyscan -- scan ./project
```

### Run Your First Scan

```bash
wyscan scan ./my-agent-project
```

That's it. wyscan will scan all Python and TypeScript/JavaScript files, build a call graph from tool definitions, and report any dangerous operations reachable without policy gates.

## CLI Reference

### Commands

| Command | Description |
|---------|-------------|
| `wyscan scan <path>` | Scan a directory or file for AFB exposures |
| `wyscan check` | Verify dependencies (tree-sitter, Node.js) |
| `wyscan version` | Print version and exit |
| `wyscan help` | Show usage information |

### Scan Options

| Flag | Description | Example |
|------|-------------|---------|
| `--json` | Output structured JSON with stable schema | `wyscan scan ./project --json` |
| `--level <severity>` | Filter by severity: `critical`, `warning`, `info` | `wyscan scan ./project --level critical` |
| `--output <file>` | Write report to file instead of stdout | `wyscan scan ./project --output report.txt` |
| `--summary` | One-line summary only (for CI pipelines) | `wyscan scan ./project --summary` |

### Exit Codes

wyscan uses exit codes for CI/CD integration:

| Code | Meaning | CI Action |
|------|---------|-----------|
| `0` | No critical or warning findings | ✓ Pass build |
| `1` | Warning level findings detected | ⚠ Optional: fail build |
| `2` | Critical level findings detected | ✗ Fail build |
| `3` | Scanner error (parse failure, dependency missing) | ✗ Fail build |

**CI/CD Example:**
```bash
# Fail build on critical findings only
wyscan scan ./src --level critical
if [ $? -eq 2 ]; then
  echo "Critical AFB exposures detected. Build failed."
  exit 1
fi
```

## Examples

### Basic Scan

```bash
wyscan scan ./agent-project
```

**Output:**
```
wyscan  v0.6.0  by Plarix
AFB Scanner — github.com/plarix-security/wyscan

Scanning: /agent-project
──────────────────────────────────────────────────

CRITICAL  tools/setup_agent.py:60
shutil.rmtree(agent_dir) — file operation reachable from @tool
(langchain), no policy gate in call path.
Agent can execute this without authorization basis.

WARNING   tools/api_client.py:42
requests.post(url, data=payload) — external API call reachable
from @tool (crewai), no policy gate in call path.
Agent can execute this without authorization basis.

INFO      tools/reader.py:28
open(file_path, 'r') — file operation reachable from @tool
(langchain), no policy gate in call path.
Agent can execute this without authorization basis.

──────────────────────────────────────────────────
1 critical  1 warning  1 info  12 files  0.3s
```

### JSON Output

```bash
wyscan scan ./project --json
```

**Output:**
```json
{
  "version": "0.6.0",
  "scanned_path": "/project",
  "files_analyzed": 12,
  "runtime_ms": 342,
  "findings": [
    {
      "severity": "CRITICAL",
      "file": "tools/setup_agent.py",
      "line": 60,
      "function": "shutil.rmtree",
      "tool_registration": "setup_agent",
      "description": "Tool \"setup_agent\" (langchain) can reach shutil.rmtree. No policy gate or authorization check detected in call path. Agent can execute this operation without authorization basis.",
      "afb_type": "AFB04"
    }
  ],
  "summary": {
    "critical": 1,
    "warning": 1,
    "info": 1,
    "suppressed": 0
  }
}
```

### Filter by Severity

```bash
# Show only critical findings
wyscan scan ./project --level critical

# Show critical and warning (hide info)
wyscan scan ./project --level warning
```

### Summary for CI

```bash
wyscan scan ./project --summary
```

**Output:**
```
1 critical  1 warning  1 info  12 files  0.3s
```

Perfect for CI pipelines that need a quick pass/fail status.

### Output to File

```bash
# Human-readable report
wyscan scan ./project --output report.txt

# Machine-readable JSON
wyscan scan ./project --json --output report.json
```

### Check Dependencies

```bash
wyscan check
```

**Output:**
```
wyscan  v0.6.0  by Plarix
AFB Scanner — github.com/plarix-security/wyscan

Checking dependencies...

  ✓ Node.js                   v18.0.0
  ✓ tree-sitter-python.wasm   found
  ✓ Parser initialization     ok

All checks passed. Ready to scan.
```

## What wyscan Detects

### Severity Levels

wyscan uses a four-level severity model based on blast radius and reversibility:

**CRITICAL** - Irreversible destruction, exfiltration, or arbitrary execution
- Shell command execution (`subprocess.run`, `os.system`)
- Dynamic code execution (`eval`, `exec`)
- File/directory deletion (`shutil.rmtree`, `os.remove`, `unlink`)

**WARNING** - Recoverable but consequential state modification or transmission
- File writes (`write_text`, `open('w')`, `shutil.copy`)
- HTTP mutations (`requests.post`, `httpx.put`, `fetch` with POST)
- Database writes (`session.add`, `execute` with INSERT/UPDATE)
- Email sending (`smtp.sendmail`)

**INFO** - Read-only access to sensitive data or external systems
- File reads (`open('r')`, `read_text`)
- HTTP GET requests (`requests.get`, `fetch`)
- Database queries (`execute` with SELECT, `fetchall`)
- Environment variable access (`os.getenv`)

**SUPPRESSED** - Low-confidence detections (logged but not reported)

### Supported Frameworks

wyscan detects tool registrations in:

- **LangChain**: `@tool` decorator, `BaseTool` subclasses, `Tool()` constructor
- **CrewAI**: `@task` decorator, `@agent` decorator
- **AutoGen**: `register_function`, `function_map`
- **LlamaIndex**: `FunctionTool`, `QueryEngineTool`
- **MCP**: `@server.tool` decorator
- **OpenAI**: Raw function calling with `tools=` parameter

### Supported Languages

- **Python**: Full AST parsing with tree-sitter, cross-file call graph analysis
- **TypeScript/JavaScript**: Planned (detector exists but currently returns empty findings)

## How It Works

1. **Parse source files** using tree-sitter to build an AST
2. **Identify tool registrations** by detecting framework-specific patterns
3. **Build a call graph** from each tool definition
4. **Trace execution paths** to find dangerous operations
5. **Check for policy gates** in call paths (authorization checks)
6. **Report findings** with severity based on operation type and context

**Policy Gate Detection:**

wyscan looks for structural authorization checks between tools and dangerous operations:
- Functions that raise `PermissionError`, `AuthorizationError`, or similar
- Conditional branches that check parameters and can prevent execution
- Early returns when authorization fails

If no gate is detected in the call path, the finding is reported.

## JSON Schema

The `--json` output follows this stable schema (versioned):

```json
{
  "version": "0.6.0",
  "scanned_path": "/absolute/path",
  "files_analyzed": 34,
  "runtime_ms": 1200,
  "findings": [
    {
      "severity": "CRITICAL|WARNING|INFO|SUPPRESSED",
      "file": "relative/path/to/file.py",
      "line": 47,
      "function": "shutil.rmtree",
      "tool_registration": "function_name_with_@tool",
      "description": "Detailed explanation of the finding",
      "afb_type": "AFB04"
    }
  ],
  "summary": {
    "critical": 2,
    "warning": 3,
    "info": 5,
    "suppressed": 10
  }
}
```

**Schema Stability:** The JSON schema will not change between patch versions. Breaking schema changes require a minor version bump with migration documentation.

## GitHub App Mode

wyscan can run as a GitHub App to scan pull requests and push events automatically.

### Setup

1. Create a GitHub App with webhook events enabled
2. Set environment variables:
   ```bash
   GITHUB_APP_ID=your-app-id
   GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n..."
   GITHUB_WEBHOOK_SECRET=your-webhook-secret
   PORT=3000
   ```
3. Start the service:
   ```bash
   npm run build
   npm start
   ```

### Endpoints

- `GET /health` - Health check
- `POST /webhook` - GitHub webhook events

The GitHub App mode uses the same scanner engine as the CLI. Findings are identical.

## Configuration

wyscan uses sensible defaults. No configuration file is required.

**Default exclusions:**
- `node_modules/`
- `.venv/`, `venv/`
- `__pycache__/`
- `dist/`, `build/`
- `.git/`
- `test/`, `tests/`, `*.test.*`, `*.spec.*`

**Default limits:**
- Max files: 1000
- Confidence threshold: 0.7
- Include: `**/*.py`, `**/*.ts`, `**/*.tsx`, `**/*.js`, `**/*.jsx`

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Link for development
npm run link

# Run locally without install
npm run wyscan -- scan ./project
```

### Project Structure

```
wyscan/
├── src/
│   ├── cli/              # CLI interface
│   │   ├── index.ts      # Entry point and commands
│   │   ├── formatter.ts  # Terminal output formatting
│   │   └── version.ts    # Version constants
│   ├── analyzer/         # Scanner engine
│   │   ├── index.ts      # Orchestrator
│   │   ├── python/       # Python analyzer
│   │   │   ├── detector.ts     # Detection logic
│   │   │   ├── ast-parser.ts   # Tree-sitter AST parser
│   │   │   └── call-graph.ts   # Call graph builder
│   │   └── typescript/   # TypeScript analyzer (planned)
│   ├── github/           # GitHub App integration
│   ├── reporter/         # Output formatters
│   └── types/            # TypeScript types
├── wasm/                 # Tree-sitter WASM binaries
└── test-repos/           # Test fixtures
```

## Limitations

**Current scope:**
- AFB04 (Unauthorized Action) detection only
- Python language support (TypeScript planned)
- Tree-sitter based AST parsing
- Single-level cross-file call resolution

**Out of scope:**
- AFB01 (Instruction Injection) - requires semantic analysis
- AFB02 (Context Poisoning) - requires data provenance tracking
- AFB03 (Constraint Bypass) - requires business logic understanding
- Runtime behavior analysis
- Automatic remediation or code generation
- Multi-language projects (Python + TypeScript in same scan)

## Roadmap

- [ ] Full TypeScript/JavaScript support
- [ ] Multi-level transitive import resolution
- [ ] Custom pattern definitions
- [ ] IDE plugins (VSCode, JetBrains)
- [ ] AFB01-03 detection with semantic analysis
- [ ] Configuration file support

## Contributing

Contributions are welcome. See the project's GitHub repository for guidelines.

## License

MIT License. See LICENSE file for details.

## Links

- **Repository**: https://github.com/plarix-security/wyscan
- **Documentation**: https://github.com/plarix-security/wyscan/blob/main/README.md
- **Issues**: https://github.com/plarix-security/wyscan/issues
- **AFB Specification**: https://github.com/plarix-security/wyscan/blob/main/afb-spec/

## About AFB

**Agent Failure Boundary (AFB)** is a security taxonomy for AI agent systems that defines four critical boundaries:

- **AFB01**: Instruction Boundary - separates system instructions from user input
- **AFB02**: Context Boundary - separates trustworthy from untrusted retrieved context
- **AFB03**: Constraint Boundary - enforces operational limits and guardrails
- **AFB04**: Unauthorized Action - controls what operations agents can perform

wyscan currently detects AFB04 boundaries through static analysis. Future versions will support AFB01-03 with semantic analysis capabilities.

---

**Built by Plarix Security** • Securing agentic AI systems from the ground up
