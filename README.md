# WyScan

Static analyzer for agentic AI codebases that detects unsafe tool boundaries.

WyScan finds places in your Python agent code where tools can execute dangerous operations without authorization checks. It builds a call graph from tool registrations (like `@tool` decorators) and traces paths to dangerous operations (like `subprocess.run` or `shutil.rmtree`). If there is no policy gate in the path, WyScan reports it.

```
wyscan  v0.7.0-beta  by Plarix
AFB Scanner

Scanning: ./agent-project
--------------------------------------------------

CRITICAL  tools/setup.py:60
shutil.rmtree(agent_dir) reachable from @tool (langchain)
No policy gate in call path. Agent can delete directories.

WARNING   tools/api.py:42
requests.post(url, data) reachable from @tool (crewai)
No policy gate in call path. Agent can send HTTP requests.

--------------------------------------------------
1 critical  1 warning  3 info  12 files  0.4s
```

## What It Does

WyScan scans Python agent codebases and reports:

- Tool functions exposed to LLM reasoning that can execute shell commands
- File system operations (delete, write, move) reachable from agent tools without authorization checks
- External API calls (HTTP POST/PUT/DELETE) accessible from tool definitions
- Database write operations reachable from tools
- Dynamic code execution (eval, exec) in agent-callable functions

It uses tree-sitter for real AST parsing and builds a call graph to trace from tool registrations to dangerous operations.

## What It Does NOT Do

- **Does not execute your code.** Static analysis only.
- **Does not use LLMs or inference.** Pure call graph analysis.
- **Does not scan TypeScript or JavaScript.** The TypeScript detector is disabled and returns no findings. Python is the only supported language.
- **Does not resolve imports beyond one level.** If tool A calls helper B which calls helper C which calls subprocess.run, the path from A to subprocess.run may not be detected.
- **Does not trace calls into external packages.** Only project files are analyzed.

## Why This Exists

When you decorate a function with `@tool`, it becomes callable by an LLM. If that tool can reach `subprocess.run()`, `shutil.rmtree()`, or `requests.post()` through any call path without authorization checks, the agent has unrestricted access to those capabilities.

Pattern-based scanners like Semgrep or Bandit will find `subprocess.run()` everywhere in your codebase. They do not know whether that code is reachable from an agent tool.

WyScan traces from tool registration points to dangerous operations. It reports only the paths that an AI agent can actually invoke.

## Quick Start

```bash
# Clone and install
git clone https://github.com/plarix-security/wyscan.git
cd wyscan
npm install
npm run build
npm link

# Scan your agent project
wyscan scan ./my-agent-project
```

That is it. WyScan will scan all Python files, build a call graph from tool definitions, and report any dangerous operations reachable without policy gates.

## CLI Reference

### Commands

| Command | Description |
|---------|-------------|
| `wyscan scan <path>` | Scan a directory or file for AFB exposures |
| `wyscan check` | Verify dependencies (tree-sitter, Node.js) |
| `wyscan version` | Print version and exit |
| `wyscan help` | Show usage information |

### Scan Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--level <severity>` | `-l` | Minimum severity to report: `critical`, `warning`, `info` |
| `--output <file>` | `-o` | Write report to file instead of stdout |
| `--json` | `-j` | Output structured JSON |
| `--summary` | `-s` | One-line summary only |
| `--recursive` | `-r` | Scan recursively (default: true) |
| `--quiet` | `-q` | Suppress output, exit code only |
| `--debug` | `-d` | Show debug information |

### Exit Codes

| Code | Meaning | CI Action |
|------|---------|-----------|
| 0 | No critical or warning findings | Pass |
| 1 | Warning level findings detected | Optional fail |
| 2 | Critical level findings detected | Fail |
| 3 | Scanner error (parse failure, missing dependency) | Fail |

### CI/CD Example

```bash
wyscan scan ./src --level critical
if [ $? -eq 2 ]; then
  echo "Critical AFB exposures detected"
  exit 1
fi
```

## What It Detects

WyScan uses a severity model based on blast radius and reversibility.

### Severity Levels

**CRITICAL** - Irreversible destruction, exfiltration, or arbitrary execution

| Category | Operations |
|----------|-----------|
| Shell execution | `subprocess.run`, `subprocess.Popen`, `subprocess.call`, `os.system`, `os.popen`, `os.exec*`, `asyncio.create_subprocess_*` |
| Code execution | `eval`, `exec` |
| File deletion | `shutil.rmtree`, `os.remove`, `os.unlink`, `os.rmdir`, `Path.unlink`, `Path.rmdir` |

**WARNING** - Recoverable but consequential state modification

| Category | Operations |
|----------|-----------|
| File writes | `Path.write_text`, `Path.write_bytes`, `file.write`, `Path.mkdir`, `shutil.copy`, `shutil.move`, `os.rename`, `os.makedirs` |
| HTTP mutations | `requests.post`, `requests.put`, `requests.patch`, `requests.delete`, `httpx.*`, `aiohttp.*` |
| Database writes | `session.add`, `session.delete`, `session.commit`, `session.flush`, `model.save`, `model.create`, `cursor.insert`, `bulk_create` |
| Email | `smtp.send_message`, `smtp.send_email`, `smtp.sendmail` |

**INFO** - Read-only access to sensitive data or external systems

| Category | Operations |
|----------|-----------|
| File reads | `open()`, `Path.read_text`, `Path.read_bytes`, `file.read` |
| HTTP reads | `requests.get`, `httpx.get`, `urllib.request.*`, `aiohttp.*.get` |
| Database reads | `cursor.execute` (SELECT), `cursor.fetchall`, `cursor.fetchone`, `cursor.query`, `cursor.select` |
| Environment | `os.getenv`, `os.environ`, `Path.listdir`, `Path.glob` |

## Supported Frameworks

WyScan detects tool registrations in these frameworks:

| Framework | Detection Patterns |
|-----------|-------------------|
| LangChain | `@tool`, `BaseTool`, `StructuredTool`, `Tool()`, `create_react_agent`, `AgentExecutor` |
| CrewAI | `@task`, `@agent`, `crewai.tool`, `CrewAITool` |
| AutoGen | `register_function`, `function_map`, `UserProxyAgent`, `AssistantAgent` |
| LlamaIndex | `FunctionTool`, `QueryEngineTool`, `ToolOutput` |
| MCP | `mcp.server`, `@server.tool`, `tool_handler`, `ToolProvider` |
| OpenAI | `tools=[...]`, `function_call`, `tool_choice`, `"type": "function"` |

## How It Works

1. **Parse source files** using tree-sitter to build a real AST (not regex)
2. **Identify tool registrations** by matching against framework-specific patterns
3. **Build a call graph** from each tool definition
4. **Trace execution paths** to find dangerous operations
5. **Check for policy gates** in call paths (functions that raise authorization exceptions or have conditional returns)
6. **Report findings** with severity based on operation type

### Policy Gate Detection

WyScan recognizes these as structural policy gates:

- Functions that raise `PermissionError`, `AuthorizationError`, `AccessDeniedError`, or similar
- Functions with conditional branches that check parameters and can prevent execution
- Known authorization decorators: `@require_permission`, `@permission_required`, `@login_required`, `@authenticated`, `@require_role`, `@role_required`, `@user_passes_test`

If a policy gate exists in the call path between a tool and a dangerous operation, the finding is not reported.

## JSON Output Schema

```bash
wyscan scan ./project --json
```

```json
{
  "version": "0.7.0-beta",
  "scanned_path": "/absolute/path",
  "files_analyzed": 34,
  "runtime_ms": 1200,
  "findings": [
    {
      "severity": "CRITICAL",
      "file": "tools/setup.py",
      "line": 60,
      "function": "shutil.rmtree",
      "tool_registration": "setup_agent",
      "description": "Tool setup_agent (langchain) can reach shutil.rmtree. No policy gate detected in call path.",
      "afb_type": "AFB04"
    }
  ],
  "summary": {
    "critical": 2,
    "warning": 3,
    "info": 5,
    "suppressed": 0
  }
}
```

The JSON schema will not change between patch versions. Breaking changes require a minor version bump.

## GitHub App Setup

WyScan can run as a GitHub App to scan pull requests and push events automatically.

### Configuration

Set these environment variables:

```bash
GITHUB_APP_ID=your-app-id
GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n..."
GITHUB_WEBHOOK_SECRET=your-webhook-secret
PORT=3000
```

### Start the Service

```bash
npm run build
npm start
```

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `POST /webhook` | GitHub webhook events |

### Supported Events

- **push** to default branch: Full directory scan, creates GitHub Check
- **pull_request** (opened, synchronize): Scans changed files only, creates GitHub Check and posts PR comment

The GitHub App uses the same scanner engine as the CLI. Findings are identical.

## Current Limitations

These are honest limitations of the current version:

1. **TypeScript/JavaScript detection is disabled.** The TypeScript detector returns no findings to avoid false positives from pattern matching. Python is the only working language.

2. **Cross-file call resolution is single-level only.** If your tool calls a helper that calls another helper that calls subprocess.run, the path may not be detected. Only one level of imports is resolved.

3. **External package calls are not traced.** If your tool calls a function from a third-party package that internally calls subprocess.run, WyScan will not detect it.

4. **AFB04 only.** This version detects Unauthorized Action boundaries only. AFB01 (Instruction Injection), AFB02 (Context Poisoning), and AFB03 (Constraint Bypass) require semantic analysis and are not implemented.

5. **Call graph depth is limited to 10.** Very deep call chains may not be fully traced.

## Why Not Semgrep or Bandit?

**Semgrep** is pattern-based. It finds `subprocess.run()` everywhere in your codebase, whether in test fixtures, CLI utilities, or agent tools. It does not know which code paths are reachable from LLM-callable functions.

**Bandit** is a Python security scanner. It flags dangerous functions but does not understand agent frameworks. A `subprocess.run()` in a LangChain `@tool` is treated the same as one in a standalone script.

**WyScan** is agent-aware. It:

1. Identifies tool registration points (`@tool`, `BaseTool`, `register_function`, etc.)
2. Builds a call graph from those tools
3. Traces execution paths to dangerous operations
4. Reports only operations reachable from agent-callable code

The key difference: Semgrep might report 50 subprocess calls across your codebase. WyScan reports the 3 that an AI agent can actually invoke through tool definitions.

## Roadmap

These features are planned but not yet implemented:

- [ ] Full TypeScript/JavaScript support with tree-sitter parsing
- [ ] Multi-level transitive import resolution
- [ ] Custom pattern definitions via configuration file
- [ ] IDE plugins (VSCode, JetBrains)
- [ ] AFB01-03 detection with semantic analysis
- [ ] Configuration file support for include/exclude patterns

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

# Run locally without global install
npm run wyscan -- scan ./project
```

## Project Structure

```
wyscan/
├── src/
│   ├── cli/                # CLI interface
│   │   ├── index.ts        # Entry point and commands
│   │   ├── formatter.ts    # Terminal output formatting
│   │   └── version.ts      # Version constants
│   ├── analyzer/           # Scanner engine
│   │   ├── index.ts        # Orchestrator
│   │   ├── python/         # Python detector (working)
│   │   │   ├── detector.ts
│   │   │   ├── ast-parser.ts
│   │   │   └── call-graph.ts
│   │   └── typescript/     # TypeScript detector (disabled)
│   ├── github/             # GitHub App integration
│   ├── reporter/           # Output formatters
│   └── types/              # TypeScript types
├── wasm/                   # Tree-sitter WASM binaries
├── test/                   # Test files
├── test-repos/             # Test fixtures
├── examples/               # Example files
├── docs/                   # GitHub Pages documentation
├── package.json
├── tsconfig.json
└── LICENSE
```

## Docs

Full documentation is available at: https://plarix-security.github.io/wyscan

## Contributing

Contributions are welcome. Please open an issue first to discuss what you would like to change.

See https://github.com/plarix-security/wyscan/issues

## License

Apache-2.0 License. See [LICENSE](LICENSE) file for details.

## Links

- Repository: https://github.com/plarix-security/wyscan
- Issues: https://github.com/plarix-security/wyscan/issues
- Documentation: https://plarix-security.github.io/wyscan
