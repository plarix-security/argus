# <a href="https://plarix.dev">WyScan</a>

Static scanner for Python, TypeScript, and JavaScript agent code that reports reachable operations from detected tool registrations.

Runtime: CLI scanner plus GitHub App webhook backend. No HTML/CSS frontend is shipped.

WyScan is an AFB04 scanner that parses Python, TypeScript, and JavaScript with tree-sitter, resolves tool registrations semantically when the code structure allows it, traces reachable calls across the analyzed file set, and reports matched operations when no credited structural policy gate is detected in that analyzed path.

```bash
wyscan scan ./agent-project
```

Example output:

```text
wyscan v1.5.8  ·  Plarix

Scanning  agent-project

-----------------------------------------------------
1 critical  ·  1 warning
-----------------------------------------------------

CRITICAL  tools/setup.py:60
shutil.rmtree(agent_dir)
Detected reachable call from tool registration to shutil.rmtree. No policy gate detected in the analyzed call path.

WARNING   tools/api.py:42
requests.post(url, data)
Detected reachable call from tool registration to requests.post. No policy gate detected in the analyzed call path.
```

## Scope

WyScan currently does all of the following:

- Parses Python and TypeScript/JavaScript source with tree-sitter.
- Resolves tool registrations from framework-specific code structure through semantic analysis.
- Matches reachable operations such as shell execution, file mutation, file reads, HTTP requests, email sends, and common database calls.
- Suppresses findings when a structural policy gate is detected in the analyzed path.
- Carries supporting evidence such as traced input flow, resource hints, and structural versus semantic registration evidence into CEEs.

WyScan currently does not do any of the following:

- Execute your code.
- Trace into third-party package internals.
- Detect AFB01, AFB02, or AFB03.

## Quick Start

```bash
git clone https://github.com/plarix-security/wyscan.git
cd wyscan
npm install
npm run build
npm link

wyscan scan ./my-agent-project

# one-step CLI setup
wyscan install
```

## Commands

| Command | Description |
|---------|-------------|
| `wyscan install` | Run install/build/link/check and print setup dashboard |
| `wyscan scan <path>` | Scan a directory or file |
| `wyscan check` | Verify local scanner dependencies |
| `wyscan version` | Print the package version |
| `wyscan help` | Show CLI help |

## Scan Flags

| Flag | Short | Current behavior |
|------|-------|------------------|
| `--level <severity>` | `-l` | Filters detailed findings by `critical`, `warning`, or `info` |
| `--output <file>` | `-o` | Writes terminal or JSON output to a file |
| `--json` | `-j` | Emits structured JSON |
| `--summary` | `-s` | Prints a one-line summary |
| `--quiet` | `-q` | Suppresses output and relies on exit code |
| `--debug` | `-d` | Prints thrown errors during failures |

## Exit Codes

| Code | Current meaning |
|------|-----------------|
| 0 | No critical or warning findings were reported |
| 1 | At least one warning finding was reported and no critical finding was reported |
| 2 | At least one critical finding was reported |
| 3 | Scanner initialization failed, the target path was invalid, or one or more files failed to analyze |

Exit codes follow the filtered report level. For example, `--level critical` ignores warning-only results when computing the exit code.

## Detection Model

WyScan reports matched operations reachable from detected tool registrations.

Severity is determined by operation category:

- Irreversible operations such as `subprocess.run`, `eval`, `exec`, and file deletion are `CRITICAL`.
- State-modifying operations such as file writes and HTTP POST requests are `WARNING`.
- Read-only operations such as file reads and HTTP GET requests are `INFO`.

### Operation Categories

`CRITICAL`

- Shell execution such as `subprocess.run`, `subprocess.Popen`, `os.system`, and similar process spawns
- Dynamic code execution such as `eval`, `exec`, unsafe deserialization, and native library loading
- File or directory deletion such as `shutil.rmtree`, `os.remove`, or `.unlink()`
- `cursor.executescript()` and Redis flush operations

`WARNING`

- File writes and directory creation such as `.write_text()`, `.mkdir()`, `shutil.copy()`, and `open(..., "w")`
- HTTP requests that match write-style calls such as `requests.post()` and `httpx.patch()`
- HTTP GET calls currently matched by the shipped detector, such as `requests.get()` and `httpx.get()`
- Common database write-style calls such as `.save()`, `.create()`, `.commit()`, Mongo insert or update calls, and email sends

`INFO`

- File reads such as `.read_text()`, `open(..., "r")`, and directory listing or glob operations
- Generic database reads such as `.execute()`, `.fetchone()`, `.fetchall()`, `.query()`, and Redis `get` or `keys`

## Framework Labels

Framework detection supports both Python and TypeScript/JavaScript. WyScan uses semantic extraction from framework code structure such as decorator imports, tool lists, helper-returned tool bundles, `create_react_agent(...)`, `bind_tools(...)`, and `function_map` style registrations.

### Python Frameworks

- LangChain/LangGraph
- CrewAI
- AutoGen
- OpenAI tool schemas and dispatch maps
- LlamaIndex
- MCP
- Framework-core structural decorator registrations

### TypeScript/JavaScript Frameworks

- OpenAI SDK
- LangChain.js/LangGraph.js
- Vercel AI SDK
- MCP SDK
- Mastra
- Playwright/Puppeteer browser automation
- Framework-core structural registrations only (no generic exported-entry fallback)

Framework labels are derived from structural analysis, not pattern tables.

## Policy Gate Detection

WyScan credits a policy gate only when the analyzed path contains code it recognizes as a structural authorization gate.

Current gate credit comes from:

- A function with conditional branches that check parameters and raise an authorization-like exception
- Decorators that are structurally analyzed as wrappers that can prevent execution
- Imported decorators whose wrapper logic is structurally analyzed as gates

Current non-gates:

- Logging calls
- `try/except` around an operation
- Generic exceptions that do not look authorization-related
- Decorator or function naming alone without structural proof

## JSON Output

```bash
wyscan scan ./project --json
```

Current CLI JSON shape:

```json
{
  "version": "1.5.8",
  "scanned_path": "/absolute/path",
  "files_analyzed": 34,
  "runtime_ms": 1200,
  "total_cees": 10,
  "findings": [
    {
      "severity": "CRITICAL",
      "file": "/absolute/path/tools/setup.py",
      "line": 60,
      "column": 5,
      "operation": "File system operation: shutil.rmtree",
      "tool": "setup_agent",
      "framework": "langchain",
      "tool_file": "/absolute/path/tools/setup.py",
      "tool_line": 12,
      "call_path": [
        "/absolute/path/tools/setup.py:setup_agent",
        "/absolute/path/helpers/files.py:delete_workspace"
      ],
       "involves_cross_file": true,
       "unresolved_calls": [],
       "depth_limit_hit": false,
       "evidence_kind": "semantic",
       "supporting_evidence": [
         "Tool registration evidence: decorator tool imported from langchain.tools",
         "Operation evidence: resolved module alias shutil"
       ],
       "resource": "agent_dir",
       "changes_state": true,
       "description": "Detected reachable call from tool \"setup_agent\" (langchain) to shutil.rmtree through 1 intermediate call(s). No policy gate detected in the analyzed call path.",
       "code_snippet": "shutil.rmtree(agent_dir)",
       "category": "file_operation"
    }
  ],
  "cees": [
    {
      "severity": "CRITICAL",
      "file": "/absolute/path/tools/setup.py",
      "line": 60,
      "column": 5,
      "operation": "File system operation: shutil.rmtree",
      "tool": "setup_agent",
      "framework": "langchain",
      "tool_file": "/absolute/path/tools/setup.py",
      "tool_line": 12,
      "call_path": [
        "/absolute/path/tools/setup.py:setup_agent",
        "/absolute/path/helpers/files.py:delete_workspace"
      ],
      "gate_status": "absent",
      "afb_type": "AFB04",
       "classification_note": "Detected reachable call from tool \"setup_agent\" (langchain) to shutil.rmtree through 1 intermediate call(s). The analyzed path crosses file boundaries. No policy gate detected in the analyzed call path.",
       "involves_cross_file": true,
       "unresolved_calls": [],
       "depth_limit_hit": false,
       "evidence_kind": "semantic",
       "supporting_evidence": [
         "Tool registration evidence: decorator tool imported from langchain.tools",
         "Operation evidence: resolved module alias shutil"
       ],
       "resource": "agent_dir",
       "changes_state": true,
       "code_snippet": "shutil.rmtree(agent_dir)",
       "category": "file_operation"
    }
  ],
  "summary": {
    "cees": 10,
    "critical": 2,
    "warning": 3,
    "info": 5,
    "suppressed": 0
  },
  "coverage": {
    "languages_scanned": ["python", "typescript", "javascript"],
    "languages_skipped": [],
    "frameworks_detected": ["langchain", "openai"],
    "files_analyzed": 34,
    "files_skipped": 0,
    "failed_files": [],
    "skipped_files": [],
    "partial": false,
    "total_files_discovered": 34,
    "file_limit": 9007199254740991,
    "file_limit_hit": false,
      "limitations": [
        "The analyzed file set is graphed together per language. Changed-file scans do not guarantee full repository coverage."
      ]
  },
  "methodology": {
    "short_answer": "No. WyScan is on the right track, but it is not yet ready to guarantee full CEE coverage for large-scale agentic systems such as Eliza.",
    "regex_main_method": false,
    "primary_method": "Tree-sitter AST parsing plus semantic tool-registration and call-path analysis.",
    "large_scale_agentic_readiness": {
      "ready": false,
      "verdict": "Not nearly ready for complete coverage of all CEEs in large-scale agentic systems."
    },
    "plan_for_large_scale_cee_coverage": [
      "Build and maintain a versioned large-scale benchmark corpus (including Eliza-style repositories) with hand-labeled CEEs.",
      "Add whole-repository symbol and module resolution for dynamic exports/imports and cross-file indirection.",
      "Add deeper interprocedural dataflow and alias tracking from tool inputs to execution sinks.",
      "Improve dynamic registration recovery (config-driven/plugin-based/runtime-composed tools) with explicit uncertainty reporting.",
      "Replace remaining regex sink matching paths with typed semantic sink models where possible; keep regex as fallback only.",
      "Gate releases on benchmark precision/recall targets and publish those metrics in CI artifacts and release notes."
    ]
  }
}
```

Notes:

- `files_analyzed` at the top level is the report file count used by the current CLI output.
- `coverage.files_analyzed` counts all analyzed files across languages.
- `cees` is the full detected execution-event inventory for the analyzed path set.
- `findings` is the AFB04 subset of `cees`.
- `call_path` lists the traced function path in the analyzed file set.
- `evidence_kind`, `supporting_evidence`, `resource`, and `changes_state` expose the current proof and action summary for each finding or CEE.
- `methodology` includes a blunt readiness verdict, whether regex is the main method, and the concrete plan for large-scale CEE coverage.
- The repository does not currently promise a separately versioned stable JSON schema.

## GitHub App

WyScan can run as a GitHub App for supported webhook events.

Current behavior:

- Push events run only on the repository default branch.
- Pull request events run on `opened` and `synchronize`.
- Push scans the repository working tree.
- Pull request scans changed analyzable files.
- Findings appear in a GitHub Check.
- Pull requests receive an updated issue comment only when findings are present.

Failure and partial-coverage reporting are being tightened further in the implementation. For current details, see `docs/github-app.md` and the CLI output itself.

## GitHub App Deployment

### Quick Start

1. **Build Docker Image**
```bash
docker build -t wyscan-github-app .
```

2. **Run Container**
```bash
docker run -d \
  --name wyscan-app \
  -p 3000:3000 \
  -e GITHUB_APP_ID=your-app-id \
  -e GITHUB_PRIVATE_KEY="$(cat private-key.pem)" \
  -e GITHUB_WEBHOOK_SECRET=your-webhook-secret \
  wyscan-github-app
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_APP_ID` | Yes | GitHub App ID from app settings page |
| `GITHUB_PRIVATE_KEY` | Yes | Private key PEM content (use newlines as `\n` in env) |
| `GITHUB_WEBHOOK_SECRET` | Yes | Secret for webhook signature verification |
| `PORT` | No | Server port (default: 3000) |

### How It Works

When the Wyscan GitHub App is installed on a repository:

1. **Installation Event** (`installation.created`)
   - Automatically scans all repositories in the installation
   - Posts a security issue to each repo with AFB04 scan results
   - Creates and applies "security" label

2. **Push Events** (default branch only)
   - Scans the entire repository at the new commit
   - Creates a GitHub Check run
   - Posts a new security issue with findings

3. **Pull Request Events** (`opened`, `synchronize`)
   - Scans only changed files
   - Creates a GitHub Check run
   - Posts/updates PR comment with findings

### Issue Format

Security issues are titled: `[Wyscan] Security Scan Report — <commit_sha>`

Each issue contains:
- **Summary table** with files analyzed, CEEs detected, findings by severity
- **Detailed findings** organized by severity (Critical, Warning, Info)
- **Coverage notes** explaining analysis scope and limitations
- **Terminal-style formatting** with dividers and emoji severity indicators

### Health Check

```bash
curl http://localhost:3000/health
# Response: {"status":"ok"}
```

### Logs

```bash
docker logs -f wyscan-app
```

For complete setup instructions including GitHub App registration, see `docs/GITHUB_APP_SETUP.md`.

## Current Limitations

- Directory scans graph the analyzed file set together per language. Changed-file scans still do not guarantee full repository coverage.
- External packages are not traced.
- Dynamic runtime tool registration is not guaranteed to be detected.
- Framework labels and sink matching are not complete runtime framework models and are not guaranteed to cover all CEEs in large-scale systems.
- Validation-helper severity downgrades are heuristic only.
- AFB01, AFB02, and AFB03 are not implemented.
- Rust support is not yet implemented.

## Development

```bash
npm install
npm run build
npm test
npm run wyscan -- scan ./project
```

## Documentation

- `docs/install.md`
- `docs/usage.md`
- `docs/detection.md`
- `docs/github-app.md`
- `docs/limitations.md`

## License

Apache-2.0. See `LICENSE`.
