# [WyScan](https://plarix.dev)

> Static scanner for Python, TypeScript, and JavaScript agent code that reports dangerous operations reachable from detected tool registrations.

**WyScan is an AFB04 scanner.** It parses source files with tree-sitter, resolves tool registrations through semantic analysis of framework code structure, traces reachable calls across the analyzed file set, and reports matched operations when no structural policy gate is detected in that path.

```bash
wyscan scan ./agent-project
```

---

## Output

```
  wyscan v1.6.2  ·  Plarix
  ─────────────────────────────────────────────────────

  Scanning  agent-project

  ─────────────────────────────────────────────────────
  1 critical  ·  1 warning
  4 cees detected
  ─────────────────────────────────────────────────────

  ● CRITICAL  setup.py:60:5
    shutil.rmtree(agent_dir)
    Detected reachable call from tool "setup_agent" (langchain) to shutil.rmtree through 1 intermediate call. No policy gate detected.
    tool: tools/setup.py:12
    path: cross-file

  ● WARNING   api.py:42:12
    requests.post(url, data)
    Detected reachable call from tool "api_tool" (langchain) to requests.post. No policy gate detected.

  ─────────────────────────────────────────────────────
  34 files  ·  1.2s
```

**`--summary` flag** (one-liner for CI):

```
1 critical  ·  1 warning  ·  4 cees  ·  34 files  ·  1.2s
```

**`wyscan check`**:

```
  wyscan v1.6.2  ·  Plarix
  ─────────────────────────────────────────────────────

  Checking dependencies...

  ✓ Node.js                   v20.11.0
  ✓ tree-sitter-python.wasm   found
  ✓ Parser initialization     ok

  All checks passed. Ready to scan.
```

**`wyscan tui`**:

```
  ┌──────────────────────────────────────────────────────┐
  │ WYSCAN CLI QUICK PANEL                               │
  ├──────────────────────────────────────────────────────┤
  │ install : wyscan install                             │
  │ scan  : wyscan scan <path> [-l critical|warning]     │
  │ check : wyscan check                                 │
  │ json  : wyscan scan <path> --json                    │
  │ quiet : wyscan scan <path> --summary                 │
  └──────────────────────────────────────────────────────┘
```

**`wyscan install`**:

```
  wyscan v1.6.2  ·  Plarix
  ─────────────────────────────────────────────────────

  Preparing local CLI installation...

  ┌──────────────────────────────────────────────────────┐
  │ WYSCAN INSTALL DASHBOARD                             │
  ├──────────────────────────────────────────────────────┤
  │ ✔ npm install    ·  ok                               │
  │ ✔ npm run build  ·  ok                               │
  │ ✔ npm link       ·  ok                               │
  │ ✔ check          ·  all checks passed                │
  ├──────────────────────────────────────────────────────┤
  │ Next: wyscan scan <path>  |  wyscan help             │
  └──────────────────────────────────────────────────────┘
```

---

## Quick Start

```bash
git clone https://github.com/plarix-security/wyscan.git
cd wyscan
npm install
npm run build
npm link

wyscan scan ./my-agent-project
```

One-step installer:

```bash
git clone https://github.com/plarix-security/wyscan.git
cd wyscan
npm install && node dist/cli/index.js install
```

---

## Commands

| Command | Description |
|---------|-------------|
| `wyscan install` | Run npm install + build + link + check, print setup dashboard |
| `wyscan scan <path>` | Scan a file or directory |
| `wyscan check` | Verify scanner dependencies and parser initialization |
| `wyscan tui` | Print the quick command panel |
| `wyscan version` | Print version |
| `wyscan help [scan]` | Show help, optionally for a subcommand |

---

## Scan Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--level <severity>` | `-l` | Filter findings to `critical`, `warning`, or `info` (default: `info`) |
| `--output <file>` | `-o` | Write output to file |
| `--json` | `-j` | Structured JSON output |
| `--summary` | `-s` | One-line count only |
| `--quiet` | `-q` | No output, rely on exit code |
| `--debug` | `-d` | Print thrown errors on scan failure |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above the filtered level |
| 1 | At least one warning, no critical |
| 2 | At least one critical |
| 3 | Initialization failed, invalid path, or parse failure |

Exit codes follow the filtered level. `--level critical` ignores warning-only results when computing the exit code.

---

## Detection Model

WyScan reports operations reachable from a detected tool registration with no structural policy gate in the analyzed call path.

### Severity

| Severity | Condition | Examples |
|----------|-----------|---------|
| `CRITICAL` | Irreversible or arbitrary execution | `subprocess.run`, `os.system`, `eval`, `exec`, `shutil.rmtree`, `os.remove`, `fs.rm`, `child_process.exec`, `cursor.executescript`, Redis flush |
| `WARNING` | State-modifying writes | File writes, `requests.post`, `axios.post`, `httpx.put`, DB INSERT/UPDATE/DELETE, email sends |
| `INFO` | Read-only external access | `requests.get`, `axios.get`, file reads, `.read_text()`, DB SELECT, Redis `get` |

HTTP severity is method-aware: `GET`, `HEAD`, and `OPTIONS` resolve to `INFO`; `POST`, `PUT`, `PATCH`, and `DELETE` resolve to `WARNING`. Generic `fetch` calls (where the method is in the options object) are conservatively `WARNING`.

### Policy Gate Detection

A gate is credited only when the analyzed path contains a function with conditional branches that check parameters and raise an authorization-like exception, or a decorator whose wrapper logic is structurally analyzed as a gate.

**Not credited:** logging calls, `try/except` around the operation, generic exceptions without authorization semantics, decorator names alone without structural proof.

---

## Supported Frameworks

### Python

| Framework | Detection |
|-----------|-----------|
| LangChain / LangGraph | `@tool` decorator, `bind_tools`, `create_react_agent`, `StructuredTool.from_function` |
| CrewAI | `@tool` decorator, `class MyTool(BaseTool)` subclasses |
| AutoGen v0.2 / v0.4 | `register_function`, `ConversableAgent`, `AssistantAgent` tool lists |
| OpenAI / Swarm | `tools=` argument, dispatch maps, `Agent` tool parameter |
| Pydantic AI | `@agent.tool`, `@agent.tool_plain` |
| LlamaIndex | `FunctionTool`, `QueryEngineTool` |
| Haystack | `@component`, `Pipeline.add_component` |
| Google ADK | `Agent`, `LlmAgent`, `tool` parameter |
| Smolagents / HF Agents | `@tool`, `ToolCollection`, `PipelineTool` |
| Semantic Kernel (Python) | `@kernel_function`, plugin classes |
| MCP Python SDK | `@server.call_tool`, `@mcp.tool` |
| Generic `@tool` | Any `@tool`-shaped import from any package |

### TypeScript / JavaScript

| Framework | Detection |
|-----------|-----------|
| ElizaOS | `Action` typed objects with `handler`, plugin arrays, `runtime.registerAction` |
| OpenAI Agents SDK | `tool()`, `Agent` constructor `tools=` |
| LangChain.js / LangGraph.js | `DynamicTool`, `StructuredTool`, `createReactAgent` |
| Vercel AI SDK | `tool()`, `streamText tools=`, `generateText tools=` |
| MCP SDK | `server.tool()`, `server.setRequestHandler` |
| Mastra | `createTool`, `Agent`, workflow step tools |
| Anthropic SDK | `messages.create` with `tools=` |
| Inngest | `inngest.createFunction` |
| Temporal | Workflow activity registrations |
| Playwright / Puppeteer | Browser automation action roots |

Framework labels come from structural analysis of imports and code shape, not string matching against known project names.

---

## Benchmarks

Scanned on real production agentic repositories (v1.6.2). All results generated live — no sampling or summarization.

| Repository | Language | Files | CEEs | Critical | Warning | Info |
|------------|----------|------:|-----:|---------:|--------:|-----:|
| [AutoGPT](https://github.com/Significant-Gravitas/AutoGPT) | Python + TS | 1,735 | **556** | 3 | 92 | 272 |
| [MetaGPT](https://github.com/geekan/MetaGPT) | Python | 660 | **455** | 10 | 191 | 175 |
| [elizaos/eliza](https://github.com/elizaos/eliza) | TypeScript | 512 | **198** | 2 | 78 | 20 |
| [SuperAGI](https://github.com/TransformerOptimus/SuperAGI) | Python + TS | 362 | **125** | 2 | 48 | 35 |
| [OpenHands](https://github.com/All-Hands-AI/OpenHands) | Python + TS | 1,702 | **80** | 0 | 5 | 10 |
| [gpt-researcher](https://github.com/assafelovic/gpt-researcher) | Python | 278 | **40** | 0 | 0 | 3 |
| [AgentGPT](https://github.com/reworkd/AgentGPT) | Python + TS | 234 | **29** | 0 | 10 | 10 |
| [ChatDev](https://github.com/OpenBMB/ChatDev) | Python | 201 | **1** | 0 | 0 | 0 |
| [TaskWeaver](https://github.com/microsoft/TaskWeaver) | Python | 144 | 0 | 0 | 0 | 0 |
| [devika](https://github.com/stitionai/devika) | Python | 85 | 0 | 0 | 0 | 0 |

**Zero-result systems** (TaskWeaver, devika): Tool calls are present but no standard tool-registration patterns are detected — no `@tool` decorators, no `BaseTool` subclasses, no recognized framework registrations. WyScan correctly emits nothing rather than guessing.

**CEEs vs. findings:** `cees` is the full canonical execution event inventory. `findings` is the AFB04-classified subset (operations where no gate was detected in the traced path). CEE count reflects scanner coverage depth; finding count reflects actual exposure.

---

## JSON Output

```bash
wyscan scan ./project --json
```

```json
{
  "version": "1.6.2",
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
      "classification_note": "Detected reachable call from tool \"setup_agent\" (langchain) to shutil.rmtree through 1 intermediate call(s). The analyzed path crosses file boundaries. No policy gate detected.",
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
    "languages_scanned": ["python", "typescript"],
    "languages_skipped": [],
    "frameworks_detected": ["langchain", "openai"],
    "files_analyzed": 34,
    "files_skipped": 0,
    "failed_files": [],
    "skipped_files": [],
    "partial": false,
    "total_files_discovered": 34,
    "file_limit": null,
    "file_limit_hit": false,
    "limitations": [
      "The analyzed file set is graphed together per language. Changed-file scans do not guarantee full repository coverage."
    ]
  },
  "methodology": {
    "runtime_surfaces": ["cli_only", "github_app_backend"],
    "regex_main_method": false,
    "primary_method": "Tree-sitter AST parsing plus semantic tool-registration and call-path analysis.",
    "anti_overfit_policy": {
      "hardcoded_agent_schema_rules": false,
      "memorized_framework_schema_rules": false,
      "note": "Detection relies on language and framework structural first principles, not memorized project-specific schemas."
    },
    "evidence_integrity_policy": [
      "Only report operations tied to parsed code and traced evidence.",
      "No hardcoded repository-specific shortcuts in detector logic.",
      "Uncertainty is surfaced explicitly through unresolved_calls, depth_limit_hit, and evidence_kind fields."
    ],
    "coverage_note": "Coverage is limited to the analyzed file set. External packages and dynamically composed tool registrations are not traced."
  }
}
```

**Field notes:**

- `findings` — AFB04-classified subset; operations with `gate_status: absent`. Drives the exit code.
- `cees` — full canonical execution event inventory across all analyzed paths.
- `call_path` — traced function chain from tool registration to matched operation.
- `evidence_kind` — `semantic` (framework import resolved), `structural` (code shape), or `heuristic`.
- `depth_limit_hit` — call tracing reached the configured depth ceiling; result is lower confidence.
- `coverage_note` — plain-language scope note for this scan.

---

## Scope

WyScan currently does all of the following:

- Parses Python and TypeScript/JavaScript source with tree-sitter.
- Resolves tool registrations from framework-specific code structure through semantic analysis.
- Matches reachable operations: shell execution, file mutation, file reads, HTTP requests, email sends, and common database calls.
- Classifies HTTP severity by method.
- Suppresses findings when a structural policy gate is detected in the analyzed path.
- Carries supporting evidence (resource hints, structural vs. semantic registration evidence) into CEEs.

WyScan currently does not do any of the following:

- Execute your code.
- Trace into third-party package internals.
- Detect AFB01, AFB02, or AFB03.
- Support Rust.

---

## GitHub App

WyScan can run as a GitHub App for supported webhook events.

- Push events run on the repository default branch only.
- Pull request events run on `opened` and `synchronize`.
- Findings appear in a GitHub Check run.
- Pull requests receive an updated comment only when findings are present.

### Deployment

```bash
docker build -t wyscan-github-app .

docker run -d \
  --name wyscan-app \
  -p 3000:3000 \
  -e GITHUB_APP_ID=your-app-id \
  -e GITHUB_PRIVATE_KEY="$(cat private-key.pem)" \
  -e GITHUB_WEBHOOK_SECRET=your-webhook-secret \
  wyscan-github-app
```

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_APP_ID` | Yes | GitHub App ID from app settings |
| `GITHUB_PRIVATE_KEY` | Yes | PEM content (`\n` for newlines in env) |
| `GITHUB_WEBHOOK_SECRET` | Yes | Webhook signature secret |
| `PORT` | No | Server port (default: 3000) |

```bash
curl http://localhost:3000/health
# {"status":"ok"}
```

For full setup, see `docs/GITHUB_APP_SETUP.md`.

---

## Current Limitations

- Directory scans graph the analyzed file set per language. Changed-file scans do not guarantee full repository coverage.
- External packages are not traced.
- Dynamic runtime tool registration is not guaranteed to be detected.
- Framework labels and sink matching are not complete runtime framework models.
- Validation-helper severity downgrades are heuristic only.
- AFB01, AFB02, and AFB03 are not implemented.

---

## Development

```bash
npm install
npm run build
npm test
npm run wyscan -- scan ./project
```

### Makefile Targets

| Target | Description |
|--------|-------------|
| `make build` | Build TypeScript |
| `make test` | Run tests |
| `make lint` | Run linter |
| `make check` | Run wyscan self-check |
| `make install` | Build and npm link globally |
| `make clean` | Remove build artifacts |
| `make typecheck` | Type check without emit |
| `make watch` | Watch mode |
| `make benchmark-N` | Scan benchmark fixture N |

---

## Documentation

- `docs/install.md`
- `docs/usage.md`
- `docs/detection.md`
- `docs/github-app.md`
- `docs/limitations.md`
- `docs/GITHUB_APP_SETUP.md`

---

## License

Apache-2.0. See `LICENSE`.
