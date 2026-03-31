# WyScan

Static scanner for Python agent code that reports reachable operations from detected tool registrations.

WyScan is currently a Python-first AFB04 scanner. It parses Python with tree-sitter, resolves tool registrations semantically when the code structure allows it, traces reachable calls across the analyzed Python file set, and reports matched operations when no credited structural policy gate is detected in that analyzed path.

TypeScript and JavaScript scanning are intentionally deferred. `.ts`, `.tsx`, `.js`, and `.jsx` files are skipped explicitly and produce no findings.

```bash
wyscan scan ./agent-project
```

Example output:

```text
wyscan v1.2.1  ·  Plarix

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

- Parses Python source with tree-sitter.
- Resolves Python tool registrations from framework-specific code structure first, then falls back to registration patterns when semantic resolution is incomplete.
- Matches reachable operations such as shell execution, file mutation, file reads, HTTP requests, email sends, and common database calls.
- Suppresses findings when a structural policy gate is detected in the analyzed path.
- Carries supporting evidence such as traced input flow, resource hints, and structural versus fallback registration evidence into CEEs.

WyScan currently does not do any of the following:

- Execute your code.
- Scan TypeScript or JavaScript for findings.
- Guarantee full-repository coverage in changed-file GitHub App scans.
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
```

## Commands

| Command | Description |
|---------|-------------|
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

Severity is based on the matched operation category. Limited naming heuristics still exist, but they only adjust fallback-classified paths where structural or semantic proof was incomplete:

- Irreversible operations such as `subprocess.run`, `eval`, `exec`, and file deletion are forced to `CRITICAL`.
- Names and snippets that suggest sensitive data can elevate fallback-classified paths by one level.
- Validation-helper names in the analyzed path can downgrade fallback-classified paths by one level.

These severity adjustments are heuristic only. They are not proof of attacker intent, exploitability, or data flow.

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

Framework detection is Python-only. WyScan prefers semantic extraction from framework code structure such as decorator imports, tool lists, helper-returned tool bundles, `create_react_agent(...)`, `bind_tools(...)`, and `function_map` style registrations. Pattern matching remains as fallback when structural resolution is incomplete.

The shipped detector currently labels patterns for frameworks such as:

- LangChain
- CrewAI
- AutoGen
- OpenAI tool schemas and dispatch maps
- LlamaIndex
- MCP
- Generic Python decorator-style tool registrations

Some additional framework names still exist in fallback pattern tables, but Python semantic coverage is the primary path and the only supported finding scope for now.

## Policy Gate Detection

WyScan credits a policy gate only when the analyzed path contains code it recognizes as a structural authorization gate.

Current gate credit comes from:

- A function with conditional branches that check parameters and raise an authorization-like exception
- Decorators that are structurally analyzed as wrappers that can prevent execution
- Imported decorators whose wrapper logic is structurally analyzed as gates

Current non-gates:

- Validation-helper names alone
- Authorization-like decorator names alone
- Logging calls
- `try/except` around an operation
- Generic exceptions that do not look authorization-related

## JSON Output

```bash
wyscan scan ./project --json
```

Current CLI JSON shape:

```json
{
  "version": "1.2.1",
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
    "languages_scanned": ["python"],
    "languages_skipped": ["typescript", "javascript"],
    "frameworks_detected": ["langchain", "openai"],
    "files_analyzed": 34,
    "files_skipped": 2,
    "failed_files": [],
    "skipped_files": [
      {
        "file": "/absolute/path/src/tool.ts",
        "language": "typescript",
        "reason": "TypeScript scanning is not implemented in this version. File skipped."
      }
    ],
    "partial": true,
    "total_files_discovered": 36,
    "file_limit": 9007199254740991,
    "file_limit_hit": false,
    "limitations": [
      "The analyzed Python file set is graphed together. Changed-file scans do not guarantee full repository coverage."
    ]
  }
}
```

Notes:

- `files_analyzed` at the top level is the report file count used by the current CLI output.
- `coverage.files_analyzed` counts Python files only.
- TypeScript and JavaScript files are reflected as skipped coverage, not findings.
- `cees` is the full detected execution-event inventory for the analyzed path set.
- `findings` is the AFB04 subset of `cees`.
- `call_path` lists the traced function path in the analyzed file set.
- `evidence_kind`, `supporting_evidence`, `resource`, and `changes_state` expose the current proof and action summary for each finding or CEE.
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

## Current Limitations

- Python is the only supported finding language.
- TypeScript and JavaScript files are skipped explicitly and produce no findings.
- Directory scans graph the analyzed Python file set together. Changed-file scans still do not guarantee full repository coverage.
- External packages are not traced.
- Dynamic runtime tool registration is not guaranteed to be detected.
- Framework labels are pattern matches, not complete framework models.
- Validation-helper severity downgrades are heuristic only.
- AFB01, AFB02, and AFB03 are not implemented.

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
