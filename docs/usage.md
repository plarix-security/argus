# Usage

## Commands

```bash
wyscan scan <path> [flags]
wyscan check
wyscan version
wyscan help
```

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

## JSON Output

Current CLI JSON shape:

```json
{
  "version": "1.0.0",
  "scanned_path": "/absolute/path",
  "files_analyzed": 34,
  "runtime_ms": 1200,
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
      "description": "Detected reachable call from tool \"setup_agent\" (langchain) to shutil.rmtree through 1 intermediate call(s). No policy gate detected in the analyzed call path.",
      "code_snippet": "shutil.rmtree(agent_dir)",
      "category": "file_operation"
    }
  ],
  "summary": {
    "critical": 2,
    "warning": 3,
    "info": 5,
    "suppressed": 0
  },
  "coverage": {
    "languages_scanned": ["python"],
    "languages_skipped": ["typescript", "javascript"],
    "frameworks_detected": ["langchain"],
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

## Examples

```bash
wyscan scan ./my-agent-project
wyscan scan ./tools/agent.py
wyscan scan ./project --json
wyscan scan ./project --level critical
wyscan scan ./project --output report.txt
wyscan scan ./project --summary
```
