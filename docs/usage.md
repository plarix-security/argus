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
| `--recursive` | `-r` | Accepted, but scanning is already recursive |
| `--quiet` | `-q` | Suppresses output and relies on exit code |
| `--debug` | `-d` | Prints thrown errors during failures |

## Exit Codes

| Code | Current meaning |
|------|-----------------|
| 0 | No critical or warning findings were reported |
| 1 | At least one warning finding was reported and no critical finding was reported |
| 2 | At least one critical finding was reported |
| 3 | Scanner initialization failed, the target path was invalid, or a single-file scan failed |

Directory scans currently keep failed files in report metadata instead of promoting the whole run to exit code `3`.

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
      "description": "Tool \"setup_agent\" (langchain) can reach shutil.rmtree through 1 call(s). No policy gate or authorization check detected in call path. Agent can execute this operation without authorization basis.",
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
    "files_skipped": 2
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
