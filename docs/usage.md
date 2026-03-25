# Usage

## Commands

### wyscan scan

Scan a directory or file for AFB exposures.

```bash
wyscan scan <path> [flags]
```

Examples:

```bash
# Scan a directory
wyscan scan ./my-agent-project

# Scan a single file
wyscan scan ./tools/agent.py

# Output JSON
wyscan scan ./project --json

# Show only critical findings
wyscan scan ./project --level critical

# Write report to file
wyscan scan ./project --output report.txt

# One-line summary for CI
wyscan scan ./project --summary
```

### wyscan check

Verify dependencies are installed correctly.

```bash
wyscan check
```

### wyscan version

Print version and exit.

```bash
wyscan version
```

### wyscan help

Show usage information.

```bash
wyscan help
wyscan help scan
```

## Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--level <severity>` | `-l` | Minimum severity to report: `critical`, `warning`, `info` |
| `--output <file>` | `-o` | Write report to file instead of stdout |
| `--json` | `-j` | Output structured JSON |
| `--summary` | `-s` | One-line summary only |
| `--recursive` | `-r` | Scan recursively (default: true) |
| `--quiet` | `-q` | Suppress output, exit code only |
| `--debug` | `-d` | Show debug information |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No critical or warning findings |
| 1 | Warning level findings detected |
| 2 | Critical level findings detected |
| 3 | Scanner error (parse failure, missing dependency) |

## CI/CD Integration

### Fail on Critical

```bash
wyscan scan ./src --level critical
if [ $? -eq 2 ]; then
  echo "Critical AFB exposures detected"
  exit 1
fi
```

### Fail on Warning or Critical

```bash
wyscan scan ./src
if [ $? -ne 0 ]; then
  echo "AFB exposures detected"
  exit 1
fi
```

### JSON for Processing

```bash
wyscan scan ./src --json > report.json
```

## JSON Output Schema

```json
{
  "version": "1.0.0",
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
      "description": "Tool setup_agent (langchain) can reach shutil.rmtree. No policy gate detected.",
      "afb_type": "AFB04"
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
    "frameworks_detected": ["langchain", "crewai"],
    "files_analyzed": 34,
    "files_skipped": 2,
    "call_graph_depth_used": 3,
    "confidence_note": "Non-comprehensive. Static analysis only. Runtime-generated tool wiring and external package internals are not traced."
  }
}
```
