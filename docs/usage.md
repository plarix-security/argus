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

## Examples

```bash
wyscan scan ./my-agent-project
wyscan scan ./tools/agent.py
wyscan scan ./project --json
wyscan scan ./project --level critical
wyscan scan ./project --output report.txt
wyscan scan ./project --summary
```
