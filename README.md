# Argus

Argus is a static analysis tool for agentic AI codebases. It identifies **AFB04 (Unauthorized Action)** boundaries, the points where an agent can execute actions that affect systems or data.

The project provides:
- A command-line scanner for local analysis
- A GitHub App mode for automated pull request and push scanning

## What Argus Detects

Argus focuses on action-capable execution paths in Python and TypeScript/JavaScript projects, including:
- Tool definitions exposed to agent reasoning
- Shell command execution
- File system writes and destructive file operations
- External API calls
- Database execution paths
- Dynamic code execution primitives

## Why This Matters

In agentic systems, boundaries between reasoning and execution are high-risk points. Argus helps teams find these boundaries early so they can review authorization, validation, and guardrail coverage before deployment.

## Installation

Build the project:

```bash
npm install
npm run build
```

## CLI Usage

### Install globally

**NPM package** (when published):
```bash
npm install -g @plarix/argus
```

**Link locally for development**:
```bash
npm run build && npm link
```

After installation or linking, the `argus` command is available system-wide:

```bash
argus scan ./my-agent-repo
argus check
argus version
```

### Direct usage (without install):

### Direct usage (without install):

For development without global install:

```bash
npm run argus -- scan ./path/to/project
```

Or use the compiled binary directly:

```bash
node dist/cli/index.js scan ./path/to/project
```

### Commands

**Scan a directory or file:**
```bash
argus scan <path>
```

**Check dependencies:**
```bash
argus check
```

**Show version:**
```bash
argus version
```

**Show help:**
```bash
argus help
```

### Scan Options

**JSON output** (stable schema for CI/CD):
```bash
argus scan ./project --json
```

**Filter by severity level:**
```bash
argus scan ./project --level critical
argus scan ./project --level warning
argus scan ./project --level info
```

**Write to file:**
```bash
argus scan ./project --output report.txt
argus scan ./project --json --output report.json
```

**Summary only** (one line for CI):
```bash
argus scan ./project --summary
```

### Exit Codes

- `0`: No critical or warning findings
- `1`: Warning level findings detected
- `2`: Critical level findings detected
- `3`: Scanner error (parse failure, missing dependency)

### JSON Schema

The `--json` flag outputs structured data with a stable schema:

```json
{
  "version": "0.1.0",
  "scanned_path": "/path/to/repo",
  "files_analyzed": 34,
  "runtime_ms": 1200,
  "findings": [
    {
      "severity": "CRITICAL",
      "file": "path/to/file.py",
      "line": 47,
      "function": "shutil.rmtree",
      "tool_registration": "setup_agent",
      "description": "Tool can reach dangerous operation without gate",
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

### Example Output

Terminal output (default):
```
argus  v0.1.0  by Plarix
AFB Scanner — github.com/plarix-security/argus

Scanning: /path/to/agent-project
──────────────────────────────────────────────────

CRITICAL  agent_tools.py:19
subprocess.run(command, shell=True) — shell command execution
reachable from @tool (langchain), no policy gate in call path.
Agent can execute this without authorization basis.

WARNING   api_client.py:42
requests.post(url, data=payload) — external API call reachable
from @tool (langchain), no policy gate in call path.
Agent can execute this without authorization basis.

──────────────────────────────────────────────────
2 critical  1 warning  3 info  34 files  1.2s
```

## GitHub App Mode

Argus can run as a GitHub App webhook service and scan pull request and push events.

### Required environment variables

```bash
GITHUB_APP_ID=your-app-id
GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n..."
GITHUB_WEBHOOK_SECRET=your-webhook-secret
PORT=3000
```

### Run the service

```bash
npm start
```

The service exposes:
- `GET /health` for health checks
- `POST /webhook` for GitHub webhook events

## Scope and Limitations

Current scope:
- AFB04 detection
- Python and TypeScript/JavaScript scanning
- Pattern-based static analysis using AST parsing

Out of scope in the current version:
- AFB01, AFB02, and AFB03 classes
- Runtime behavior analysis
- Automatic remediation

## Development

```bash
npm run build
npm test
npm run dev
```

## License

MIT
