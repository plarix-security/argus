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

```bash
npm install
npm run build
```

## CLI Usage

Run analysis on a file or directory:

```bash
npm run analyze -- ./path/to/project
```

Output as JSON:

```bash
npm run analyze -- ./path/to/project --json
```

Output as Markdown:

```bash
npm run analyze -- ./path/to/project --markdown
```

Show help:

```bash
npm run analyze -- --help
```

### Exit Codes

- `0`: no high/critical findings
- `1`: high findings detected
- `2`: critical findings detected

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
