# 01-react-tool-agent

A minimal ReAct-pattern agent using the OpenAI SDK (2025 responses API) demonstrating basic tool detection patterns.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      ReAct Agent Loop                        │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐  │
│  │ Reason  │ -> │   Act   │ -> │ Observe │ -> │ Reason  │  │
│  └─────────┘    └─────────┘    └─────────┘    └─────────┘  │
│       │              │                              │       │
│       v              v                              v       │
│   OpenAI LLM    Tool Calls                   Continue/Stop  │
└─────────────────────────────────────────────────────────────┘
                       │
         ┌─────────────┼─────────────┐
         v             v             v
    ┌─────────┐  ┌──────────┐  ┌──────────┐
    │   Web   │  │Calculator│  │  File    │
    │ Search  │  │  (eval)  │  │  Writer  │
    └─────────┘  └──────────┘  └──────────┘
         │             │             │
         v             v             v
    External API   eval() ⚠️    Filesystem ⚠️
```

## Intentional Vulnerabilities

### CRITICAL: Code Execution via eval() (AFB04)
- **File**: `src/tools/calculator.py:25`
- **Pattern**: `eval(expression)` with LLM-generated expression
- **Attack**: `calculate("__import__('os').system('whoami')")`

### CRITICAL: Shell Execution via subprocess (AFB04)
- **File**: `src/tools/calculator.py:38`
- **Pattern**: `subprocess.run(['python', '-c', expression])`
- **Attack**: Fallback calculator executes Python in shell

### WARNING: Path Traversal (AFB04)
- **File**: `src/tools/file_writer.py:32`
- **Pattern**: `Path(filepath).write_text(content)` without validation
- **Attack**: `write_file("../../../etc/cron.d/backdoor", "malicious")`

## Running

```bash
# Set up environment
cp .env.example .env
# Edit .env with your API keys

# Install dependencies
pip install -r requirements.txt

# Run the agent
python -m src.main "What is 2+2 and save the result to output.txt"
```

## Expected WyScan Findings

| ID | Severity | Operation | Tool |
|----|----------|-----------|------|
| REACT-001 | CRITICAL | eval | calculate |
| REACT-002 | CRITICAL | subprocess.run | calculate_subprocess |
| REACT-003 | WARNING | Path.write_text | write_file |
| REACT-004 | WARNING | mkdir | write_file |
| REACT-005 | WARNING | httpx.get | web_search |
| REACT-006 | INFO | Path.read_text | read_file |
| REACT-007 | INFO | glob | list_files |

## Files

```
01-react-tool-agent/
├── README.md                 # This file
├── .env.example              # Environment variables template
├── cee_manifest.json         # Ground truth for WyScan validation
├── findings.json             # WyScan output (populated by scan)
├── requirements.txt          # Python dependencies
├── Dockerfile                # Container build
└── src/
    ├── __init__.py
    ├── main.py               # Entry point
    ├── agent.py              # ReAct agent implementation
    └── tools/
        ├── __init__.py
        ├── calculator.py     # eval() vulnerability
        ├── file_writer.py    # Path traversal vulnerability
        ├── web_search.py     # External API call
        └── safe_calculator.py # Gated example (true negative)
```
