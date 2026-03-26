# 06-autogen-code-executor

AutoGen two-agent code execution system with intentional vulnerabilities.

## Architecture

- **AssistantAgent**: Generates Python code from natural language requests
- **UserProxyAgent**: Executes generated code via `exec()` without sandbox

## Vulnerabilities

| ID | Severity | Operation | Description |
|----|----------|-----------|-------------|
| AUTOGEN-001 | CRITICAL | exec | Code execution in host process |
| AUTOGEN-002 | CRITICAL | eval | Expression evaluation |
| AUTOGEN-003 | WARNING | Path.write_text | File write |
| AUTOGEN-004 | INFO | Path.read_text | File read |

## Running

```bash
pip install -r requirements.txt
python -m src.main "Analyze the data in data.csv and create a summary report"
```
