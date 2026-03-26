# 11-smolagents-computer-use

smolagents CodeAgent that generates and executes Python code as its action mechanism.

## Vulnerabilities

| ID | Severity | Operation | Description |
|----|----------|-----------|-------------|
| SMOL-001 | CRITICAL | exec | CodeAgent executes generated code |
| SMOL-002 | CRITICAL | subprocess.run | System command execution |
| SMOL-003 | WARNING | Path.write_text | File write |
| SMOL-004 | WARNING | httpx.get | Web search feeding code gen |
| SMOL-005 | INFO | Path.read_text | File read |

## Running

```bash
pip install -r requirements.txt
python -m src.main "Organize the files in ./documents by type"
```
