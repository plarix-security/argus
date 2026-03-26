# 09-multi-agent-pipeline-fastapi

Production-style agentic API service with FastAPI and LangGraph.

## Vulnerabilities

| ID | Severity | Operation | Description |
|----|----------|-----------|-------------|
| FASTAPI-001 | CRITICAL | eval | Pandas operations via eval |
| FASTAPI-002 | CRITICAL | subprocess.run | Script execution |
| FASTAPI-003 | WARNING | httpx.post | Recursive agent spawning |
| FASTAPI-004 | WARNING | Path.read_text | Path traversal via agent_id |
| FASTAPI-005 | WARNING | requests.post | Content publishing |
| FASTAPI-006 | INFO | cursor.execute | Database query |

## Running

```bash
pip install -r requirements.txt
uvicorn src.api:app --host 0.0.0.0 --port 8000
curl -X POST http://localhost:8000/run-agent -d '{"task": "analyze sales data"}'
```
